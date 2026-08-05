/**
 * Regression for issue #301: a commitment_signed owed at the moment of a
 * crash is never sent after restart + reestablish, and the in-flight HTLC
 * stalls until its CLTV expiry.
 *
 * The interleaving needs a real wire, not the loopback relay: the receiver
 * processes the payer's commitment_signed (persisting addLocallyRevoked and
 * needsCommitment, advancing the local commitment number), its revoke_and_ack
 * DELIVERS, and then the process dies before the counter commitment_signed is
 * built. The payer holds the revoke, so BOLT 2's reestablish numbers ask
 * neither side to retransmit anything; the peer is purely waiting for our
 * commitment_signed, and only the reestablish tail can release it.
 */

import { expect } from 'chai';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ChannelState } from '../../src/lightning/channel/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { MessageType } from '../../src/lightning/message/types';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	createChaosNode,
	buildDirectGraph,
	openReadyChannel,
	settle,
	KillSwitch,
	sealableStorage
} from './helpers/chaos-harness';

const PAYER_SEED = 74;
const VICTIM_SEED = 75;

async function waitForCond(
	cond: () => boolean,
	what: string,
	timeoutMs = 5_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		if (cond()) return;
		await settle();
	}
	throw new Error(`timed out waiting for ${what}`);
}

describe('Reestablish releases a durably owed commitment_signed (#301)', function () {
	this.timeout(30_000);

	let payer: LightningNode;
	let victim: LightningNode | null = null;
	let restored: LightningNode | null = null;
	let storage: SqliteStorage | null = null;
	let dbDir: string;

	beforeEach(() => {
		dbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-owed-cs-'));
	});

	afterEach(() => {
		for (const n of [victim, restored, payer]) {
			try {
				n?.destroy();
			} catch {
				/* ignore */
			}
		}
		victim = null;
		restored = null;
		try {
			storage?.close();
		} catch {
			/* ignore */
		}
		storage = null;
		fs.rmSync(dbDir, { recursive: true, force: true });
	});

	it('sends the owed commitment_signed after a crash between revoke_and_ack and the counter-sign', async function () {
		const dbPath = path.join(dbDir, 'victim.db');
		storage = new SqliteStorage(dbPath);
		storage.open();

		payer = createChaosNode(PAYER_SEED);
		// The seal makes the crash exact: at the kill instant every later
		// write is dropped, so the durable state is precisely what commit-
		// before-send guaranteed at the revoke_and_ack — WITHOUT the counter
		// commitment_signed the process would have built next.
		const kill = new KillSwitch();
		victim = createChaosNode(VICTIM_SEED, {
			storage: sealableStorage(storage, kill)
		});
		const payerId = payer.getNodeId();
		const victimId = victim.getNodeId();

		// Manual wire. `currentVictim` re-points after the restart;
		// `victimDead` silences the dead process the instant its final
		// revoke_and_ack has left, exactly like a SIGKILL right after the
		// send returns.
		let currentVictim = victim;
		let victimDead = false;
		let armed = false;
		payer.on(
			'message:outbound',
			(peerId: string, type: number, payload: Buffer) => {
				if (peerId !== victimId) return;
				currentVictim.handlePeerMessage(payerId, type, payload);
			}
		);
		victim.on(
			'message:outbound',
			(peerId: string, type: number, payload: Buffer) => {
				if (victimDead || peerId !== payerId) return;
				payer.handlePeerMessage(victimId, type, payload);
				if (armed && type === MessageType.REVOKE_AND_ACK) {
					victimDead = true;
					kill.fire('post-send:revoke_and_ack');
				}
			}
		);

		openReadyChannel(payer, victim, 1_000_000n);
		buildDirectGraph(payer, PAYER_SEED, VICTIM_SEED);

		// Baseline round proves the harness end to end.
		const baseline = victim.createInvoice({
			amountMsat: 50_000n,
			description: 'owed-cs baseline'
		});
		const baselinePayment = payer.sendPayment(baseline.bolt11);
		await waitForCond(
			() => baselinePayment.status === PaymentStatus.COMPLETED,
			'baseline payment to complete'
		);

		// Interrupted round: the revoke_and_ack delivers, everything after
		// dies with the process.
		const interrupted = victim.createInvoice({
			amountMsat: 40_000n,
			description: 'owed-cs interrupted'
		});
		const interruptedHash = interrupted.paymentHash.toString('hex');
		armed = true;
		const interruptedPayment = payer.sendPayment(interrupted.bolt11);
		await waitForCond(() => victimDead, 'the kill to fire');
		expect(interruptedPayment.status).to.equal(PaymentStatus.PENDING);

		// The payer holds the revoke but never received the counter
		// commitment_signed: the HTLC is still live on its side.
		const payerChannel = payer.getChannelManager().listChannels()[0];
		expect(payerChannel.getFullState().htlcs.size).to.be.greaterThan(0);

		// Crash: destroy the victim, close its storage connection.
		victim.removeAllListeners('message:outbound');
		victim.destroy();
		victim = null;
		storage.close();
		payer.getChannelManager().handlePeerDisconnected(victimId);

		// Fresh process on the same DB file.
		storage = new SqliteStorage(dbPath);
		storage.open();
		restored = createChaosNode(VICTIM_SEED, { storage });
		expect(restored.getNodeId()).to.equal(victimId);
		currentVictim = restored;
		// Hold the restored node's outbound until both sides have emitted
		// their channel_reestablish, then flush in order: what a real socket
		// pair delivers (both reestablishes cross before either response).
		let holdQueue: Array<[number, Buffer]> | null = [];
		restored.on(
			'message:outbound',
			(peerId: string, type: number, payload: Buffer) => {
				if (peerId !== payerId) return;
				if (holdQueue) {
					holdQueue.push([type, payload]);
					return;
				}
				payer.handlePeerMessage(victimId, type, payload);
			}
		);

		const restoredChannel = restored.getChannelManager().listChannels()[0];
		expect(restoredChannel.getState()).to.equal(
			ChannelState.AWAITING_REESTABLISH
		);

		// Reconnect: both sides exchange channel_reestablish.
		restored.getChannelManager().handlePeerReconnected(payerId);
		payer.getChannelManager().handlePeerReconnected(victimId);
		const held = holdQueue;
		holdQueue = null;
		for (const [t, p] of held) {
			payer.handlePeerMessage(victimId, t, p);
		}
		await settle();

		await waitForCond(
			() => restoredChannel.getState() === ChannelState.NORMAL,
			'restored channel to reestablish'
		);

		// The owed commitment_signed must flow now: the round completes, the
		// receiver fulfills, and the payer's blocked payment resolves.
		await waitForCond(
			() => interruptedPayment.status === PaymentStatus.COMPLETED,
			'the interrupted payment to complete after reestablish'
		);
		const received = restored
			.listPayments()
			.find(
				(p) =>
					p.direction === PaymentDirection.INCOMING &&
					p.paymentHash.toString('hex') === interruptedHash
			);
		expect(received?.status).to.equal(PaymentStatus.COMPLETED);

		// Both sides are clean: no stuck HTLCs, both NORMAL.
		await waitForCond(
			() => payerChannel.getFullState().htlcs.size === 0,
			'payer HTLCs to resolve'
		);
		expect(
			restored.getChannelManager().listChannels()[0].getFullState().htlcs.size
		).to.equal(0);
		expect(payerChannel.getState()).to.equal(ChannelState.NORMAL);
	});
});
