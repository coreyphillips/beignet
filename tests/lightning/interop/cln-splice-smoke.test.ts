/**
 * Smoke test: Beignet ↔ CLN splice_init → splice_ack handshake (regtest).
 *
 * Validates Phases 1-3 over the REAL wire against a CLN node built with
 * --experimental-splicing: feature negotiation (option_splice / bit 63), the
 * auto-quiescence STFU exchange, and that CLN replies to our splice_init with a
 * splice_ack (our splice session reaches TX_NEGOTIATION).
 *
 * This does NOT yet complete a splice — driving the interactive-tx, signing and
 * broadcasting is the next phase. It only proves the handshake interops.
 *
 * Requires a CLN container with --experimental-splicing. If you run a standalone
 * container, point the helpers at it:
 *   CLN_CONTAINER=cln-splice npx mocha --exit --timeout 180000 \
 *     -r ts-node/register tests/lightning/interop/cln-splice-smoke.test.ts
 */

import { expect } from 'chai';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	setupClnChannel,
	sleep
} from './cln-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { SpliceState } from '../../../src/lightning/channel/splice';

describe('Interop: Beignet ↔ CLN splice handshake (regtest)', function () {
	this.timeout(180_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let node: LightningNode | undefined;
	let skipAll = false;

	before(async function () {
		const available = await isClnAvailable();
		if (!available) {
			skipAll = true;
			console.log(
				'    ⚠ CLN not available — skipping. Start CLN with --experimental-splicing.'
			);
			this.skip();
			return;
		}
		const client = await createClnClient();
		if (!client) {
			skipAll = true;
			this.skip();
			return;
		}
		cln = client;
		await waitForClnSync(cln);
		const info = await cln.getInfo();
		clnPubkey = info.id;
	});

	afterEach(function () {
		if (node) {
			node.destroy();
			node = undefined;
		}
	});

	it('CLN replies to beignet splice_init with splice_ack (splice-out)', async function () {
		if (skipAll) this.skip();

		// CLN funds a 500k channel to beignet and pushes 200k msat-worth so
		// beignet holds enough local balance to splice-out. (CLN-funded is the
		// reliable setup path; beignet-funded broadcast is debugged separately.)
		const setup = await setupClnChannel(
			cln,
			clnPubkey,
			212,
			500_000,
			200_000_000
		);
		node = setup.node;
		const channelId = setup.channelId;

		const cm = node.getChannelManager();
		const ch = cm.getChannel(channelId);
		expect(ch, 'channel exists').to.not.be.undefined;
		expect(ch!.getState(), 'channel is NORMAL before splice').to.equal(
			'NORMAL'
		);

		// Trace outbound message types so we can see how far the splice drives.
		const MSG_NAMES: Record<number, string> = {
			2: 'stfu',
			66: 'tx_add_input',
			67: 'tx_add_output',
			70: 'tx_complete',
			71: 'tx_signatures',
			74: 'tx_abort',
			80: 'splice_init',
			81: 'splice_ack',
			77: 'splice_locked'
		};
		cm.on('message:outbound', (_pk: string, type: number) => {
			if (MSG_NAMES[type])
				console.log(`    [beignet→CLN] ${MSG_NAMES[type]} (${type})`);
		});

		// Request a splice-out of 50k. This drives auto-quiescence (STFU) then
		// sends splice_init; CLN should reply with splice_ack.
		const result = node.spliceOut(channelId, 50_000n, 3000);
		expect(result.ok, `spliceOut accepted: ${result.error || ''}`).to.equal(
			true
		);

		// Poll the splice session as it advances:
		//   splice_init sent -> AWAITING_ACK
		//   splice_ack from CLN -> TX_NEGOTIATION
		//   our tx_add_input/output + both tx_complete -> AWAITING_TX_SIGNATURES
		// The session is created only once quiescence completes over the real
		// wire (spliceOut is fire-and-forget), and against a fast CLN the
		// intermediate states can flash by between polls — so poll tightly,
		// tolerate a missing session while quiescence is in flight, and treat
		// any at-or-past-signatures state as proof the ack + negotiation
		// happened.
		let sawTxNegotiation = false;
		let reachedTxSigs = false;
		let sawSession = false;
		const deadline = Date.now() + 90_000;
		while (Date.now() < deadline) {
			const session = cm.getChannel(channelId)?.getSpliceSession();
			const state = session?.getState();
			if (state !== undefined) sawSession = true;
			if (state === SpliceState.TX_NEGOTIATION) sawTxNegotiation = true;
			if (
				state === SpliceState.AWAITING_TX_SIGNATURES ||
				state === SpliceState.AWAITING_SPLICE_LOCKED ||
				state === SpliceState.COMPLETE
			) {
				reachedTxSigs = true;
				break;
			}
			if (state === SpliceState.ABORTED || (sawSession && state === undefined)) {
				break;
			}
			await sleep(200);
		}

		// The interactive-tx negotiation (shared input + outputs + tx_complete)
		// completed with CLN — which implies splice_init/splice_ack succeeded
		// even when the transient TX_NEGOTIATION state fell between polls.
		expect(
			reachedTxSigs,
			'interactive-tx negotiation completed with CLN (AWAITING_TX_SIGNATURES)'
		).to.equal(true);
		expect(sawTxNegotiation || reachedTxSigs).to.equal(true);
	});
});
