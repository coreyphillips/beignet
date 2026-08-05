/**
 * tx_abort must terminate (issue 294).
 *
 * handleTxAbort's no-session branch echoed unconditionally, on the BOLT 2
 * reasoning that a node which has not itself sent tx_abort must
 * acknowledge. But "has not itself sent one" was tracked by a one-shot
 * boolean latch armed only on the proactive forget path, so a node that
 * had just echoed did not count as having sent anything, and two nodes
 * with no session (both restarted, both unwound, or one talking to a peer
 * that answers answers) echoed each other forever. In the chaos matrix
 * every splice kill point tripped it: the restarted side sends two aborts
 * (the proactive forget and the answer to the peer's next_funding_txid),
 * the latch absorbs only one ack, and the second echo starts the loop.
 * Before the harness grew a wire valve, the loop exhausted the V8 heap
 * and killed the process with no output.
 *
 * The fix: every tx_abort this channel sends marks the negotiation, and
 * while marked, incoming aborts are consumed silently. BOLT 2's actual
 * rule is exactly that (a node that has itself sent tx_abort MUST NOT
 * send another in reply). The mark clears on disconnect and when a fresh
 * interactive negotiation starts, so a genuine new abort conversation
 * still gets its echo.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import { encodeTxAbortMessage } from '../../src/lightning/message/interactive-tx';
import {
	IRecoveryCommitResult,
	SafetyTransition
} from '../../src/lightning/recovery/types';

const ALICE_SEED = 91;
const BOB_SEED = 92;

/**
 * Hard ceiling on tx_abort deliveries. Pre-fix the exchange is unbounded
 * (synchronous loopback recursion), so the wire stops delivering aborts
 * past this count and the assertions report the count instead of the
 * runner dying inside an infinite echo.
 */
const ABORT_VALVE = 40;

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`txabort-seed-${id}`).digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(
	seedId: number,
	storage?: IStorageBackend
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		storage
	};
}

function createNode(seedId: number, storage?: IStorageBackend): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, storage));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function sealableStorage(
	inner: IStorageBackend,
	dead: { val: boolean }
): IStorageBackend {
	return new Proxy(inner, {
		get(target, prop, receiver): unknown {
			const value = Reflect.get(target, prop, receiver);
			if (typeof value !== 'function') return value;
			if (dead.val && prop !== 'close') {
				return (): undefined => undefined;
			}
			return value.bind(target);
		}
	}) as IStorageBackend;
}

interface IAbortMeter {
	total: number;
}

/**
 * Two-way wire with a dead switch, an optional armed cut behind a message
 * type (the armed message is delivered, everything after it finds the
 * wire gone), and a tx_abort meter with the valve above.
 */
function wire(
	alice: LightningNode,
	bob: LightningNode,
	dead: { val: boolean },
	meter: IAbortMeter,
	cutBehind?: { type: number; armed: { val: boolean } }
): void {
	const route = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			if (dead.val) return;
			if (t === MessageType.TX_ABORT) {
				meter.total++;
				if (meter.total > ABORT_VALVE) return;
			}
			if (
				cutBehind &&
				from === alice &&
				cutBehind.armed.val &&
				t === cutBehind.type
			) {
				dead.val = true;
				to.handlePeerMessage(from.getNodeId(), t, p);
				return;
			}
			to.handlePeerMessage(from.getNodeId(), t, p);
		});
	};
	route(alice, bob);
	route(bob, alice);
}

async function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode
): Promise<Buffer> {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	await settle();
	return channelId;
}

function buildDirectGraph(payer: LightningNode, payeeSeedId: number): void {
	const payerBuf = Buffer.from(payer.getNodeId(), 'hex');
	const payeePubkey = getPublicKey(makeNodeConfig(payeeSeedId).nodePrivateKey);
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });
	const payerIsNode1 = Buffer.compare(payerBuf, payeePubkey) < 0;
	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: payerIsNode1 ? payerBuf : payeePubkey,
		nodeId2: payerIsNode1 ? payeePubkey : payerBuf,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	payer.getGraph().addChannelAnnouncement(announcement);
	const update: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
	payer.getGraph().applyChannelUpdate(update);
	payer.getGraph().applyChannelUpdate({ ...update, channelFlags: 1 });
	payer.registerChannelScid(
		payer.getChannelManager().listChannels()[0].getChannelId()!,
		scid
	);
}

/**
 * A deterministic wallet input for a splice-in, the shape splice.test.ts
 * builds (the interactive-tx audit requires a real input with a working
 * witness signer).
 */
function makeSpliceWallet(amountSats: bigint): {
	walletInput: ISpliceWalletInput;
	changeScript: Buffer;
} {
	bitcoin.initEccLib(ecc);
	const walletPriv = crypto
		.createHash('sha256')
		.update('txabort-splice-wallet')
		.digest();
	const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
	const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub }).output!;
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
	const value = amountSats + 100_000n;
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(walletScript, Number(value));
	return {
		walletInput: {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: 0,
			value,
			sequence: 0xfffffffd,
			signWitness: (
				tx: bitcoin.Transaction,
				inputIndex: number,
				inputValue: bigint
			): Buffer[] => {
				const sighash = tx.hashForWitnessV0(
					inputIndex,
					scriptCode,
					Number(inputValue),
					bitcoin.Transaction.SIGHASH_ALL
				);
				const sig64 = Buffer.from(ecc.sign(sighash, walletPriv));
				const der = bitcoin.script.signature.encode(
					sig64,
					bitcoin.Transaction.SIGHASH_ALL
				);
				return [der, walletPub];
			}
		},
		changeScript: walletScript
	};
}

function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

async function settle(rounds = 6): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

/** Reconnect with both channel_reestablish crossing before any response. */
async function reconnect(
	a: LightningNode,
	b: LightningNode,
	meter: IAbortMeter
): Promise<void> {
	const queue: Array<{
		to: LightningNode;
		from: string;
		type: number;
		payload: Buffer;
	}> = [];
	let hold = true;
	const rewire = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			if (t === MessageType.TX_ABORT) {
				meter.total++;
				if (meter.total > ABORT_VALVE) return;
			}
			if (hold) {
				queue.push({ to, from: from.getNodeId(), type: t, payload: p });
			} else {
				to.handlePeerMessage(from.getNodeId(), t, p);
			}
		});
	};
	rewire(a, b);
	rewire(b, a);
	a.getChannelManager().handlePeerReconnected(b.getNodeId());
	b.getChannelManager().handlePeerReconnected(a.getNodeId());
	while (queue.length > 0) {
		const m = queue.shift()!;
		m.to.handlePeerMessage(m.from, m.type, m.payload);
	}
	hold = false;
	await settle();
}

describe('tx_abort terminates (issue 294)', () => {
	it('an answer to our answer is consumed, never answered again', async function () {
		this.timeout(20_000);
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED);
		const dead = { val: false };
		const meter: IAbortMeter = { total: 0 };
		wire(alice, bob, dead, meter);
		const channelId = await openReadyChannel(alice, bob);
		buildDirectGraph(alice, BOB_SEED);

		// One unsolicited tx_abort with nothing in progress. BOLT 2 owes it
		// exactly one echo; on the live wire the peer (also session-less)
		// then echoes that echo back, and before the fix each side kept
		// answering the other forever.
		alice.handlePeerMessage(
			bob.getNodeId(),
			MessageType.TX_ABORT,
			encodeTxAbortMessage({ channelId, data: Buffer.alloc(0) })
		);
		await settle();
		expect(
			meter.total,
			`the abort exchange converged (valve at ${ABORT_VALVE})`
		).to.be.at.most(2);

		// The channel is unharmed and still operational.
		for (const node of [alice, bob]) {
			expect(node.getChannelManager().listChannels()[0].getState()).to.equal(
				ChannelState.NORMAL
			);
		}
		const invoice = bob.createInvoice({
			amountMsat: 40_000n,
			description: 'after abort noise'
		});
		const payment = alice.sendPayment(invoice.bolt11);
		await settle();
		expect(payment.status, 'payment after the aborts').to.equal(
			PaymentStatus.COMPLETED
		);

		// A disconnect opens a fresh conversation: a new unsolicited abort
		// after reconnect deserves its echo again.
		const before = meter.total;
		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());
		alice.removeAllListeners('message:outbound');
		bob.removeAllListeners('message:outbound');
		await reconnect(alice, bob, meter);
		alice.handlePeerMessage(
			bob.getNodeId(),
			MessageType.TX_ABORT,
			encodeTxAbortMessage({ channelId, data: Buffer.alloc(0) })
		);
		await settle();
		expect(
			meter.total,
			'the fresh conversation got its echo and converged'
		).to.be.within(before + 1, before + 2);

		alice.destroy();
		bob.destroy();
	});

	it('a restart during a splice negotiation converges instead of looping', async function () {
		this.timeout(30_000);
		const dbPath = tempDb('txabort-splice');
		const raw = new SqliteStorage(dbPath);
		raw.open();
		const dead = { val: false };
		const armed = { val: false };
		const meter: IAbortMeter = { total: 0 };
		const alice = createNode(ALICE_SEED, sealableStorage(raw, dead));
		const bob = createNode(BOB_SEED);
		wire(alice, bob, dead, meter, {
			type: MessageType.TX_COMPLETE,
			armed
		});

		const holder = alice as unknown as {
			recovery: {
				commit: (transition: SafetyTransition) => IRecoveryCommitResult;
			};
		};
		const realCommit = holder.recovery.commit.bind(holder.recovery);
		holder.recovery.commit = (
			transition: SafetyTransition
		): IRecoveryCommitResult => {
			if (dead.val) {
				return {
					committed: false,
					released: [],
					frameSequence: null,
					error: new Error('crashed')
				} as unknown as IRecoveryCommitResult;
			}
			return realCommit(transition);
		};

		const channelId = await openReadyChannel(alice, bob);
		buildDirectGraph(alice, BOB_SEED);

		// Splice-in, killed the instant Alice's tx_complete crosses (the
		// chaos matrix cell): her negotiation state died with the process,
		// Bob answers with his own tx_complete and splice commitment into
		// the dead wire so his session survives the disconnect, and the
		// restart must talk both sides out of the splice without echoing
		// forever.
		const manager = alice.getChannelManager();
		manager.initiateQuiescence(channelId);
		const wallet = makeSpliceWallet(100_000n);
		manager
			.getChannel(channelId)!
			.setSpliceInInputs([wallet.walletInput], wallet.changeScript);
		armed.val = true;
		manager.initiateSplice(channelId, 100_000n, 253);
		await settle(10);
		expect(dead.val, 'the kill fired at tx_complete').to.equal(true);
		alice.destroy();
		bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());
		alice.removeAllListeners('message:outbound');
		bob.removeAllListeners('message:outbound');

		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		const restarted = createNode(ALICE_SEED, inspect);
		await reconnect(restarted, bob, meter);
		await settle(10);

		expect(
			meter.total,
			`the abort exchange converged (valve at ${ABORT_VALVE})`
		).to.be.at.most(4);
		for (const [who, node] of [
			['restarted', restarted],
			['peer', bob]
		] as const) {
			const channel = node.getChannelManager().listChannels()[0];
			expect(channel.getState(), `${who} back to NORMAL`).to.equal(
				ChannelState.NORMAL
			);
			expect(
				channel.getFullState().spliceInFlight,
				`${who} forgot the splice`
			).to.equal(null);
		}

		// The channel still works: pay over it.
		buildDirectGraph(restarted, BOB_SEED);
		const invoice = bob.createInvoice({
			amountMsat: 40_000n,
			description: 'after splice abort'
		});
		const payment = restarted.sendPayment(invoice.bolt11);
		await settle(10);
		expect(payment.status, 'payment after convergence').to.equal(
			PaymentStatus.COMPLETED
		);

		restarted.destroy();
		bob.destroy();
	});
});
