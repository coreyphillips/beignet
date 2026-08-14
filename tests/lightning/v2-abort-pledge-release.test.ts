/**
 * Issue #311: fabricated prevTx in interactive-tx can freeze pledged funding
 * inputs until TTL.
 *
 * Interactive-tx validation is self-consistency over bytes the peer chose, so
 * a fabricated prev_tx negotiates a funding tx that can never confirm while
 * our pledged wallet inputs stay frozen. Two defenses, both exercised here at
 * the node level:
 *
 * - With a chain backend, peer prevouts are verified as tx_add_input arrives
 *   and a conclusive spent-or-missing verdict aborts the negotiation.
 * - A v2 open that dies terminally before our tx_signatures were released
 *   frees its funding pledges at once (IFundingProvider.releaseInputPledges)
 *   instead of waiting out the pledge TTL. Once signatures left, nothing is
 *   released: the peer may broadcast, and an early unfreeze could double
 *   spend a funding tx that still confirms.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, IFundingProvider } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeTxAddInputMessage,
	encodeTxAbortMessage
} from '../../src/lightning/message/interactive-tx';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`i311-seed-${id}`).digest();
}

function makeBasepoints(seedId: number): {
	basepoints: IChannelBasepoints;
	fundingPrivkey: Buffer;
	htlcSecret: Buffer;
} {
	const seed = makeSeed(seedId);
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: getPublicKey(keys[5])
		},
		fundingPrivkey: keys[0],
		htlcSecret: keys[4]
	};
}

function makeNodeConfig(
	seedId: number,
	opts: {
		fundingProvider?: IFundingProvider;
		chainBackend?: IChainBackend;
	} = {}
): INodeConfig {
	const seed = makeSeed(seedId);
	const { basepoints, fundingPrivkey, htlcSecret } = makeBasepoints(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: basepoints,
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret: htlcSecret,
		...opts
	};
}

/** A real spendable P2WPKH UTXO with a working witness-signing closure. */
function makeWalletInput(valueSats: number): ISpliceWalletInput {
	const priv = crypto.randomBytes(32);
	const pub = getPublicKey(priv);
	const payment = bitcoin.payments.p2wpkh({ pubkey: pub });
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(payment.output!, valueSats);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
	return {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value): Buffer[] => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [
				bitcoin.script.signature.encode(
					Buffer.from(ecc.sign(sighash, priv)),
					bitcoin.Transaction.SIGHASH_ALL
				),
				pub
			];
		}
	};
}

const outpointOf = (
	input: ISpliceWalletInput
): { txid: string; vout: number } => ({
	txid: bitcoin.Transaction.fromBuffer(input.prevTx).getId(),
	vout: input.prevOutputIndex
});

function fundingProviderWith(input: ISpliceWalletInput): {
	provider: IFundingProvider;
	released: Array<Array<{ txid: string; vout: number }>>;
} {
	const released: Array<Array<{ txid: string; vout: number }>> = [];
	const changeScript = bitcoin.payments.p2wpkh({
		hash: crypto.randomBytes(20)
	}).output!;
	const provider: IFundingProvider = {
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run for a v2 open');
		},
		broadcastTransaction: async () => 'unused',
		selectSpliceInputs: async () => ({ inputs: [input], changeScript }),
		releaseInputPledges: async (outpoints) => {
			released.push(outpoints);
		}
	};
	return { provider, released };
}

/**
 * A chain backend whose script-hash answers are fixed per test. The relay
 * below yields between deliveries, so a verdict from these immediate
 * responses always lands before the next wire message, the way a real
 * network (where a round trip never beats a microtask) behaves.
 */
class StubBackend implements IChainBackend {
	utxos: Array<{
		txid: string;
		outputIndex: number;
		valueSat: number;
		height: number;
	}> = [];

	history: Array<{ txid: string; height: number }> = [];
	queries = 0;
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		this.queries++;
		return this.history;
	}

	async getTransaction(): Promise<Buffer> {
		throw new Error('not needed');
	}

	async broadcastTransaction(): Promise<string> {
		return '';
	}

	async listUnspent(): Promise<
		Array<{
			txid: string;
			outputIndex: number;
			valueSat: number;
			height: number;
		}>
	> {
		this.queries++;
		return this.utxos;
	}
}

/**
 * Async loopback wire: each message is delivered on its own macrotask, so
 * microtask work (a resolved chain verdict, a settled selection) interleaves
 * between deliveries instead of the whole negotiation running synchronously.
 */
function connectNodes(
	a: LightningNode,
	b: LightningNode
): { stop: () => void } {
	let stopped = false;
	const wire = (from: LightningNode, to: LightningNode): void => {
		from.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey !== to.getNodeId() || stopped) return;
				setImmediate(() => {
					if (stopped) return;
					to.handlePeerMessage(from.getNodeId(), type, payload);
				});
			}
		);
	};
	wire(a, b);
	wire(b, a);
	return {
		stop: (): void => {
			stopped = true;
		}
	};
}

async function settle(pred: () => boolean, ms = 5000): Promise<void> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (pred()) return;
		await new Promise((resolve) => setImmediate(resolve));
	}
}

describe('Issue #311: v2 open pledge release and chain verification (node level)', function () {
	this.timeout(20_000);

	it('an acceptor with a chain backend aborts a spent prevout and the opener frees its pledge', async function () {
		const input = makeWalletInput(200_000);
		const { provider, released } = fundingProviderWith(input);
		const opener = new LightningNode(
			makeNodeConfig(1, { fundingProvider: provider })
		);
		// Positive evidence of a spend: the input's tx is confirmed on its
		// script but the outpoint is no longer in the unspent set.
		const backend = new StubBackend();
		backend.history = [{ txid: outpointOf(input).txid, height: 100 }];
		const acceptor = new LightningNode(
			makeNodeConfig(2, { chainBackend: backend })
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const aborts: number[] = [];
		acceptor.on('message:outbound', (_peer: string, type: number) => {
			if (type === MessageType.TX_ABORT) aborts.push(type);
		});
		connectNodes(opener, acceptor);

		opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});

		await settle(() => released.length > 0);
		expect(
			backend.queries,
			'the acceptor consulted its chain'
		).to.be.greaterThan(0);
		expect(aborts.length, 'the acceptor refused the open').to.be.greaterThan(0);
		expect(released, 'the opener freed its pledged input').to.deep.equal([
			[outpointOf(input)]
		]);

		opener.destroy();
		acceptor.destroy();
	});

	it('a chain-verified prevout lets the open complete', async function () {
		const input = makeWalletInput(200_000);
		const { provider, released } = fundingProviderWith(input);
		const opener = new LightningNode(
			makeNodeConfig(3, { fundingProvider: provider })
		);
		const backend = new StubBackend();
		const op = outpointOf(input);
		backend.utxos = [
			{ txid: op.txid, outputIndex: op.vout, valueSat: 200_000, height: 100 }
		];
		backend.history = [{ txid: op.txid, height: 100 }];
		const acceptor = new LightningNode(
			makeNodeConfig(4, { chainBackend: backend })
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		connectNodes(opener, acceptor);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(
			() => channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(
			backend.queries,
			'the acceptor consulted its chain'
		).to.be.greaterThan(0);
		expect(released, 'nothing was released').to.have.length(0);

		opener.destroy();
		acceptor.destroy();
	});

	it('a prevout this server has not indexed is never refuted (fail open)', async function () {
		// BOLT 2 permits unconfirmed inputs, and a valid unconfirmed parent
		// may simply not have reached the acceptor's server yet: absence
		// alone must not abort an honest open.
		const input = makeWalletInput(200_000);
		const { provider, released } = fundingProviderWith(input);
		const opener = new LightningNode(
			makeNodeConfig(9, { fundingProvider: provider })
		);
		const backend = new StubBackend();
		const acceptor = new LightningNode(
			makeNodeConfig(10, { chainBackend: backend })
		);
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		connectNodes(opener, acceptor);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(
			() => channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(
			backend.queries,
			'the acceptor consulted its chain'
		).to.be.greaterThan(0);
		expect(released, 'nothing was released').to.have.length(0);

		opener.destroy();
		acceptor.destroy();
	});

	it('a pre-signature abort frees the pledged input at the echo', async function () {
		const input = makeWalletInput(200_000);
		const { provider, released } = fundingProviderWith(input);
		const opener = new LightningNode(
			makeNodeConfig(5, { fundingProvider: provider })
		);
		const acceptor = new LightningNode(makeNodeConfig(6));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		const wire = connectNodes(opener, acceptor);

		// Freeze the wire the moment the opener contributes its input: the
		// contribution is registered, nothing is signed, and the peer walks
		// away with a tx_abort.
		let negotiationChannelId: Buffer | null = null;
		opener.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) => {
				if (type !== MessageType.TX_ADD_INPUT || negotiationChannelId) return;
				negotiationChannelId = decodeTxAddInputMessage(payload).channelId;
				wire.stop();
			}
		);

		opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(() => negotiationChannelId !== null);
		expect(
			negotiationChannelId,
			'the opener contributed its input'
		).to.not.equal(null);
		expect(released, 'nothing released while the open lives').to.have.length(0);

		opener.handlePeerMessage(
			acceptor.getNodeId(),
			MessageType.TX_ABORT,
			encodeTxAbortMessage({
				channelId: negotiationChannelId!,
				data: Buffer.from('cancel', 'ascii')
			})
		);
		await settle(() => released.length > 0);

		expect(released, 'the pledge came back at the echo').to.deep.equal([
			[outpointOf(input)]
		]);

		opener.destroy();
		acceptor.destroy();
	});

	it('an abort against a signatures-exchanged open releases nothing and keeps the channel', async function () {
		const input = makeWalletInput(200_000);
		const { provider, released } = fundingProviderWith(input);
		const opener = new LightningNode(
			makeNodeConfig(7, { fundingProvider: provider })
		);
		const acceptor = new LightningNode(makeNodeConfig(8));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		connectNodes(opener, acceptor);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(
			() => channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		const channelId = channel.getChannelId()!;

		// A hostile late abort: our witnesses are out, so the peer may hold a
		// broadcastable funding tx and nothing must be unfrozen or forgotten.
		opener.handlePeerMessage(
			acceptor.getNodeId(),
			MessageType.TX_ABORT,
			encodeTxAbortMessage({
				channelId,
				data: Buffer.from('too late', 'ascii')
			})
		);
		await new Promise((resolve) => setImmediate(resolve));
		await new Promise((resolve) => setImmediate(resolve));

		expect(
			released,
			'no pledge released after signature release'
		).to.have.length(0);
		expect(
			opener.getChannelManager().getChannel(channelId),
			'the channel is retained'
		).to.equal(channel);
		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		opener.destroy();
		acceptor.destroy();
	});

	/** A completed open white-boxed into the diverged-RBF terminal shape. */
	async function divergedOpen(seed: number): Promise<{
		opener: LightningNode;
		acceptor: LightningNode;
		channelId: Buffer;
		input: ISpliceWalletInput;
		released: Array<Array<{ txid: string; vout: number }>>;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		channel: any;
	}> {
		const input = makeWalletInput(200_000);
		const { provider, released } = fundingProviderWith(input);
		const opener = new LightningNode(
			makeNodeConfig(seed, { fundingProvider: provider })
		);
		const acceptor = new LightningNode(makeNodeConfig(seed + 1));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		connectNodes(opener, acceptor);
		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(
			() => channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		// The peer answered reestablish with unknown-channel after dropping
		// its side: errored, with nothing anyone could broadcast.
		const st = channel.getFullState() as unknown as {
			state: ChannelState;
			pendingFundingTxHex: string | null;
			v2InFlight: unknown;
		};
		st.state = ChannelState.ERRORED;
		st.pendingFundingTxHex = null;
		st.v2InFlight = {
			sentTxSignatures: false,
			fullySigned: false,
			ourWalletInputIndices: [0],
			ourWitnesses: []
		};
		return {
			opener,
			acceptor,
			channelId: channel.getChannelId()!,
			input,
			released,
			channel
		};
	}

	it('the diverged-RBF void releases the pledges once the terminal decision lands', async function () {
		const h = await divergedOpen(11);
		(
			h.opener as unknown as {
				handleChannelErrored(id: Buffer, reason: string): void;
			}
		).handleChannelErrored(h.channelId, 'diverged RBF');
		await settle(() => h.released.length > 0);

		expect(h.released).to.deep.equal([[outpointOf(h.input)]]);
		expect(
			h.opener.getChannelManager().getChannel(h.channelId),
			'the channel was voided'
		).to.equal(undefined);

		h.opener.destroy();
		h.acceptor.destroy();
	});

	it('a void that can neither delete nor condemn the row keeps the pledges', async function () {
		const h = await divergedOpen(13);
		// A store that refuses everything: the terminal decision cannot land
		// durably, a restart would restore the open, and its inputs must
		// stay reserved.
		(h.opener as unknown as { storage: unknown }).storage = {
			loadChannel: (): never => {
				throw new Error('io failure');
			},
			deleteChannel: (): never => {
				throw new Error('io failure');
			}
		};
		(
			h.opener as unknown as {
				handleChannelErrored(id: Buffer, reason: string): void;
			}
		).handleChannelErrored(h.channelId, 'diverged RBF');
		await new Promise((resolve) => setImmediate(resolve));
		await new Promise((resolve) => setImmediate(resolve));

		expect(h.released, 'no release without a durable decision').to.have.length(
			0
		);
		expect(
			h.opener.getChannelManager().getChannel(h.channelId),
			'the channel stays tracked for a retry'
		).to.equal(h.channel);

		h.opener.destroy();
		h.acceptor.destroy();
	});

	it('the node answers the durable-row probe from storage, failing toward keeping pledges', function () {
		const node = new LightningNode(makeNodeConfig(15));
		const probe = (
			node.getChannelManager() as unknown as {
				config: { hasResumableChannelRow?: (id: Buffer) => boolean };
			}
		).config.hasResumableChannelRow!;
		const id = crypto.randomBytes(32);
		const nodeStorage = node as unknown as { storage: unknown };

		expect(probe(id), 'no storage: nothing durable exists').to.equal(false);
		nodeStorage.storage = { loadChannel: (): null => null };
		expect(probe(id), 'no row: nothing to resume').to.equal(false);
		nodeStorage.storage = {
			loadChannel: (): object => ({
				state: { condemned: false },
				peerPubkey: 'aa'
			})
		};
		expect(probe(id), 'a live row survives a restart').to.equal(true);
		nodeStorage.storage = {
			loadChannel: (): object => ({
				state: { condemned: true },
				peerPubkey: 'aa'
			})
		};
		expect(probe(id), 'a condemned row is deletion-owed').to.equal(false);
		nodeStorage.storage = {
			loadChannel: (): never => {
				throw new Error('io failure');
			}
		};
		expect(probe(id), 'unreadable: assume it survives').to.equal(true);

		node.destroy();
	});
});
