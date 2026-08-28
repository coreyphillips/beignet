/**
 * LightningNode surface for splice external inputs (issue #592):
 *
 *  - the channel:splice-txsigs-needed relay reaches the node event;
 *  - provideSpliceExternalWitness validates its arguments, delegates to the
 *    manager and surfaces failures as PROVIDE_EXTERNAL_WITNESS_FAILED;
 *  - spliceInWithInputs refuses a malformed caller-supplied contribution
 *    BEFORE the channel moves to SPLICING, including an external input whose
 *    witness could never be verified;
 *  - spliceIn's directed selection is enforced, not merely forwarded: a
 *    provider that ignores fundingUtxos fails the splice instead of funding it
 *    with other coins.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';

bitcoin.initEccLib(ecc);

import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import {
	Channel,
	ISpliceWalletInput
} from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IFundingProvider,
	ILightningError,
	IUtxoSelectionOpts
} from '../../src/lightning/node/types';

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

function createTestNode(
	fundingProvider?: Partial<IFundingProvider>
): LightningNode {
	const seed = crypto
		.createHash('sha256')
		.update('splice-external-node')
		.digest();
	const node = new LightningNode({
		nodePrivateKey: crypto
			.createHash('sha256')
			.update('splice-external-priv')
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		network: Network.REGTEST,
		fundingProvider: fundingProvider as IFundingProvider
	});
	node.on('error', () => undefined);
	node.on('node:error', () => undefined);
	return node;
}

/** A NORMAL channel injected straight into the node's manager. */
function injectChannel(node: LightningNode): {
	channelId: Buffer;
	channel: Channel;
} {
	const seed = crypto.randomBytes(32);
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: seed
	});
	state.channelId = crypto.randomBytes(32);
	state.state = ChannelState.NORMAL;
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.localBalanceMsat = 1_000_000_000n;
	state.remoteBalanceMsat = 0n;
	const channel = new Channel(state);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const manager = (node as any).channelManager;
	const idHex = state.channelId!.toString('hex');
	manager.channels.set(idHex, channel);
	manager.channelPeers.set(idHex, '02'.padEnd(66, 'ab'));
	return { channelId: state.channelId!, channel };
}

/** A caller-supplied splice input paying `script`, worth `valueSats`. */
function makeInput(
	valueSats: number,
	script: Buffer,
	external = false
): ISpliceWalletInput {
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(script, valueSats);
	return {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		external: external || undefined,
		signWitness: (): Buffer[] => [Buffer.alloc(71, 1), Buffer.alloc(33, 2)]
	};
}

const p2wpkhScript = (): Buffer =>
	bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!;
const changeScript = (): Buffer => p2wpkhScript();

describe('LightningNode splice external-input surface (issue #592)', function () {
	it('relays channel:splice-txsigs-needed', function () {
		const node = createTestNode();
		const seen: Array<{
			channelId: Buffer;
			spliceTxid: Buffer;
			newFundingOutputIndex: number;
			externalInputIndices: number[];
		}> = [];
		node.on('channel:splice-txsigs-needed', (data: (typeof seen)[number]) => {
			seen.push(data);
		});
		const channelId = crypto.randomBytes(32);
		const spliceTxid = crypto.randomBytes(32);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).channelManager.emit(
			'channel:splice-txsigs-needed',
			channelId,
			spliceTxid,
			1,
			[2]
		);
		expect(seen).to.have.length(1);
		expect(seen[0].channelId.equals(channelId)).to.equal(true);
		expect(seen[0].spliceTxid.equals(spliceTxid)).to.equal(true);
		expect(seen[0].newFundingOutputIndex).to.equal(1);
		expect(seen[0].externalInputIndices).to.deep.equal([2]);
		node.destroy();
	});

	it('provideSpliceExternalWitness validates shapes and surfaces failures', function () {
		const node = createTestNode();
		const errors: ILightningError[] = [];
		node.on('node:error', (err: ILightningError) => errors.push(err));

		expect(() =>
			node.provideSpliceExternalWitness(
				Buffer.alloc(16),
				Buffer.alloc(32),
				0,
				[]
			)
		).to.throw(/channelId/);
		expect(() =>
			node.provideSpliceExternalWitness(
				Buffer.alloc(32),
				Buffer.alloc(16),
				0,
				[]
			)
		).to.throw(/prevTxid/);
		expect(() =>
			node.provideSpliceExternalWitness(
				Buffer.alloc(32),
				Buffer.alloc(32),
				-1,
				[]
			)
		).to.throw(/prevOutputIndex/);
		expect(() =>
			node.provideSpliceExternalWitness(Buffer.alloc(32), Buffer.alloc(32), 0, [
				'nope' as unknown as Buffer
			])
		).to.throw(/witness/);
		expect(errors, 'validation throws are not node errors').to.have.length(0);

		// A channel with no splice refuses the delivery without failing it.
		const { channelId } = injectChannel(node);
		const refused = node.provideSpliceExternalWitness(
			channelId,
			crypto.randomBytes(32),
			0,
			[crypto.randomBytes(71)]
		);
		expect(refused.ok).to.equal(false);
		expect(refused.error).to.match(/no in-flight splice record/);
		const failed = errors.filter(
			(e) => e.code === 'PROVIDE_EXTERNAL_WITNESS_FAILED'
		);
		expect(failed).to.have.length(1);
		expect(failed[0].channelId?.equals(channelId)).to.equal(true);
		node.destroy();
	});

	it('spliceInWithInputs refuses a malformed contribution before SPLICING', function () {
		const node = createTestNode();
		const { channelId, channel } = injectChannel(node);
		const amount = 100_000n;
		const good = (): ISpliceWalletInput[] => [
			makeInput(200_000, p2wpkhScript())
		];

		expect(() =>
			node.spliceInWithInputs(Buffer.alloc(16), amount, good(), changeScript())
		).to.throw(/channelId/);
		expect(() =>
			node.spliceInWithInputs(channelId, 0n, good(), changeScript())
		).to.throw(/amountSats/);
		expect(() =>
			node.spliceInWithInputs(channelId, amount, [], changeScript())
		).to.throw(/non-empty array/);
		expect(() =>
			node.spliceInWithInputs(channelId, amount, good(), Buffer.alloc(0))
		).to.throw(/changeScript/);
		expect(() =>
			node.spliceInWithInputs(channelId, amount, good(), changeScript(), 0)
		).to.throw(/fundingFeeratePerkw/);

		// An unreadable prevTx, and a value disagreeing with the output named.
		const unreadable = good();
		unreadable[0].prevTx = Buffer.from('not a transaction');
		expect(() =>
			node.spliceInWithInputs(channelId, amount, unreadable, changeScript())
		).to.throw(/parseable transaction/);
		const mispriced = good();
		mispriced[0].value = 199_999n;
		expect(() =>
			node.spliceInWithInputs(channelId, amount, mispriced, changeScript())
		).to.throw(/does not match the value of the output it names/);
		const outOfRange = good();
		outOfRange[0].prevOutputIndex = 7;
		expect(() =>
			node.spliceInWithInputs(channelId, amount, outOfRange, changeScript())
		).to.throw(/not an output of its prevTx/);

		// The inputs must at least cover the amount they claim to fund.
		expect(() =>
			node.spliceInWithInputs(channelId, 500_000n, good(), changeScript())
		).to.throw(/below the splice amount/);

		// An EXTERNAL input whose witness could never be verified is refused
		// here, not after the negotiation has committed to it.
		const p2wsh = Buffer.concat([
			Buffer.from([0x00, 0x20]),
			crypto.randomBytes(32)
		]);
		expect(() =>
			node.spliceInWithInputs(
				channelId,
				amount,
				[makeInput(200_000, p2wsh, true)],
				changeScript()
			)
		).to.throw(/unsupported output type/);
		const unknown = node.spliceInWithInputs(
			crypto.randomBytes(32),
			amount,
			good(),
			changeScript()
		);
		expect(unknown.ok).to.equal(false);
		expect(unknown.error).to.match(/Channel not found/);

		// Every refusal so far left the channel where it was.
		expect(channel.getState()).to.equal(ChannelState.NORMAL);

		// The same script is fine for an input we sign ourselves, and an
		// accepted contribution reaches the negotiation (quiescence first).
		const outbound: number[] = [];
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).channelManager.on(
			'message:outbound',
			(_peer: string, type: number) => outbound.push(type)
		);
		const started = node.spliceInWithInputs(
			channelId,
			amount,
			[makeInput(200_000, p2wsh)],
			changeScript()
		);
		expect(started.ok).to.equal(true);
		expect(outbound, 'the splice was actually initiated').to.deep.equal([
			MessageType.STFU
		]);
		node.destroy();
	});

	it('getPendingSpliceTx is null without a built splice', function () {
		const node = createTestNode();
		const { channelId } = injectChannel(node);
		expect(node.getPendingSpliceTx(channelId)).to.equal(null);
		expect(node.getPendingSpliceTx(crypto.randomBytes(32))).to.equal(null);
		expect(() => node.getPendingSpliceTx(Buffer.alloc(16))).to.throw(
			/channelId/
		);
		node.destroy();
	});

	it('spliceIn forwards fundingUtxos and enforces the selection', function () {
		const calls: Array<IUtxoSelectionOpts | undefined> = [];
		let selection: ISpliceWalletInput[] = [];
		const node = createTestNode({
			selectSpliceInputs: async (
				_amountSats: bigint,
				_feeratePerKw: number,
				opts?: IUtxoSelectionOpts
			) => {
				calls.push(opts);
				return { inputs: selection, changeScript: changeScript() };
			},
			releaseInputPledges: async () => undefined
		});
		const { channelId, channel } = injectChannel(node);
		const errors: ILightningError[] = [];
		node.on('node:error', (err: ILightningError) => errors.push(err));
		let registered = 0;
		channel.setSpliceInInputs = ((): void => {
			registered++;
		}) as Channel['setSpliceInInputs'];

		// Shape is refused up front, before anything is selected.
		expect(() =>
			node.spliceIn(channelId, 100_000n, 253, { utxos: [] })
		).to.throw(/non-empty array/);
		expect(() =>
			node.spliceIn(channelId, 100_000n, 253, {
				utxos: [{ txid: 'zz', vout: 0 }]
			})
		).to.throw(/64-hex txid/);
		// An untyped caller's "false" is truthy at every site that consumes
		// allowTopUp, so it would authorize coins the caller never named.
		expect(() =>
			node.spliceIn(channelId, 100_000n, 253, {
				utxos: [{ txid: 'aa'.repeat(32), vout: 0 }],
				allowTopUp: 'false'
			} as unknown as IUtxoSelectionOpts)
		).to.throw(/allowTopUp must be a boolean/);
		expect(calls, 'a bad request never reaches the provider').to.have.length(0);

		// A provider that ignores the named coins fails the splice instead of
		// funding it with something else.
		const named = makeInput(200_000, p2wpkhScript());
		const namedTxid = bitcoin.Transaction.fromBuffer(named.prevTx).getId();
		selection = [makeInput(200_000, p2wpkhScript())];
		node.spliceIn(channelId, 100_000n, 253, {
			utxos: [{ txid: namedTxid.toUpperCase(), vout: 0 }]
		});
		return new Promise<void>((resolve) => setImmediate(resolve)).then(() => {
			expect(calls).to.have.length(1);
			expect(calls[0]!.utxos![0].txid).to.equal(namedTxid.toUpperCase());
			expect(
				errors.some(
					(e) =>
						e.code === 'SPLICE_IN_FAILED' &&
						/provider ignored fundingUtxos/.test(e.message)
				),
				'the violation is reported as a splice failure'
			).to.equal(true);
			expect(registered, 'nothing was registered on the channel').to.equal(0);
			node.destroy();
		});
	});
});
