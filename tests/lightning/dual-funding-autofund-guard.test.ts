/**
 * autoFundDualFundedOpen's embedder-contribution guard (issue #572).
 *
 * A contribution the embedder registered on the channel (possibly carrying an
 * EXTERNAL input, issue #554) must win over the manager's own wallet
 * selection: a second setDualFundingContribution would overwrite it and
 * corrupt the negotiated funding. Two arms are pinned here:
 *
 *  - synchronous: the contribution was registered before accept_channel2
 *    arrives; the manager must not select at all and must DRIVE the
 *    registered contribution (the initiator sends the first tx_add_input).
 *  - race: accept_channel2 arrived first and the wallet selection is in
 *    flight when the embedder registers; the registered contribution wins,
 *    the stale selection's never-registered coins release their pledges.
 *
 * Also pinned: IDualFundingParams.fundingUtxos reaches the dual-funding
 * selector as the trailing IUtxoSelectionOpts argument.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import {
	encodeAcceptChannel2Message,
	IAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import { decodeTxAddInputMessage } from '../../src/lightning/message/interactive-tx';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import { ChannelState } from '../../src/lightning/channel/types';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { MessageType } from '../../src/lightning/message/types';
import {
	IFundingProvider,
	IUtxoSelectionOpts
} from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

// ─────────────── Helpers ───────────────

const PEER = '02' + 'ab'.repeat(32);

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(crypto.randomBytes(32)),
		revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
		paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
		firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	};
}

function makeDualFundingParams(
	overrides?: Partial<IDualFundingParams>
): IDualFundingParams {
	return {
		fundingSatoshis: 100_000n,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 253,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32),
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
		channelType: Buffer.from('1000', 'hex'),
		...overrides
	};
}

function makeAcceptChannel2Msg(channelId: Buffer): IAcceptChannel2Message {
	const bp = makeBasepoints();
	return {
		channelId,
		fundingSatoshis: 0n,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		minimumDepth: 3,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		fundingPubkey: bp.fundingPubkey,
		revocationBasepoint: bp.revocationBasepoint,
		paymentBasepoint: bp.paymentBasepoint,
		delayedPaymentBasepoint: bp.delayedPaymentBasepoint,
		htlcBasepoint: bp.htlcBasepoint,
		firstPerCommitmentPoint: bp.firstPerCommitmentPoint,
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
		channelType: Buffer.from('1000', 'hex')
	};
}

function makeInput(valueSats: number): ISpliceWalletInput {
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(
		bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!,
		valueSats
	);
	return {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (): Buffer[] => []
	};
}

function changeScript(): Buffer {
	return bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!;
}

function makeManager(provider: Partial<IFundingProvider>): {
	mgr: ChannelManager;
	sent: Array<{ type: number; payload: Buffer }>;
	errors: string[];
} {
	const mgr = new ChannelManager({
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32),
		localFundingPrivkey: crypto.randomBytes(32)
	});
	mgr.setFundingProvider({
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run in this test');
		},
		broadcastTransaction: async () => {
			throw new Error('broadcast must not run in this test');
		},
		...provider
	} as IFundingProvider);
	const sent: Array<{ type: number; payload: Buffer }> = [];
	mgr.on('message:outbound', (_peer: string, type: number, payload: Buffer) =>
		sent.push({ type, payload })
	);
	const errors: string[] = [];
	mgr.on('error', (_id: Buffer | null, msg: string) => errors.push(msg));
	return { mgr, sent, errors };
}

async function settlePromises(): Promise<void> {
	await new Promise<void>((resolve) => setImmediate(resolve));
	await new Promise<void>((resolve) => setImmediate(resolve));
}

function sentPrevTxs(sent: Array<{ type: number; payload: Buffer }>): Buffer[] {
	return sent
		.filter((m) => m.type === MessageType.TX_ADD_INPUT)
		.map((m) => decodeTxAddInputMessage(m.payload).prevTx);
}

// ─────────────── Tests ───────────────

describe('autoFundDualFundedOpen embedder-contribution guard (issue #572)', () => {
	it('a pre-registered contribution is driven, never selected over', async () => {
		const { mgr, sent, errors } = makeManager({
			selectDualFundingInputs: async () => {
				throw new Error('selection must not run');
			},
			selectSpliceInputs: async () => {
				throw new Error('selection must not run');
			}
		});
		const registered = makeInput(200_000);
		const channel = mgr.createDualFundedChannel(PEER, makeDualFundingParams());
		channel.setDualFundingContribution(
			[registered],
			changeScript(),
			100_000n,
			1000
		);

		mgr.handleMessage(
			PEER,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(
				makeAcceptChannel2Msg(channel.getTemporaryChannelId())
			)
		);
		await settlePromises();

		// The registered input (and only it) went out as tx_add_input, and
		// the throwing selectors were never consulted.
		const prevTxs = sentPrevTxs(sent);
		expect(prevTxs, 'exactly the registered input contributed').to.have.length(
			1
		);
		expect(prevTxs[0].equals(registered.prevTx)).to.equal(true);
		expect(
			errors.filter((e) => /selection must not run/.test(e)),
			'no selection ran'
		).to.deep.equal([]);
		expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
	});

	it('a contribution registered mid-selection wins; the stale selection releases its pledges', async () => {
		let resolveSelection:
			| ((v: { inputs: ISpliceWalletInput[]; changeScript: Buffer }) => void)
			| null = null;
		const released: Array<{ txid: string; vout: number }> = [];
		const { mgr, sent, errors } = makeManager({
			selectDualFundingInputs: () =>
				new Promise((resolve) => {
					resolveSelection = resolve;
				}),
			releaseInputPledges: async (outpoints) => {
				released.push(...outpoints);
			}
		});
		const registered = makeInput(200_000);
		const stale = makeInput(150_000);
		const channel = mgr.createDualFundedChannel(PEER, makeDualFundingParams());

		// accept_channel2 first: the wallet selection is now in flight.
		mgr.handleMessage(
			PEER,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(
				makeAcceptChannel2Msg(channel.getTemporaryChannelId())
			)
		);
		expect(resolveSelection, 'selection started').to.not.equal(null);

		// The embedder registers while the selection is pending, then the
		// selection lands late with a DIFFERENT coin.
		channel.setDualFundingContribution(
			[registered],
			changeScript(),
			100_000n,
			1000
		);
		resolveSelection!({ inputs: [stale], changeScript: changeScript() });
		await settlePromises();

		// The registered contribution drove the open; the stale selection's
		// coin was never contributed and its pledge released.
		const prevTxs = sentPrevTxs(sent);
		expect(prevTxs).to.have.length(1);
		expect(prevTxs[0].equals(registered.prevTx)).to.equal(true);
		expect(released).to.deep.equal([
			{
				txid: bitcoin.Transaction.fromBuffer(stale.prevTx).getId(),
				vout: 0
			}
		]);
		expect(errors).to.deep.equal([]);
		expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
	});

	it('fundingUtxos reaches the dual-funding selector as the trailing opts', async () => {
		const calls: Array<{
			amountSats: bigint;
			initiator: boolean;
			topUp?: boolean;
			opts?: IUtxoSelectionOpts;
		}> = [];
		const { mgr, sent } = makeManager({
			selectDualFundingInputs: async (
				amountSats,
				_feeratePerKw,
				initiator,
				topUp,
				opts
			) => {
				calls.push({ amountSats, initiator, topUp, opts });
				return { inputs: [makeInput(200_000)], changeScript: changeScript() };
			}
		});
		const fundingUtxos = {
			utxos: [{ txid: 'aa'.repeat(32), vout: 1 }],
			allowTopUp: true
		};
		const channel = mgr.createDualFundedChannel(
			PEER,
			makeDualFundingParams({ fundingUtxos })
		);
		mgr.handleMessage(
			PEER,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(
				makeAcceptChannel2Msg(channel.getTemporaryChannelId())
			)
		);
		await settlePromises();

		expect(calls).to.have.length(1);
		expect(calls[0].amountSats).to.equal(100_000n);
		expect(calls[0].initiator).to.equal(true);
		expect(calls[0].opts).to.deep.equal(fundingUtxos);
		expect(
			sent.filter((m) => m.type === MessageType.TX_ADD_INPUT)
		).to.have.length(1);
	});
});
