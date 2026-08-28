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
	decodeOpenChannel2Message,
	IAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import { decodeTxAddInputMessage } from '../../src/lightning/message/interactive-tx';
import { verifyDirectedSelection } from '../../src/lightning/node/funding-selection';
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

	it('fundingUtxos reaches the dual-funding selector and an honoring selection funds the open', async () => {
		const calls: Array<{
			amountSats: bigint;
			initiator: boolean;
			topUp?: boolean;
			opts?: IUtxoSelectionOpts;
		}> = [];
		const directed = makeInput(200_000);
		const fundingUtxos = {
			utxos: [
				{
					txid: bitcoin.Transaction.fromBuffer(directed.prevTx).getId(),
					vout: 0
				}
			],
			allowTopUp: true
		};
		const { mgr, sent } = makeManager({
			selectDualFundingInputs: async (
				amountSats,
				_feeratePerKw,
				initiator,
				topUp,
				opts
			) => {
				calls.push({ amountSats, initiator, topUp, opts });
				return { inputs: [directed], changeScript: changeScript() };
			}
		});
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

	it('the overlap between a late selection and the winning contribution keeps its pledge', async () => {
		// The wallet can legitimately re-offer a coin the registered
		// contribution already spends (its pledge TTL lapsed while the open
		// sat unsigned). Releasing THAT pledge would let the next wallet
		// spend orphan the channel: only the non-overlapping coin releases.
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
		const shared = makeInput(200_000);
		const extra = makeInput(150_000);
		const channel = mgr.createDualFundedChannel(PEER, makeDualFundingParams());
		mgr.handleMessage(
			PEER,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(
				makeAcceptChannel2Msg(channel.getTemporaryChannelId())
			)
		);
		channel.setDualFundingContribution(
			[shared],
			changeScript(),
			100_000n,
			1000
		);
		resolveSelection!({
			inputs: [shared, extra],
			changeScript: changeScript()
		});
		await settlePromises();

		expect(released, 'only the coin nothing spends releases').to.deep.equal([
			{
				txid: bitcoin.Transaction.fromBuffer(extra.prevTx).getId(),
				vout: 0
			}
		]);
		const prevTxs = sentPrevTxs(sent);
		expect(prevTxs).to.have.length(1);
		expect(prevTxs[0].equals(shared.prevTx)).to.equal(true);
		expect(errors).to.deep.equal([]);
	});

	it('a selection failure after registration drives the contribution instead of aborting', async () => {
		let rejectSelection: ((err: Error) => void) | null = null;
		const { mgr, sent, errors } = makeManager({
			selectDualFundingInputs: () =>
				new Promise((_resolve, reject) => {
					rejectSelection = reject;
				})
		});
		const registered = makeInput(200_000);
		const channel = mgr.createDualFundedChannel(PEER, makeDualFundingParams());
		mgr.handleMessage(
			PEER,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(
				makeAcceptChannel2Msg(channel.getTemporaryChannelId())
			)
		);
		channel.setDualFundingContribution(
			[registered],
			changeScript(),
			100_000n,
			1000
		);
		rejectSelection!(new Error('wallet empty'));
		await settlePromises();

		// The selection's failure is moot: the registered contribution funds
		// the open, nothing errors, nothing aborts.
		const prevTxs = sentPrevTxs(sent);
		expect(prevTxs).to.have.length(1);
		expect(prevTxs[0].equals(registered.prevTx)).to.equal(true);
		expect(errors).to.deep.equal([]);
		expect(sent.filter((m) => m.type === MessageType.TX_ABORT)).to.have.length(
			0
		);
		expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
	});

	it('opts.contribution wins under a fully synchronous accept_channel2', async () => {
		// The accept can be processed INSIDE createDualFundedChannel (a
		// synchronous transport), before the caller could register anything
		// on the returned channel. The contribution option registers before
		// the open_channel2 dispatch, so the guard arm drives it even then.
		const { mgr, sent, errors } = makeManager({
			selectDualFundingInputs: async () => {
				throw new Error('selection must not run');
			},
			selectSpliceInputs: async () => {
				throw new Error('selection must not run');
			}
		});
		mgr.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) => {
				if (type !== MessageType.OPEN_CHANNEL2) return;
				const open = decodeOpenChannel2Message(payload);
				mgr.handleMessage(
					PEER,
					MessageType.ACCEPT_CHANNEL2,
					encodeAcceptChannel2Message(makeAcceptChannel2Msg(open.channelId))
				);
			}
		);
		const contributed = makeInput(200_000);
		const channel = mgr.createDualFundedChannel(PEER, makeDualFundingParams(), {
			contribution: {
				inputs: [contributed],
				changeScript: changeScript()
			}
		});

		// By the time the call returned, the synchronous accept had already
		// been answered from the registered contribution.
		const prevTxs = sentPrevTxs(sent);
		expect(prevTxs).to.have.length(1);
		expect(prevTxs[0].equals(contributed.prevTx)).to.equal(true);
		expect(errors).to.deep.equal([]);
		expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
		await settlePromises();
		expect(
			errors.filter((e) => /selection must not run/.test(e)),
			'no selection ran'
		).to.deep.equal([]);
	});

	it('a provider that ignores fundingUtxos is a funding failure, not a silent substitution', async () => {
		const released: Array<{ txid: string; vout: number }> = [];
		const ignored = makeInput(200_000);
		const { mgr, sent, errors } = makeManager({
			// A third-party provider written against the older signature:
			// returns a successful selection over an arbitrary coin.
			selectDualFundingInputs: async () => ({
				inputs: [ignored],
				changeScript: changeScript()
			}),
			releaseInputPledges: async (outpoints) => {
				released.push(...outpoints);
			}
		});
		const channel = mgr.createDualFundedChannel(
			PEER,
			makeDualFundingParams({
				fundingUtxos: { utxos: [{ txid: 'bb'.repeat(32), vout: 0 }] }
			})
		);
		mgr.handleMessage(
			PEER,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(
				makeAcceptChannel2Msg(channel.getTemporaryChannelId())
			)
		);
		await settlePromises();

		expect(
			errors.some((e) => /provider ignored fundingUtxos/.test(e)),
			`violation reported (got: ${errors.join(' | ')})`
		).to.equal(true);
		expect(
			sent.filter((m) => m.type === MessageType.TX_ABORT),
			'the open aborted on the wire'
		).to.have.length(1);
		expect(
			sent.filter((m) => m.type === MessageType.TX_ADD_INPUT),
			'the arbitrary coin never funded anything'
		).to.have.length(0);
		expect(
			released,
			'the unusable selection released its pledge'
		).to.deep.equal([
			{
				txid: bitcoin.Transaction.fromBuffer(ignored.prevTx).getId(),
				vout: 0
			}
		]);
	});

	it('a malformed stale selection cannot block the registered contribution', async () => {
		// The overlap computation parses every selected prevTx; a broken
		// third-party provider result must degrade to best-effort pledge
		// cleanup (the TTL covers what cannot be named), never block driving
		// the perfectly valid registered contribution (issue #572 review).
		let resolveSelection:
			| ((v: { inputs: ISpliceWalletInput[]; changeScript: Buffer }) => void)
			| null = null;
		const { mgr, sent, errors } = makeManager({
			selectDualFundingInputs: () =>
				new Promise((resolve) => {
					resolveSelection = resolve;
				}),
			releaseInputPledges: async () => undefined
		});
		const registered = makeInput(200_000);
		const channel = mgr.createDualFundedChannel(PEER, makeDualFundingParams());
		mgr.handleMessage(
			PEER,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(
				makeAcceptChannel2Msg(channel.getTemporaryChannelId())
			)
		);
		channel.setDualFundingContribution(
			[registered],
			changeScript(),
			100_000n,
			1000
		);
		const malformed: ISpliceWalletInput = {
			...makeInput(150_000),
			prevTx: Buffer.from('not a transaction', 'ascii')
		};
		resolveSelection!({
			inputs: [malformed],
			changeScript: changeScript()
		});
		await settlePromises();

		const prevTxs = sentPrevTxs(sent);
		expect(prevTxs, 'registered contribution still drove').to.have.length(1);
		expect(prevTxs[0].equals(registered.prevTx)).to.equal(true);
		expect(
			errors.filter((e) => /dispatch failed/.test(e)),
			'no dispatch failure'
		).to.deep.equal([]);
		expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
	});

	it('an empty directed list is a funding failure, never unrestricted selection', async () => {
		// A direct manager caller can hand IDualFundingParams.fundingUtxos an
		// empty utxos array, bypassing the node-level validation; combined
		// with the providers' unrestricted fallback that would fund with
		// arbitrary coins while the caller believed the selection was
		// constrained (issue #572 review). The shared selection entry refuses
		// instead, failing the open loudly.
		const { mgr, sent, errors } = makeManager({
			selectDualFundingInputs: async () => ({
				inputs: [makeInput(200_000)],
				changeScript: changeScript()
			})
		});
		const channel = mgr.createDualFundedChannel(
			PEER,
			makeDualFundingParams({ fundingUtxos: { utxos: [] } })
		);
		mgr.handleMessage(
			PEER,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(
				makeAcceptChannel2Msg(channel.getTemporaryChannelId())
			)
		);
		await settlePromises();

		expect(
			errors.some((e) => /must not be empty/.test(e)),
			`refusal reported (got: ${errors.join(' | ')})`
		).to.equal(true);
		expect(
			sent.filter((m) => m.type === MessageType.TX_ADD_INPUT),
			'no unrestricted coin ever contributed'
		).to.have.length(0);
		expect(
			sent.filter((m) => m.type === MessageType.TX_ABORT),
			'the open aborted on the wire'
		).to.have.length(1);
	});

	it('verifyDirectedSelection treats an empty directed list as a violation', () => {
		expect(
			verifyDirectedSelection([makeInput(100_000)], { utxos: [] })
		).to.match(/empty/);
		expect(verifyDirectedSelection([makeInput(100_000)], {})).to.equal(null);
	});

	it('fundingUtxos with a provider that cannot select aborts loudly instead of stalling', async () => {
		const { mgr, sent, errors } = makeManager({});
		const channel = mgr.createDualFundedChannel(
			PEER,
			makeDualFundingParams({
				fundingUtxos: { utxos: [{ txid: 'cc'.repeat(32), vout: 0 }] }
			})
		);
		mgr.handleMessage(
			PEER,
			MessageType.ACCEPT_CHANNEL2,
			encodeAcceptChannel2Message(
				makeAcceptChannel2Msg(channel.getTemporaryChannelId())
			)
		);
		await settlePromises();

		expect(
			errors.some((e) => /fundingUtxos requires a funding provider/.test(e)),
			`refusal reported (got: ${errors.join(' | ')})`
		).to.equal(true);
		expect(
			sent.filter((m) => m.type === MessageType.TX_ABORT),
			'the open aborted on the wire'
		).to.have.length(1);
	});
});
