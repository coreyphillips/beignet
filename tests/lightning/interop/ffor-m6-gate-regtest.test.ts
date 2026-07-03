/**
 * FFOR M6 GATE (spec §15, capstone) vs live regtest bitcoind:
 *
 * One continuous beignet-to-beignet scenario:
 *   1. S advertises bLIP-51 lease rates + FFOR standing terms (§11.3) in a
 *      signed node_announcement; R reads both off the wire.
 *   2. R BUYS a lease sized for the epoch: a real dual-funded (v2) channel
 *      open with request_funds/will_fund, REAL regtest UTXOs on both sides,
 *      real interactive-tx, real funding broadcast + confirmation. S becomes
 *      the lessor (isLessor + lease CLTV encumbrance).
 *   3. A variant-B epoch (tower, G > 0) is established ON the leased channel,
 *      with terms echoing S's advertisement (S enforces them).
 *   4. R goes offline; payments settle through S to the K/budget boundary;
 *      the over-limit payment fails cleanly upstream.
 *   5. R returns: replay -> reconcile -> tower fetch -> vouchers to balance.
 *   6. R splices OUT its revenue; the splice tx confirms on regtest.
 *   7. The channel is still fully operational: a plain payment settles last.
 *
 * Exact final balances are asserted across the whole arc, including the
 * lease fee and the FFOR fees. Auto-skips without regtest bitcoind.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../../src/lightning/channel/channel-manager';
import { Channel } from '../../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../../src/lightning/channel/types';
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import { MessageType } from '../../../src/lightning/message/types';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { perCommitmentPointFromSecret } from '../../../src/lightning/keys/derivation';
import {
	generateFromSeed,
	MAX_INDEX
} from '../../../src/lightning/keys/shachain';
import { createFundingScript } from '../../../src/lightning/script/funding';
import { ILeaseRates, IFforTerms } from '../../../src/lightning/gossip/types';
import {
	encodeNodeAnnouncementMessage,
	decodeNodeAnnouncementMessage
} from '../../../src/lightning/gossip/messages';
import { computeLeaseFeeSat } from '../../../src/lightning/channel/liquidity-ads';
import {
	FforVariant,
	FforEpochState,
	IFforEpochParams
} from '../../../src/lightning/ffor/types';
import {
	FforTower,
	LoopbackTowerClient,
	MemoryTowerStore,
	generateTowerPreimages,
	IFforTowerProvisioning
} from '../../../src/lightning/ffor/tower';
import { buildSpliceTx } from '../../../src/lightning/channel/splice-tx';
import { bitcoinRpc, mineBlocks, ensureBitcoindFunds } from './shared-helpers';

const NETWORK = bitcoin.networks.regtest;
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

async function bitcoindUp(): Promise<boolean> {
	try {
		await bitcoinRpc('getblockchaininfo');
		return true;
	} catch {
		return false;
	}
}

function makeSeed(id: string): Buffer {
	return sha256(Buffer.from(`ffor-m6-gate-${id}`));
}
function makeConfig(
	name: string,
	overrides?: Partial<IChannelManagerConfig>
): IChannelManagerConfig {
	const seed = makeSeed(name);
	const k = (i: number): Buffer =>
		sha256(Buffer.concat([seed, Buffer.from([i])]));
	const commitSeed = makeSeed(name + '-commit');
	const bp: IChannelBasepoints = {
		fundingPubkey: getPublicKey(k(0)),
		revocationBasepoint: getPublicKey(k(1)),
		paymentBasepoint: getPublicKey(k(2)),
		delayedPaymentBasepoint: getPublicKey(k(3)),
		htlcBasepoint: getPublicKey(k(4)),
		// v2 opens use the basepoints VERBATIM (no manager fill-in): the first
		// per-commitment point must be the real one for commitment #0.
		firstPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(commitSeed, MAX_INDEX)
		)
	};
	return {
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			toSelfDelay: 6,
			feeratePerKw: 2500
		},
		localBasepoints: bp,
		localPerCommitmentSeed: commitSeed,
		localFundingPrivkey: k(0),
		htlcBasepointSecret: k(4),
		revocationBasepointSecret: k(1),
		paymentBasepointSecret: k(2),
		delayedPaymentBasepointSecret: k(3),
		nodePrivateKey: makeSeed(name + '-node'),
		preferAnchors: true,
		...overrides
	};
}

interface ILinkCtl {
	down: () => void;
	up: () => void;
}
function connect(
	a: ChannelManager,
	aPub: string,
	b: ChannelManager,
	bPub: string
): ILinkCtl {
	let on = true;
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (on && peer === bPub) b.handleMessage(aPub, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (on && peer === aPub) a.handleMessage(bPub, type, payload);
	});
	return {
		down: (): void => {
			on = false;
		},
		up: (): void => {
			on = true;
		}
	};
}

/** Fund a fresh wallet UTXO of `sats` and return its raw prevTx + vout. */
async function fundUtxo(
	sats: bigint
): Promise<{ prevTx: Buffer; txid: string; vout: number }> {
	const addr = (await bitcoinRpc('getnewaddress', ['', 'bech32'])) as string;
	const txid = (await bitcoinRpc('sendtoaddress', [
		addr,
		Number(sats) / 1e8
	])) as string;
	await mineBlocks(1);
	const raw = (await bitcoinRpc('getrawtransaction', [txid])) as string;
	const tx = bitcoin.Transaction.fromHex(raw);
	const want = bitcoin.address.toOutputScript(addr, NETWORK);
	const vout = tx.outs.findIndex((o) => Buffer.from(o.script).equals(want));
	return { prevTx: Buffer.from(raw, 'hex'), txid, vout };
}

const flush = (ms = 10): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe('FFOR M6 GATE: lease -> epoch -> boundary -> reconcile -> splice (regtest)', function () {
	this.timeout(300_000);
	let skip = false;
	before(async function () {
		this.timeout(30_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds(3);
	});

	it('runs the full continuous scenario with exact balances', async function () {
		if (skip) this.skip();

		// ── 1. S advertises lease rates + FFOR terms (§11.3) ──
		const RATES: ILeaseRates = {
			fundingWeightWitness: 666,
			leaseFeeBasis: 40, // 0.4%
			leaseFeeBaseSat: 500,
			channelFeeMaxBaseMsat: 5000,
			channelFeeMaxProportionalThousandths: 10
		};
		const TERMS: IFforTerms = {
			ffFeeBaseMsat: 1000,
			ffFeePpm: 5000,
			maxBudgetMsat: 200_000_000n,
			maxEpochBlocks: 4032,
			variants: 0b11
		};
		const sConfig = makeConfig('S', { leaseRates: RATES, fforTerms: TERMS });
		const rConfig = makeConfig('R');
		const pConfig = makeConfig('P');
		const sAnnouncement = encodeNodeAnnouncementMessage({
			signature: Buffer.alloc(64, 1),
			features: Buffer.alloc(0),
			timestamp: 1,
			nodeId: getPublicKey(sConfig.nodePrivateKey!),
			rgbColor: Buffer.alloc(3),
			alias: Buffer.alloc(32),
			addresses: [],
			leaseRates: RATES,
			fforTerms: TERMS
		});
		// R reads the ad off the wire.
		const ad = decodeNodeAnnouncementMessage(sAnnouncement);
		expect(ad.leaseRates).to.deep.equal(RATES);
		expect(ad.fforTerms).to.deep.equal(TERMS);

		const pPub = getPublicKey(pConfig.nodePrivateKey!).toString('hex');
		const sPub = getPublicKey(sConfig.nodePrivateKey!).toString('hex');
		const rPub = getPublicKey(rConfig.nodePrivateKey!).toString('hex');
		const pManager = new ChannelManager(pConfig);
		const sManager = new ChannelManager(sConfig);
		const rManager = new ChannelManager(rConfig);
		const pErrors: string[] = [];
		const sErrors: string[] = [];
		const rErrors: string[] = [];
		pManager.on('error', (_i, m: string) => pErrors.push(m));
		sManager.on('error', (_i, m: string) => sErrors.push(m));
		rManager.on('error', (_i, m: string) => rErrors.push(m));
		const pFulfilled: Buffer[] = [];
		const pFailed: bigint[] = [];
		pManager.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
			pFulfilled.push(preimage)
		);
		pManager.on('htlc:failed', (_c, id: bigint) => pFailed.push(id));
		const broadcasts: Buffer[] = [];
		rManager.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
		sManager.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		connect(pManager, pPub, sManager, sPub);
		const srLink = connect(sManager, sPub, rManager, rPub);

		// ── 2. R BUYS the lease: real dual-funded open ──
		// R contributes 100k sat and leases 200k sat of inbound from S.
		const R_FUNDING = 100_000n;
		const REQUESTED = 200_000n;
		const CAPACITY = R_FUNDING + REQUESTED;
		const FUNDING_FEERATE_PERKW = 1000;
		const tip0 = (await bitcoinRpc('getblockcount')) as number;
		const leaseFeeSat = computeLeaseFeeSat(
			RATES,
			REQUESTED,
			FUNDING_FEERATE_PERKW
		);

		let leaseEvent: { requestedSats: bigint } | null = null;
		rManager.on('channel:lease', (l: { requestedSats: bigint }) => {
			leaseEvent = l;
		});

		const rChannel = rManager.createDualFundedChannel(sPub, {
			fundingSatoshis: R_FUNDING,
			fundingFeeratePerkw: FUNDING_FEERATE_PERKW,
			commitmentFeeratePerkw: 2500,
			dustLimitSatoshis: 546n,
			maxHtlcValueInFlightMsat: 300_000_000_000n,
			htlcMinimumMsat: 1000n,
			toSelfDelay: 6,
			maxAcceptedHtlcs: 30,
			locktime: 0,
			localBasepoints: rConfig.localBasepoints,
			localPerCommitmentSeed: rConfig.localPerCommitmentSeed,
			secondPerCommitmentPoint: perCommitmentPointFromSecret(
				generateFromSeed(rConfig.localPerCommitmentSeed, MAX_INDEX - 1n)
			),
			// channel_type = option_anchors_zero_fee_htlc_tx (22) +
			// option_static_remotekey (12) — the standard anchors type (FFOR
			// prerequisite, spec §5).
			channelType: ((): Buffer | undefined => {
				const {
					FeatureFlags,
					Feature
				} = require('../../../src/lightning/features/flags');
				const f = FeatureFlags.empty();
				f.setBit(Feature.ANCHOR_ZERO_FEE_HTLC);
				f.setBit(Feature.STATIC_REMOTE_KEY);
				return f.toBuffer();
			})(),
			requestFunds: { requestedSats: REQUESTED, blockheight: tip0 },
			maxLeaseRates: RATES
		});
		// open_channel2/accept_channel2 (+will_fund) flowed synchronously.
		expect(leaseEvent, rErrors.join('; ')).to.not.equal(null);
		expect(leaseEvent!.requestedSats).to.equal(REQUESTED);
		const sChannel = sManager
			.listChannels()
			.find((c) => c.getChannelId()?.equals(rChannel.getChannelId()!))!;
		expect(sChannel, 'S created the v2 channel').to.not.equal(undefined);

		// Interactive tx with REAL UTXOs. R (initiator, even serial ids) adds
		// its input, the shared funding output, and change; S (odd ids) adds
		// its leased contribution + change.
		const fundingScript = createFundingScript(
			rConfig.localBasepoints.fundingPubkey,
			sConfig.localBasepoints.fundingPubkey,
			NETWORK
		);
		const R_IN = R_FUNDING + 10_000n; // input covers contribution + fee
		const S_IN = REQUESTED + 10_000n;
		const rUtxo = await fundUtxo(R_IN);
		const sUtxo = await fundUtxo(S_IN);
		const rChangeScript = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress', ['', 'bech32'])) as string,
			NETWORK
		);
		const sChangeScript = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress', ['', 'bech32'])) as string,
			NETWORK
		);
		const R_FEE = 3_000n;
		const S_FEE = 3_000n;

		// Channel-level v2 construction methods RETURN their wire actions; the
		// test is the transport, so deliver each SEND_MESSAGE to the peer
		// manager (which routes by the derived v2 channel_id).
		const act = (
			label: string,
			from: 'R' | 'S',
			actions: ReturnType<Channel['addTxInput']>
		): void => {
			const err = actions.find((a) => a.type === ChannelActionType.ERROR) as
				| { message: string }
				| undefined;
			expect(err?.message ?? '', label).to.equal('');
			for (const a of actions) {
				if (a.type !== ChannelActionType.SEND_MESSAGE) continue;
				const send = a as unknown as {
					messageType: number;
					payload: Buffer;
				};
				if (from === 'R') {
					sManager.handleMessage(rPub, send.messageType, send.payload);
				} else {
					rManager.handleMessage(sPub, send.messageType, send.payload);
				}
			}
		};
		act(
			'R input',
			'R',
			rChannel.addTxInput({
				serialId: 0n,
				prevTxid: Buffer.from(rUtxo.txid, 'hex').reverse(),
				prevOutputIndex: rUtxo.vout,
				sequence: 0xfffffffd,
				prevTx: rUtxo.prevTx,
				prevTxVout: rUtxo.vout
			})
		);
		act(
			'funding output',
			'R',
			rChannel.addTxOutput({
				serialId: 2n,
				amountSats: CAPACITY,
				scriptPubkey: bitcoin.address.toOutputScript(
					fundingScript.address!,
					NETWORK
				)
			})
		);
		act(
			'R change',
			'R',
			rChannel.addTxOutput({
				serialId: 4n,
				amountSats: R_IN - R_FUNDING - R_FEE,
				scriptPubkey: rChangeScript
			})
		);
		act(
			'S input',
			'S',
			sChannel.addTxInput({
				serialId: 1n,
				prevTxid: Buffer.from(sUtxo.txid, 'hex').reverse(),
				prevOutputIndex: sUtxo.vout,
				sequence: 0xfffffffd,
				prevTx: sUtxo.prevTx,
				prevTxVout: sUtxo.vout
			})
		);
		act(
			'S change',
			'S',
			sChannel.addTxOutput({
				serialId: 3n,
				amountSats: S_IN - REQUESTED - S_FEE,
				scriptPubkey: sChangeScript
			})
		);
		act('R complete', 'R', rChannel.sendTxComplete());
		act('S complete', 'S', sChannel.sendTxComplete());
		// The commitment_signed round for commitment #0 ran over the loopback.

		// Assemble the negotiated funding tx (final ordering = ascending serial
		// id, exactly what buildSpliceTx produces) and sign both wallet inputs.
		const session = rChannel.getDualFundingSession()!;
		const built = session.buildTransaction()!;
		const fundingTx = buildSpliceTx(
			built.inputs.map((i) => ({
				serialId: i.serialId,
				prevTxid:
					i.prevTx && i.prevTx.length >= 32
						? bitcoin.Transaction.fromBuffer(i.prevTx).getHash()
						: i.prevTxid,
				prevOutputIndex: i.prevTxVout ?? i.prevOutputIndex,
				sequence: i.sequence
			})),
			built.outputs.map((o) => ({
				serialId: o.serialId,
				script: o.scriptPubkey,
				valueSats: o.amountSats
			})),
			built.locktime
		);
		const signed = (await bitcoinRpc('signrawtransactionwithwallet', [
			fundingTx.toHex()
		])) as { hex: string; complete: boolean };
		expect(signed.complete, 'wallet signed both inputs').to.equal(true);
		const signedTx = bitcoin.Transaction.fromHex(signed.hex);
		const fundingTxid = signedTx.getId();
		const fundingIndex = signedTx.outs.findIndex((o) =>
			Buffer.from(o.script).equals(
				bitcoin.address.toOutputScript(fundingScript.address!, NETWORK)
			)
		);
		// Each side hands over the witnesses for ITS OWN inputs (tx order).
		const witnessesFor = (txidHex: string): Buffer[][] => {
			const w: Buffer[][] = [];
			signedTx.ins.forEach((inp) => {
				const prevIdHex = Buffer.from(inp.hash).reverse().toString('hex');
				if (prevIdHex === txidHex) {
					w.push(inp.witness.map((x) => Buffer.from(x)));
				}
			});
			return w;
		};
		act(
			'R tx_signatures',
			'R',
			rChannel.sendTxSignatures(
				Buffer.from(fundingTxid, 'hex').reverse(),
				fundingIndex,
				witnessesFor(rUtxo.txid)
			)
		);
		act(
			'S tx_signatures',
			'S',
			sChannel.sendTxSignatures(
				Buffer.from(fundingTxid, 'hex').reverse(),
				fundingIndex,
				witnessesFor(sUtxo.txid)
			)
		);

		// The acceptor provided its witnesses via the channel-level API (a
		// production driver routes them through the manager, which promotes
		// the v2 channel out of tempChannels) — promote explicitly here.
		(
			sManager as unknown as {
				_promoteV2ChannelIfReady: (p: string, c: Channel) => void;
			}
		)._promoteV2ChannelIfReady(rPub, sChannel);

		// Broadcast the funding tx for real and confirm it.
		await bitcoinRpc('sendrawtransaction', [signed.hex]);
		await mineBlocks(3);
		const channelId = rChannel.getChannelId()!;
		rManager.handleFundingConfirmed(channelId);
		sManager.handleFundingConfirmed(channelId);
		expect(rChannel.getState(), rErrors.join('; ')).to.equal(
			ChannelState.NORMAL
		);
		expect(sChannel.getState(), sErrors.join('; ')).to.equal(
			ChannelState.NORMAL
		);

		// Lease state: S is the lessor; both sides carry lease_expiry; R paid
		// the lease fee out of its balance.
		expect(sChannel.getFullState().isLessor).to.equal(true);
		expect(sChannel.getFullState().leaseExpiry).to.equal(tip0 + 4032);
		expect(rChannel.getFullState().leaseExpiry).to.equal(tip0 + 4032);
		const rStart = rChannel.getBalances().localMsat;
		const sStart = sChannel.getBalances().localMsat;
		expect(rStart).to.equal((R_FUNDING - leaseFeeSat) * 1000n);
		expect(sStart).to.equal((REQUESTED + leaseFeeSat) * 1000n);
		// eslint-disable-next-line no-console
		console.log(
			`      GATE M6 leased funding tx: ${fundingTxid} (capacity ${CAPACITY}, lease fee ${leaseFeeSat} sat)`
		);

		// ── P-S upstream channel (fake funding — only S-R needs the chain) ──
		const pCh = pManager.openChannel(sPub, 1_000_000n);
		pManager.createFunding(
			pCh,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);
		const psChannelId = pCh.getChannelId()!;
		pManager.handleFundingConfirmed(psChannelId);
		sManager.handleFundingConfirmed(psChannelId);

		// ── 3. Variant-B epoch (tower, G > 0) echoing the advertised terms ──
		const K = 2;
		const tower = new FforTower(new MemoryTowerStore());
		const gen = generateTowerPreimages(K);
		const towerNodeKey = makeSeed('tower');
		sManager.setFforTowerClient(new LoopbackTowerClient(tower));
		const tip1 = (await bitcoinRpc('getblockcount')) as number;
		const D = tip1 + 100;
		const T_EXP = D + 1008;
		// Budget: exactly v1 + v2 for the two boundary payments below.
		const A1 = 50_000_000n;
		const A2 = 30_000_000n;
		const fee = (a: bigint): bigint =>
			BigInt(ad.fforTerms!.ffFeeBaseMsat) +
			(a * BigInt(ad.fforTerms!.ffFeePpm)) / 1_000_000n;
		const V1 = A1 - fee(A1);
		const V2 = A2 - fee(A2);
		const BUDGET = V1 + V2; // exhausted to the msat at the boundary
		const G = 50_000_000n;
		const params: Omit<IFforEpochParams, 'rPerCommitmentPoints'> = {
			variant: FforVariant.B,
			budgetMsat: BUDGET,
			maxPayments: K,
			minPaymentMsat: 600_000n,
			settlementDeadline: D,
			voucherExpiry: T_EXP,
			feeBaseMsat: ad.fforTerms!.ffFeeBaseMsat, // echo the ad
			feeProportionalMillionths: ad.fforTerms!.ffFeePpm,
			escapeGranularityMsat: G,
			paymentHashes: gen.paymentHashes,
			towerNodeId: getPublicKey(towerNodeKey),
			towerUri: 'inproc://tower'
		};
		const res = rManager.initiateFforEpoch(channelId, params);
		expect(res.ok, rErrors.concat(sErrors).join('; ')).to.equal(true);
		const rEpoch = rChannel.getFforEpoch()!;
		expect(rEpoch.state).to.equal(FforEpochState.FF_EPOCH);
		expect(sChannel.getFforEpoch()!.escapeSigs.length).to.be.greaterThan(0);
		// B.1 step 5: the escape set was derived WITH the lease encumbrance
		// (setup verified R's signatures over it) and snapshotted.
		expect(sChannel.getFforEpoch()!.sLeaseExpiry).to.equal(tip0 + 4032);

		// Provision the tower (statics incl. the §10 escape context).
		const provisioning: IFforTowerProvisioning = {
			epochId: rEpoch.epochId,
			params: rEpoch.params,
			preimages: gen.preimages,
			channel: {
				fundingTxid: sChannel.getFullState().fundingTxid!,
				fundingOutputIndex: sChannel.getFullState().fundingOutputIndex,
				fundingSatoshis: CAPACITY,
				channelType: sChannel.getFullState().channelType!,
				rIsOpener: true,
				rBasepoints: rConfig.localBasepoints,
				sBasepoints: sConfig.localBasepoints,
				rConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
				sConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
				preEpochRLocalMsat: rStart,
				preEpochSLocalMsat: sStart,
				nR: rChannel.getCommitmentNumbers().local,
				n0: sChannel.getCommitmentNumbers().local,
				sPerCommitmentPointN0:
					rChannel.getFullState().remoteCurrentPerCommitmentPoint!,
				sPerCommitmentPointN0Plus1:
					rChannel.getFullState().remoteNextPerCommitmentPoint!,
				sIsOpener: false,
				sToSelfDelay: 6,
				sLeaseExpiry: tip0 + 4032,
				frozenFeeratePerKw: sChannel.getFforEpoch()!.frozenFeeratePerKw
			},
			rNodeId: Buffer.from(rPub, 'hex'),
			sNodeId: Buffer.from(sPub, 'hex')
		};
		tower.provision(provisioning);
		tower.setBlockHeight(tip1);

		// ── 4. R offline; settle to the K/budget boundary ──
		srLink.down();
		sManager.handlePeerDisconnected(rPub);
		rManager.handlePeerDisconnected(sPub);
		const pay = (hash: Buffer, amount: bigint): void => {
			pManager.addHtlc(psChannelId, amount, hash, D + 200, Buffer.alloc(1366));
		};
		pay(gen.paymentHashes[0], A1);
		await flush();
		pay(gen.paymentHashes[1], A2);
		await flush();
		expect(pFulfilled, sErrors.join('; ')).to.have.length(2);
		expect(sChannel.getFforEpoch()!.lastSeq).to.equal(K);
		// Over-limit: K and budget both exhausted — fails cleanly upstream.
		pay(gen.paymentHashes[1], A2);
		await flush();
		expect(pFailed).to.have.length(1);
		expect(pFulfilled).to.have.length(2);
		expect(sChannel.getFforEpoch()!.lastSeq).to.equal(K);

		// ── 5. R returns: replay -> reconcile -> tower fetch -> conversion ──
		srLink.up();
		const reest = (actions: ReturnType<Channel['createReestablish']>): Buffer =>
			(
				actions.find((a) => a.type === ChannelActionType.SEND_MESSAGE) as {
					payload: Buffer;
				}
			).payload;
		const sRe = reest(sChannel.createReestablish());
		const rRe = reest(rChannel.createReestablish());
		rManager.handleMessage(sPub, MessageType.CHANNEL_REESTABLISH, sRe);
		sManager.handleMessage(rPub, MessageType.CHANNEL_REESTABLISH, rRe);
		const allErrs = rErrors.concat(sErrors).join('; ');
		expect(rChannel.getState(), allErrs).to.equal(ChannelState.NORMAL);
		expect(rChannel.getFforEpoch()!.state, allErrs).to.equal(
			FforEpochState.FF_CLOSED
		);
		expect(sChannel.getFforEpoch()!.state, allErrs).to.equal(
			FforEpochState.FF_CLOSED
		);
		// Variant B: the preimages come from the tower (§11.1 step 6).
		const rec = await rManager.fforRecoverFromTower(
			channelId,
			new LoopbackTowerClient(tower)
		);
		expect(rec.ok, rErrors.join('; ')).to.equal(true);
		expect(rManager.fforFulfillVouchers(channelId).ok).to.equal(true);
		const REVENUE = V1 + V2;
		expect(rChannel.getBalances().localMsat).to.equal(rStart + REVENUE);
		expect(sChannel.getBalances().localMsat).to.equal(sStart - REVENUE);
		// S's arc: it received A1+A2 upstream and paid out REVENUE — its skim
		// is exactly the advertised FFOR fees.
		expect(A1 + A2 - REVENUE).to.equal(fee(A1) + fee(A2));

		// ── 6. R splices out revenue; the splice CONFIRMS on regtest ──
		const spliceOutSats = 60_000n;
		const spliceFee = 2_000n; // folded into relative_satoshis (BOLT/CLN rule)
		const rWalletAddr = (await bitcoinRpc('getnewaddress', [
			'm6-gate-revenue',
			'bech32'
		])) as string;
		const rDest = bitcoin.address.toOutputScript(rWalletAddr, NETWORK);
		rChannel.setSpliceOutDestination(rDest, spliceOutSats);
		broadcasts.length = 0;
		const spl = rManager.initiateSplice(
			channelId,
			-(spliceOutSats + spliceFee),
			2500
		);
		expect(spl.ok, rErrors.concat(sErrors).join('; ')).to.equal(true);
		expect(broadcasts.length, 'splice tx broadcast').to.be.greaterThan(0);
		const spliceTx = bitcoin.Transaction.fromBuffer(
			broadcasts[broadcasts.length - 1]
		);
		await bitcoinRpc('sendrawtransaction', [spliceTx.toHex()]);
		await mineBlocks(3);
		const spliceInfo = (await bitcoinRpc('getrawtransaction', [
			spliceTx.getId(),
			true
		])) as { confirmations?: number };
		expect(spliceInfo.confirmations ?? 0, 'splice confirmed').to.be.greaterThan(
			0
		);
		expect(rManager.sendSpliceLocked(channelId).ok).to.equal(true);
		expect(sManager.sendSpliceLocked(channelId).ok).to.equal(true);
		expect(rChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(sChannel.getState()).to.equal(ChannelState.NORMAL);
		const received = (await bitcoinRpc('getreceivedbyaddress', [
			rWalletAddr,
			1
		])) as number;
		expect(Math.round(received * 1e8)).to.equal(Number(spliceOutSats));
		// eslint-disable-next-line no-console
		console.log(`      GATE M6 splice-out tx:      ${spliceTx.getId()}`);

		// R's balance: revenue minus the withdrawal and the splice fee it paid
		// as initiator.
		const postSplice = rChannel.getBalances().localMsat;
		const spliceFeeMsat = rStart + REVENUE - spliceOutSats * 1000n - postSplice;
		expect(spliceFeeMsat >= 0n && spliceFeeMsat < 10_000_000n).to.equal(true);
		// S's balance is untouched by R's splice-out.
		expect(sChannel.getBalances().localMsat).to.equal(sStart - REVENUE);

		// ── 7. Channel fully operational: a plain payment settles last ──
		const preimage = crypto.randomBytes(32);
		rManager.addHtlc(
			channelId,
			1_000_000n,
			sha256(preimage),
			D + 500,
			Buffer.alloc(1366)
		);
		sManager.fulfillHtlc(
			channelId,
			rChannel.getFullState().localHtlcCounter - 1n,
			preimage
		);
		expect(rChannel.getBalances().localMsat).to.equal(postSplice - 1_000_000n);
		expect(sChannel.getBalances().localMsat).to.equal(
			sStart - REVENUE + 1_000_000n
		);
	});
});
