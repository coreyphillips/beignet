/**
 * FFOR M5 regtest gates (real bitcoind, spec §10 / Appendix B escapes):
 *
 * GATE M5-A (R never returns): variant-A epoch with G > 0, 2 settlements, R
 * gone past D + escape_delay. S broadcasts the correct E_j (j = ceil(owed/G));
 * it is accepted + confirmed. Then:
 *   A1 (this run): R appears with ONLY its seed + funding outpoint and claims
 *      the aggregate voucher via path 3 (1-CSV), confirmed.
 *   A2 (separate run): R never appears, T_exp passes, S claims the refund via
 *      path 2 (nLockTime = T_exp, nSequence = to_self_delay), confirmed.
 *
 * GATE M5-B (stale escape penalty): full epoch + settlements + complete
 * reconciliation (escapes killed by the n0+1 reveal), then S broadcasts an E_j
 * anyway; R classifies it as a revoked-state breach and confirms a justice tx
 * sweeping the aggregate voucher via revocation path 1.
 *
 * Auto-skips when regtest bitcoind is unreachable.
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
import { createFundingScript } from '../../../src/lightning/script/funding';
import { FforEpochState } from '../../../src/lightning/ffor/types';
import {
	IEscapeChannelContext,
	buildEscapeSRefund,
	matchEscapeBroadcast
} from '../../../src/lightning/ffor/escape';
import { bitcoinRpc, mineBlocks, ensureBitcoindFunds } from './shared-helpers';

const NETWORK = bitcoin.networks.regtest;
const TO_SELF_DELAY = 6;
const FUNDING = 1_000_000n;
const G = 50_000_000n; // 50k sat
const BUDGET = 100_000_000n; // J = 2
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
	return sha256(Buffer.from(`ffor-m5-rt-${id}`));
}
function makeConfig(name: string): IChannelManagerConfig {
	const seed = makeSeed(name);
	const k = (i: number): Buffer =>
		sha256(Buffer.concat([seed, Buffer.from([i])]));
	const bp: IChannelBasepoints = {
		fundingPubkey: getPublicKey(k(0)),
		revocationBasepoint: getPublicKey(k(1)),
		paymentBasepoint: getPublicKey(k(2)),
		delayedPaymentBasepoint: getPublicKey(k(3)),
		htlcBasepoint: getPublicKey(k(4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
	return {
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			toSelfDelay: TO_SELF_DELAY,
			feeratePerKw: 2500
		},
		localBasepoints: bp,
		localPerCommitmentSeed: makeSeed(name + '-commit'),
		localFundingPrivkey: k(0),
		htlcBasepointSecret: k(4),
		revocationBasepointSecret: k(1),
		paymentBasepointSecret: k(2),
		delayedPaymentBasepointSecret: k(3),
		nodePrivateKey: makeSeed(name + '-node'),
		preferAnchors: true
	};
}
function connect(
	a: ChannelManager,
	aPub: string,
	b: ChannelManager,
	bPub: string
): { down: () => void; up: () => void; dropTypes: Set<number> } {
	let on = true;
	const dropTypes = new Set<number>();
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (on && peer === bPub && !dropTypes.has(type))
			b.handleMessage(aPub, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (on && peer === aPub && !dropTypes.has(type))
			a.handleMessage(bPub, type, payload);
	});
	return {
		down: (): void => {
			on = false;
		},
		up: (): void => {
			on = true;
		},
		dropTypes
	};
}

interface IScn {
	pManager: ChannelManager;
	sManager: ChannelManager;
	rManager: ChannelManager;
	rConfig: IChannelManagerConfig;
	sConfig: IChannelManagerConfig;
	sPub: string;
	rPub: string;
	psChannelId: Buffer;
	srChannelId: Buffer;
	sChannel: Channel;
	rChannel: Channel;
	srLink: { down: () => void; up: () => void; dropTypes: Set<number> };
	hashes: Buffer[];
	rBroadcasts: Buffer[];
	sBroadcasts: Buffer[];
	rErrors: string[];
	sErrors: string[];
	tip: number;
	D: number;
	tExp: number;
}

async function setup(name: string, settlements: bigint[]): Promise<IScn> {
	const pC = makeConfig(`${name}-P`);
	const sC = makeConfig(`${name}-S`);
	const rC = makeConfig(`${name}-R`);
	const pPub = getPublicKey(pC.nodePrivateKey!).toString('hex');
	const sPub = getPublicKey(sC.nodePrivateKey!).toString('hex');
	const rPub = getPublicKey(rC.nodePrivateKey!).toString('hex');
	const pManager = new ChannelManager(pC);
	const sManager = new ChannelManager(sC);
	const rManager = new ChannelManager(rC);
	pManager.on('error', () => {});
	const sErrors: string[] = [];
	const rErrors: string[] = [];
	sManager.on('error', (_i, m: string) => sErrors.push(m));
	rManager.on('error', (_i, m: string) => rErrors.push(m));
	const rBroadcasts: Buffer[] = [];
	const sBroadcasts: Buffer[] = [];
	rManager.on('broadcast:tx', (t: Buffer) => rBroadcasts.push(t));
	sManager.on('broadcast:tx', (t: Buffer) => sBroadcasts.push(t));

	connect(pManager, pPub, sManager, sPub);
	const srLink = connect(sManager, sPub, rManager, rPub);

	const pCh = pManager.openChannel(sPub, FUNDING);
	pManager.createFunding(
		pCh,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	);
	const psChannelId = pCh.getChannelId()!;
	pManager.handleFundingConfirmed(psChannelId);
	sManager.handleFundingConfirmed(psChannelId);

	const funding = createFundingScript(
		sC.localBasepoints.fundingPubkey,
		rC.localBasepoints.fundingPubkey,
		NETWORK
	);
	const fundTxid = (await bitcoinRpc('sendtoaddress', [
		funding.address,
		Number(FUNDING) / 1e8
	])) as string;
	await mineBlocks(1);
	const fundTx = (await bitcoinRpc('getrawtransaction', [fundTxid, true])) as {
		vout: Array<{ n: number; scriptPubKey: { address?: string } }>;
	};
	const fout = fundTx.vout.find(
		(v) => v.scriptPubKey.address === funding.address
	)!;
	const sCh = sManager.openChannel(rPub, FUNDING);
	sManager.createFunding(
		sCh,
		Buffer.from(fundTxid, 'hex').reverse(),
		fout.n,
		crypto.randomBytes(64)
	);
	const srChannelId = sCh.getChannelId()!;
	sManager.handleFundingConfirmed(srChannelId);
	rManager.handleFundingConfirmed(srChannelId);
	const rCh = rManager
		.getChannelsByPeer(sPub)
		.find((c) => c.getChannelId()?.equals(srChannelId))!;

	const tip = (await bitcoinRpc('getblockcount')) as number;
	const D = tip + 20;
	const tExp = D + 1008;
	expect(
		rManager.initiateFforEpoch(srChannelId, {
			variant: 1,
			budgetMsat: BUDGET,
			maxPayments: 3,
			minPaymentMsat: 600_000n,
			settlementDeadline: D,
			voucherExpiry: tExp,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 5000,
			escapeGranularityMsat: G
		}).ok,
		rErrors.join('; ')
	).to.equal(true);
	const hashes = sCh.getFforEpoch()!.params.paymentHashes!;
	expect(sCh.getFforEpoch()!.escapeSigs.length).to.equal(2);

	srLink.down();
	sManager.handlePeerDisconnected(rPub);
	rManager.handlePeerDisconnected(sPub);
	for (let i = 0; i < settlements.length; i++) {
		pManager.addHtlc(
			psChannelId,
			settlements[i],
			hashes[i],
			tip + 400,
			Buffer.alloc(1366)
		);
	}
	expect(sCh.getFforEpoch()!.lastSeq).to.equal(settlements.length);

	return {
		pManager,
		sManager,
		rManager,
		rConfig: rC,
		sConfig: sC,
		sPub,
		rPub,
		psChannelId,
		srChannelId,
		sChannel: sCh,
		rChannel: rCh,
		srLink,
		hashes,
		rBroadcasts,
		sBroadcasts,
		rErrors,
		sErrors,
		tip,
		D,
		tExp
	};
}

async function acceptAndConfirm(txHex: string, label: string): Promise<string> {
	const accept = (await bitcoinRpc('testmempoolaccept', [[txHex]])) as Array<{
		allowed: boolean;
		'reject-reason'?: string;
	}>;
	expect(
		accept[0].allowed,
		`${label}: ${accept[0]['reject-reason'] ?? ''}`
	).to.equal(true);
	const txid = (await bitcoinRpc('sendrawtransaction', [txHex])) as string;
	await mineBlocks(1);
	const info = (await bitcoinRpc('getrawtransaction', [txid, true])) as {
		confirmations?: number;
	};
	expect(info.confirmations ?? 0, `${label} confirmed`).to.be.greaterThan(0);
	return txid;
}

/** Mine until the chain tip is at least `height`. */
async function mineTo(height: number): Promise<void> {
	const cur = (await bitcoinRpc('getblockcount')) as number;
	if (cur < height) await mineBlocks(height - cur);
}

describe('FFOR M5: pre-signed escapes (regtest bitcoind)', function () {
	this.timeout(240_000);
	let skip = false;
	before(async function () {
		this.timeout(30_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds(3);
	});

	it('GATE M5-A/A1: R gone; S broadcasts E_j; R claims the aggregate voucher (path 3)', async function () {
		if (skip) this.skip();
		const t = await setup('m5a1', [50_000_000n, 20_000_000n]);
		// owed = v1 + v2 ~ 69,749,000 msat -> j = ceil(owed/G) = 2 (100k sat).

		// Past D + escape_delay; use a small escape_delay for the test.
		await mineTo(t.D + 10 + 1);
		const height = (await bitcoinRpc('getblockcount')) as number;
		const esc = t.sManager.fforBroadcastEscape(t.srChannelId, height, 10);
		expect(esc.ok, t.sErrors.join('; ')).to.equal(true);
		expect(esc.j).to.equal(2);
		expect(esc.voucherValueSat).to.equal(100_000n);
		const escTxid = await acceptAndConfirm(esc.txHex!, 'escape E_2');
		// eslint-disable-next-line no-console
		console.log(`      GATE M5-A escape commitment: ${escTxid}`);

		// R appears with ONLY its seed + funding outpoint. Rebuild the escape
		// context from the channel statics R saved (standalone claim).
		const rDest = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress', ['m5a-r', 'bech32'])) as string,
			NETWORK
		);
		const claim = t.rManager.fforClaimEscapeVoucher(
			t.srChannelId,
			esc.txHex!,
			rDest,
			400n
		);
		expect(claim.ok, t.rErrors.join('; ')).to.equal(true);
		const claimTx = bitcoin.Transaction.fromHex(claim.txHex!);
		expect(claimTx.ins[0].sequence).to.equal(1); // 1-CSV
		// The escape has 1 confirmation, satisfying the 1-block CSV.
		const claimTxid = await acceptAndConfirm(
			claim.txHex!,
			'R voucher claim (path 3)'
		);
		// eslint-disable-next-line no-console
		console.log(`      GATE M5-A R claim (path 3):  ${claimTxid}`);

		const rAddr = bitcoin.address.fromOutputScript(rDest, NETWORK);
		const received = (await bitcoinRpc('getreceivedbyaddress', [
			rAddr,
			1
		])) as number;
		const receivedSats = Math.round(received * 1e8);
		// voucher j*G = 100,000 sat, minus the 400 sat fee.
		expect(receivedSats).to.equal(100_000 - 400);
		// S's rounding cost: owed 69,749,000 msat, j*G = 100,000,000 msat, so
		// S overpaid R by (100000 - 69749) sat < G/1000 = 50,000 sat. Wait: j=2
		// because owed 69.749k > G/1000=50k -> j=2. rounding cost = 100k-69.749k.
		const owedSat = 69_749n; // 50M + 20M - fees, /1000
		expect(Number(esc.voucherValueSat! - owedSat)).to.be.lessThan(
			Number(G / 1000n)
		);
	});

	it('GATE M5-A/A2: R never appears; after T_exp S claims the refund (path 2)', async function () {
		if (skip) this.skip();
		const t = await setup('m5a2', [50_000_000n]);
		// owed = v1 ~ 49,749,000 msat -> j = ceil(owed/G) = 1 (50k sat).

		await mineTo(t.D + 10 + 1);
		let height = (await bitcoinRpc('getblockcount')) as number;
		const esc = t.sManager.fforBroadcastEscape(t.srChannelId, height, 10);
		expect(esc.ok, t.sErrors.join('; ')).to.equal(true);
		expect(esc.j).to.equal(1);
		const escTxid = await acceptAndConfirm(esc.txHex!, 'escape E_1');
		// eslint-disable-next-line no-console
		console.log(`      GATE M5-A2 escape commitment: ${escTxid}`);

		// R never appears. After T_exp (and the to_self_delay CSV), S claims the
		// refund via path 2. Build the path-2 spend directly from S's context.
		const escTx = bitcoin.Transaction.fromHex(esc.txHex!);
		const ectx = (
			t.sChannel as unknown as {
				_buildEscapeContext: () => IEscapeChannelContext;
			}
		)._buildEscapeContext();
		const match = matchEscapeBroadcast(escTx, ectx, G);
		expect(match.isEscape).to.equal(true);

		// S's delayed payment secret at n0+1: derived from S's delayed basepoint
		// SECRET (config.delayedPaymentBasepointSecret) + S's point at n0+1.
		const {
			derivePrivateKey,
			perCommitmentPointFromSecret
		} = require('../../../src/lightning/keys/derivation');
		const {
			generateFromSeed,
			MAX_INDEX
		} = require('../../../src/lightning/keys/shachain');
		const epoch = t.sChannel.getFforEpoch()!;
		const n0 = epoch.sCommitmentNumber!;
		const sSeed = t.sChannel.getFullState().localPerCommitmentSeed;
		const sPointN0Plus1 = perCommitmentPointFromSecret(
			generateFromSeed(sSeed, MAX_INDEX - (n0 + 1n))
		);
		const realSDelayed = derivePrivateKey(
			t.sConfig.delayedPaymentBasepointSecret!,
			sPointN0Plus1,
			ectx.sBasepoints.delayedPaymentBasepoint
		);
		const sDest = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress', ['m5a2-s', 'bech32'])) as string,
			NETWORK
		);
		const refund = buildEscapeSRefund(
			{
				escapeTxid: escTx.getId(),
				voucherOutputIndex: match.voucherOutputIndex!,
				voucherValueSat: match.voucherValueSat!,
				voucherScript: match.voucherScript!,
				destinationScript: sDest,
				feeSatoshis: 400n
			},
			realSDelayed,
			t.tExp,
			TO_SELF_DELAY
		);
		expect(refund.locktime).to.equal(t.tExp);
		expect(refund.ins[0].sequence).to.equal(TO_SELF_DELAY);

		// Advance chain past T_exp AND the CSV (escape confirmed already).
		await mineTo(t.tExp + TO_SELF_DELAY + 1);
		height = (await bitcoinRpc('getblockcount')) as number;
		const refundTxid = await acceptAndConfirm(
			refund.toHex(),
			'S refund (path 2)'
		);
		// eslint-disable-next-line no-console
		console.log(`      GATE M5-A2 S refund (path 2): ${refundTxid}`);
		const sAddr = bitcoin.address.fromOutputScript(sDest, NETWORK);
		const received = (await bitcoinRpc('getreceivedbyaddress', [
			sAddr,
			1
		])) as number;
		expect(Math.round(received * 1e8)).to.equal(50_000 - 400);
	});

	it('GATE M5-B: stale escape after reconciliation -> R penalizes via revocation path 1', async function () {
		if (skip) this.skip();
		const t = await setup('m5b', [50_000_000n, 20_000_000n]);

		// Full reconciliation reveals per_commitment_secret_S[n0+1].
		t.srLink.up();
		const p = (a: ReturnType<Channel['createReestablish']>): Buffer =>
			(
				a.find((x) => x.type === ChannelActionType.SEND_MESSAGE) as {
					payload: Buffer;
				}
			).payload;
		t.rManager.handleMessage(
			t.sPub,
			MessageType.CHANNEL_REESTABLISH,
			p(t.sChannel.createReestablish())
		);
		t.sManager.handleMessage(
			t.rPub,
			MessageType.CHANNEL_REESTABLISH,
			p(t.rChannel.createReestablish())
		);
		expect(t.rChannel.getState(), t.rErrors.join('; ')).to.equal(
			ChannelState.NORMAL
		);
		expect(t.rChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_CLOSED);

		// S cheats: rebuilds and broadcasts E_1 anyway (now a revoked state).
		const built = t.sChannel.fforBuildEscapeForBroadcast(1);
		expect(built.ok, built.error).to.equal(true);
		const staleTxid = await acceptAndConfirm(built.txHex!, 'stale escape E_1');
		// eslint-disable-next-line no-console
		console.log(`      GATE M5-B stale escape:   ${staleTxid}`);

		// R penalizes the aggregate voucher via revocation path 1.
		const rDest = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress', ['m5b-r', 'bech32'])) as string,
			NETWORK
		);
		const pen = t.rManager.fforPenalizeStaleEscape(
			t.srChannelId,
			built.txHex!,
			rDest,
			400n
		);
		expect(pen.ok, pen.error).to.equal(true);
		const penTx = bitcoin.Transaction.fromHex(pen.txHex!);
		expect(penTx.ins[0].sequence).to.equal(0xffffffff);
		expect(penTx.ins[0].witness[1].length).to.equal(33); // revocationPubkey
		const penTxid = await acceptAndConfirm(
			pen.txHex!,
			'R justice (revocation path 1)'
		);
		// eslint-disable-next-line no-console
		console.log(`      GATE M5-B justice tx:     ${penTxid}`);
		const rAddr = bitcoin.address.fromOutputScript(rDest, NETWORK);
		const received = (await bitcoinRpc('getreceivedbyaddress', [
			rAddr,
			1
		])) as number;
		// aggregate voucher j=1 -> 50k sat minus 400 fee.
		expect(Math.round(received * 1e8)).to.equal(50_000 - 400);
	});
});
