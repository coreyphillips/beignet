/**
 * FFOR M5 escape-flow integration (in-memory, no bitcoind): the escape
 * broadcast preconditions (spec §10), the R aggregate-voucher claim (path 3),
 * and the stale-escape penalty after reconciliation (path 1). Three in-process
 * nodes P - S - R with a variant-A epoch and G > 0.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	FforEpochState,
	IFforEpochParams
} from '../../src/lightning/ffor/types';
import { matchEscapeBroadcast } from '../../src/lightning/ffor/escape';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

let seedN = 0;
function makeConfig(name: string): IChannelManagerConfig {
	const seed = sha256(Buffer.from(`ffor-escflow-${name}-${seedN}`));
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
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
		localBasepoints: bp,
		localPerCommitmentSeed: sha256(Buffer.from(`${name}-commit-${seedN}`)),
		localFundingPrivkey: k(0),
		htlcBasepointSecret: k(4),
		revocationBasepointSecret: k(1),
		paymentBasepointSecret: k(2),
		delayedPaymentBasepointSecret: k(3),
		nodePrivateKey: sha256(Buffer.from(`${name}-node-${seedN}`)),
		preferAnchors: true
	};
}

interface ILink {
	down: () => void;
	up: () => void;
	dropTypes: Set<number>;
}
function connect(
	a: ChannelManager,
	aPub: string,
	b: ChannelManager,
	bPub: string
): ILink {
	let connected = true;
	const dropTypes = new Set<number>();
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (connected && peer === bPub && !dropTypes.has(type)) {
			b.handleMessage(aPub, type, payload);
		}
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (connected && peer === aPub && !dropTypes.has(type)) {
			a.handleMessage(bPub, type, payload);
		}
	});
	return {
		down: (): void => {
			connected = false;
		},
		up: (): void => {
			connected = true;
		},
		dropTypes
	};
}

const FUNDING = 1_000_000n;
const G = 50_000_000n; // 50k sat
const BUDGET = 100_000_000n; // J = 2
const D = 1000;

interface IScn {
	pManager: ChannelManager;
	sManager: ChannelManager;
	rManager: ChannelManager;
	sPub: string;
	rPub: string;
	psChannelId: Buffer;
	srChannelId: Buffer;
	sChannel: Channel;
	rChannel: Channel;
	srLink: ILink;
	hashes: Buffer[];
	rBroadcasts: Buffer[];
	sBroadcasts: Buffer[];
	rErrors: string[];
	sErrors: string[];
}

function setup(settlements: bigint[]): IScn {
	seedN++;
	const pC = makeConfig('P');
	const sC = makeConfig('S');
	const rC = makeConfig('R');
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

	const open = (
		om: ChannelManager,
		am: ChannelManager,
		oPub: string,
		aPub: string
	): { id: Buffer; opener: Channel; acceptor: Channel } => {
		const opener = om.openChannel(aPub, FUNDING);
		om.createFunding(opener, crypto.randomBytes(32), 0, crypto.randomBytes(64));
		const id = opener.getChannelId()!;
		om.handleFundingConfirmed(id);
		am.handleFundingConfirmed(id);
		const acceptor = am
			.getChannelsByPeer(oPub)
			.find((c) => c.getChannelId()?.equals(id))!;
		return { id, opener, acceptor };
	};
	const ps = open(pManager, sManager, pPub, sPub);
	const sr = open(sManager, rManager, sPub, rPub);

	const params: Omit<IFforEpochParams, 'rPerCommitmentPoints'> = {
		variant: 1,
		budgetMsat: BUDGET,
		maxPayments: 3,
		minPaymentMsat: 600_000n,
		settlementDeadline: D,
		voucherExpiry: D + 1008,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: G
	};
	expect(
		rManager.initiateFforEpoch(sr.id, params).ok,
		rErrors.join('; ')
	).to.equal(true);
	const hashes = sr.opener.getFforEpoch()!.params.paymentHashes!;
	// Real escape sigs exchanged: S holds J verified sigs.
	expect(sr.opener.getFforEpoch()!.escapeSigs.length).to.equal(2);
	for (const s of sr.opener.getFforEpoch()!.escapeSigs) {
		expect(s.length).to.equal(64);
		expect(s.equals(Buffer.alloc(64))).to.equal(false); // not a placeholder
	}

	// R offline; P settles.
	srLink.down();
	sManager.handlePeerDisconnected(rPub);
	rManager.handlePeerDisconnected(sPub);
	for (let i = 0; i < settlements.length; i++) {
		pManager.addHtlc(ps.id, settlements[i], hashes[i], 900, Buffer.alloc(1366));
	}
	expect(sr.opener.getFforEpoch()!.lastSeq).to.equal(settlements.length);

	return {
		pManager,
		sManager,
		rManager,
		sPub,
		rPub,
		psChannelId: ps.id,
		srChannelId: sr.id,
		sChannel: sr.opener,
		rChannel: sr.acceptor,
		srLink,
		hashes,
		rBroadcasts,
		sBroadcasts,
		rErrors,
		sErrors
	};
}

const DEST = bitcoin.payments.p2wpkh({ hash: Buffer.alloc(20, 7) }).output!;

describe('FFOR M5: escape broadcast preconditions (spec §10)', function () {
	it('rejects escape before height > D + escape_delay', function () {
		const t = setup([1_000_000n, 1_000_000n]);
		// owed = v1 + v2 ~ 1,988,000 msat -> j = ceil(owed/G) = 1. But too early.
		const res = t.sManager.fforBroadcastEscape(t.srChannelId, D + 100, 2016);
		expect(res.ok).to.equal(false);
		expect(res.error).to.match(/escape_delay|not permitted/);
		expect(t.sBroadcasts.length).to.equal(0);
	});

	it('rejects escape once reconciliation has begun', function () {
		const t = setup([1_000_000n]);
		// Force the epoch into FF_RECONCILE by driving replay via reconnect but
		// dropping ff_reconcile so it stays reconciling on S.
		t.srLink.up();
		t.srLink.dropTypes.add(MessageType.FF_RECONCILE);
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
		expect(t.sChannel.getFforEpoch()!.state).to.equal(
			FforEpochState.FF_RECONCILE
		);
		const res = t.sManager.fforBroadcastEscape(t.srChannelId, D + 5000, 2016);
		expect(res.ok).to.equal(false);
		expect(res.error).to.match(/reconciliation began/);
	});

	it('broadcasts E_j with j = ceil(owed/G) when preconditions hold', function () {
		const t = setup([50_000_000n, 20_000_000n]);
		// v1 = 50M - fee, v2 = 20M - fee. owed ~ 69,749,000 msat -> j = 2.
		const res = t.sManager.fforBroadcastEscape(t.srChannelId, D + 2017, 2016);
		expect(res.ok, t.sErrors.join('; ')).to.equal(true);
		expect(res.j).to.equal(2);
		expect(res.voucherValueSat).to.equal(100_000n); // 2 * G
		expect(t.sBroadcasts.length).to.equal(1);
		// The broadcast is a well-formed escape recognizable by R.
		const escapeTx = bitcoin.Transaction.fromBuffer(t.sBroadcasts[0]);
		const ectx = (
			t.rChannel as unknown as {
				_buildEscapeContext: () => import('../../src/lightning/ffor/escape').IEscapeChannelContext;
			}
		)._buildEscapeContext();
		const m = matchEscapeBroadcast(escapeTx, ectx, G);
		expect(m.isEscape).to.equal(true);
		expect(m.j).to.equal(2);
	});
});

describe('FFOR M5: R aggregate-voucher claim (path 3, spec §10)', function () {
	it('R claims the aggregate voucher of a broadcast E_j to its wallet', function () {
		const t = setup([50_000_000n, 20_000_000n]);
		const esc = t.sManager.fforBroadcastEscape(t.srChannelId, D + 2017, 2016);
		expect(esc.ok).to.equal(true);
		const claim = t.rManager.fforClaimEscapeVoucher(
			t.srChannelId,
			esc.txHex!,
			DEST
		);
		expect(claim.ok, t.rErrors.join('; ')).to.equal(true);
		const claimTx = bitcoin.Transaction.fromHex(claim.txHex!);
		// Path 3 witness: [R_sig, 0x01, script], input nSequence = 1.
		expect(claimTx.ins[0].sequence).to.equal(1);
		expect(claimTx.ins[0].witness.length).to.equal(3);
		expect(claimTx.ins[0].witness[1].equals(Buffer.from([0x01]))).to.equal(
			true
		);
		// Pays R's destination (voucher 100k sat minus fee).
		expect(Buffer.from(claimTx.outs[0].script).equals(DEST)).to.equal(true);
		expect(claimTx.outs[0].value).to.be.lessThan(100_000);
		expect(claimTx.outs[0].value).to.be.greaterThan(99_000);
	});
});

describe('FFOR M5: stale-escape penalty after reconciliation (path 1, §B.5)', function () {
	it('R penalizes a post-reconciliation E_j via the aggregate-voucher revocation path', function () {
		const t = setup([50_000_000n, 20_000_000n]);
		// Full reconciliation: reconnect, replay, reconcile, ack (reveals n0+1),
		// revoke batch, ff_end.
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

		// S cheats: it rebuilds and broadcasts E_1 anyway (now a revoked state).
		// Build E_1 directly from S's channel (bypassing the manager guard).
		const built = t.sChannel.fforBuildEscapeForBroadcast(1);
		expect(built.ok, built.error).to.equal(true);

		// R penalizes the aggregate voucher via revocation path 1.
		const pen = t.rManager.fforPenalizeStaleEscape(
			t.srChannelId,
			built.txHex!,
			DEST
		);
		expect(pen.ok, pen.error).to.equal(true);
		const penTx = bitcoin.Transaction.fromHex(pen.txHex!);
		// Revocation witness: [rev_sig, revocationPubkey(33), script], no timelock.
		expect(penTx.ins[0].sequence).to.equal(0xffffffff);
		expect(penTx.ins[0].witness.length).to.equal(3);
		expect(penTx.ins[0].witness[1].length).to.equal(33);
		expect(Buffer.from(penTx.outs[0].script).equals(DEST)).to.equal(true);
		// Sweeps the aggregate voucher (j=1 -> 50k sat) minus fee.
		expect(penTx.outs[0].value).to.be.lessThan(50_000);
		expect(penTx.outs[0].value).to.be.greaterThan(49_000);
	});
});
