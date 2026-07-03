/**
 * FFOR M3 unit tests (no bitcoind): on-chain enforcement plumbing.
 *
 * - Classification: a broadcast C_{n0}^S after settlement 1 is
 *   THEIR_REVOKED_COMMITMENT on R even though R's remote commitment number
 *   still points at n0 (FFOR pre-revocation, spec §9.3) - and the monitor
 *   produces a penalty sweep from the package-1 secret.
 * - R force-closes with its adopted C_j^R straight from the epoch (S refuses
 *   reconcile): the broadcast commitment carries every voucher output, and
 *   the monitor claims each voucher via a fully-witnessed HTLC-success tx
 *   built from the package htlc_sigs + preimage.
 * - ff_error after ff_begin triggers the recipient's on-chain fallback
 *   (spec §11.1) instead of aborting into limbo.
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
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	FforEpochState,
	IFforEpochParams
} from '../../src/lightning/ffor/types';
import {
	FF_ERROR_TYPE,
	encodeFforErrorMessage
} from '../../src/lightning/ffor/messages';
import { classifyCommitmentTx } from '../../src/lightning/chain/output-resolver';
import {
	CommitmentType,
	ChainActionType
} from '../../src/lightning/chain/types';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

function makeSeed(id: string): Buffer {
	return sha256(Buffer.from(`ffor-m3-${id}`));
}

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	secrets: Buffer[];
} {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(sha256(Buffer.concat([seed, Buffer.from([i])])));
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		secrets: keys
	};
}

function makeConfig(name: string): IChannelManagerConfig {
	const seed = makeSeed(name);
	const { basepoints, secrets } = makeBasepoints(seed);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
		localBasepoints: basepoints,
		localPerCommitmentSeed: makeSeed(name + '-commit'),
		localFundingPrivkey: secrets[0],
		htlcBasepointSecret: secrets[4],
		revocationBasepointSecret: secrets[1],
		paymentBasepointSecret: secrets[2],
		delayedPaymentBasepointSecret: secrets[3],
		nodePrivateKey: makeSeed(name + '-node'),
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

const FUNDING_SATOSHIS = 1_000_000n;

function paramsA(
	overrides?: Partial<IFforEpochParams>
): Omit<IFforEpochParams, 'rPerCommitmentPoints'> {
	return {
		variant: 1,
		budgetMsat: 100_000_000n,
		maxPayments: 2,
		minPaymentMsat: 500_000n,
		settlementDeadline: 1000,
		voucherExpiry: 2008,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: 0n,
		...overrides
	};
}

/**
 * Three in-memory nodes; S-R channel with an established variant-A epoch,
 * `payments` delegated settlements while R is offline, then a reconnect whose
 * FF_RECONCILE is DROPPED - leaving R with adopted packages and S
 * unreconciled (the "S refuses reconcile" posture of §12.1).
 */
function setupRefusedReconcile(payments: bigint[]): {
	sManager: ChannelManager;
	rManager: ChannelManager;
	sChannel: Channel;
	rChannel: Channel;
	srChannelId: Buffer;
	sPub: string;
	rPub: string;
	rBroadcasts: Buffer[];
	rErrors: string[];
} {
	const pConfig = makeConfig(`P-${payments.length}-${payments[0]}`);
	const sConfig = makeConfig(`S-${payments.length}-${payments[0]}`);
	const rConfig = makeConfig(`R-${payments.length}-${payments[0]}`);
	const pPub = getPublicKey(pConfig.nodePrivateKey!).toString('hex');
	const sPub = getPublicKey(sConfig.nodePrivateKey!).toString('hex');
	const rPub = getPublicKey(rConfig.nodePrivateKey!).toString('hex');
	const pManager = new ChannelManager(pConfig);
	const sManager = new ChannelManager(sConfig);
	const rManager = new ChannelManager(rConfig);
	pManager.on('error', () => {});
	sManager.on('error', () => {});
	const rErrors: string[] = [];
	rManager.on('error', (_id, m: string) => rErrors.push(m));
	const rBroadcasts: Buffer[] = [];
	rManager.on('broadcast:tx', (tx: Buffer) => rBroadcasts.push(tx));

	connect(pManager, pPub, sManager, sPub);
	const srLink = connect(sManager, sPub, rManager, rPub);

	const open = (
		om: ChannelManager,
		am: ChannelManager,
		oPub: string
	): { id: Buffer; opener: Channel; acceptor: Channel } => {
		const opener = om.openChannel(
			om === pManager ? sPub : rPub,
			FUNDING_SATOSHIS
		);
		om.createFunding(opener, crypto.randomBytes(32), 0, crypto.randomBytes(64));
		const id = opener.getChannelId()!;
		om.handleFundingConfirmed(id);
		am.handleFundingConfirmed(id);
		const acceptor = am
			.getChannelsByPeer(oPub)
			.find((c) => c.getChannelId()?.equals(id))!;
		return { id, opener, acceptor };
	};
	const ps = open(pManager, sManager, pPub);
	const sr = open(sManager, rManager, sPub);

	expect(rManager.initiateFforEpoch(sr.id, paramsA()).ok).to.equal(true);
	const hashes = sr.opener.getFforEpoch()!.params.paymentHashes!;

	// R offline.
	srLink.down();
	sManager.handlePeerDisconnected(rPub);
	rManager.handlePeerDisconnected(sPub);

	for (let i = 0; i < payments.length; i++) {
		pManager.addHtlc(ps.id, payments[i], hashes[i], 900, Buffer.alloc(1366));
	}
	expect(sr.opener.getFforEpoch()!.lastSeq).to.equal(payments.length);

	// Reconnect, but S never sees R's ff_reconcile (S "refuses" to reconcile).
	srLink.up();
	srLink.dropTypes.add(MessageType.FF_RECONCILE);
	const payloadOf = (
		actions: ReturnType<Channel['createReestablish']>
	): Buffer =>
		(
			actions.find((a) => a.type === ChannelActionType.SEND_MESSAGE) as {
				payload: Buffer;
			}
		).payload;
	const sRe = payloadOf(sr.opener.createReestablish());
	const rRe = payloadOf(sr.acceptor.createReestablish());
	rManager.handleMessage(sPub, MessageType.CHANNEL_REESTABLISH, sRe);
	sManager.handleMessage(rPub, MessageType.CHANNEL_REESTABLISH, rRe);

	// Replay reached R (packages validated + C_j adopted) but reconciliation
	// never completed on S.
	expect(sr.acceptor.getFforEpoch()!.lastSeq).to.equal(payments.length);
	expect(sr.acceptor.getFforEpoch()!.state).to.equal(
		FforEpochState.FF_RECONCILE
	);
	expect(sr.acceptor.getState()).to.equal(ChannelState.FF_EPOCH);
	expect(sr.opener.getState()).to.equal(ChannelState.FF_EPOCH);

	return {
		sManager,
		rManager,
		sChannel: sr.opener,
		rChannel: sr.acceptor,
		srChannelId: sr.id,
		sPub,
		rPub,
		rBroadcasts,
		rErrors
	};
}

describe('FFOR M3: on-chain enforcement (unit)', function () {
	it('classifies a broadcast revoked C_{n0}^S as THEIR_REVOKED via the package-1 secret', function () {
		const t = setupRefusedReconcile([1_000_000n]);

		// S misbehaves: broadcasts its pre-epoch commitment - the only state it
		// ever signed, revoked by package 1 (§9.3/§12.1).
		const sSigner = t.sChannel.getSigner()!;
		const actions = t.sChannel.forceClose(sSigner);
		const broadcast = actions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		) as { tx: Buffer };
		expect(broadcast, 'S can build its revoked commitment').to.not.equal(
			undefined
		);
		const revokedTx = bitcoin.Transaction.fromBuffer(broadcast.tx);

		// R's classifier: even though R's remote commitment number still points
		// at n0 (no reconcile happened), the held pre-revocation secret decides.
		const classified = classifyCommitmentTx(
			revokedTx,
			t.rChannel.getFullState()
		);
		expect(classified.type).to.equal(CommitmentType.THEIR_REVOKED_COMMITMENT);
		expect(classified.commitmentNumber).to.equal(
			t.rChannel.getFforEpoch()!.sCommitmentNumber!
		);

		// And the monitor turns it into a penalty sweep of S's to_local.
		const dest = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20)
		}).output!;
		const chainActions = t.rManager.handleFundingSpent(
			t.srChannelId,
			revokedTx,
			500,
			dest
		);
		const sweeps = chainActions.filter(
			(a) => a.type === ChainActionType.BROADCAST_TX
		) as Array<{ tx: Buffer }>;
		expect(sweeps.length).to.be.greaterThan(0);
		const justice = bitcoin.Transaction.fromBuffer(sweeps[0].tx);
		// The justice tx spends the revoked commitment and pays our destination.
		expect(
			Buffer.from(justice.ins[0].hash).equals(revokedTx.getHash())
		).to.equal(true);
		expect(Buffer.from(justice.outs[0].script).equals(dest)).to.equal(true);
	});

	it('R force-closes with the adopted C_j^R from the epoch and claims every voucher', function () {
		const t = setupRefusedReconcile([1_000_000n, 550_000n]);
		const dest = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20)
		}).output!;

		const result = t.rManager.fforForceClose(t.srChannelId, dest);
		expect(result.ok, t.rErrors.join('; ')).to.equal(true);
		expect(t.rChannel.getState()).to.equal(ChannelState.FORCE_CLOSED);

		// The broadcast commitment is C_2^R: two voucher outputs (994 + 546 sat)
		// plus two anchors and S's to_remote (R's own to_local is 0 -> absent).
		expect(t.rBroadcasts.length).to.be.greaterThan(0);
		const commitment = bitcoin.Transaction.fromBuffer(t.rBroadcasts[0]);
		const values = commitment.outs.map((o) => o.value).sort((a, b) => a - b);
		expect(values).to.include(994);
		expect(values).to.include(546);
		expect(commitment.outs.length).to.equal(5); // 2 anchors + 2 vouchers + to_remote

		// The monitor resolves each voucher with a fully-witnessed HTLC-success
		// tx (package htlc_sigs + our sig + preimage).
		const before = t.rBroadcasts.length;
		t.rManager.handleFundingSpent(t.srChannelId, commitment, 500, dest);
		t.rManager.handleNewBlock(501);
		const successes = t.rBroadcasts
			.slice(before)
			.map((b) => bitcoin.Transaction.fromBuffer(b))
			.filter((tx) => Buffer.from(tx.ins[0].hash).equals(commitment.getHash()));
		expect(successes.length, t.rErrors.join('; ')).to.equal(2);
		for (const s of successes) {
			const witness = s.ins[0].witness;
			// BOLT 3 HTLC-success witness: [0, remote_sig, local_sig, preimage, script]
			expect(witness.length).to.equal(5);
			expect(witness[3].length).to.equal(32); // the voucher preimage
			const hash = sha256(witness[3]);
			expect(
				t.rChannel
					.getFforEpoch()!
					.params.paymentHashes!.some((h) => h.equals(hash))
			).to.equal(true);
		}
	});

	it('ff_error after ff_begin triggers the recipient on-chain fallback (§11.1)', function () {
		const t = setupRefusedReconcile([1_000_000n]);
		const dest = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20)
		}).output!;
		t.rManager.setMonitorDestinationScript(dest);

		// S signals a protocol violation mid-epoch instead of reconciling.
		const errPayload = encodeFforErrorMessage({
			channelId: t.srChannelId,
			epochId: t.rChannel.getFforEpoch()!.epochId,
			data: Buffer.from('protocol violation', 'utf8')
		});
		t.rManager.handleMessage(t.sPub, FF_ERROR_TYPE, errPayload);

		// R did NOT abort into limbo - it force-closed its adopted C_1^R.
		expect(t.rChannel.getState()).to.equal(ChannelState.FORCE_CLOSED);
		expect(t.rBroadcasts.length).to.be.greaterThan(0);
		const commitment = bitcoin.Transaction.fromBuffer(t.rBroadcasts[0]);
		expect(commitment.outs.some((o) => o.value === 994)).to.equal(true);
		expect(t.rErrors.some((e) => e.includes('ff_error from peer'))).to.equal(
			true
		);
	});

	it('does NOT trigger the fallback on the settlement peer (it must not broadcast, §9.3)', function () {
		const t = setupRefusedReconcile([1_000_000n]);
		const dest = bitcoin.payments.p2wpkh({
			hash: crypto.randomBytes(20)
		}).output!;
		t.sManager.setMonitorDestinationScript(dest);
		const sBroadcasts: Buffer[] = [];
		t.sManager.on('broadcast:tx', (tx: Buffer) => sBroadcasts.push(tx));

		const errPayload = encodeFforErrorMessage({
			channelId: t.srChannelId,
			epochId: t.sChannel.getFforEpoch()!.epochId,
			data: Buffer.from('go away', 'utf8')
		});
		t.sManager.handleMessage(t.rPub, FF_ERROR_TYPE, errPayload);

		expect(t.sChannel.getState()).to.equal(ChannelState.FF_EPOCH);
		expect(sBroadcasts.length).to.equal(0);
	});
});
