/**
 * FFOR M3 regtest gates (real bitcoind, spec §15.3):
 *
 * GATE A: variant-A epoch with 2 delegated settlements while R is offline;
 * R returns, replay completes, S refuses reconciliation; R force-closes its
 * adopted C_2^R on regtest. The commitment, both voucher HTLC-success txs
 * (package htlc_sigs + preimages, wallet fee inputs attached), and the
 * CSV-matured second-level sweeps are all accepted and confirmed by bitcoind,
 * ending with the voucher value at R's wallet address.
 *
 * GATE B: after settlement 1, S broadcasts its revoked C_{n0}^S; R's monitor
 * classifies it via the package-1 pre-revocation secret and confirms a
 * justice transaction sweeping S's to_local.
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
	bitcoinRpc,
	mineBlocks,
	ensureBitcoindFunds,
	BitcoindFundingProvider
} from './shared-helpers';

const NETWORK = bitcoin.networks.regtest;
const TO_SELF_DELAY = 6;
const FUNDING_SATOSHIS = 1_000_000n;

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

function sleep(ms: number): Promise<void> {
	return new Promise((r) => setTimeout(r, ms));
}

function makeSeed(id: string): Buffer {
	return sha256(Buffer.from(`ffor-m3-rt-${id}`));
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
		// Frozen epoch feerate 2500 sat/kw (~2.5 sat/vB) keeps the broadcast
		// commitment above min-relay without CPFP; short CSV keeps the test fast.
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			toSelfDelay: TO_SELF_DELAY,
			feeratePerKw: 2500
		},
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

interface IScenario {
	pManager: ChannelManager;
	sManager: ChannelManager;
	rManager: ChannelManager;
	sPub: string;
	rPub: string;
	psChannelId: Buffer;
	srChannelId: Buffer;
	sChannel: Channel;
	rChannel: Channel;
	rBroadcasts: Buffer[];
	sBroadcasts: Buffer[];
	rErrors: string[];
	hashes: Buffer[];
	tip: number;
}

/**
 * Real-funded S-R channel on regtest + in-memory P-S channel; variant-A
 * epoch; `amounts` delegated settlements while R is offline; reconnect with
 * FF_RECONCILE dropped (S refuses reconciliation).
 */
async function setupOnRegtest(
	name: string,
	amounts: bigint[]
): Promise<IScenario> {
	const pConfig = makeConfig(`${name}-P`);
	const sConfig = makeConfig(`${name}-S`);
	const rConfig = makeConfig(`${name}-R`);
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
	const sBroadcasts: Buffer[] = [];
	sManager.on('broadcast:tx', (tx: Buffer) => sBroadcasts.push(tx));

	connect(pManager, pPub, sManager, sPub);
	const srLink = connect(sManager, sPub, rManager, rPub);

	// P-S channel needs no on-chain footprint.
	const pChannel = pManager.openChannel(sPub, FUNDING_SATOSHIS);
	pManager.createFunding(
		pChannel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	);
	const psChannelId = pChannel.getChannelId()!;
	pManager.handleFundingConfirmed(psChannelId);
	sManager.handleFundingConfirmed(psChannelId);

	// S-R channel funded by a REAL regtest outpoint paying the BOLT 3 P2WSH
	// 2-of-2 of the two funding pubkeys.
	const funding = createFundingScript(
		sConfig.localBasepoints.fundingPubkey,
		rConfig.localBasepoints.fundingPubkey,
		NETWORK
	);
	const fundTxid = (await bitcoinRpc('sendtoaddress', [
		funding.address,
		Number(FUNDING_SATOSHIS) / 1e8
	])) as string;
	await mineBlocks(1);
	const fundTx = (await bitcoinRpc('getrawtransaction', [fundTxid, true])) as {
		vout: Array<{ n: number; scriptPubKey: { address?: string } }>;
	};
	const fout = fundTx.vout.find(
		(v) => v.scriptPubKey.address === funding.address
	)!;

	const sChannel = sManager.openChannel(rPub, FUNDING_SATOSHIS);
	sManager.createFunding(
		sChannel,
		Buffer.from(fundTxid, 'hex').reverse(),
		fout.n,
		crypto.randomBytes(64)
	);
	const srChannelId = sChannel.getChannelId()!;
	sManager.handleFundingConfirmed(srChannelId);
	rManager.handleFundingConfirmed(srChannelId);
	const rChannel = rManager
		.getChannelsByPeer(sPub)
		.find((c) => c.getChannelId()?.equals(srChannelId))!;
	expect(sChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(rChannel.getState()).to.equal(ChannelState.NORMAL);

	// Variant-A epoch with heights anchored to the real regtest tip.
	const tip = (await bitcoinRpc('getblockcount')) as number;
	const result = rManager.initiateFforEpoch(srChannelId, {
		variant: 1,
		budgetMsat: 400_000_000n,
		maxPayments: Math.max(2, amounts.length),
		minPaymentMsat: 500_000n,
		settlementDeadline: tip + 5000,
		voucherExpiry: tip + 5000 + 1008,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: 0n
	});
	expect(result.ok, rErrors.join('; ')).to.equal(true);
	const hashes = sChannel.getFforEpoch()!.params.paymentHashes!;

	// R offline; P pays the delegated invoices.
	srLink.down();
	sManager.handlePeerDisconnected(rPub);
	rManager.handlePeerDisconnected(sPub);
	for (let i = 0; i < amounts.length; i++) {
		pManager.addHtlc(
			psChannelId,
			amounts[i],
			hashes[i],
			tip + 400,
			Buffer.alloc(1366)
		);
	}
	expect(sChannel.getFforEpoch()!.lastSeq).to.equal(amounts.length);

	// R returns; replay completes; S never sees ff_reconcile (refusal).
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
	const sRe = payloadOf(sChannel.createReestablish());
	const rRe = payloadOf(rChannel.createReestablish());
	rManager.handleMessage(sPub, MessageType.CHANNEL_REESTABLISH, sRe);
	sManager.handleMessage(rPub, MessageType.CHANNEL_REESTABLISH, rRe);
	expect(rChannel.getFforEpoch()!.lastSeq).to.equal(amounts.length);
	expect(rChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_RECONCILE);

	return {
		pManager,
		sManager,
		rManager,
		sPub,
		rPub,
		psChannelId,
		srChannelId,
		sChannel,
		rChannel,
		rBroadcasts,
		sBroadcasts,
		rErrors,
		hashes,
		tip
	};
}

async function acceptAndConfirm(txHex: string, label: string): Promise<string> {
	const accept = (await bitcoinRpc('testmempoolaccept', [[txHex]])) as Array<{
		txid: string;
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

describe('FFOR M3: on-chain enforcement (regtest bitcoind)', function () {
	this.timeout(180_000);
	let skip = false;

	before(async function () {
		this.timeout(30_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds(3);
	});

	it('GATE A: R force-closes C_j^R, sweeps every voucher via HTLC-success + CSV sweep to its wallet', async function () {
		if (skip) this.skip();
		const t = await setupOnRegtest('gateA', [200_000_000n, 100_000_000n]);

		// R's sweep destination: a real bitcoind wallet address so the recovered
		// value is wallet-visible at the end.
		const destAddress = (await bitcoinRpc('getnewaddress', [
			'ffor-r-sweeps',
			'bech32'
		])) as string;
		const destScript = bitcoin.address.toOutputScript(destAddress, NETWORK);

		// Wallet fee inputs for the zero-fee HTLC-success txs.
		const feeProvider = new BitcoindFundingProvider();
		await feeProvider.prefundFeeInputs(4, 50_000);
		t.rManager.setFundingProvider(feeProvider);

		// R force-closes with its adopted C_2^R (S refused to reconcile).
		const res = t.rManager.fforForceClose(
			t.srChannelId,
			destScript,
			10,
			NETWORK
		);
		expect(res.ok, t.rErrors.join('; ')).to.equal(true);
		expect(t.rChannel.getState()).to.equal(ChannelState.FORCE_CLOSED);
		const commitment = bitcoin.Transaction.fromBuffer(t.rBroadcasts[0]);
		expect(commitment.outs.some((o) => o.value === 198_999)).to.equal(true);
		expect(commitment.outs.some((o) => o.value === 99_499)).to.equal(true);

		// Commitment accepted + confirmed on regtest.
		const commitTxid = await acceptAndConfirm(
			commitment.toHex(),
			'C_2^R commitment'
		);
		// eslint-disable-next-line no-console
		console.log(`      GATE A commitment: ${commitTxid}`);

		// Monitor classifies OUR commitment and claims both vouchers via
		// second-level HTLC-success (async wallet fee attach).
		const confHeight = (await bitcoinRpc('getblockcount')) as number;
		const before = t.rBroadcasts.length;
		t.rManager.handleFundingSpent(
			t.srChannelId,
			commitment,
			confHeight,
			destScript,
			10,
			undefined,
			undefined,
			NETWORK
		);
		// The zero-fee HTLC-success txs carry nSequence = 1 (anchor rules), so
		// they are held until the commitment has one confirmation of depth.
		await mineBlocks(1);
		t.rManager.handleNewBlock((await bitcoinRpc('getblockcount')) as number);
		await sleep(4000);

		const successTxs = t.rBroadcasts
			.slice(before)
			.map((b) => bitcoin.Transaction.fromBuffer(b))
			.filter((tx) =>
				tx.ins.some((i) => Buffer.from(i.hash).equals(commitment.getHash()))
			);
		expect(successTxs.length, t.rErrors.join('; ')).to.equal(2);

		// Each HTLC-success (with attached wallet fee input) accepted + confirmed.
		const successTxids: string[] = [];
		const secondLevelInfo: Array<{ tx: bitcoin.Transaction; vout: number }> =
			[];
		for (const s of successTxs) {
			expect(s.ins.length, 'wallet fee input attached').to.be.greaterThan(1);
			const preimage = s.ins[0].witness[3];
			expect(t.hashes.some((h) => h.equals(sha256(preimage)))).to.equal(true);
			const txid = await acceptAndConfirm(s.toHex(), 'HTLC-success');
			successTxids.push(txid);
			const commitVout = s.ins[0].index;
			secondLevelInfo.push({ tx: s, vout: commitVout });
			// eslint-disable-next-line no-console
			console.log(`      GATE A HTLC-success: ${txid}`);
		}

		// Tell the monitor the voucher outputs were spent by our own success txs
		// so it tracks the CSV-delayed second-level outputs.
		let height = (await bitcoinRpc('getblockcount')) as number;
		for (const { tx, vout } of secondLevelInfo) {
			t.rManager.handleOutputSpent(commitTxid, vout, tx, height);
		}

		// CSV (to_self_delay = 6) matures; the second-level sweeps release.
		const beforeSweeps = t.rBroadcasts.length;
		await mineBlocks(TO_SELF_DELAY + 1);
		height = (await bitcoinRpc('getblockcount')) as number;
		t.rManager.handleNewBlock(height);
		await sleep(1500);

		const successTxidSet = new Set(
			successTxs.map((s) => s.getHash().toString('hex'))
		);
		const sweeps = t.rBroadcasts
			.slice(beforeSweeps)
			.map((b) => bitcoin.Transaction.fromBuffer(b))
			.filter((tx) =>
				tx.ins.some((i) =>
					successTxidSet.has(Buffer.from(i.hash).toString('hex'))
				)
			);
		expect(sweeps.length, t.rErrors.join('; ')).to.equal(2);

		// Sweeps accepted + confirmed; they pay R's wallet address.
		let sweptSats = 0;
		for (const sweep of sweeps) {
			expect(Buffer.from(sweep.outs[0].script).equals(destScript)).to.equal(
				true
			);
			sweptSats += sweep.outs[0].value;
			const txid = await acceptAndConfirm(sweep.toHex(), 'second-level sweep');
			// eslint-disable-next-line no-console
			console.log(`      GATE A CSV sweep:    ${txid}`);
		}

		// The recovered value is wallet-visible and equals the voucher value
		// minus only the sweep fees (voucher sats: 198,999 + 99,499 = 298,498).
		const received = (await bitcoinRpc('getreceivedbyaddress', [
			destAddress,
			1
		])) as number;
		const receivedSats = Math.round(received * 1e8);
		expect(receivedSats).to.equal(sweptSats);
		expect(sweptSats).to.be.greaterThan(0);
		expect(sweptSats).to.be.at.most(198_999 + 99_499);
		// Sweep fee sanity: at 10 sat/vB a 1-in-1-out P2WSH spend costs well
		// under 3000 sat per sweep.
		expect(sweptSats).to.be.greaterThan(198_999 + 99_499 - 2 * 3000);
	});

	it('GATE B: S broadcasts the revoked C_{n0}^S; R confirms a justice tx from the package-1 secret', async function () {
		if (skip) this.skip();
		const t = await setupOnRegtest('gateB', [1_000_000n]);

		// S misbehaves: force-closes with its pre-epoch commitment - revoked by
		// the package-1 secret the moment payment 1 settled (§12.1).
		const sDest = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress', ['ffor-s-cheat', 'bech32'])) as string,
			NETWORK
		);
		const cheat = t.sManager.forceClose(t.srChannelId, sDest, 10, NETWORK);
		expect(cheat.ok).to.equal(true);
		const revokedTx = bitcoin.Transaction.fromBuffer(t.sBroadcasts[0]);
		const revokedTxid = await acceptAndConfirm(
			revokedTx.toHex(),
			'revoked C_{n0}^S'
		);
		// eslint-disable-next-line no-console
		console.log(`      GATE B revoked commitment: ${revokedTxid}`);

		// R's monitor: classification via the pre-revocation secret + justice.
		const destAddress = (await bitcoinRpc('getnewaddress', [
			'ffor-r-justice',
			'bech32'
		])) as string;
		const destScript = bitcoin.address.toOutputScript(destAddress, NETWORK);
		const height = (await bitcoinRpc('getblockcount')) as number;
		const before = t.rBroadcasts.length;
		t.rManager.handleFundingSpent(
			t.srChannelId,
			revokedTx,
			height,
			destScript,
			10,
			undefined,
			undefined,
			NETWORK
		);
		const justiceCandidates = t.rBroadcasts
			.slice(before)
			.map((b) => bitcoin.Transaction.fromBuffer(b))
			.filter((tx) =>
				tx.ins.some((i) => Buffer.from(i.hash).equals(revokedTx.getHash()))
			);
		expect(justiceCandidates.length, t.rErrors.join('; ')).to.be.greaterThan(0);

		// The justice tx sweeps S's to_local (the channel's whole S-side balance,
		// minus the voucher already skimmed at commitment level) to R's wallet.
		const justice = justiceCandidates[0];
		expect(Buffer.from(justice.outs[0].script).equals(destScript)).to.equal(
			true
		);
		const sweptValue = justice.outs[0].value;
		// S's to_local on C_{n0}^S = capacity - commitment fee (2810 sat at
		// 2500 sat/kw, no HTLCs) - 2 anchors (660). R had no balance.
		expect(sweptValue).to.be.greaterThan(900_000);

		const justiceTxid = await acceptAndConfirm(justice.toHex(), 'justice tx');
		// eslint-disable-next-line no-console
		console.log(`      GATE B justice tx:         ${justiceTxid}`);

		const received = (await bitcoinRpc('getreceivedbyaddress', [
			destAddress,
			1
		])) as number;
		expect(Math.round(received * 1e8)).to.equal(sweptValue);
	});
});
