/**
 * FFOR M4 regtest gates (real bitcoind, spec §15 Variant B tower):
 *
 * GATE M4-A (milestone gate): variant-B epoch, 2 delegated payments settle via
 * TOWER release while R is offline (payer completes). S then VANISHES
 * permanently (no reconnect, no replay). R returns, recovers packages +
 * preimages from the tower ALONE, adopts C_j^R, force-closes, and sweeps every
 * voucher on regtest to its wallet. Wallet credit equals voucher total minus
 * sweep fees.
 *
 * GATE M4-B: while R is offline, S broadcasts the revoked C_{n0}^S; the tower
 * detects it and (penalty option (a)) confirms a justice tx sweeping S's
 * to_local to R's mandated sweep script.
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
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { createFundingScript } from '../../../src/lightning/script/funding';
import {
	FforVariant,
	IFforEpochParams
} from '../../../src/lightning/ffor/types';
import {
	FforTower,
	MemoryTowerStore,
	LoopbackTowerClient,
	generateTowerPreimages,
	IFforTowerProvisioning
} from '../../../src/lightning/ffor/tower';
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
	return sha256(Buffer.from(`ffor-m4-rt-${id}`));
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
}
function connect(
	a: ChannelManager,
	aPub: string,
	b: ChannelManager,
	bPub: string
): ILink {
	let connected = true;
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (connected && peer === bPub) b.handleMessage(aPub, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (connected && peer === aPub) a.handleMessage(bPub, type, payload);
	});
	return {
		down: (): void => {
			connected = false;
		},
		up: (): void => {
			connected = true;
		}
	};
}

interface IVbRegtest {
	pManager: ChannelManager;
	sManager: ChannelManager;
	rManager: ChannelManager;
	sConfig: IChannelManagerConfig;
	rConfig: IChannelManagerConfig;
	sPub: string;
	rPub: string;
	psChannelId: Buffer;
	srChannelId: Buffer;
	sChannel: Channel;
	rChannel: Channel;
	rBroadcasts: Buffer[];
	sBroadcasts: Buffer[];
	rErrors: string[];
	tower: FforTower;
	towerStore: MemoryTowerStore;
	towerPreimages: Buffer[];
	hashes: Buffer[];
	sweepScript: Buffer;
}

/**
 * Set up P-S-R on regtest (S-R real-funded), a variant-B epoch with a tower,
 * `amounts` tower-settled payments while R is offline. Penalty option (a) is
 * provisioned (R's scoped revocation secret + a mandated sweep script).
 */
async function setupVariantBRegtest(
	name: string,
	amounts: bigint[]
): Promise<IVbRegtest> {
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

	// P-S: no on-chain footprint.
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

	// S-R: real regtest funding outpoint (BOLT 3 P2WSH 2-of-2).
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

	// Tower: R generates preimages/hashes, wires the tower to S, provisions it.
	const tower = new FforTower(new MemoryTowerStore());
	const towerStore = (tower as unknown as { _store: MemoryTowerStore })._store;
	const K = Math.max(2, amounts.length);
	const gen = generateTowerPreimages(K);
	sManager.setFforTowerClient(new LoopbackTowerClient(tower));

	const tip = (await bitcoinRpc('getblockcount')) as number;
	const params: Omit<IFforEpochParams, 'rPerCommitmentPoints'> = {
		variant: FforVariant.B,
		budgetMsat: 400_000_000n,
		maxPayments: K,
		minPaymentMsat: 500_000n,
		settlementDeadline: tip + 5000,
		voucherExpiry: tip + 5000 + 1008,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: 0n,
		paymentHashes: gen.paymentHashes,
		towerNodeId: getPublicKey(makeSeed(`${name}-tower`)),
		towerUri: 'inproc://tower'
	};
	const result = rManager.initiateFforEpoch(srChannelId, params);
	expect(result.ok, rErrors.join('; ')).to.equal(true);
	const rEpoch = rChannel.getFforEpoch()!;
	const hashes = rEpoch.params.paymentHashes!;

	// Mandated sweep script (penalty option (a)): R's own wallet address.
	const sweepAddr = (await bitcoinRpc('getnewaddress', [
		`${name}-tower-justice`,
		'bech32'
	])) as string;
	const sweepScript = bitcoin.address.toOutputScript(sweepAddr, NETWORK);

	const provisioning: IFforTowerProvisioning = {
		epochId: rEpoch.epochId,
		params: rEpoch.params,
		preimages: gen.preimages,
		channel: {
			fundingTxid: sChannel.getFullState().fundingTxid!,
			fundingOutputIndex: sChannel.getFullState().fundingOutputIndex,
			fundingSatoshis: FUNDING_SATOSHIS,
			channelType: sChannel.getFullState().channelType!,
			rIsOpener: false,
			rBasepoints: rConfig.localBasepoints,
			sBasepoints: sConfig.localBasepoints,
			rConfig: sChannel.getFullState().remoteConfig,
			sConfig: sChannel.getFullState().localConfig,
			preEpochRLocalMsat: 0n,
			preEpochSLocalMsat: FUNDING_SATOSHIS * 1000n,
			nR: rChannel.getCommitmentNumbers().local,
			n0: sChannel.getCommitmentNumbers().local,
			sPerCommitmentPointN0:
				rChannel.getFullState().remoteCurrentPerCommitmentPoint!,
			frozenFeeratePerKw: 2500
		},
		rNodeId: Buffer.from(rPub, 'hex'),
		sNodeId: Buffer.from(sPub, 'hex'),
		// Penalty option (a): scoped revocation secret + mandated sweep script.
		revocationBasepointSecret: rConfig.revocationBasepointSecret,
		sweepScript,
		network: NETWORK
	};
	tower.provision(provisioning);
	tower.setBlockHeight(tip);

	// R offline; P pays the delegated invoices; each settles via the tower.
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
		await sleep(10); // let the fire-and-forget tower settle resolve
	}

	return {
		pManager,
		sManager,
		rManager,
		sConfig,
		rConfig,
		sPub,
		rPub,
		psChannelId,
		srChannelId,
		sChannel,
		rChannel,
		rBroadcasts,
		sBroadcasts,
		rErrors,
		tower,
		towerStore,
		towerPreimages: gen.preimages,
		hashes,
		sweepScript
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

describe('FFOR M4: Variant B tower (regtest bitcoind)', function () {
	this.timeout(180_000);
	let skip = false;

	before(async function () {
		this.timeout(30_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds(3);
	});

	it('GATE M4-A: 2 tower-settled payments while R offline; S vanishes; R recovers from tower and sweeps every voucher', async function () {
		if (skip) this.skip();
		const t = await setupVariantBRegtest('m4a', [200_000_000n, 100_000_000n]);

		// Both delegated payments completed for the payer via the tower.
		const sEpoch = t.sChannel.getFforEpoch()!;
		expect(sEpoch.lastSeq).to.equal(2);
		expect(sEpoch.upstreamFulfilled).to.deep.equal([true, true]);
		expect(t.towerStore.saveLog.length).to.equal(2);

		// S VANISHES: never reconnects, storage never seen again. R recovers
		// packages + preimages from the tower ALONE.
		const recover = await t.rManager.fforRecoverFromTower(
			t.srChannelId,
			new LoopbackTowerClient(t.tower)
		);
		expect(recover.ok, t.rErrors.join('; ')).to.equal(true);
		const rEpoch = t.rChannel.getFforEpoch()!;
		expect(rEpoch.lastSeq).to.equal(2);
		for (let k = 0; k < 2; k++) {
			expect(sha256(rEpoch.preimages[k]).equals(t.hashes[k])).to.equal(true);
		}

		// R force-closes the adopted C_2^R and sweeps the vouchers.
		const destAddress = (await bitcoinRpc('getnewaddress', [
			'm4a-r-sweeps',
			'bech32'
		])) as string;
		const destScript = bitcoin.address.toOutputScript(destAddress, NETWORK);
		const feeProvider = new BitcoindFundingProvider();
		await feeProvider.prefundFeeInputs(4, 50_000);
		t.rManager.setFundingProvider(feeProvider);

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
		const commitTxid = await acceptAndConfirm(commitment.toHex(), 'C_2^R');
		// eslint-disable-next-line no-console
		console.log(`      GATE M4-A commitment: ${commitTxid}`);

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

		const secondLevel: Array<{ tx: bitcoin.Transaction; vout: number }> = [];
		for (const s of successTxs) {
			const preimage = s.ins[0].witness[3];
			expect(t.hashes.some((h) => h.equals(sha256(preimage)))).to.equal(true);
			const txid = await acceptAndConfirm(s.toHex(), 'HTLC-success');
			secondLevel.push({ tx: s, vout: s.ins[0].index });
			// eslint-disable-next-line no-console
			console.log(`      GATE M4-A HTLC-success: ${txid}`);
		}

		let height = (await bitcoinRpc('getblockcount')) as number;
		for (const { tx, vout } of secondLevel) {
			t.rManager.handleOutputSpent(commitTxid, vout, tx, height);
		}
		const beforeSweeps = t.rBroadcasts.length;
		await mineBlocks(TO_SELF_DELAY + 1);
		height = (await bitcoinRpc('getblockcount')) as number;
		t.rManager.handleNewBlock(height);
		await sleep(1500);

		const successSet = new Set(
			successTxs.map((s) => s.getHash().toString('hex'))
		);
		const sweeps = t.rBroadcasts
			.slice(beforeSweeps)
			.map((b) => bitcoin.Transaction.fromBuffer(b))
			.filter((tx) =>
				tx.ins.some((i) => successSet.has(Buffer.from(i.hash).toString('hex')))
			);
		expect(sweeps.length, t.rErrors.join('; ')).to.equal(2);

		let sweptSats = 0;
		for (const sweep of sweeps) {
			expect(Buffer.from(sweep.outs[0].script).equals(destScript)).to.equal(
				true
			);
			sweptSats += sweep.outs[0].value;
			const txid = await acceptAndConfirm(sweep.toHex(), 'CSV sweep');
			// eslint-disable-next-line no-console
			console.log(`      GATE M4-A CSV sweep:    ${txid}`);
		}

		const received = (await bitcoinRpc('getreceivedbyaddress', [
			destAddress,
			1
		])) as number;
		expect(Math.round(received * 1e8)).to.equal(sweptSats);
		// Voucher total 198,999 + 99,499 = 298,498 sat, minus only sweep fees.
		expect(sweptSats).to.be.at.most(198_999 + 99_499);
		expect(sweptSats).to.be.greaterThan(198_999 + 99_499 - 2 * 3000);
	});

	it('GATE M4-B: S broadcasts the revoked C_{n0}^S; the tower confirms a justice tx (penalty option a)', async function () {
		if (skip) this.skip();
		const t = await setupVariantBRegtest('m4b', [1_000_000n]);

		// S cheats: broadcasts its pre-epoch commitment (revoked by package 1).
		const sDest = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress', ['m4b-s-cheat', 'bech32'])) as string,
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
		console.log(`      GATE M4-B revoked commitment: ${revokedTxid}`);

		// The TOWER (not R) watches the funding outpoint, detects the breach, and
		// builds the justice tx from the package-1 secret it holds + R's scoped
		// revocation secret. The chain feed is transport (out of scope): the test
		// hands the confirmed spend to checkBroadcast.
		const height = (await bitcoinRpc('getblockcount')) as number;
		const breach = t.tower.checkBroadcast(revokedTx, height);
		expect(breach.breach, 'tower detected the revoked broadcast').to.equal(
			true
		);
		expect(breach.alert).to.match(/revoked commitment/);
		expect(breach.justiceTxs.length, 'option (a) built a justice tx').to.equal(
			1
		);

		const justice = bitcoin.Transaction.fromBuffer(breach.justiceTxs[0]);
		// Sweeps S's to_local to the mandated sweep script.
		expect(Buffer.from(justice.outs[0].script).equals(t.sweepScript)).to.equal(
			true
		);
		expect(
			Buffer.from(justice.ins[0].hash).equals(revokedTx.getHash())
		).to.equal(true);
		const sweptValue = justice.outs[0].value;
		expect(sweptValue).to.be.greaterThan(900_000);

		const justiceTxid = await acceptAndConfirm(
			justice.toHex(),
			'tower justice tx'
		);
		// eslint-disable-next-line no-console
		console.log(`      GATE M4-B justice tx:         ${justiceTxid}`);

		const receivedAddr = bitcoin.address.fromOutputScript(
			t.sweepScript,
			NETWORK
		);
		const received = (await bitcoinRpc('getreceivedbyaddress', [
			receivedAddr,
			1
		])) as number;
		expect(Math.round(received * 1e8)).to.equal(sweptValue);
	});
});
