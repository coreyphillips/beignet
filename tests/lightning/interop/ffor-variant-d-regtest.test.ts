/**
 * FFOR Variant D on regtest (spec section 15.2, issue #719): the gates that
 * need a chain. The S-R channel is funded on a REAL bitcoind output; the
 * nodes talk over in-process links (the transport is not under test) and
 * every on-chain artefact the chain monitors build is submitted to bitcoind
 * with testmempoolaccept, sent, mined, and read back.
 *
 *  - M8.0  watchtower-free penalty: R's to_self_delay on S outlives R's whole
 *          offline window, S broadcasts the revoked pre-epoch commitment with
 *          nothing watching, and a COLD-started R penalizes at leisure;
 *  - M8.4  payer rescue: S settles and vanishes; R recovers the voucher with
 *          the payer's preimage alone, through the setup-time HTLC-success
 *          signature and its CSV sweep;
 *  - M8.5  hash chain: three levels paid, R holds only the most recent
 *          preimage, three vouchers sweep;
 *  - M8.7  vanished R: no payment, S force-closes after T_exp and takes every
 *          voucher by HTLC-timeout; R's to_remote is there whenever R returns.
 *
 * Needs the bitcoind container on 43782 (docker/docker-compose.yml); skips
 * without it. Run: npm run test:interop:ffor
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import {
	BitcoindFundingProvider,
	bitcoinRpc,
	ensureBitcoindFunds,
	mineBlocks
} from './shared-helpers';
import { createFundingScript } from '../../../src/lightning/script/funding';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../../src/lightning/node/types';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import {
	CommitmentType,
	OutputStatus,
	OutputType
} from '../../../src/lightning/chain/types';
import {
	FF_RECONCILE_MARGIN_BLOCKS,
	FforSlotState
} from '../../../src/lightning/ffor/types';
import {
	IWorld,
	IWorldOptions,
	REGTEST,
	activate,
	createWorld,
	destScriptFor,
	exposeAndLeave,
	pay,
	record,
	worldConfigs
} from '../helpers/ffor-world';

const CAPACITY_SAT = 1_000_000n;
const FEERATE_PER_KW = 2500; // 10 sat/vB: a commitment bitcoind relays alone
const SWEEP_FEE_RATE = 10;

async function bitcoindUp(): Promise<boolean> {
	try {
		await bitcoinRpc('getblockchaininfo');
		return true;
	} catch {
		return false;
	}
}

async function tipHeight(): Promise<number> {
	return (await bitcoinRpc('getblockcount')) as number;
}

/** testmempoolaccept, then send. */
async function submit(tx: bitcoin.Transaction, label: string): Promise<string> {
	const [acc] = (await bitcoinRpc('testmempoolaccept', [[tx.toHex()]])) as {
		allowed: boolean;
		['reject-reason']?: string;
	}[];
	expect(acc.allowed, `${label}: ${acc['reject-reason']}`).to.equal(true);
	return (await bitcoinRpc('sendrawtransaction', [tx.toHex()])) as string;
}

async function confirmations(txid: string): Promise<number> {
	const got = (await bitcoinRpc('getrawtransaction', [txid, true])) as {
		confirmations?: number;
	};
	return got.confirmations ?? 0;
}

async function waitFor<T>(
	probe: () => T | undefined,
	label: string,
	timeoutMs = 15_000
): Promise<T> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const got = probe();
		if (got !== undefined) return got;
		if (Date.now() > deadline)
			throw new Error(`timed out waiting for ${label}`);
		await new Promise((r) => setTimeout(r, 50));
	}
}

/** Every tx a node asks to have broadcast, parsed. */
function taps(node: LightningNode): bitcoin.Transaction[] {
	const list: bitcoin.Transaction[] = [];
	node.on('broadcast:tx', (raw: Buffer) => {
		list.push(bitcoin.Transaction.fromBuffer(raw));
	});
	return list;
}

function spends(
	tx: bitcoin.Transaction,
	prev: bitcoin.Transaction,
	vout: number
): boolean {
	const hash = prev.getHash();
	return tx.ins.some(
		(i) => Buffer.from(i.hash).equals(hash) && i.index === vout
	);
}

function paidTo(tx: bitcoin.Transaction, script: Buffer): bigint {
	return tx.outs
		.filter((o) => Buffer.from(o.script).equals(script))
		.reduce((s, o) => s + BigInt(o.value), 0n);
}

/** The chain as the nodes see it: mine, then tell every node the new tip. */
class Chain {
	constructor(
		public height: number,
		private readonly nodes: LightningNode[]
	) {}
	async mine(n: number): Promise<void> {
		await mineBlocks(n);
		this.height += n;
		for (const node of this.nodes) node.handleNewBlock(this.height);
	}
	watch(node: LightningNode): void {
		this.nodes.push(node);
		node.handleNewBlock(this.height);
	}
	unwatch(node: LightningNode): void {
		const at = this.nodes.indexOf(node);
		if (at >= 0) this.nodes.splice(at, 1);
	}
}

let seedBase = 50_000;

interface IRegtestWorld {
	w: IWorld;
	chain: Chain;
	rDest: Buffer;
	sDest: Buffer;
	fundingTx: bitcoin.Transaction;
}

/**
 * A world whose S-R channel is a real 2-of-2 output on bitcoind, with fee
 * inputs prefunded for both S and R so the chain monitors can attach fees
 * to zero-fee anchor second-level transactions and CPFP the commitment.
 */
async function regtestWorld(opts: {
	rToSelfDelay?: number;
	rStorage?: SqliteStorage;
	srPushMsat?: bigint;
	feeInputs?: number;
}): Promise<IRegtestWorld> {
	await ensureBitcoindFunds(3);
	const sProvider = new BitcoindFundingProvider();
	const rProvider = new BitcoindFundingProvider();
	await sProvider.prefundFeeInputs(opts.feeInputs ?? 4, 100_000);
	await rProvider.prefundFeeInputs(opts.feeInputs ?? 4, 100_000);
	seedBase += 10;
	// The providers are attached AFTER the channel is open (below): a node
	// built with one auto-funds every accepted channel, and that background
	// funding would replace the outpoint the fixture funded by hand.
	const worldOpts: IWorldOptions = {
		seedBase,
		rStorage: opts.rStorage,
		sChannel: { feeratePerKw: FEERATE_PER_KW },
		rChannel: {
			feeratePerKw: FEERATE_PER_KW,
			...(opts.rToSelfDelay ? { toSelfDelay: opts.rToSelfDelay } : {})
		},
		srCapacitySats: CAPACITY_SAT,
		srPushMsat: opts.srPushMsat
	};
	const { sConfig, rConfig } = worldConfigs(seedBase, worldOpts);
	const script = createFundingScript(
		sConfig.channelBasepoints!.fundingPubkey,
		rConfig.channelBasepoints!.fundingPubkey,
		REGTEST
	);
	const txid = (await bitcoinRpc('sendtoaddress', [
		script.address,
		Number(CAPACITY_SAT) / 1e8
	])) as string;
	await mineBlocks(1);
	const fundingTx = bitcoin.Transaction.fromHex(
		(await bitcoinRpc('getrawtransaction', [txid])) as string
	);
	const vout = fundingTx.outs.findIndex((o) =>
		Buffer.from(o.script).equals(script.p2wshOutput)
	);
	expect(vout, 'funding output').to.be.greaterThan(-1);
	const tip = await tipHeight();
	const w = createWorld({
		...worldOpts,
		funding: {
			sr: { txid: Buffer.from(txid, 'hex').reverse(), outputIndex: vout }
		},
		tip
	});
	for (const [node, provider] of [
		[w.s, sProvider],
		[w.r, rProvider]
	] as const) {
		(
			node as unknown as { fundingProvider: BitcoindFundingProvider }
		).fundingProvider = provider;
		node.getChannelManager().setFundingProvider(provider);
	}
	const chain = new Chain(tip, [w.p, w.s, w.r]);
	return {
		w,
		chain,
		rDest: destScriptFor(w.rConfig.fundingPrivkey!),
		sDest: destScriptFor(w.sConfig.fundingPrivkey!),
		fundingTx
	};
}

/** Force-close `closer`'s S-R channel and confirm the commitment. */
async function forceCloseOnChain(
	rw: IRegtestWorld,
	closer: LightningNode,
	dest: Buffer
): Promise<{ commitment: bitcoin.Transaction; confirmedAt: number }> {
	const res = closer
		.getChannelManager()
		.forceClose(rw.w.srChannelId, dest, SWEEP_FEE_RATE, REGTEST);
	expect(res.ok, res.error).to.equal(true);
	const broadcast = res.actions.find(
		(a) => a.type === ChannelActionType.BROADCAST_TX
	) as { tx: Buffer } | undefined;
	expect(broadcast, 'commitment broadcast').to.exist;
	const commitment = bitcoin.Transaction.fromBuffer(broadcast!.tx);
	expect(
		spends(
			commitment,
			rw.fundingTx,
			rw.fundingTx.outs.findIndex((o) =>
				Buffer.from(o.script).equals(
					createFundingScript(
						rw.w.sConfig.channelBasepoints!.fundingPubkey,
						rw.w.rConfig.channelBasepoints!.fundingPubkey,
						REGTEST
					).p2wshOutput
				)
			)
		)
	).to.equal(true);
	await submit(commitment, 'commitment');
	await rw.chain.mine(1);
	return { commitment, confirmedAt: rw.chain.height };
}

/**
 * Report a confirmed commitment to `observer`, then drive every HTLC output
 * of `type` through its second-level transaction and CSV sweep to `dest`.
 * Returns the sweeps that confirmed.
 */
async function resolveHtlcs(
	rw: IRegtestWorld,
	observer: LightningNode,
	commitment: bitcoin.Transaction,
	confirmedAt: number,
	dest: Buffer,
	type: OutputType,
	expectedCommitment: CommitmentType
): Promise<bitcoin.Transaction[]> {
	const seen = taps(observer);
	observer
		.getChannelManager()
		.handleFundingSpent(
			rw.w.srChannelId,
			commitment,
			confirmedAt,
			dest,
			SWEEP_FEE_RATE,
			undefined,
			undefined,
			REGTEST
		);
	const monitor = observer.getChannelManager().getMonitor(rw.w.srChannelId)!;
	expect(monitor.getFullState().commitmentBroadcast?.commitmentType).to.equal(
		expectedCommitment
	);
	const htlcs = monitor
		.getTrackedOutputs()
		.filter((o) => o.outputType === type);
	expect(htlcs.length, `${type} outputs tracked`).to.be.greaterThan(0);
	// Anchors: the second-level transactions are zero-fee and get wallet fee
	// inputs attached asynchronously before they are broadcast.
	await rw.chain.mine(2);
	const secondLevel: bitcoin.Transaction[] = [];
	for (const h of htlcs) {
		const tx = await waitFor(
			() => seen.find((t) => spends(t, commitment, h.outputIndex)),
			`second-level tx for HTLC output ${h.outputIndex}`
		);
		secondLevel.push(tx);
	}
	for (const tx of secondLevel) await submit(tx, 'second-level HTLC tx');
	await rw.chain.mine(1);
	for (let i = 0; i < htlcs.length; i++) {
		expect(await confirmations(secondLevel[i].getId())).to.be.at.least(1);
		observer
			.getChannelManager()
			.handleOutputSpent(
				commitment.getId(),
				htlcs[i].outputIndex,
				secondLevel[i],
				rw.chain.height
			);
	}
	// The second-level outputs are CSV-locked by the peer's to_self_delay on
	// us; mature them and the sweeps to `dest` are released.
	const csv = observer
		.getChannelManager()
		.getChannel(rw.w.srChannelId)!
		.getFullState().remoteConfig.toSelfDelay;
	await rw.chain.mine(csv + 1);
	const sweeps: bitcoin.Transaction[] = [];
	for (const tx of secondLevel) {
		const sweep = await waitFor(
			() => seen.find((t) => spends(t, tx, 0)),
			`CSV sweep of ${tx.getId()}`
		);
		sweeps.push(sweep);
	}
	for (const sweep of sweeps) await submit(sweep, 'CSV sweep');
	await rw.chain.mine(1);
	for (const sweep of sweeps) {
		expect(await confirmations(sweep.getId())).to.be.at.least(1);
		expect(paidTo(sweep, dest) > 0n, 'sweep pays our destination').to.equal(
			true
		);
	}
	return sweeps;
}

describe('FFOR Variant D on regtest (spec section 15.2)', function () {
	this.timeout(600_000);
	let skip = false;
	const tmpFiles: string[] = [];

	before(async function () {
		this.timeout(30_000);
		skip = !(await bitcoindUp());
		if (skip) {
			console.log(
				'    bitcoind not reachable on 43782: skipping the FFOR regtest gates'
			);
		}
	});

	after(() => {
		for (const f of tmpFiles) {
			try {
				fs.rmSync(f, { force: true });
			} catch {
				// best effort
			}
		}
	});

	it('M8.4: S settles and vanishes; R recovers the voucher with the payer preimage alone', async function () {
		if (skip) this.skip();
		const rw = await regtestWorld({});
		const { w, chain, rDest } = rw;
		const h = chain.height;
		const d = 200_000_000n;
		activate(w, {
			amounts: [d],
			minPaymentMsat: 100_000_000n,
			settlementDeadline: h + 60,
			voucherExpiry: h + 60 + FF_RECONCILE_MARGIN_BLOCKS
		});
		const [inv] = exposeAndLeave(w, [1]);
		const payment = pay(w, inv);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.SETTLED);
		// S never reconnects. R returns holding only the payer's receipt.
		chain.unwatch(w.s);
		expect(w.r.fforAddPreimage(w.srHex, payment.preimage!).ok).to.equal(true);

		const { commitment, confirmedAt } = await forceCloseOnChain(rw, w.r, rDest);
		const sweeps = await resolveHtlcs(
			rw,
			w.r,
			commitment,
			confirmedAt,
			rDest,
			OutputType.RECEIVED_HTLC,
			CommitmentType.OUR_COMMITMENT
		);
		expect(sweeps).to.have.length(1);
		// The whole voucher, less two transactions' fees, reached R's wallet.
		expect(Number(paidTo(sweeps[0], rDest))).to.be.greaterThan(
			Number(d / 1000n - 20_000n)
		);
	});

	it('M8.5: three chained levels paid, R holds only x_3, and all three vouchers sweep', async function () {
		if (skip) this.skip();
		const rw = await regtestWorld({ feeInputs: 8 });
		const { w, chain, rDest } = rw;
		const h = chain.height;
		const G = 100_000_000n;
		activate(w, {
			amounts: [G, G, G],
			hashChain: true,
			minPaymentMsat: G,
			settlementDeadline: h + 60,
			voucherExpiry: h + 60 + FF_RECONCILE_MARGIN_BLOCKS
		});
		const [inv1, inv2, inv3] = exposeAndLeave(w, [1, 2, 3]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		expect(pay(w, inv2).status).to.equal(PaymentStatus.COMPLETED);
		const third = pay(w, inv3);
		expect(third.status).to.equal(PaymentStatus.COMPLETED);
		chain.unwatch(w.s);
		// One 32-byte secret from the most recent payer credits all three.
		expect(w.r.fforAddPreimage(w.srHex, third.preimage!).ok).to.equal(true);
		expect(record(w.r, w.srHex).knownPreimages.every((p) => p !== null)).to.be
			.true;

		const { commitment, confirmedAt } = await forceCloseOnChain(rw, w.r, rDest);
		const sweeps = await resolveHtlcs(
			rw,
			w.r,
			commitment,
			confirmedAt,
			rDest,
			OutputType.RECEIVED_HTLC,
			CommitmentType.OUR_COMMITMENT
		);
		expect(sweeps).to.have.length(3);
		const total = sweeps.reduce((s, t) => s + paidTo(t, rDest), 0n);
		expect(Number(total)).to.be.greaterThan(Number((3n * G) / 1000n - 60_000n));
	});

	it('M8.7: R never returns; S force-closes after T_exp and takes every voucher by HTLC-timeout, R to_remote intact', async function () {
		if (skip) this.skip();
		const rw = await regtestWorld({ feeInputs: 8, srPushMsat: 100_000_000n });
		const { w, chain, rDest, sDest } = rw;
		const h = chain.height;
		const G = 100_000_000n;
		activate(w, {
			amounts: [G, G, G],
			minPaymentMsat: G,
			settlementDeadline: h + 20,
			voucherExpiry: h + 20 + FF_RECONCILE_MARGIN_BLOCKS
		});
		exposeAndLeave(w, [1, 2, 3]);
		chain.unwatch(w.r);
		// Nobody pays. Past T_exp, S takes the vouchers back on its own.
		await chain.mine(20 + FF_RECONCILE_MARGIN_BLOCKS + 1);
		const { commitment, confirmedAt } = await forceCloseOnChain(rw, w.s, sDest);
		const sweeps = await resolveHtlcs(
			rw,
			w.s,
			commitment,
			confirmedAt,
			sDest,
			OutputType.OFFERED_HTLC,
			CommitmentType.OUR_COMMITMENT
		);
		expect(sweeps).to.have.length(3);
		const total = sweeps.reduce((s, t) => s + paidTo(t, sDest), 0n);
		expect(Number(total)).to.be.greaterThan(Number((3n * G) / 1000n - 60_000n));

		// R returns much later and finds its to_remote on S's commitment.
		chain.watch(w.r);
		const rSeen = taps(w.r);
		w.r
			.getChannelManager()
			.handleFundingSpent(
				w.srChannelId,
				commitment,
				confirmedAt,
				rDest,
				SWEEP_FEE_RATE,
				undefined,
				undefined,
				REGTEST
			);
		const rMonitor = w.r.getChannelManager().getMonitor(w.srChannelId)!;
		expect(
			rMonitor.getFullState().commitmentBroadcast?.commitmentType
		).to.equal(CommitmentType.THEIR_CURRENT_COMMITMENT);
		const toRemote = rMonitor
			.getTrackedOutputs()
			.find((o) => o.outputType === OutputType.TO_REMOTE);
		expect(toRemote, 'to_remote tracked').to.exist;
		await chain.mine(2);
		const claim = await waitFor(
			() => rSeen.find((t) => spends(t, commitment, toRemote!.outputIndex)),
			'to_remote claim'
		);
		await submit(claim, 'to_remote claim');
		await chain.mine(1);
		expect(await confirmations(claim.getId())).to.be.at.least(1);
		expect(Number(paidTo(claim, rDest))).to.be.greaterThan(90_000);
	});

	it('M8.0: watchtower-free penalty: S broadcasts the revoked pre-epoch commitment, nothing watches, a cold R penalizes after the full window', async function () {
		if (skip) this.skip();
		const dbPath = path.join(
			os.tmpdir(),
			`ffor-m80-${crypto.randomBytes(4).toString('hex')}.db`
		);
		tmpFiles.push(dbPath);
		const rStorage = new SqliteStorage(dbPath);
		rStorage.open();
		// R chose a to_self_delay on S's outputs longer than its whole offline
		// window (spec section 5.1); the channel is opened with it.
		const rw = await regtestWorld({ rToSelfDelay: 2016, rStorage });
		const { w, chain, rDest } = rw;
		const sChannel = w.s.getChannelManager().getChannel(w.srChannelId)!;
		expect(sChannel.getFullState().remoteConfig.toSelfDelay).to.equal(2016);

		// S's commitment BEFORE the epoch: the voucher round revokes it.
		const plan = sChannel.prepareForceClose(sChannel.getSigner()!, {});
		expect(plan.ok, plan.ok ? '' : plan.error).to.equal(true);
		if (!plan.ok) return;
		const stale = bitcoin.Transaction.fromBuffer(plan.commitmentTx);
		const n0 = sChannel.getFullState().localCommitmentNumber;

		const h = chain.height;
		activate(w, {
			amounts: [200_000_000n],
			minPaymentMsat: 100_000_000n,
			settlementDeadline: h + 60,
			voucherExpiry: h + 60 + FF_RECONCILE_MARGIN_BLOCKS
		});
		expect(
			Number(sChannel.getFullState().localCommitmentNumber)
		).to.be.greaterThan(Number(n0));
		// R goes offline: no chain feed, no peer, nothing watching for it.
		w.sr.disconnect();
		chain.unwatch(w.r);

		// S broadcasts the revoked state with R gone, and the chain moves on
		// for a hundred blocks: well inside the 2016-block delay on S's funds.
		await submit(stale, 'revoked pre-epoch commitment');
		await chain.mine(1);
		const confirmedAt = chain.height;
		await chain.mine(100);

		// R comes back COLD: a fresh process over its database, no tower, no
		// memory of the epoch beyond what it persisted.
		const r2 = new LightningNode(w.rConfig);
		r2.on('node:error', () => {});
		chain.watch(r2);
		expect(r2.getNodeId()).to.equal(w.r.getNodeId());
		expect(r2.getFforEpoch(w.srHex)?.state).to.equal(
			record(w.r, w.srHex).state
		);
		const seen = taps(r2);
		r2.getChannelManager().handleFundingSpent(
			w.srChannelId,
			stale,
			confirmedAt,
			rDest,
			SWEEP_FEE_RATE,
			undefined,
			undefined,
			REGTEST
		);
		const monitor = r2.getChannelManager().getMonitor(w.srChannelId)!;
		// Section 9.3: a counterparty commitment whose revocation secret we
		// hold is revoked, whatever its number says next to ours.
		expect(monitor.getFullState().commitmentBroadcast?.commitmentType).to.equal(
			CommitmentType.THEIR_REVOKED_COMMITMENT
		);
		const toLocal = monitor
			.getTrackedOutputs()
			.find((o) => o.outputType === OutputType.TO_LOCAL);
		expect(toLocal, "S's to_local tracked for justice").to.exist;
		await chain.mine(2);
		const justice = await waitFor(
			() => seen.find((t) => spends(t, stale, toLocal!.outputIndex)),
			'justice transaction'
		);
		await submit(justice, 'justice');
		await chain.mine(1);
		expect(await confirmations(justice.getId())).to.be.at.least(1);
		// The penalty took S's whole balance, with R's CSV margin untouched:
		// no CSV was needed and 1900 blocks of the delay remain.
		expect(Number(paidTo(justice, rDest))).to.be.greaterThan(900_000);
		expect(
			monitor
				.getTrackedOutputs()
				.find((o) => o.outputType === OutputType.TO_LOCAL)!.status
		).to.equal(OutputStatus.SPEND_BROADCAST);
		rStorage.close();
	});
});
