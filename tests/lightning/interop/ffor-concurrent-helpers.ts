/** Shared Bitcoin Core fixture for concurrent receive qualification. */
import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	BitcoindFundingProvider,
	bitcoinRpc,
	ensureBitcoindFunds,
	mineBlocks
} from './shared-helpers';
import { createFundingScript } from '../../../src/lightning/script/funding';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import { CommitmentType, OutputType } from '../../../src/lightning/chain/types';
import {
	IWorld,
	IWorldOptions,
	REGTEST,
	createWorld,
	destScriptFor,
	worldConfigs
} from '../helpers/ffor-world';
import { createConcurrentWorld } from '../helpers/ffor-concurrent-world';

export const CAPACITY_SAT = 1_000_000n;
export const FEERATE_PER_KW = 2500; // 10 sat/vB: a commitment bitcoind relays alone
export const SWEEP_FEE_RATE = 10;

export async function bitcoindUp(): Promise<boolean> {
	try {
		await bitcoinRpc('getblockchaininfo');
		return true;
	} catch {
		return false;
	}
}

export async function tipHeight(): Promise<number> {
	return (await bitcoinRpc('getblockcount')) as number;
}

/** testmempoolaccept, then send. */
export async function submit(
	tx: bitcoin.Transaction,
	label: string
): Promise<string> {
	const [acc] = (await bitcoinRpc('testmempoolaccept', [[tx.toHex()]])) as {
		allowed: boolean;
		['reject-reason']?: string;
	}[];
	expect(acc.allowed, `${label}: ${acc['reject-reason']}`).to.equal(true);
	return (await bitcoinRpc('sendrawtransaction', [tx.toHex()])) as string;
}

export async function confirmations(txid: string): Promise<number> {
	const got = (await bitcoinRpc('getrawtransaction', [txid, true])) as {
		confirmations?: number;
	};
	return got.confirmations ?? 0;
}

export async function waitFor<T>(
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
export function taps(node: LightningNode): bitcoin.Transaction[] {
	const list: bitcoin.Transaction[] = [];
	node.on('broadcast:tx', (raw: Buffer) => {
		list.push(bitcoin.Transaction.fromBuffer(raw));
	});
	return list;
}

export function spends(
	tx: bitcoin.Transaction,
	prev: bitcoin.Transaction,
	vout: number
): boolean {
	const hash = prev.getHash();
	return tx.ins.some(
		(i) => Buffer.from(i.hash).equals(hash) && i.index === vout
	);
}

export function paidTo(tx: bitcoin.Transaction, script: Buffer): bigint {
	return tx.outs
		.filter((o) => Buffer.from(o.script).equals(script))
		.reduce((s, o) => s + BigInt(o.value), 0n);
}

/** The chain as the nodes see it: mine, then tell every node the new tip. */
export class Chain {
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

let seedBase = 80_000;

export interface IRegtestWorld {
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
export async function regtestWorld(opts: {
	rToSelfDelay?: number;
	rStorage?: SqliteStorage;
	sStorage?: SqliteStorage;
	srPushMsat?: bigint;
	feeInputs?: number;
	concurrent?: boolean;
	sChannel?: IWorldOptions['sChannel'];
	rChannel?: IWorldOptions['rChannel'];
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
		sStorage: opts.sStorage,
		sChannel: { feeratePerKw: FEERATE_PER_KW, ...opts.sChannel },
		rChannel: {
			feeratePerKw: FEERATE_PER_KW,
			...opts.rChannel,
			...(opts.rToSelfDelay ? { toSelfDelay: opts.rToSelfDelay } : {})
		},
		srCapacitySats: CAPACITY_SAT,
		srPushMsat: opts.srPushMsat,
		...(opts.concurrent
			? {
					sExtra: {
						fforConcurrent: { enabled: true },
						fforSettle: { enabled: true, allowConcurrent: true }
					},
					rExtra: { fforConcurrent: { enabled: true } }
			  }
			: {})
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
	const w = (opts.concurrent ? createConcurrentWorld : createWorld)({
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
export async function forceCloseOnChain(
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
export async function resolveHtlcs(
	rw: IRegtestWorld,
	observer: LightningNode,
	commitment: bitcoin.Transaction,
	confirmedAt: number,
	dest: Buffer,
	type: OutputType,
	expectedCommitment: CommitmentType,
	options: { paymentHashes?: string[]; afterObserve?: () => void } = {}
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
		.filter(
			(o) =>
				o.outputType === type &&
				(!options.paymentHashes ||
					options.paymentHashes.includes(o.paymentHash?.toString('hex') ?? ''))
		);
	expect(htlcs.length, `${type} outputs tracked`).to.be.greaterThan(0);
	options.afterObserve?.();
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
