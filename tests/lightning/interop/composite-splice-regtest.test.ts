/**
 * Regtest qualification of the multi-channel splice-out (issue #1922, step
 * 5e, docs/MULTI-CHANNEL-SPLICE-OUT.md section 10): a wallet daemon with
 * channels to beignet primaries over TCP on the docker regtest stack pays an
 * address out of several channels in one transaction, through the BeignetNode
 * quote and execute surface of step 5d. Every transaction is checked on
 * bitcoind, every channel adopts it after splice_locked, one record and one
 * spend charge remain. Then: an amount that fits one channel takes the
 * single-channel path, a peer without the capability is left out by name, a
 * restart after the release keeps the record and the charge and still locks,
 * a primary that disconnects during the negotiation aborts the composite at
 * once with every channel usable again and nothing charged, and a composite
 * across a beignet primary and Core Lightning completes (a default CLN is not
 * recognised as composite-capable; that case says why and vouches for it).
 *
 * The cases share one daemon and build on each other's balances: a composite
 * drains its largest channel first, so the later cases open a fresh primary
 * and size their amount above what any one channel can send alone.
 *
 * Needs the docker stack of docker/docker-compose.yml (bitcoind on 43782,
 * electrs on 60001, CLN on 3010/19846 for the last case); skipped when
 * bitcoind is unreachable.
 */
import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as net from 'net';
import { IStartedDaemon, startDaemon } from '../../../src/cli/daemon';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { Feature } from '../../../src/lightning/features/flags';
import { MessageType } from '../../../src/lightning/message/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	ChannelState,
	REGTEST_CHAIN_HASH
} from '../../../src/lightning/channel/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import type { ChannelSendStatus } from '../../../src/cli/types';
import {
	bitcoinRpc,
	BitcoindFundingProvider,
	ensureBitcoindFunds,
	mineBlocks,
	sleep,
	TEST_MNEMONIC
} from './shared-helpers';
import {
	CLN_P2P_HOST,
	CLN_P2P_PORT,
	createClnClient,
	fundClnWallet,
	payBeignetInvoiceStrict,
	waitForClnPeerChannelNormal,
	waitForClnSync
} from './cln-helpers';
import type { ClnRestClient } from './cln-client';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

async function bitcoindReachable(): Promise<boolean> {
	try {
		await bitcoinRpc('getblockcount', []);
		return true;
	} catch {
		return false;
	}
}

async function waitFor(
	predicate: () => boolean,
	what: string,
	timeoutMs = 60_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (predicate()) return;
		await sleep(200);
	}
	throw new Error(`timed out waiting for ${what}`);
}

async function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = net.createServer();
		server.on('error', reject);
		server.listen(0, '127.0.0.1', () => {
			const port = (server.address() as net.AddressInfo).port;
			server.close(() => resolve(port));
		});
	});
}

/**
 * A beignet primary with a bitcoind-backed funding provider, splicing on and
 * v1 opens (open_channel2 has no push_msat, and the primary pushes most of
 * the capacity to the wallet so the wallet has balance without on-chain
 * funds of its own). `composite: false` leaves option_composite_splice_inputs
 * out, the peer a composite must not select.
 */
function makePrimary(
	tag: string,
	provider: BitcoindFundingProvider,
	composite = true
): LightningNode {
	const features = LightningNode.defaultFeatures();
	features.setOptional(Feature.SPLICE);
	features.setOptional(Feature.QUIESCE);
	features.clearBit(Feature.DUAL_FUND);
	features.clearBit(Feature.DUAL_FUND + 1);
	if (!composite) {
		features.clearBit(Feature.OPTION_COMPOSITE_SPLICE_INPUTS);
		features.clearBit(Feature.OPTION_COMPOSITE_SPLICE_INPUTS + 1);
	}
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		tag,
		LnCoinType.REGTEST
	);
	return new LightningNode({
		...keys,
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: features,
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true,
		fundingProvider: provider
	});
}

async function fetchTx(txid: string): Promise<bitcoin.Transaction | undefined> {
	const until = Date.now() + 60_000;
	while (Date.now() < until) {
		try {
			return bitcoin.Transaction.fromHex(
				(await bitcoinRpc('getrawtransaction', [txid])) as string
			);
		} catch {
			await sleep(250);
		}
	}
	return undefined;
}

describe('Regtest: multi-channel splice-out through the daemon (issue #1922, step 5e)', function () {
	this.timeout(900_000);
	let skipAll = false;
	let dir = '';
	let walletPort = 0;
	let daemon: IStartedDaemon | null = null;
	let wallet: LightningNode;
	const provider = new BitcoindFundingProvider();
	const primaries: LightningNode[] = [];
	const broadcastErrors: string[] = [];
	/** channel id -> the primary across it (null for CLN). */
	const channels = new Map<string, LightningNode | null>();
	let cln: ClnRestClient | null = null;
	let clnPubkey = '';
	let clnChannelId: Buffer | null = null;

	const daemonOptions = (): Parameters<typeof startDaemon>[0] => ({
		dataDir: dir,
		network: 'regtest',
		mnemonic: MNEMONIC,
		daemonPort: 0,
		electrumHost: '127.0.0.1',
		electrumPort: 60001,
		electrumTls: false,
		rapidGossipSync: false,
		autoGossipSync: false,
		autoBootstrap: false,
		logLevel: 'silent',
		listenPort: walletPort,
		dailySpendLimitSats: 50_000_000
	});

	before(async function () {
		if (!(await bitcoindReachable())) {
			skipAll = true;
			console.log('    [skip] bitcoind not reachable on the docker stack');
			this.skip();
			return;
		}
		await ensureBitcoindFunds(5);
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'composite-regtest-'));
		walletPort = await freePort();
		daemon = await startDaemon(daemonOptions());
		wallet = daemon.node.getNode();
	});

	after(async function () {
		for (const p of primaries) {
			try {
				p.destroy();
			} catch {
				/* ignore */
			}
		}
		if (daemon) await daemon.stop();
		if (dir) fs.rmSync(dir, { recursive: true, force: true });
	});

	/** A primary opens to the wallet and pushes most of the capacity to it. */
	async function openFromPrimary(
		primary: LightningNode,
		capacitySats: bigint,
		pushSats: bigint
	): Promise<Buffer> {
		await primary.connectPeer(wallet.getNodeId(), '127.0.0.1', walletPort);
		await waitFor(
			() => primary.listPeers().some((p) => p.pubkey === wallet.getNodeId()),
			'primary connected to the wallet'
		);
		const pending = primary.openChannel(
			wallet.getNodeId(),
			capacitySats,
			pushSats * 1000n
		);
		await waitFor(
			() => !!pending.getFullState().fundingTxid,
			'funding created'
		);
		const id = pending.getChannelId()!;
		await mineBlocks(6);
		const tip = (await bitcoinRpc('getblockcount', [])) as number;
		for (const node of [primary, wallet]) {
			node.handleFundingConfirmed(id);
			node.handleNewBlock(tip);
		}
		await waitFor(
			() =>
				wallet.getChannelManager().getChannel(id)?.getState() ===
					ChannelState.NORMAL &&
				primary.getChannelManager().getChannel(id)?.getState() ===
					ChannelState.NORMAL,
			'channel NORMAL on both sides'
		);
		channels.set(id.toString('hex'), primary);
		return id;
	}

	function newPrimary(tag: string, composite = true): LightningNode {
		const primary = makePrimary(`${tag}-${Date.now()}`, provider, composite);
		primary.on('node:error', () => undefined);
		primary.on('broadcast:tx', (raw: Buffer) => {
			provider
				.broadcastTransaction(raw.toString('hex'))
				.catch((error) => broadcastErrors.push(String(error)));
		});
		primaries.push(primary);
		return primary;
	}

	/** Mine the composite, let every side lock it, and wait for LOCKED. */
	async function lock(
		status: () => ChannelSendStatus | null,
		ids: Buffer[]
	): Promise<void> {
		await mineBlocks(6);
		const tip = (await bitcoinRpc('getblockcount', [])) as number;
		const nodes = [wallet, ...primaries];
		for (const node of nodes) node.handleNewBlock(tip);
		await sleep(500);
		for (const id of ids) {
			for (const node of nodes) {
				if (
					node.getChannelManager().getChannel(id)?.getState() ===
					ChannelState.SPLICING
				) {
					node.getChannelManager().sendSpliceLocked(id);
				}
			}
		}
		await waitFor(
			() => status()?.stage === 'LOCKED',
			'the composite to lock',
			180_000
		);
	}

	/**
	 * An amount no single channel can send alone at 1000 sat/kw (the largest
	 * splice-out bound among the channels plus a margin), so a quote for it
	 * has to compose.
	 */
	function compositeAmount(address: string): number {
		const script = bitcoin.address.toOutputScript(
			address,
			bitcoin.networks.regtest
		);
		let largest = 0;
		for (const channel of wallet.getChannelManager().listChannels()) {
			if (channel.getState() !== ChannelState.NORMAL) continue;
			try {
				largest = Math.max(
					largest,
					wallet.spliceQuote(channel.getChannelId()!, 'out', 1000, script)
						.maxAmountSats
				);
			} catch {
				/* not spliceable right now */
			}
		}
		expect(largest, 'a spliceable channel').to.be.greaterThan(0);
		return largest + 50_000;
	}

	const ids: Buffer[] = [];
	let firstTotal = 0;

	it('pays an address out of two channels in one transaction; both channels adopt it; one record, one spend charge', async function () {
		if (skipAll) this.skip();
		for (const tag of ['composite-regtest-p1', 'composite-regtest-p2']) {
			ids.push(await openFromPrimary(newPrimary(tag), 4_000_000n, 3_600_000n));
		}
		// Both funding transactions are fetched from electrs and kept (5a).
		for (const id of ids) {
			expect(
				await wallet.getFundingTxHex(id),
				'funding hex from the chain'
			).to.not.equal(null);
		}
		const address = (await bitcoinRpc('getnewaddress', [
			'',
			'bech32'
		])) as string;
		const quote = await daemon!.node.quoteChannelSend(address, 5_000_000, 1000);
		expect(quote.kind).to.equal('composite');
		expect(quote.channels.map((c) => c.channelId).sort()).to.deep.equal(
			ids.map((i) => i.toString('hex')).sort()
		);
		firstTotal = quote.totalSats;
		const run = await daemon!.node.executeChannelSend(quote.quoteId);
		expect(run.kind).to.equal('composite');
		const compositeId = run.compositeId!;
		await waitFor(
			() =>
				['BROADCAST', 'RELEASED'].includes(
					daemon!.node.getChannelSend(quote.quoteId)?.stage ?? ''
				),
			'the composite to release',
			120_000
		);
		const txid = daemon!.node.getChannelSend(quote.quoteId)!.txid!;
		const tx = await fetchTx(txid);
		expect(tx, `composite accepted by bitcoind: ${broadcastErrors.join('; ')}`)
			.to.exist;
		expect(tx!.ins).to.have.length(2);
		expect(tx!.outs).to.have.length(3);
		const script = bitcoin.address.toOutputScript(
			address,
			bitcoin.networks.regtest
		);
		expect(tx!.outs.find((o) => o.script.equals(script))!.value).to.equal(
			5_000_000
		);
		for (const input of tx!.ins) expect(input.witness).to.have.length(4);

		await lock(() => daemon!.node.getChannelSend(quote.quoteId), ids);
		for (const id of ids) {
			for (const node of [wallet, channels.get(id.toString('hex'))!]) {
				const ch = node.getChannelManager().getChannel(id)!;
				expect(ch.getState()).to.equal(ChannelState.NORMAL);
				expect(
					Buffer.from(ch.getFullState().fundingTxid!).reverse().toString('hex')
				).to.equal(txid);
			}
		}
		expect(wallet.listCompositeSplices().map((r) => r.id)).to.deep.equal([
			compositeId
		]);
		const spend = daemon!.node.getDailySpendInfo();
		expect(spend.spentSats, 'amount plus fee charged once').to.equal(
			firstTotal
		);
		expect(spend.pendingSats).to.equal(0);
		console.log(
			`    composite ${txid} locked on both channels, fee ${quote.feeSats} sats`
		);
	});

	it('an amount that fits one channel takes the single-channel splice-out from the fuller channel', async function () {
		if (skipAll) this.skip();
		const address = (await bitcoinRpc('getnewaddress', [
			'',
			'bech32'
		])) as string;
		const quote = await daemon!.node.quoteChannelSend(address, 200_000, 1000);
		expect(quote.kind).to.equal('single');
		expect(quote.channels).to.have.length(1);
		const chosen = Buffer.from(quote.channels[0].channelId, 'hex');
		const before = daemon!.node.getDailySpendInfo().spentSats;
		const run = await daemon!.node.executeChannelSend(quote.quoteId);
		expect(run.kind).to.equal('single');
		expect(run.stage).to.equal('STARTED');
		expect(
			daemon!.node.getDailySpendInfo().spentSats,
			'charged at once'
		).to.equal(before + quote.totalSats);
		const channel = wallet.getChannelManager().getChannel(chosen)!;
		// spliceFundingTxid still names the last adopted splice (the first
		// case's composite) until the next one is signed: wait for a new one.
		const fundingBefore = Buffer.from(channel.getFullState().fundingTxid!);
		await waitFor(() => {
			const next = channel.getFullState().spliceFundingTxid;
			return !!next && !Buffer.from(next).equals(fundingBefore);
		}, 'single splice signed');
		const txid = Buffer.from(channel.getFullState().spliceFundingTxid!)
			.reverse()
			.toString('hex');
		const tx = await fetchTx(txid);
		expect(tx, 'single splice accepted by bitcoind').to.exist;
		expect(tx!.ins, 'one input: the channel alone').to.have.length(1);
		await mineBlocks(6);
		const tip = (await bitcoinRpc('getblockcount', [])) as number;
		for (const node of [wallet, channels.get(chosen.toString('hex'))!]) {
			node.handleNewBlock(tip);
			if (
				node.getChannelManager().getChannel(chosen)?.getState() ===
				ChannelState.SPLICING
			) {
				node.getChannelManager().sendSpliceLocked(chosen);
			}
		}
		await waitFor(
			() =>
				wallet.getChannelManager().getChannel(chosen)!.getState() ===
					ChannelState.NORMAL &&
				Buffer.from(
					wallet.getChannelManager().getChannel(chosen)!.getFullState()
						.fundingTxid!
				)
					.reverse()
					.toString('hex') === txid,
			'single splice locked'
		);
		expect(
			wallet.listCompositeSplices(),
			'no composite record for a single'
		).to.have.length(1);
	});

	it('a peer without option_composite_splice_inputs is left out of the plan by name', async function () {
		if (skipAll) this.skip();
		const plain = await openFromPrimary(
			newPrimary('composite-regtest-plain', false),
			4_000_000n,
			3_600_000n
		);
		const address = (await bitcoinRpc('getnewaddress', [
			'',
			'bech32'
		])) as string;
		// More than the two capable channels hold together, so the plan would
		// need the third one: refused, naming it and why.
		let refusal: { code?: string; message: string } | null = null;
		try {
			await daemon!.node.quoteChannelSend(address, 5_000_000, 1000);
		} catch (err) {
			refusal = err as { code?: string; message: string };
		}
		expect(refusal, 'refused').to.not.equal(null);
		expect(refusal!.code).to.equal('INSUFFICIENT_BALANCE');
		expect(refusal!.message).to.match(
			new RegExp(
				`${plain
					.toString('hex')
					.slice(0, 12)}: peer does not admit composite splice inputs`
			)
		);
	});

	it('a restart after the release keeps the record and the charge, and the composite still locks', async function () {
		if (skipAll) this.skip();
		// The first composite drained one channel of the pair: a fresh capable
		// primary joins, and the amount is above any one channel's bound.
		ids.push(
			await openFromPrimary(
				newPrimary('composite-regtest-p4'),
				4_000_000n,
				3_600_000n
			)
		);
		const address = (await bitcoinRpc('getnewaddress', [
			'',
			'bech32'
		])) as string;
		const quote = await daemon!.node.quoteChannelSend(
			address,
			compositeAmount(address),
			1000
		);
		expect(quote.kind).to.equal('composite');
		expect(quote.channels.length).to.be.greaterThan(1);
		const run = await daemon!.node.executeChannelSend(quote.quoteId);
		const compositeId = run.compositeId!;
		await waitFor(
			() =>
				['BROADCAST', 'RELEASED'].includes(
					daemon!.node.getChannelSend(quote.quoteId)?.stage ?? ''
				),
			'the composite to release',
			120_000
		);
		const txid = daemon!.node.getChannelSend(quote.quoteId)!.txid!;
		expect(await fetchTx(txid), 'composite accepted by bitcoind').to.exist;
		const spentBefore = daemon!.node.getDailySpendInfo().spentSats;

		// Crash the wallet between the broadcast and the locks.
		await daemon!.stop();
		daemon = await startDaemon(daemonOptions());
		wallet = daemon.node.getNode();
		const restored = daemon.node.getChannelSend(compositeId);
		expect(restored, 'record restored by composite id').to.not.equal(null);
		expect(['BROADCAST', 'RELEASED']).to.include(restored!.stage);
		expect(
			daemon.node.getDailySpendInfo().spentSats,
			'the charge survived'
		).to.equal(spentBefore);
		expect(daemon.node.getDailySpendInfo().pendingSats).to.equal(0);
		for (const p of primaries) {
			await p
				.connectPeer(wallet.getNodeId(), '127.0.0.1', walletPort)
				.catch(() => undefined);
		}
		const involved = quote.channels.map((c) => Buffer.from(c.channelId, 'hex'));
		await waitFor(
			() =>
				involved.every((id) => {
					const st = wallet.getChannelManager().getChannel(id)?.getState();
					return st === ChannelState.SPLICING || st === ChannelState.NORMAL;
				}),
			'channels reestablished after the restart',
			120_000
		);
		await lock(() => daemon!.node.getChannelSend(compositeId), involved);
		for (const id of involved) {
			expect(
				Buffer.from(
					wallet.getChannelManager().getChannel(id)!.getFullState().fundingTxid!
				)
					.reverse()
					.toString('hex')
			).to.equal(txid);
		}
		expect(
			daemon.node.getDailySpendInfo().spentSats,
			'charged once across the restart'
		).to.equal(spentBefore);
	});

	it('a primary that disconnects during the negotiation aborts the composite at once, every channel is usable again and nothing is charged', async function () {
		if (skipAll) this.skip();
		ids.push(
			await openFromPrimary(
				newPrimary('composite-regtest-p5'),
				4_000_000n,
				3_600_000n
			)
		);
		const address = (await bitcoinRpc('getnewaddress', [
			'',
			'bech32'
		])) as string;
		const quote = await daemon!.node.quoteChannelSend(
			address,
			compositeAmount(address),
			1000
		);
		expect(quote.kind).to.equal('composite');
		expect(quote.channels.length).to.be.greaterThan(1);
		const involved = quote.channels.map((c) => Buffer.from(c.channelId, 'hex'));
		// The peer of the plan's second channel goes away as soon as the wallet's
		// splice_init reaches it: before any commitment. Over a real transport
		// neither node emits message:outbound, so the hook is the leaver's
		// inbound message event.
		const leaver = channels.get(quote.channels[1].channelId)!;
		let dropped = false;
		const onInbound = (pubkey: string, type: number): void => {
			if (dropped || type !== MessageType.SPLICE) return;
			if (pubkey !== wallet.getNodeId()) return;
			dropped = true;
			setImmediate(() => leaver.disconnectPeer(wallet.getNodeId()));
		};
		leaver.getPeerManager()!.on('message', onInbound);
		const spentBefore = daemon!.node.getDailySpendInfo().spentSats;
		const recordsBefore = wallet.listCompositeSplices().length;
		const started = Date.now();
		try {
			const run = await daemon!.node.executeChannelSend(quote.quoteId);
			expect(run.kind).to.equal('composite');
			await waitFor(
				() => daemon!.node.getChannelSend(quote.quoteId)?.stage === 'ABORTED',
				'the composite to abort on the disconnect',
				30_000
			);
		} finally {
			leaver.getPeerManager()!.removeListener('message', onInbound);
		}
		expect(dropped, 'splice_init reached the leaver').to.equal(true);
		expect(
			Date.now() - started,
			'aborted at once, not at the end of the budget'
		).to.be.lessThan(10_000);
		const status = daemon!.node.getChannelSend(quote.quoteId)!;
		expect(status.reason).to.match(/disconnected before release/);
		expect(status.txid, 'no transaction was agreed').to.equal(undefined);
		expect(wallet.listCompositeSplices()).to.have.length(recordsBefore + 1);
		const spend = daemon!.node.getDailySpendInfo();
		expect(spend.spentSats, 'nothing charged').to.equal(spentBefore);
		expect(spend.pendingSats, 'reservation released').to.equal(0);
		// The leaver comes back; every involved channel is NORMAL with no splice
		// in flight on either side and is free to splice again.
		await leaver.connectPeer(wallet.getNodeId(), '127.0.0.1', walletPort);
		await waitFor(
			() =>
				involved.every((id) =>
					[wallet, channels.get(id.toString('hex'))!].every((node) => {
						const ch = node.getChannelManager().getChannel(id);
						return (
							ch?.getState() === ChannelState.NORMAL &&
							ch.getFullState().spliceInFlight === null
						);
					})
				),
			'every involved channel NORMAL again on both sides',
			60_000
		);
		for (const id of involved) {
			expect(
				wallet.getChannelManager().getChannel(id)!.spliceBusyReason(),
				'free to splice'
			).to.equal(null);
		}
	});

	it('a composite across a beignet primary and Core Lightning completes and CLN adopts it', async function () {
		if (skipAll) this.skip();
		cln = await createClnClient();
		if (!cln) {
			console.log('    [skip] CLN container not reachable');
			this.skip();
			return;
		}
		await waitForClnSync(cln);
		clnPubkey = (await cln.getInfo()).id;
		await fundClnWallet(cln);
		await wallet.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await cln.fundChannel(wallet.getNodeId(), 4_000_000);
		await waitFor(
			() => wallet.getChannelManager().listChannels().length > channels.size,
			'the CLN channel to appear',
			60_000
		);
		const clnChannel = wallet
			.getChannelManager()
			.listChannels()
			.find((c) => !channels.has(c.getChannelId()!.toString('hex')))!;
		clnChannelId = clnChannel.getChannelId()!;
		channels.set(clnChannelId.toString('hex'), null);
		await mineBlocks(6);
		const tip = (await bitcoinRpc('getblockcount', [])) as number;
		wallet.handleFundingConfirmed(clnChannelId);
		wallet.handleNewBlock(tip);
		await waitFor(
			() => clnChannel.getState() === ChannelState.NORMAL,
			'CLN channel NORMAL',
			60_000
		);
		await waitForClnPeerChannelNormal(cln, wallet.getNodeId());
		// CLN pays the wallet so the wallet has balance on that channel too.
		await payBeignetInvoiceStrict(
			wallet,
			cln,
			3_000_000_000,
			'composite-regtest-cln'
		);
		await waitFor(
			() => clnChannel.getFullState().htlcs.size === 0,
			'payment settled'
		);
		// A default CLN v26.06.1 advertises no init feature bit above 63
		// (800898882a8a59a1): neither 454/455 nor its shutdown_wrong_funding
		// pair 104/105, which CLN sets only under an experimental flag. The
		// wallet therefore does not recognise it and would leave its channel
		// out of a plan by name. Tier C3 of cln-splice-matrix proved the
		// protocol path, so this case vouches for the peer the way an operator
		// declaration would and qualifies the composite itself.
		expect(
			wallet.peerSupportsCompositeSpliceInputs(clnPubkey),
			'a default CLN is not recognised'
		).to.equal(false);
		const recognise = wallet.peerSupportsCompositeSpliceInputs.bind(wallet);
		wallet.peerSupportsCompositeSpliceInputs = (peer: string) =>
			peer === clnPubkey ? true : recognise(peer);

		const address = (await bitcoinRpc('getnewaddress', [
			'',
			'bech32'
		])) as string;
		// The beignet primary with the most left plus the CLN channel, for an
		// amount above what either can send alone.
		const richest = ids
			.map((id) => wallet.getChannelManager().getChannel(id)!)
			.sort((a, b) =>
				a.getBalances().localMsat > b.getBalances().localMsat ? -1 : 1
			)[0]
			.getChannelId()!;
		const destinationScript = bitcoin.address.toOutputScript(
			address,
			bitcoin.networks.regtest
		);
		const amountSats = BigInt(
			Math.max(
				wallet.spliceQuote(richest, 'out', 1000, destinationScript)
					.maxAmountSats,
				wallet.spliceQuote(clnChannelId, 'out', 1000, destinationScript)
					.maxAmountSats
			) + 100_000
		);
		const planned = await wallet.planCompositeSpliceOut({
			destinationScript,
			amountSats,
			fundingFeeratePerkw: 1000,
			channelIds: [richest, clnChannelId]
		});
		expect(
			planned.ok,
			JSON.stringify(planned, (_, v) =>
				typeof v === 'bigint' ? v.toString() : v
			)
		).to.equal(true);
		const started = await wallet.startCompositeSpliceOut({
			destinationScript,
			amountSats,
			fundingFeeratePerkw: 1000,
			channelIds: [richest, clnChannelId]
		});
		expect(
			started.ok,
			JSON.stringify(started, (_, v) =>
				typeof v === 'bigint' ? v.toString() : v
			)
		).to.equal(true);
		if (!started.ok) return;
		await waitFor(
			() =>
				['BROADCAST', 'RELEASED'].includes(
					wallet.getCompositeSplice(started.id)?.stage ?? ''
				),
			'the composite with CLN to release',
			120_000
		);
		const record = wallet.getCompositeSplice(started.id)!;
		const txid = Buffer.from(record.txid!, 'hex').reverse().toString('hex');
		expect(await fetchTx(txid), 'composite with CLN accepted by bitcoind').to
			.exist;
		await mineBlocks(6);
		const tip2 = (await bitcoinRpc('getblockcount', [])) as number;
		for (const node of [wallet, ...primaries]) node.handleNewBlock(tip2);
		await sleep(2000);
		for (const id of [richest, clnChannelId]) {
			for (const node of [wallet, ...primaries]) {
				if (
					node.getChannelManager().getChannel(id)?.getState() ===
					ChannelState.SPLICING
				) {
					node.getChannelManager().sendSpliceLocked(id);
				}
			}
		}
		await waitFor(
			() => wallet.getCompositeSplice(started.id)?.stage === 'LOCKED',
			'LOCKED with CLN',
			180_000
		);
		const clnView = await cln.listChannels();
		const entry = clnView.channels.find(
			(c) => c.peer_id === wallet.getNodeId() && c.funding_txid === txid
		);
		expect(entry, 'CLN runs on the composite funding').to.exist;
		expect(entry!.state).to.equal('CHANNELD_NORMAL');
		console.log(
			`    composite with CLN ${txid} locked; CLN state ${entry!.state}`
		);
	});
});
