/**
 * Integration: issue #159 — the production wallet funding path, end to end.
 *
 * Every interop test funds channels through BitcoindFundingProvider (bitcoind
 * wallet RPCs). The path the daemon actually uses in production — a real
 * Electrum-backed beignet Wallet wrapped in WalletFundingProvider, coin
 * selection, fee handling, wallet.send / wallet.sendMax, and the
 * funding-output construction — was covered only by unit tests with mocked
 * wallets. The #156 max-sweep fix lives entirely in that path and had no
 * suite coverage at all.
 *
 * This lives in integration/ (NOT interop/) deliberately: it needs only
 * bitcoind + Electrum, which CI already boots and waits for, and no
 * LND/CLN/Eclair containers. test:lightning therefore picks it up and every
 * PR runs it; the interop/** exclusion applies to the external-implementation
 * tests only.
 *
 * Two tiers, both against the regtest Electrum (docker `electrum` on 60001)
 * and polar bitcoind:
 *  1. a fixed-amount open auto-funded by the real wallet reaches NORMAL on
 *     both sides with the funding tx actually on the network, and
 *  2. a max open sweeps the whole spendable balance into the funding output
 *     (quoted with the same sendMax pricing the provider uses), reaches
 *     NORMAL, and leaves the on-chain balance at zero.
 *
 * Missing infrastructure is an auto-skip locally, but a FAILURE under CI: a
 * regression test that silently skips in CI protects nothing.
 */

import BitcoinJsonRpc from 'bitcoin-json-rpc';
import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	generateMnemonic,
	Wallet
} from '../../../';
import {
	bitcoinURL,
	electrumHost,
	electrumPort,
	initWaitForElectrumToSync,
	TWaitForElectrum
} from '../../utils';
import { bitcoinRpc } from '../interop/shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { WalletFundingProvider } from '../../../src/lightning/wallet/wallet-funding-provider';
import {
	REGTEST_CHAIN_HASH,
	ChannelState
} from '../../../src/lightning/channel/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';

const sleep = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Interop-style features WITHOUT option_dual_fund, so the open stays on the
 * v1 path handleAutoFunding drives through buildFundingTransaction — the
 * path this issue is about.
 */
function v1Features(): FeatureFlags {
	const features = FeatureFlags.empty();
	features.setOptional(Feature.DATA_LOSS_PROTECT);
	features.setOptional(Feature.STATIC_REMOTE_KEY);
	features.setOptional(Feature.PAYMENT_SECRET);
	features.setOptional(Feature.TLV_ONION);
	features.setOptional(Feature.CHANNEL_TYPE);
	return features;
}

function makeNode(
	seed: string,
	fundingProvider?: WalletFundingProvider
): LightningNode {
	const keys = deriveLightningKeysFromMnemonic(
		generateMnemonic(),
		seed,
		LnCoinType.REGTEST
	);
	const node = new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		network: Network.REGTEST,
		localFeatures: v1Features(),
		chainHashes: [REGTEST_CHAIN_HASH],
		fundingProvider
	});
	node.on('error', () => {});
	return node;
}

/** Wire two in-process nodes' outbound messages to each other. */
function wire(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId()) {
			b.handlePeerMessage(a.getNodeId(), type, payload);
		}
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId()) {
			a.handlePeerMessage(b.getNodeId(), type, payload);
		}
	});
}

describe('Integration: WalletFundingProvider funds real channels (regtest)', function () {
	this.timeout(180_000);

	const rpc = new BitcoinJsonRpc(bitcoinURL);
	let waitForElectrum: TWaitForElectrum;
	let wallet: Wallet;
	let skipAll = false;
	const nodes: LightningNode[] = [];

	before(async function () {
		this.timeout(60_000);
		try {
			let balance = await rpc.getBalance();
			const address = await rpc.getNewAddress();
			while (balance < 10) {
				await rpc.generateToAddress(10, address);
				balance = await rpc.getBalance();
			}
			waitForElectrum = await initWaitForElectrumToSync(
				{ host: electrumHost, port: electrumPort },
				bitcoinURL
			);
			await waitForElectrum();
		} catch (err) {
			// CI boots bitcoind + Electrum before the suite and this test is a
			// regression gate: unreachable infrastructure there is a broken
			// pipeline, and skipping would silently disarm the gate. Locally,
			// skip like the interop tests do.
			if (process.env.CI) {
				throw new Error(
					`bitcoind/electrum not reachable in CI: ${
						(err as Error)?.message ?? err
					}`
				);
			}
			skipAll = true;
			console.log('    [skip] bitcoind/electrum not reachable');
			this.skip();
			return;
		}

		const res = await Wallet.create({
			rbf: true,
			mnemonic: generateMnemonic(),
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions: {
				servers: [
					{
						host: electrumHost,
						ssl: 60002,
						tcp: electrumPort,
						protocol: EProtocol.tcp
					}
				],
				net,
				tls
			},
			gapLimitOptions: {
				lookAhead: 2,
				lookBehind: 2,
				lookAheadChange: 2,
				lookBehindChange: 2
			}
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		await wallet.refreshWallet({});

		// Fund the wallet with a known amount: 0.01 BTC = 1_000_000 sats.
		const addrRes = await wallet.getNextAvailableAddress();
		if (addrRes.isErr()) throw addrRes.error;
		await rpc.sendToAddress(addrRes.value.addressIndex.address, '0.01');
		await rpc.generateToAddress(1, await rpc.getNewAddress());
		await waitForElectrum();
		await wallet.refreshWallet({});
		expect(wallet.data.balance).to.equal(1_000_000);
	});

	after(async function () {
		for (const n of nodes) {
			try {
				n.destroy();
			} catch {
				/* ignore */
			}
		}
		await wallet?.electrum?.disconnect();
	});

	/**
	 * Drive an auto-funded open between two fresh in-process nodes and return
	 * once both sides are NORMAL. Returns the on-chain funding tx.
	 */
	async function openAndConfirm(
		fundingSats: bigint,
		satsPerVbyte: number,
		max: boolean
	): Promise<{ fundingTx: bitcoin.Transaction; outputIndex: number }> {
		// Capture what actually reaches the provider: with a synchronous
		// transport the fee rate and max flag used to arrive as
		// undefined/false because they were recorded only after openChannel
		// returned (see the beforeNegotiate hook in LightningNode.openChannel).
		const provider = new WalletFundingProvider(wallet);
		const buildCalls: Array<{ rate?: number; max?: boolean }> = [];
		const origBuild = provider.buildFundingTransaction.bind(provider);
		provider.buildFundingTransaction = async (...args) => {
			buildCalls.push({ rate: args[2], max: args[3] });
			return origBuild(...args);
		};
		const alice = makeNode(`wfp-alice-${Date.now()}-${max}`, provider);
		const bob = makeNode(`wfp-bob-${Date.now()}-${max}`);
		nodes.push(alice, bob);
		wire(alice, bob);

		const channel = alice.openChannel(
			bob.getNodeId(),
			fundingSats,
			undefined,
			satsPerVbyte,
			max
		);

		// Auto-funding is async: wallet coin selection, funding tx build,
		// funding_created/funding_signed exchange.
		const deadline = Date.now() + 30_000;
		while (Date.now() < deadline) {
			if (
				channel.getChannelId() &&
				channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
			) {
				break;
			}
			await sleep(250);
		}
		expect(
			channel.getState(),
			'funding negotiated (funding_signed received)'
		).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);

		// The funding tx must actually reach the network, broadcast by the
		// provider through the wallet's Electrum connection.
		const fundingTxidLE = channel.getFullState().fundingTxid!;
		const displayTxid = Buffer.from(fundingTxidLE).reverse().toString('hex');
		let rawTx: string | null = null;
		const bcastDeadline = Date.now() + 30_000;
		while (Date.now() < bcastDeadline) {
			try {
				rawTx = (await bitcoinRpc('getrawtransaction', [
					displayTxid
				])) as string;
				break;
			} catch {
				await sleep(1000);
			}
		}
		expect(rawTx, `funding tx ${displayTxid} broadcast`).to.not.equal(null);

		await rpc.generateToAddress(6, await rpc.getNewAddress());
		await waitForElectrum();

		alice.handleFundingConfirmed(channel.getChannelId()!);
		const bobChannel = bob
			.getChannelManager()
			.listChannels()
			.find((c) => c.getChannelId()?.equals(channel.getChannelId()!));
		expect(bobChannel, 'bob holds the channel').to.not.equal(undefined);
		bob.handleFundingConfirmed(bobChannel!.getChannelId()!);

		const readyDeadline = Date.now() + 20_000;
		while (Date.now() < readyDeadline) {
			if (
				channel.getState() === ChannelState.NORMAL &&
				bobChannel!.getState() === ChannelState.NORMAL
			) {
				break;
			}
			await sleep(250);
		}
		expect(channel.getState(), 'alice NORMAL').to.equal(ChannelState.NORMAL);
		expect(bobChannel!.getState(), 'bob NORMAL').to.equal(ChannelState.NORMAL);

		// The caller's fee rate and max flag must have reached the provider
		// even though the accept arrived synchronously.
		expect(buildCalls.length, 'provider funded once').to.equal(1);
		expect(
			buildCalls[0].rate,
			'requested fee rate reached the provider'
		).to.equal(satsPerVbyte);
		expect(buildCalls[0].max, 'max flag reached the provider').to.equal(max);

		const tx = bitcoin.Transaction.fromHex(rawTx!);
		return {
			fundingTx: tx,
			outputIndex: channel.getFullState().fundingOutputIndex
		};
	}

	it('auto-funds a fixed-amount open from the real wallet to NORMAL', async function () {
		if (skipAll) this.skip();

		const { fundingTx, outputIndex } = await openAndConfirm(500_000n, 2, false);
		expect(fundingTx.outs[outputIndex].value, 'funding output value').to.equal(
			500_000
		);

		await wallet.refreshWallet({});
		// 1_000_000 minus the 500_000 funding output minus the on-chain fee.
		expect(wallet.data.balance).to.be.lessThan(500_000);
		expect(wallet.data.balance).to.be.greaterThan(490_000);
	});

	it('a max open sweeps the whole balance into the funding output (issue #156 path)', async function () {
		if (skipAll) this.skip();

		// Quote the sweep the same way the provider prices it: a dry-run
		// sendMax to a P2WSH address (the funding output's script type; the
		// fee, and so the swept amount, depends on the output script size).
		const dummyWitness = crypto.randomBytes(32);
		const dummyP2wsh = bitcoin.payments.p2wsh({
			hash: bitcoin.crypto.sha256(dummyWitness),
			network: bitcoin.networks.regtest
		});
		const SATS_PER_VBYTE = 2;
		const quoteRes = await wallet.sendMax({
			address: dummyP2wsh.address!,
			broadcast: false,
			satsPerByte: SATS_PER_VBYTE
		});
		if (quoteRes.isErr()) throw quoteRes.error;
		const quotedTx = bitcoin.Transaction.fromHex(
			(quoteRes as { value: string }).value
		);
		expect(quotedTx.outs.length, 'sweep has a single output').to.equal(1);
		const maxSats = quotedTx.outs[0].value;

		const { fundingTx, outputIndex } = await openAndConfirm(
			BigInt(maxSats),
			SATS_PER_VBYTE,
			true
		);
		expect(
			fundingTx.outs.length,
			'max funding tx has no change output'
		).to.equal(1);
		expect(
			fundingTx.outs[outputIndex].value,
			'funding output equals the committed max'
		).to.equal(maxSats);

		await wallet.refreshWallet({});
		expect(wallet.data.balance, 'on-chain balance swept to zero').to.equal(0);
	});
});
