import * as repl from 'repl';
import * as net from 'net';
import * as tls from 'tls';
import * as path from 'path';
import { promises as fs } from 'fs';
import { generateMnemonic, Wallet } from '../src';
import { LightningNode } from '../src/lightning/node/lightning-node';
import { ILightningError, IFundingProvider } from '../src/lightning/node/types';
import { WalletFundingProvider } from '../src/lightning/wallet/wallet-funding-provider';
import { Network } from '../src/lightning/invoice/types';
import { BITCOIN_CHAIN_HASH } from '../src/lightning/channel/types';
import { decode as decodeInvoice } from '../src/lightning/invoice/decode';
import { SqliteStorage } from '../src/lightning/storage/sqlite-storage';

// ─────────────── CLI Arg Parsing ───────────────

const NETWORKS = ['mainnet', 'testnet', 'regtest'];

function parseArgs(argv: string[]): {
	mnemonic?: string;
	alias?: string;
	torProxy?: string;
	network?: string;
	electrumHost?: string;
	electrumPort?: number;
	electrumTls?: boolean;
} {
	const args = argv.slice(2);
	let alias: string | undefined;
	let torProxy: string | undefined;
	let network: string | undefined;
	let electrumHost: string | undefined;
	let electrumPort: number | undefined;
	let electrumTls: boolean | undefined;
	const mnemonicWords: string[] = [];

	for (let i = 0; i < args.length; i++) {
		if (args[i] === '--alias' && i + 1 < args.length) {
			alias = args[++i];
		} else if (args[i] === '--tor-proxy' && i + 1 < args.length) {
			torProxy = args[++i];
		} else if (args[i] === '--electrum-host' && i + 1 < args.length) {
			electrumHost = args[++i];
		} else if (args[i] === '--electrum-port' && i + 1 < args.length) {
			electrumPort = parseInt(args[++i], 10);
		} else if (
			args[i] === '--electrum-no-ssl' ||
			args[i] === '--electrum-tcp'
		) {
			electrumTls = false;
		} else if (args[i] === '--electrum-ssl') {
			electrumTls = true;
		} else if (NETWORKS.includes(args[i])) {
			network = args[i];
		} else if (args[i].startsWith('--')) {
			// skip flags like --low-level, --payment-flow
		} else {
			mnemonicWords.push(args[i]);
		}
	}

	return {
		mnemonic: mnemonicWords.length > 0 ? mnemonicWords.join(' ') : undefined,
		alias,
		torProxy,
		network,
		electrumHost,
		electrumPort,
		electrumTls
	};
}

// ─────────────── Help ───────────────

function printHelp(): void {
	console.log(`
--- Lightning Node REPL Commands ---

  Node Info
    node.getNodeId()                                      Node public key (hex)
    node.getNodeInfo()                                    Node ID, network, alias, counts
    node.getFundingAddress()                               On-chain P2WPKH address for funding

  Peers
    node.connectPeer(pubkey, host, port)                  Connect to a remote peer
    node.disconnectPeer(pubkey)                           Disconnect a peer
    node.listPeers()                                     List connected peers
    node.listen(port, host?)                              Listen for inbound connections
    node.stopListening()                                  Stop listening
    node.isListening()                                    Check if listening

  Channels (auto-funded when wallet is connected)
    node.openChannel(peerPubkey, fundingSats, pushMsat?)  Open a channel
    node.closeChannel(channelId, scriptPubkey)            Cooperative close
    node.forceCloseChannel(channelId, destScript)         Force close
    node.listChannels()                                   List all channels
    node.getChannel(channelId)                            Get channel details

    With a fundingProvider attached, openChannel() handles the entire
    funding flow automatically: builds the tx, signs the commitment,
    sends funding_created, and broadcasts after funding_signed.

    Without a fundingProvider, you must call createFunding() manually
    after openChannel() to provide the funding transaction details.

  Splicing (channel must be NORMAL; requires wallet funding provider)
    node.spliceIn(channelIdBuf, sats, feeratePerKw)       Add wallet funds to a channel
    node.spliceOut(channelIdBuf, sats, feeratePerKw)      Withdraw funds to the on-chain wallet

    feeratePerKw is sat/kiloweight: 253 = minimum relay, ~250 per sat/vB
    (e.g. 2500 = ~10 sat/vB). The splice initiator pays the on-chain fee;
    for splice-out it is taken from the channel, so the fee must be lower
    than the amount withdrawn. Results/errors arrive via 'node:error'.

  Invoices & Payments
    node.createInvoice({ amountMsat, description|descriptionHash })  Create a BOLT 11 invoice
    node.sendPayment(invoiceStr)                          Pay a BOLT 11 invoice
    node.getPayment(paymentHash)                          Look up a payment
    node.listPayments()                                   List all payments
    decodeInvoice(invoiceStr)                             Decode a BOLT 11 invoice

  Gossip & Routing
    node.getGraph()                                       Access the network graph
    node.initiateGossipSync(pubkey)                       Start gossip sync with peer

  Chain
    node.handleNewBlock(height)                           Notify of new block
    node.getCurrentBlockHeight()                          Current block height

  Lifecycle
    node.destroy()                                        Shut down the node
    .exit                                                 Exit REPL
`);
}

// ─────────────── Tor proxy probe ───────────────

/**
 * Check that a SOCKS5 proxy is actually listening before the node starts, and
 * print actionable guidance if not. A missing Tor daemon otherwise surfaces
 * only as opaque peer connection timeouts.
 */
async function probeSocksProxy(torProxy: string): Promise<void> {
	const [host, portStr] = torProxy.split(':');
	const port = parseInt(portStr, 10);
	const reachable = await new Promise<boolean>((resolve) => {
		const sock = net.connect({ host, port, timeout: 2000 });
		sock.once('connect', () => {
			sock.destroy();
			resolve(true);
		});
		sock.once('error', () => resolve(false));
		sock.once('timeout', () => {
			sock.destroy();
			resolve(false);
		});
	});
	if (reachable) {
		console.log(
			`[tor] SOCKS5 proxy reachable at ${torProxy} — peer connections route through it.`
		);
	} else {
		console.warn(`\n[tor] WARNING: nothing is listening at ${torProxy}.`);
		console.warn(
			'[tor] Peer connections (including .onion peers) will fail until a Tor daemon runs.'
		);
		console.warn(
			'[tor] Start one in the background with:  brew services start tor'
		);
		console.warn(
			'[tor] (A daemon may already be running if `tor` reports "Address already in use".'
		);
		console.warn(
			'[tor]  Tor Browser is NOT needed — and it listens on 9150, not 9050.)\n'
		);
	}
}

// ─────────────── Wallet + Auto-Funding Setup ───────────────

/**
 * Create a WalletFundingProvider from a beignet Wallet.
 *
 * This wires the on-chain wallet to the Lightning node so that
 * openChannel() automatically builds, signs, and broadcasts
 * the funding transaction — no manual steps required.
 *
 * Usage:
 *   const wallet = (await Wallet.create({ mnemonic, electrumOptions, ... })).value;
 *   const fundingProvider = new WalletFundingProvider(wallet);
 *   const node = LightningNode.fromMnemonic(mnemonic, { fundingProvider });
 *   node.openChannel(peerPubkey, 100_000n); // fully automatic
 */
// Exported for reuse — use this when Electrum is available
export async function createFundingProvider(
	mnemonic: string,
	electrumOptions: { net: unknown; tls: unknown; servers?: unknown }
): Promise<IFundingProvider | null> {
	try {
		const result = await Wallet.create({
			mnemonic,
			electrumOptions: electrumOptions as Parameters<
				typeof Wallet.create
			>[0]['electrumOptions']
		});
		if (result.isErr()) {
			console.warn('[wallet] Failed to create wallet:', result.error.message);
			return null;
		}
		return new WalletFundingProvider(result.value);
	} catch (err) {
		console.warn(
			'[wallet] Wallet not available (electrum not configured):',
			(err as Error).message
		);
		return null;
	}
}

// ─────────────── Example ───────────────

const runExample = async (
	mnemonic = generateMnemonic(),
	alias?: string,
	torProxy?: string
): Promise<void> => {
	// 1. Set up SQLite persistence
	const dataDir = path.resolve('example/lightningData');
	await fs.mkdir(dataDir, { recursive: true });
	const storage = new SqliteStorage(path.join(dataDir, 'node.db'));
	storage.open();

	// 2. Create a wallet-backed funding provider.
	//    openChannel() will auto-fund from the on-chain wallet when it has sats.
	//    Uses beignet's default mainnet electrum servers (no servers arg needed).
	const fundingProvider = await createFundingProvider(mnemonic, { net, tls });

	// 3. Parse SOCKS5 proxy (for Tor .onion connections)
	let socks5Proxy: { host: string; port: number } | undefined;
	if (torProxy) {
		await probeSocksProxy(torProxy);
		const [proxyHost, proxyPort] = torProxy.split(':');
		socks5Proxy = { host: proxyHost, port: parseInt(proxyPort, 10) };
	}

	// 4. Create node from mnemonic (deterministic key derivation)
	const node = LightningNode.fromMnemonic(mnemonic, {
		network: Network.MAINNET,
		enableNetworking: true,
		localFeatures: LightningNode.defaultFeatures(),
		chainHashes: [BITCOIN_CHAIN_HASH],
		storage,
		alias,
		fundingProvider: fundingProvider ?? undefined,
		socks5Proxy
	});

	// 5. Display node info
	const info = node.getNodeInfo();
	console.log('\n--- Lightning Node ---');
	console.log('Node ID:   ', info.nodeId);
	console.log('Network:   ', info.network);
	if (info.alias) console.log('Alias:     ', info.alias);
	console.log('Mnemonic:  ', mnemonic);
	console.log('Address:   ', node.getFundingAddress());
	console.log('Storage:   ', path.join(dataDir, 'node.db'));
	console.log('Channels:  ', info.channelCount);
	console.log('Peers:     ', info.peerCount);
	console.log('Networking:', info.networkingEnabled);
	console.log(
		'Tor Proxy: ',
		socks5Proxy ? `${socks5Proxy.host}:${socks5Proxy.port}` : 'disabled'
	);
	console.log(
		'Auto-fund: ',
		fundingProvider ? 'yes (wallet connected)' : 'no (manual createFunding)'
	);

	// 6. Event listeners
	node.on('payment:received', (p) => {
		console.log('\n[event] Payment received:', p.paymentHash.toString('hex'));
	});
	node.on('payment:sent', (p) => {
		console.log('\n[event] Payment sent:', p.paymentHash.toString('hex'));
	});
	node.on('channel:ready', ({ channelId }: { channelId: Buffer }) => {
		console.log('\n[event] Channel ready:', channelId.toString('hex'));
	});
	node.on('peer:connect', (pubkey: string) => {
		console.log('\n[event] Peer connected:', pubkey);
	});
	node.on('peer:disconnect', (pubkey: string) => {
		console.log('\n[event] Peer disconnected:', pubkey);
	});
	node.on('node:error', (err: ILightningError) => {
		console.error(`\n[event] Node error [${err.code}]:`, err.message);
	});

	// 7. Create & decode an invoice (fully standalone — no peers/channels needed)
	const invoiceResult = node.createInvoice({
		amountMsat: 100_000n,
		description: 'hello from beignet lightning'
	});
	console.log('\n--- Invoice Demo ---');
	console.log('Encoded:', invoiceResult.bolt11);
	console.log('Pay Hash:', invoiceResult.paymentHash.toString('hex'));

	const decoded = decodeInvoice(invoiceResult.bolt11);
	console.log('Amount:     ', decoded.amountMsat?.toString(), 'msat');
	console.log('Description:', decoded.description);
	console.log('Expiry:     ', decoded.expiry, 'seconds');

	// 8. REPL
	console.log('\n--- REPL ---');
	console.log('Type help() for available commands.\n');

	const r = repl.start('lightning> ');
	r.context.node = node;
	r.context.decodeInvoice = decodeInvoice;
	r.context.invoice = invoiceResult.bolt11;
	r.context.help = printHelp;
	r.context.WalletFundingProvider = WalletFundingProvider;

	r.on('exit', () => {
		console.log('\nShutting down...');
		node.destroy();
		storage.close();
	});
};

// ─────────────── BeignetNode Example (simplified API) ───────────────

import { BeignetNode } from '../src/cli/beignet-node';

const runBeignetExample = async (
	mnemonic = generateMnemonic(),
	network: 'mainnet' | 'testnet' | 'regtest' = 'mainnet',
	electrumHost?: string,
	electrumPort?: number,
	alias?: string,
	fullGraph = false,
	torProxy?: string,
	electrumTls?: boolean
): Promise<void> => {
	if (torProxy) await probeSocksProxy(torProxy);
	const node = await BeignetNode.create({
		mnemonic,
		network,
		electrumHost,
		electrumPort,
		electrumTls,
		preferAnchors: true,
		alias,
		// --tor-proxy host:port: route peer connections through Tor, required to
		// reach peers that only advertise a .onion address.
		torProxy,
		// --full-graph: connect to DNS-seed nodes on startup and gossip-sync the
		// full network graph, so the node can route to arbitrary public
		// destinations (not just its direct channel peers).
		autoBootstrap: fullGraph
	});

	if (network === 'mainnet') {
		console.log(
			'\n[graph] Rapid Gossip Sync downloading the network graph in the background...'
		);
		console.log(
			'[graph] Multi-hop routing works once node.getHealth().graphChannels is populated (~a few seconds).'
		);
	}
	if (fullGraph) {
		console.log(
			'[full-graph] Also bootstrapping to DNS-seed peers for live p2p gossip.'
		);
	}

	// Wait for node to be fully operational (peers reconnected, channels restored)
	try {
		await node.waitForReady(10_000);
		console.log('\n[ready] Node is fully operational');
	} catch {
		console.log(
			'\n[ready] Timed out waiting for node ready (continuing anyway)'
		);
	}

	console.log('\n--- BeignetNode ---');
	console.log('Info:', JSON.stringify(node.getInfo(), null, 2));
	console.log('Balance:', JSON.stringify(node.getBalance()));
	console.log('Health:', JSON.stringify(node.getHealth()));

	// Listen for events
	node.on('node:ready', () => {
		console.log('\n[event] Node ready');
	});
	node.on('channel:ready', (e) => {
		console.log('\n[event] Channel ready:', e.channelId);
	});
	node.on('channel:closed', (e) => {
		console.log('\n[event] Channel closed:', e.channelId);
	});
	node.on('peer:connect', (pubkey) => {
		console.log('\n[event] Peer connected:', pubkey);
	});
	node.on('peer:disconnect', (pubkey) => {
		console.log('\n[event] Peer disconnected:', pubkey);
	});
	node.on('peer:error', (e) => {
		console.error('\n[event] Peer error:', e.pubkey, '-', e.message);
	});
	node.on('payment:received', (p) => {
		console.log(
			'\n[event] Payment received:',
			p.paymentHash,
			`(${p.amountSats} sats)`
		);
	});
	node.on('payment:sent', (p) => {
		console.log(
			'\n[event] Payment sent:',
			p.paymentHash,
			`(${p.amountSats} sats)`
		);
	});
	node.on('node:error', (err) => {
		console.error('\n[error]', err.code, '-', err.message);
	});

	// REPL
	console.log('\n--- REPL ---');
	console.log('Type help() for available commands.\n');

	const r = repl.start('beignet> ');
	r.context.node = node;
	r.context.help = () => {
		console.log(`
  Node
    node.getInfo()                              Node info (JSON)
    node.getHealth()                            Health check
    node.getBalance()                           On-chain + Lightning balances
    node.getStats(windowMs?)                    Time-windowed node stats
    node.getMetrics()                           Prometheus text exposition
    node.getMainnetReadiness()                  Weighted readiness checklist
    node.getNodeUri(externalHost?)              Shareable pubkey@host:port
    node.getMnemonic()                          Recovery phrase
    node.waitForReady(timeoutMs?)               Wait for node ready (async)
    node.isReady()                              Ready boolean

  On-chain Wallet
    node.getNewAddress()                        New deposit address (async)
    node.sendOnchain(addr, sats, satsPerVbyte?) Send on-chain (async)
    node.sendMaxOnchain(addr, satsPerVbyte?)    Sweep entire balance (async)
    node.listOnchainTransactions()              On-chain tx history (newest first)
    node.listUtxos()                            Spendable on-chain UTXOs
    node.getFeeEstimates()                      Fee estimates in sats/vB (async)
    node.validateAddress(addr)                  Validate a bitcoin address
    node.refreshWallet()                        Resync wallet (async)

  Peers
    node.connectPeer(pubkey, host, port)        Connect to a peer (async)
    node.disconnectPeer(pubkey)                 Disconnect a peer
    node.listPeers()                            List connected peers
    node.bootstrapPeers()                       Discover peers via DNS seeds (async)
    node.connectToSeeds(maxPeers?)              Connect to seed peers (async)
    node.syncGossip(pubkey?)                    Pull the gossip graph from a peer (p2p; all peers if omitted)
    node.syncRapidGossip()                      Download the full graph via Rapid Gossip Sync (async)
    node.addTrustedPeer(pubkey)                 Trust a peer (zero-conf etc.)
    node.removeTrustedPeer(pubkey)              Untrust a peer
    node.listTrustedPeers()                     List trusted peers

  Channels
    node.openChannel(pubkey, sats, pushSats?)   Open a channel
    node.openChannelAndWait(pubkey, sats, opts?)        Open + await ready (async)
    node.connectAndOpenChannel(pubkey, host, port, sats, ...)  Connect + open (async)
    node.openZeroConfChannel(pubkey, sats, pushSats?)   Zero-conf channel
    node.closeChannel(channelId)                Cooperative close (async)
    node.forceCloseChannel(channelId)           Force close (async)
    node.listChannels()                         List channels
    node.getReadyChannels()                     Channels usable for routing
    node.getChannel(channelId)                  Channel details
    node.getChannelHealth(channelId)            Balance %, HTLC counts, warnings
    node.getChannelDiagnostics(channelId)       Debug routing/announcement issues
    node.updateChannelFee(channelId, feeratePerKw)      Set forwarding fee
    node.canSend(sats)                          Check outbound capacity
    node.canReceive(sats)                       Check inbound capacity
    node.waitForChannelReady(channelId, ms?)    Await NORMAL state (async)
    node.getChannelSuggestions(count?)          Who to open channels with
    node.ensureMinimumChannels(...)             Auto-open via suggestions (async)

  Splicing
    node.spliceIn(channelId, sats, feeratePerKw)        Add funds to live channel
    node.spliceOut(channelId, sats, feeratePerKw)       Remove funds

  Invoices
    node.createInvoice(sats, desc, expiry?, descHash?)  Create a BOLT 11 invoice
    node.decodeInvoice(bolt11)                  Decode invoice (check routingHints!)
    node.getInvoice(paymentHash)                Look up an invoice
    node.listInvoices()                         List invoices

  BOLT 12 Offers
    node.createOffer({ description, amountSats?, issuer? })  Create a reusable offer
    node.decodeOfferString(offer)               Decode an offer
    node.listOffers()                           List created offers
    node.payOffer(offer, amountSats?)           Pay an offer (async)

  Payments
    node.payInvoice(bolt11, ms?, maxFeeSats?, amountSats?)   Pay (throws on fail, async)
    node.payInvoiceSafe(bolt11, ...)            Pay — never throws (async)
    node.payInvoiceWithRetry(bolt11, opts)      Pay w/ backoff retry (async)
    node.sendPaymentAsync(bolt11, ...)          Fire-and-forget; returns paymentHash
    node.sendKeysend(pubkey, sats, ...)         Spontaneous payment (async)
    node.sendKeysendSafe(pubkey, sats, ...)     Keysend — never throws (async)
    node.validatePayment(bolt11, sats?)         Pre-flight check
    node.estimateRouteFee(bolt11, sats?)        Fee estimate
    node.estimatePayment(bolt11, sats?)         Success-probability estimate
    node.probeRoute(destPubkey, sats)           Probe a route (async)
    node.waitForPayment(paymentHash, ms?)       Await completion (async)
    node.cancelPayment(paymentHash)             Cancel a pending payment
    node.listPayments(filter?)                  List payments
    node.getPayment(paymentHash)                Look up a payment
    node.getPaymentProof(paymentHash)           Preimage proof bundle
    node.verifyPaymentProof(paymentHash)        Verify proof

  Payment Queue
    node.enqueuePayment(bolt11, priority?, opts?)       Queue a payment
    node.listQueue()                            List queued payments
    node.cancelQueuedPayment(id)                Remove from queue

  Liquidity & Fees
    node.getLiquiditySnapshot()                 Inbound/outbound snapshot
    node.getFeeSnapshot()                       Fee trend/percentiles
    node.getDailySpendInfo()                    Daily spend tracking
    node.setDraining(true|false)                Stop accepting new HTLCs
    node.isDraining()                           Draining state
    node.hasPendingPayments()                   Pending payments boolean

  Diagnostics & Ops
    node.getActionLog(opts?)                    Structured action log
    node.backup(destPath)                       Backup DB to path (async)
    node.triggerBackup()                        Trigger configured backup
    node.getNode()                              Underlying LightningNode (low-level)
    node.getWallet()                            Underlying on-chain Wallet (low-level)
    node.getStorage()                           Underlying SqliteStorage

  Lifecycle
    node.gracefulShutdown(ms?)                  Flush then shut down (async)
    node.destroy()                              Shut down (async)
    .exit                                       Exit REPL
`);
	};

	r.on('exit', async () => {
		console.log('\nShutting down...');
		await node.destroy();
		process.exit(0);
	});
};

// ─────────────── Two-Node Payment Flow Example ───────────────
//
// This demonstrates a complete payment lifecycle between two BeignetNodes.
// In a real setup, each node would have funded on-chain wallets and be
// connected to an Electrum server. This example shows the API surface
// you'd use once channels are established.
//
// Run with: npm run example:lightning -- --payment-flow

const runPaymentFlowExample = async (): Promise<void> => {
	console.log('\n=== Two-Node Payment Flow ===\n');

	// 1. Create Alice and Bob
	const alice = await BeignetNode.create({
		mnemonic: generateMnemonic(),
		network: 'regtest',
		alias: 'alice',
		logLevel: 'info'
	});
	const bob = await BeignetNode.create({
		mnemonic: generateMnemonic(),
		network: 'regtest',
		alias: 'bob',
		logLevel: 'info'
	});

	console.log('Alice nodeId:', alice.getInfo().nodeId);
	console.log('Bob   nodeId:', bob.getInfo().nodeId);

	// 2. Wire up event listeners
	alice.on('payment:sent', (p) => {
		console.log(
			`\n[Alice] Payment sent: ${p.paymentHash} (${p.amountSats} sats, fee: ${
				p.feeSats ?? 0
			} sats)`
		);
	});
	bob.on('payment:received', (p) => {
		console.log(
			`\n[Bob] Payment received: ${p.paymentHash} (${p.amountSats} sats)`
		);
	});

	// 3. In production, you would:
	//    a) Connect peers: await alice.connectPeer(bobPubkey, 'localhost', 9735)
	//    b) Open channel:  alice.openChannel(bobPubkey, 100_000)
	//    c) Wait for channel: await alice.waitForChannelReady(channelId)
	//    d) Handle funding confirmation via chain backend

	// 4. Bob creates an invoice
	const invoice = bob.createInvoice(1000, 'Payment for coffee');
	console.log(
		'\n[Bob] Created invoice:',
		invoice.bolt11.substring(0, 40) + '...'
	);
	console.log('[Bob] Payment hash:', invoice.paymentHash);

	// 5. Alice decodes and inspects the invoice
	const decoded = alice.decodeInvoice(invoice.bolt11);
	console.log('\n[Alice] Decoded invoice:');
	console.log('  Amount:', decoded.amountSats, 'sats');
	console.log('  Description:', decoded.description);
	console.log('  Expiry:', decoded.expiry, 'seconds');

	// 6. Pre-flight check: can Alice send this amount?
	const sendCheck = alice.canSend(1000);
	console.log('\n[Alice] Can send 1000 sats?', sendCheck.canSend);
	console.log('[Alice] Available outbound:', sendCheck.availableSats, 'sats');

	// 7. In production with channels established:
	//    const payment = await alice.payInvoice(invoice.bolt11);
	//    console.log('Payment status:', payment.status);
	//
	//    Or with automatic retry:
	//    const result = await alice.payInvoiceWithRetry(invoice.bolt11, {
	//      maxRetries: 3,
	//      backoffMs: 2000,
	//      maxFeeSats: 10,
	//    });
	//    console.log('Attempts:', result.attempts);

	// 8. After payment, get the proof
	//    const proof = alice.getPaymentProof(invoice.paymentHash);
	//    console.log('Preimage:', proof.preimage);

	// 9. Check node health
	console.log('\n[Alice] Health:', JSON.stringify(alice.getHealth()));
	console.log('[Bob]   Health:', JSON.stringify(bob.getHealth()));

	// 10. Check readiness for mainnet
	const readiness = alice.getMainnetReadiness();
	console.log('\n[Alice] Mainnet readiness score:', readiness.score);
	for (const check of readiness.checks) {
		console.log(`  [${check.status}] ${check.name}: ${check.message}`);
	}

	// 11. Clean shutdown
	console.log('\nShutting down...');
	await alice.destroy();
	await bob.destroy();
	console.log('Done.');
};

// ─────────────── Entry Point ───────────────

const {
	mnemonic,
	alias,
	torProxy,
	network,
	electrumHost,
	electrumPort,
	electrumTls
} = parseArgs(process.argv);
const useLowLevel = process.argv.includes('--low-level');
const usePaymentFlow = process.argv.includes('--payment-flow');
const useFullGraph = process.argv.includes('--full-graph');

// Surface startup failures (e.g. a second instance hitting the data-dir lock)
// as a clean one-line message instead of an unhandled-rejection stack trace.
const onStartupError = (err: unknown): void => {
	const e = err as { code?: string; message?: string };
	if (e?.code === 'INSTANCE_ALREADY_RUNNING') {
		console.error(`\n[beignet] ${e.message}\n`);
	} else {
		console.error('\n[beignet] Failed to start:', e?.message ?? err, '\n');
	}
	process.exit(1);
};

if (usePaymentFlow) {
	runPaymentFlowExample().catch(onStartupError);
} else if (useLowLevel) {
	runExample(mnemonic, alias, torProxy).catch(onStartupError);
} else {
	runBeignetExample(
		mnemonic,
		(network as 'mainnet' | 'testnet' | 'regtest') || 'mainnet',
		electrumHost,
		electrumPort,
		alias,
		useFullGraph,
		torProxy,
		electrumTls
	).catch(onStartupError);
}
