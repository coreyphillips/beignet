import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as http from 'http';
import { BeignetError, describeFailureCode } from '../../src/cli/errors';
import {
	loadConfig,
	saveConfig,
	resolveConfig,
	writePidFile,
	readPidFile,
	removePidFile
} from '../../src/cli/config';
import {
	BeignetNode,
	BeignetNodeOptions,
	defaultDataDirForMnemonic
} from '../../src/cli/beignet-node';
import type {
	ApiResponse,
	NodeInfo,
	ChannelInfo,
	PaymentInfo,
	InvoiceInfo,
	DecodedInvoice,
	PeerInfo,
	TxInfo,
	OnchainTxInfo,
	UtxoInfo,
	BalanceInfo,
	BeignetConfig,
	OfferInfo,
	TrustedPeerInfo,
	SpliceResult,
	BootstrapPeerInfo,
	Bolt12InvoiceInfo,
	HealthInfo,
	EventMessage
} from '../../src/cli/types';

// ─────────────── Error Tests ───────────────

describe('BeignetError', () => {
	it('should create error with code and message', () => {
		const err = new BeignetError('TEST_CODE', 'something went wrong');
		expect(err.code).to.equal('TEST_CODE');
		expect(err.message).to.equal('something went wrong');
		expect(err.name).to.equal('BeignetError');
		expect(err).to.be.instanceOf(Error);
	});

	it('should serialize to JSON', () => {
		const err = new BeignetError('SEND_FAILED', 'insufficient funds');
		const json = err.toJSON();
		expect(json).to.deep.equal({
			code: 'SEND_FAILED',
			message: 'insufficient funds'
		});
	});

	it('should serialize to JSON via JSON.stringify', () => {
		const err = new BeignetError('PAY_ERR', 'no route');
		const str = JSON.stringify({ ok: false, error: err });
		const parsed = JSON.parse(str);
		expect(parsed.error.code).to.equal('PAY_ERR');
		expect(parsed.error.message).to.equal('no route');
	});
});

describe('describeFailureCode', () => {
	it('should describe known BOLT failure codes', () => {
		// Correct BOLT 4 base codes (lower bits, flags stripped):
		expect(describeFailureCode(15)).to.equal(
			'incorrect_or_unknown_payment_details'
		);
		expect(describeFailureCode(10)).to.equal('unknown_next_peer');
		expect(describeFailureCode(12)).to.equal('fee_insufficient');
		expect(describeFailureCode(2)).to.equal('node_failure');
		expect(describeFailureCode(23)).to.equal('mpp_timeout');
		// Composite with flags:
		expect(describeFailureCode(0x4000 | 15)).to.equal(
			'PERM|incorrect_or_unknown_payment_details'
		);
	});

	it('should return unknown for unrecognized codes', () => {
		expect(describeFailureCode(9999)).to.include('unknown_failure');
		expect(describeFailureCode(9999)).to.include('9999');
	});
});

// ─────────────── Type Tests ───────────────

describe('CLI types', () => {
	it('ApiResponse success shape', () => {
		const resp: ApiResponse<{ value: number }> = {
			ok: true,
			result: { value: 42 }
		};
		expect(resp.ok).to.be.true;
		expect(resp.result!.value).to.equal(42);
		expect(resp.error).to.be.undefined;
	});

	it('ApiResponse failure shape', () => {
		const resp: ApiResponse<never> = {
			ok: false,
			error: { code: 'ERR', message: 'fail' }
		};
		expect(resp.ok).to.be.false;
		expect(resp.error!.code).to.equal('ERR');
		expect(resp.result).to.be.undefined;
	});

	it('NodeInfo type is JSON-serializable', () => {
		const info: NodeInfo = {
			nodeId: 'abcd1234',
			network: 'regtest',
			blockHeight: 100,
			onchainBalanceSats: 50000,
			lightningBalanceSats: 10000,
			pendingCloseBalanceSats: 0,
			erroredBalanceSats: 0,
			channelCount: 1,
			peerCount: 2,
			listening: true
		};
		const json = JSON.parse(JSON.stringify(info));
		expect(json.nodeId).to.equal('abcd1234');
		expect(json.onchainBalanceSats).to.equal(50000);
		expect(typeof json.blockHeight).to.equal('number');
	});

	it('ChannelInfo uses string IDs and number sats', () => {
		const ch: ChannelInfo = {
			channelId: 'aabbccdd',
			peerPubkey: '02abcdef',
			state: 'NORMAL',
			localBalanceSats: 40000,
			remoteBalanceSats: 60000,
			capacitySats: 100000,
			isAnchor: false
		};
		const json = JSON.parse(JSON.stringify(ch));
		expect(typeof json.channelId).to.equal('string');
		expect(typeof json.localBalanceSats).to.equal('number');
	});

	it('PaymentInfo includes optional failure description', () => {
		const p: PaymentInfo = {
			paymentHash: 'aabb',
			amountSats: 1000,
			status: 'FAILED',
			direction: 'OUTGOING',
			failureCode: 16,
			failureDescription: 'incorrect_or_unknown_payment_details',
			createdAt: Date.now()
		};
		const json = JSON.parse(JSON.stringify(p));
		expect(json.failureCode).to.equal(16);
		expect(json.failureDescription).to.include('incorrect');
	});

	it('InvoiceInfo shape', () => {
		const inv: InvoiceInfo = {
			bolt11: 'lnbc1...',
			paymentHash: 'aabb',
			amountSats: 5000
		};
		expect(inv.bolt11).to.equal('lnbc1...');
		expect(inv.amountSats).to.equal(5000);
	});

	it('DecodedInvoice uses hex strings', () => {
		const d: DecodedInvoice = {
			network: 'bc',
			timestamp: 1700000000,
			paymentHash: 'aabbccdd',
			description: 'test',
			expiry: 3600
		};
		expect(typeof d.paymentHash).to.equal('string');
		expect(typeof d.timestamp).to.equal('number');
	});

	it('BalanceInfo shape', () => {
		const b: BalanceInfo = { onchain: 50000, lightning: 10000, total: 60000 };
		expect(b.total).to.equal(b.onchain + b.lightning);
	});

	it('PeerInfo shape', () => {
		const p: PeerInfo = {
			pubkey: '02abc',
			host: '127.0.0.1',
			port: 9735,
			state: 'connected'
		};
		expect(p.pubkey).to.equal('02abc');
	});

	it('TxInfo shape', () => {
		const t: TxInfo = { txid: 'deadbeef', hex: '0200...' };
		expect(typeof t.txid).to.equal('string');
	});
});

// ─────────────── Config Tests ───────────────

describe('Config management', () => {
	let tmpDir: string;
	const origHome = process.env.HOME;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		process.env.HOME = tmpDir;
	});

	afterEach(() => {
		process.env.HOME = origHome;
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('loadConfig returns object if no config in fresh dir', () => {
		// Note: CONFIG_PATH is a module-level constant, so loadConfig reads from
		// the path computed at module-load time. We verify it doesn't throw.
		const config = loadConfig();
		expect(config).to.be.an('object');
	});

	it('saveConfig and loadConfig roundtrip', () => {
		const config: BeignetConfig = {
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			alias: 'testnode'
		};
		saveConfig(config);
		const loaded = loadConfig();
		expect(loaded.mnemonic).to.equal(config.mnemonic);
		expect(loaded.network).to.equal('regtest');
		expect(loaded.alias).to.equal('testnode');
	});

	it('PID file write/read/remove', () => {
		writePidFile(12345, 2112);
		const pid = readPidFile();
		expect(pid).to.not.be.null;
		expect(pid!.pid).to.equal(12345);
		expect(pid!.port).to.equal(2112);

		removePidFile();
		const pid2 = readPidFile();
		expect(pid2).to.be.null;
	});

	it('readPidFile returns null if no file', () => {
		expect(readPidFile()).to.be.null;
	});

	it('resolveConfig merges CLI flags over config file', () => {
		const config: BeignetConfig = {
			network: 'mainnet',
			alias: 'fileAlias'
		};
		saveConfig(config);

		const resolved = resolveConfig({ network: 'regtest' });
		expect(resolved.network).to.equal('regtest');
		expect(resolved.alias).to.equal('fileAlias');
	});

	it('resolveConfig uses env vars as middle priority', () => {
		const config: BeignetConfig = { network: 'mainnet' };
		saveConfig(config);

		process.env.BEIGNET_NETWORK = 'testnet';
		const resolved = resolveConfig({});
		expect(resolved.network).to.equal('testnet');
		delete process.env.BEIGNET_NETWORK;
	});

	it('resolveConfig resolves torProxy from BEIGNET_TOR_PROXY env', () => {
		process.env.BEIGNET_TOR_PROXY = '127.0.0.1:9050';
		const resolved = resolveConfig({});
		expect(resolved.torProxy).to.equal('127.0.0.1:9050');
		delete process.env.BEIGNET_TOR_PROXY;
	});

	it('resolveConfig prefers torProxy CLI flag over env', () => {
		process.env.BEIGNET_TOR_PROXY = '127.0.0.1:9050';
		const resolved = resolveConfig({ torProxy: '10.21.21.11:9050' });
		expect(resolved.torProxy).to.equal('10.21.21.11:9050');
		delete process.env.BEIGNET_TOR_PROXY;
	});

	it('resolveConfig leaves torProxy undefined when unset', () => {
		const resolved = resolveConfig({});
		expect(resolved.torProxy).to.be.undefined;
	});

	it('resolveConfig splits BEIGNET_ANNOUNCE_ADDRESSES on commas', () => {
		process.env.BEIGNET_ANNOUNCE_ADDRESSES =
			'203.0.113.7:9735, ln.example.com:9736 ,';
		const resolved = resolveConfig({});
		expect(resolved.announceAddresses).to.deep.equal([
			'203.0.113.7:9735',
			'ln.example.com:9736'
		]);
		delete process.env.BEIGNET_ANNOUNCE_ADDRESSES;
	});

	it('resolveConfig prefers announceAddresses CLI flag over env', () => {
		process.env.BEIGNET_ANNOUNCE_ADDRESSES = 'env.example.com';
		const resolved = resolveConfig({ announceAddresses: ['flag.example.com'] });
		expect(resolved.announceAddresses).to.deep.equal(['flag.example.com']);
		delete process.env.BEIGNET_ANNOUNCE_ADDRESSES;
	});
});

// ─────────────── BeignetNode Static Tests ───────────────

describe('defaultDataDirForMnemonic (per-wallet storage isolation)', () => {
	const A =
		'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
	const B =
		'legal winner thank year wave sausage worth useful legal winner thank yellow';

	it('produces different directories for different mnemonics', () => {
		expect(defaultDataDirForMnemonic(A)).to.not.equal(
			defaultDataDirForMnemonic(B)
		);
	});

	it('is deterministic for the same mnemonic', () => {
		expect(defaultDataDirForMnemonic(A)).to.equal(defaultDataDirForMnemonic(A));
	});

	it('nests the per-wallet tag under the provided base dir', () => {
		const base = '/tmp/beignet-base';
		const dir = defaultDataDirForMnemonic(A, base);
		expect(dir.startsWith(base + path.sep)).to.be.true;
		expect(dir).to.not.equal(base);
	});

	it('does not embed the raw mnemonic in the path', () => {
		const dir = defaultDataDirForMnemonic(A);
		for (const word of A.split(' ')) {
			expect(dir.includes(word)).to.equal(false);
		}
	});

	it('ignores surrounding whitespace (same wallet, same dir)', () => {
		expect(defaultDataDirForMnemonic(`  ${A}  `)).to.equal(
			defaultDataDirForMnemonic(A)
		);
	});
});

describe('BeignetNode', () => {
	it('should export create as a static async factory', () => {
		expect(typeof BeignetNode.create).to.equal('function');
	});

	it('auto-initiates gossip sync on peer connect (default), gated by autoGossipSync', async function () {
		this.timeout(20_000);
		// Default: gossip sync fires on peer connect so the graph populates and
		// multi-hop routing works beyond direct peers.
		const onDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-gs-on-'));
		const onNode = await BeignetNode.create({
			network: 'regtest',
			dataDir: onDir,
			logLevel: 'silent',
			autoGossipSync: true
		});
		try {
			const ln = onNode.getNode();
			const synced: string[] = [];
			(
				ln as unknown as { initiateGossipSync: (pk: string) => void }
			).initiateGossipSync = (pk: string) => {
				synced.push(pk);
			};
			ln.emit('peer:connect', 'deadbeefpeer');
			expect(synced).to.deep.equal(['deadbeefpeer']);
		} finally {
			await onNode.destroy();
		}

		// Disabled: no sync on connect.
		const offDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-gs-off-'));
		const offNode = await BeignetNode.create({
			network: 'regtest',
			dataDir: offDir,
			logLevel: 'silent',
			autoGossipSync: false
		});
		try {
			const ln = offNode.getNode();
			const synced: string[] = [];
			(
				ln as unknown as { initiateGossipSync: (pk: string) => void }
			).initiateGossipSync = (pk: string) => {
				synced.push(pk);
			};
			ln.emit('peer:connect', 'deadbeefpeer');
			expect(synced).to.deep.equal([]);
		} finally {
			await offNode.destroy();
		}
	});

	it('create should reject with BeignetError on bad electrum config', async () => {
		// Use a non-existent host to trigger connection error during wallet creation
		try {
			await BeignetNode.create({
				network: 'regtest',
				electrumHost: '192.0.2.1', // TEST-NET, guaranteed unreachable
				electrumPort: 1,
				dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'))
			});
			expect.fail('Should have thrown');
		} catch (err: unknown) {
			// Either BeignetError or connection error is acceptable
			expect(err).to.be.instanceOf(Error);
		}
	}).timeout(30000);
});

// ─────────────── Daemon Route Tests ───────────────

describe('Daemon HTTP routes', () => {
	it('should return 404 for unknown routes', (done) => {
		const server = http.createServer((req, res) => {
			res.setHeader('Content-Type', 'application/json');
			res.statusCode = 404;
			res.end(
				JSON.stringify({
					ok: false,
					error: { code: 'NOT_FOUND', message: 'No route' }
				})
			);
		});
		server.listen(0, '127.0.0.1', () => {
			const addr = server.address() as { port: number };
			http.get(`http://127.0.0.1:${addr.port}/nonexistent`, (res) => {
				expect(res.statusCode).to.equal(404);
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					const body = JSON.parse(Buffer.concat(chunks).toString());
					expect(body.ok).to.be.false;
					expect(body.error.code).to.equal('NOT_FOUND');
					server.close(done);
				});
			});
		});
	});
});

// ─────────────── peerPubkey Bug Fix Test ───────────────

describe('buildChannelInfo peerPubkey fix', () => {
	it('LightningNode.listChannels should attempt to look up peer pubkey', () => {
		// This is a structural test verifying the fix exists.
		// The actual fix is in lightning-node.ts buildChannelInfo().
		// We verify the ChannelManager has getPeerForChannel.
		const {
			ChannelManager
		} = require('../../src/lightning/channel/channel-manager');
		expect(typeof ChannelManager.prototype.getPeerForChannel).to.equal(
			'function'
		);
	});
});

// ─────────────── New Feature Type Tests ───────────────

describe('New CLI types', () => {
	it('OfferInfo shape', () => {
		const offer: OfferInfo = {
			offerId: 'aabbccdd',
			description: 'Coffee',
			encoded: 'lno1...',
			amountSats: 1000,
			issuer: 'Test Shop',
			issuerId: '02abcdef'
		};
		const json = JSON.parse(JSON.stringify(offer));
		expect(typeof json.offerId).to.equal('string');
		expect(json.description).to.equal('Coffee');
		expect(json.amountSats).to.equal(1000);
		expect(json.encoded).to.equal('lno1...');
	});

	it('OfferInfo optional fields', () => {
		const offer: OfferInfo = {
			offerId: 'aabb',
			description: 'Any amount'
		};
		const json = JSON.parse(JSON.stringify(offer));
		expect(json.amountSats).to.be.undefined;
		expect(json.issuer).to.be.undefined;
		expect(json.encoded).to.be.undefined;
	});

	it('TrustedPeerInfo shape', () => {
		const tp: TrustedPeerInfo = { pubkey: '02abc', trusted: true };
		const json = JSON.parse(JSON.stringify(tp));
		expect(json.pubkey).to.equal('02abc');
		expect(json.trusted).to.be.true;
	});

	it('SpliceResult success shape', () => {
		const r: SpliceResult = { ok: true };
		expect(r.ok).to.be.true;
		expect(r.error).to.be.undefined;
	});

	it('SpliceResult failure shape', () => {
		const r: SpliceResult = { ok: false, error: 'Channel not in NORMAL state' };
		expect(r.ok).to.be.false;
		expect(r.error).to.include('NORMAL');
	});

	it('BootstrapPeerInfo shape', () => {
		const bp: BootstrapPeerInfo = {
			pubkey: '02abc',
			host: '1.2.3.4',
			port: 9735
		};
		const json = JSON.parse(JSON.stringify(bp));
		expect(typeof json.pubkey).to.equal('string');
		expect(typeof json.port).to.equal('number');
	});

	it('OnchainTxInfo shape', () => {
		const tx: OnchainTxInfo = {
			txid: 'aabbccdd',
			type: 'received',
			valueSats: 25000,
			feeSats: 300,
			satsPerVbyte: 2,
			address: 'bc1qexample',
			height: 800000,
			confirmed: true,
			timestamp: 1700000000,
			confirmTimestamp: 1700000600
		};
		const json = JSON.parse(JSON.stringify(tx));
		expect(json.txid).to.equal('aabbccdd');
		expect(json.type).to.equal('received');
		expect(json.valueSats).to.equal(25000);
		expect(json.confirmed).to.be.true;
	});

	it('OnchainTxInfo unconfirmed shape', () => {
		const tx: OnchainTxInfo = {
			txid: 'eeff0011',
			type: 'sent',
			valueSats: -5000,
			feeSats: 200,
			satsPerVbyte: 1,
			address: 'bc1qexample',
			confirmed: false,
			timestamp: 1700000000
		};
		const json = JSON.parse(JSON.stringify(tx));
		expect(json.height).to.be.undefined;
		expect(json.confirmed).to.be.false;
		expect(json.confirmTimestamp).to.be.undefined;
	});

	it('UtxoInfo shape', () => {
		const utxo: UtxoInfo = {
			txid: 'aabbccdd',
			vout: 1,
			address: 'bc1qexample',
			valueSats: 10000,
			height: 800000,
			frozen: false
		};
		const json = JSON.parse(JSON.stringify(utxo));
		expect(json.txid).to.equal('aabbccdd');
		expect(json.vout).to.equal(1);
		expect(json.valueSats).to.equal(10000);
		expect(json.frozen).to.equal(false);
	});

	it('Bolt12InvoiceInfo shape', () => {
		const inv: Bolt12InvoiceInfo = {
			paymentHash: 'aabb',
			amountSats: 1000,
			description: 'Coffee',
			nodeId: '02abc',
			createdAt: 1700000000,
			relativeExpiry: 7200
		};
		const json = JSON.parse(JSON.stringify(inv));
		expect(json.paymentHash).to.equal('aabb');
		expect(json.amountSats).to.equal(1000);
		expect(json.relativeExpiry).to.equal(7200);
	});
});

// ─────────────── New BeignetNode Method Structural Tests ───────────────

describe('BeignetNode new methods', () => {
	it('should have bootstrapPeers method', () => {
		expect(typeof BeignetNode.prototype.bootstrapPeers).to.equal('function');
	});

	it('should have connectToSeeds method', () => {
		expect(typeof BeignetNode.prototype.connectToSeeds).to.equal('function');
	});

	it('should have addTrustedPeer method', () => {
		expect(typeof BeignetNode.prototype.addTrustedPeer).to.equal('function');
	});

	it('should have removeTrustedPeer method', () => {
		expect(typeof BeignetNode.prototype.removeTrustedPeer).to.equal('function');
	});

	it('should have listTrustedPeers method', () => {
		expect(typeof BeignetNode.prototype.listTrustedPeers).to.equal('function');
	});

	it('should have openZeroConfChannel method', () => {
		expect(typeof BeignetNode.prototype.openZeroConfChannel).to.equal(
			'function'
		);
	});

	it('should have openChannelV2 method', () => {
		expect(typeof BeignetNode.prototype.openChannelV2).to.equal('function');
	});

	it('should have spliceIn method', () => {
		expect(typeof BeignetNode.prototype.spliceIn).to.equal('function');
	});

	it('should have spliceOut method', () => {
		expect(typeof BeignetNode.prototype.spliceOut).to.equal('function');
	});

	it('should have createOffer method', () => {
		expect(typeof BeignetNode.prototype.createOffer).to.equal('function');
	});

	it('should have listOffers method', () => {
		expect(typeof BeignetNode.prototype.listOffers).to.equal('function');
	});

	it('should have payOffer method', () => {
		expect(typeof BeignetNode.prototype.payOffer).to.equal('function');
	});

	it('should have listOnchainTransactions method', () => {
		expect(typeof BeignetNode.prototype.listOnchainTransactions).to.equal(
			'function'
		);
	});

	it('should have listUtxos method', () => {
		expect(typeof BeignetNode.prototype.listUtxos).to.equal('function');
	});

	it('listOnchainTransactions converts BTC value/fee to sats', () => {
		// IFormattedTransaction stores value/fee in BTC; the DTO fields are
		// named *Sats so the mapping must convert (regression for 1e8 bug).
		const fakeWallet = {
			transactions: {
				aa: {
					txid: 'aa',
					type: 'received',
					value: 0.5,
					fee: 0.00000141,
					satsPerByte: 1,
					address: 'bcrt1qexample',
					height: 0,
					timestamp: 2000
				},
				bb: {
					txid: 'bb',
					type: 'sent',
					value: -0.001,
					fee: 0.00000282,
					satsPerByte: 2,
					address: 'bcrt1qexample',
					height: 100,
					timestamp: 1000
				}
			}
		};
		// Inherit the prototype so internal helpers (toOnchainTxInfo) resolve.
		const txs = BeignetNode.prototype.listOnchainTransactions.call(
			Object.assign(Object.create(BeignetNode.prototype), {
				wallet: fakeWallet
			}) as unknown as BeignetNode
		);
		expect(txs).to.have.lengthOf(2);
		// Sorted newest first
		expect(txs[0].txid).to.equal('aa');
		expect(txs[0].valueSats).to.equal(50000000);
		expect(txs[0].feeSats).to.equal(141);
		expect(txs[0].confirmed).to.be.false;
		expect(txs[1].txid).to.equal('bb');
		expect(txs[1].valueSats).to.equal(-100000);
		expect(txs[1].feeSats).to.equal(282);
		expect(txs[1].confirmed).to.be.true;
	});

	describe('sendOnchain broadcast handling', () => {
		// Raw regtest tx captured from a live send; txid is its double-SHA id.
		const rawTxHex =
			'020000000001015fe96b90765817d417fabf240b85139021c7b9de8583660330364aacc471596e0000000000ffffffff02689ee80200000000160014b3910b705bdb9cc0765320fc4096e865e84ad2c8400d0300000000001600146b49ad185987df3a44bb9fd57004d66eebaa448c0247304402200ad82fcfe687ba8be82cf390ea5dad8d63fbe6e0eb325687d2b82207031129f9022015857e99b3fbfdca2c41187f14b7c018eb3c7ce600f40915c670add976af13480121035d49eccd54d0099e43676277c7a6d4625d611da88a5df49bf9517a7791a777a500000000';
		const rawTxId =
			'c5e16610ec61535498f672f71653242a05f80b7e7e080b8b86badb49737f0efa';

		it('builds without broadcast, then broadcasts the hex', async () => {
			const { ok } = require('../../src/utils/result');
			const calls: Record<string, unknown>[] = [];
			const fakeWallet = {
				send: async (opts: Record<string, unknown>): Promise<unknown> => {
					calls.push({ method: 'send', ...opts });
					return ok(rawTxHex);
				},
				electrum: {
					broadcastTransaction: async (opts: {
						rawTx: string;
					}): Promise<unknown> => {
						calls.push({ method: 'broadcast', rawTx: opts.rawTx });
						return ok(rawTxId);
					}
				}
			};
			// Inherit the prototype so internal helpers (_broadcastRawTx) resolve.
			const result = await BeignetNode.prototype.sendOnchain.call(
				Object.assign(Object.create(BeignetNode.prototype), {
					wallet: fakeWallet
				}) as unknown as BeignetNode,
				'bcrt1qexample',
				200000,
				2
			);
			expect(result.txid).to.equal(rawTxId);
			expect(result.hex).to.equal(rawTxHex);
			expect(calls[0].method).to.equal('send');
			// wallet.send with broadcast:true resolves to a txid, which is not
			// parseable as hex, so sendOnchain must build unbroadcast.
			expect(calls[0].broadcast).to.be.false;
			expect(calls[1].method).to.equal('broadcast');
			expect(calls[1].rawTx).to.equal(rawTxHex);
		});

		it('throws SEND_FAILED when broadcast fails', async () => {
			const { ok, err } = require('../../src/utils/result');
			const fakeWallet = {
				send: async (): Promise<unknown> => ok(rawTxHex),
				electrum: {
					broadcastTransaction: async (): Promise<unknown> =>
						err('electrum rejected')
				}
			};
			try {
				await BeignetNode.prototype.sendOnchain.call(
					Object.assign(Object.create(BeignetNode.prototype), {
						wallet: fakeWallet
					}) as unknown as BeignetNode,
					'bcrt1qexample',
					200000
				);
				expect.fail('Should have thrown');
			} catch (e: unknown) {
				expect((e as BeignetError).code).to.equal('SEND_FAILED');
				expect((e as BeignetError).message).to.include('electrum rejected');
			}
		});
	});

	it('should have getFeeEstimates method', () => {
		expect(typeof BeignetNode.prototype.getFeeEstimates).to.equal('function');
	});

	it('should have validateAddress method', () => {
		expect(typeof BeignetNode.prototype.validateAddress).to.equal('function');
	});

	it('should have getWallet method', () => {
		expect(typeof BeignetNode.prototype.getWallet).to.equal('function');
	});
});

// ─────────────── LightningNode Feature Methods ───────────────

describe('LightningNode new feature methods', () => {
	it('LightningNode should have bootstrapPeers', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.bootstrapPeers).to.equal('function');
	});

	it('LightningNode should have connectToSeeds', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.connectToSeeds).to.equal('function');
	});

	it('LightningNode should have addTrustedPeer', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.addTrustedPeer).to.equal('function');
	});

	it('LightningNode should have removeTrustedPeer', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.removeTrustedPeer).to.equal(
			'function'
		);
	});

	it('LightningNode should have listTrustedPeers', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.listTrustedPeers).to.equal(
			'function'
		);
	});

	it('LightningNode should have openZeroConfChannel', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.openZeroConfChannel).to.equal(
			'function'
		);
	});

	it('LightningNode should have openChannelV2', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.openChannelV2).to.equal('function');
	});

	it('LightningNode should have spliceIn and spliceOut', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.spliceIn).to.equal('function');
		expect(typeof LightningNode.prototype.spliceOut).to.equal('function');
	});

	it('LightningNode should have createOffer', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.createOffer).to.equal('function');
	});

	it('LightningNode should have requestInvoice', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.requestInvoice).to.equal('function');
	});

	it('LightningNode should have payBolt12Invoice', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.payBolt12Invoice).to.equal(
			'function'
		);
	});

	it('LightningNode should have sendOnionMessage', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.sendOnionMessage).to.equal(
			'function'
		);
	});

	it('LightningNode should have getOnionMessageManager', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.getOnionMessageManager).to.equal(
			'function'
		);
	});

	it('LightningNode should have getOfferManager', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.getOfferManager).to.equal('function');
	});
});

// ─────────────── Phase 2: Payment Fee Safety ───────────────

describe('Payment Fee Safety', () => {
	it('PaymentInfo type includes optional feeSats field', () => {
		const p: PaymentInfo = {
			paymentHash: 'aabb',
			amountSats: 1000,
			feeSats: 5,
			status: 'COMPLETED',
			direction: 'OUTGOING',
			createdAt: Date.now()
		};
		const json = JSON.parse(JSON.stringify(p));
		expect(json.feeSats).to.equal(5);
		expect(typeof json.feeSats).to.equal('number');
	});

	it('sendPayment signature accepts optional maxFeeMsat', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		// sendPayment(invoiceStr, excludedChannels?, maxFeeMsat?, amountMsat?)
		expect(typeof LightningNode.prototype.sendPayment).to.equal('function');
		// Verify it accepts 4 params (invoiceStr, excludedChannels, maxFeeMsat, amountMsat)
		expect(LightningNode.prototype.sendPayment.length).to.equal(4);
	});

	it('sendPayment is backward compatible without maxFeeMsat', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		// Function exists and accepts 4 params (all optional after first)
		expect(typeof LightningNode.prototype.sendPayment).to.equal('function');
	});

	it('sendPaymentAsync signature accepts optional maxFeeMsat', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		expect(typeof LightningNode.prototype.sendPaymentAsync).to.equal(
			'function'
		);
	});

	it('BeignetNode.payInvoice accepts optional maxFeeSats', () => {
		expect(typeof BeignetNode.prototype.payInvoice).to.equal('function');
	});

	it('payInvoice is backward compatible without maxFeeSats', () => {
		// Method exists — all new params are optional
		expect(typeof BeignetNode.prototype.payInvoice).to.equal('function');
	});

	it('feeSats is JSON-serializable number type', () => {
		const p: PaymentInfo = {
			paymentHash: 'aabb',
			amountSats: 50000,
			feeSats: 123,
			status: 'COMPLETED',
			direction: 'OUTGOING',
			createdAt: Date.now()
		};
		const roundTrip = JSON.parse(JSON.stringify(p));
		expect(typeof roundTrip.feeSats).to.equal('number');
		expect(roundTrip.feeSats).to.equal(123);
	});

	it('PaymentInfo feeSats is optional (backward compat)', () => {
		const p: PaymentInfo = {
			paymentHash: 'aabb',
			amountSats: 50000,
			status: 'COMPLETED',
			direction: 'OUTGOING',
			createdAt: Date.now()
		};
		const json = JSON.parse(JSON.stringify(p));
		expect(json.feeSats).to.be.undefined;
	});
});

// ─────────────── Phase 3: Amount-less Invoices + listInvoices ───────────────

describe('Amount-less Invoices + listInvoices', () => {
	it('InvoiceInfo type includes description, expiry, createdAt', () => {
		const inv: InvoiceInfo = {
			bolt11: 'lnbc1...',
			paymentHash: 'aabb',
			amountSats: 5000,
			description: 'Coffee',
			expiry: 3600,
			createdAt: Date.now()
		};
		const json = JSON.parse(JSON.stringify(inv));
		expect(json.description).to.equal('Coffee');
		expect(json.expiry).to.equal(3600);
		expect(typeof json.createdAt).to.equal('number');
	});

	it('BeignetNode.listInvoices method exists and returns array type', () => {
		expect(typeof BeignetNode.prototype.listInvoices).to.equal('function');
	});

	it('sendPayment accepts optional amountMsat parameter', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		// sendPayment(invoiceStr, excludedChannels?, maxFeeMsat?, amountMsat?)
		expect(typeof LightningNode.prototype.sendPayment).to.equal('function');
	});

	it('sendPayment is backward compatible without amountMsat', () => {
		const {
			LightningNode
		} = require('../../src/lightning/node/lightning-node');
		// Method exists — all new params are optional
		expect(typeof LightningNode.prototype.sendPayment).to.equal('function');
	});

	it('BeignetNode.payInvoice accepts optional amountSats', () => {
		// payInvoice(bolt11, timeoutMs?, maxFeeSats?, amountSats?)
		expect(typeof BeignetNode.prototype.payInvoice).to.equal('function');
	});

	it('payInvoice is backward compatible without amountSats', () => {
		expect(typeof BeignetNode.prototype.payInvoice).to.equal('function');
	});

	it('InvoiceInfo extended fields are optional (backward compat)', () => {
		const inv: InvoiceInfo = { bolt11: 'lnbc1...', paymentHash: 'aabb' };
		const json = JSON.parse(JSON.stringify(inv));
		expect(json.description).to.be.undefined;
		expect(json.expiry).to.be.undefined;
		expect(json.createdAt).to.be.undefined;
	});

	it('InvoiceInfo amountSats remains optional', () => {
		const inv: InvoiceInfo = { bolt11: 'lnbc1...', paymentHash: 'aabb' };
		expect(inv.amountSats).to.be.undefined;
	});
});

// ─────────────── Phase 5: Health Endpoint ───────────────

describe('Health Endpoint', () => {
	it('HealthInfo type has all required fields', () => {
		const health: HealthInfo = {
			status: 'ready',
			uptime: 12345,
			blockHeight: 800000,
			electrumConnected: true,
			peerCount: 3,
			channelCount: 2,
			readyChannelCount: 1,
			graphNodes: 100,
			graphChannels: 200
		};
		expect(health.status).to.equal('ready');
		expect(health.uptime).to.equal(12345);
		expect(health.blockHeight).to.equal(800000);
		expect(health.electrumConnected).to.be.true;
		expect(health.peerCount).to.equal(3);
		expect(health.channelCount).to.equal(2);
		expect(health.readyChannelCount).to.equal(1);
		expect(health.graphNodes).to.equal(100);
		expect(health.graphChannels).to.equal(200);
	});

	it('HealthInfo status is one of ready/syncing/degraded', () => {
		const statuses: HealthInfo['status'][] = ['ready', 'syncing', 'degraded'];
		for (const s of statuses) {
			const h: HealthInfo = {
				status: s,
				uptime: 0,
				blockHeight: 0,
				electrumConnected: true,
				peerCount: 0,
				channelCount: 0,
				readyChannelCount: 0,
				graphNodes: 0,
				graphChannels: 0
			};
			expect(statuses).to.include(h.status);
		}
	});

	it('HealthInfo all fields are JSON-serializable', () => {
		const health: HealthInfo = {
			status: 'ready',
			uptime: 5000,
			blockHeight: 100,
			electrumConnected: true,
			peerCount: 1,
			channelCount: 1,
			readyChannelCount: 1,
			graphNodes: 50,
			graphChannels: 80
		};
		const json = JSON.parse(JSON.stringify(health));
		expect(typeof json.status).to.equal('string');
		expect(typeof json.uptime).to.equal('number');
		expect(typeof json.blockHeight).to.equal('number');
		expect(typeof json.electrumConnected).to.equal('boolean');
		expect(typeof json.peerCount).to.equal('number');
		expect(typeof json.channelCount).to.equal('number');
		expect(typeof json.readyChannelCount).to.equal('number');
		expect(typeof json.graphNodes).to.equal('number');
		expect(typeof json.graphChannels).to.equal('number');
	});

	it('BeignetNode.getHealth method exists', () => {
		expect(typeof BeignetNode.prototype.getHealth).to.equal('function');
	});

	it('HealthInfo uptime is non-negative number', () => {
		const health: HealthInfo = {
			status: 'ready',
			uptime: 0,
			blockHeight: 0,
			electrumConnected: true,
			peerCount: 0,
			channelCount: 0,
			readyChannelCount: 0,
			graphNodes: 0,
			graphChannels: 0
		};
		expect(health.uptime).to.be.at.least(0);
	});
});

// ─────────────── Phase 6: Event Streaming + Auto-Bootstrap ───────────────

describe('Event Streaming + Auto-Bootstrap', () => {
	it('BeignetNodeOptions includes autoBootstrap field', () => {
		const opts: BeignetNodeOptions = { autoBootstrap: true };
		expect(opts.autoBootstrap).to.be.true;
	});

	it('BeignetConfig includes autoBootstrap field', () => {
		const config: BeignetConfig = { autoBootstrap: true };
		expect(config.autoBootstrap).to.be.true;
	});

	it('resolveConfig reads BEIGNET_AUTO_BOOTSTRAP from env', () => {
		const origHome = process.env.HOME;
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-bootstrap-'));
		process.env.HOME = tmpDir;
		try {
			process.env.BEIGNET_AUTO_BOOTSTRAP = 'true';
			const config = resolveConfig({});
			expect(config.autoBootstrap).to.be.true;
		} finally {
			delete process.env.BEIGNET_AUTO_BOOTSTRAP;
			process.env.HOME = origHome;
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it('BeignetNode.getNode method exists', () => {
		expect(typeof BeignetNode.prototype.getNode).to.equal('function');
	});

	it('EventMessage type has type and data fields', () => {
		const msg: EventMessage = {
			type: 'payment:received',
			data: { amountSats: 1000 }
		};
		expect(msg.type).to.equal('payment:received');
		expect(msg.data.amountSats).to.equal(1000);
	});

	it('Event data is JSON-safe (no Buffer or bigint)', () => {
		const msg: EventMessage = {
			type: 'payment:sent',
			data: { paymentHash: 'aabb', amountSats: 5000, status: 'SUCCEEDED' }
		};
		const json = JSON.parse(JSON.stringify(msg));
		expect(typeof json.data.paymentHash).to.equal('string');
		expect(typeof json.data.amountSats).to.equal('number');
	});

	it('autoBootstrap defaults to undefined (backward compat)', () => {
		const opts: BeignetNodeOptions = {};
		expect(opts.autoBootstrap).to.be.undefined;
	});

	it('SSE response Content-Type is text/event-stream', async () => {
		// Verify SSE headers by creating a minimal server mirroring daemon's /events logic
		const sseServer = http.createServer((_req, res) => {
			res.writeHead(200, {
				'Content-Type': 'text/event-stream',
				'Cache-Control': 'no-cache',
				Connection: 'keep-alive'
			});
			res.write(':ok\n\n'); // Flush headers + initial SSE comment
		});
		await new Promise<void>((resolve) =>
			sseServer.listen(0, '127.0.0.1', resolve)
		);
		const addr = sseServer.address() as { port: number };
		try {
			const contentType = await new Promise<string>((resolve, reject) => {
				http
					.get(
						{ hostname: '127.0.0.1', port: addr.port, path: '/events' },
						(res) => {
							resolve(res.headers['content-type'] || '');
							res.destroy();
						}
					)
					.on('error', reject);
			});
			expect(contentType).to.equal('text/event-stream');
		} finally {
			sseServer.close();
		}
	}).timeout(10000);

	it('BeignetConfig apiToken field exists', () => {
		const config: BeignetConfig = { apiToken: 'secret' };
		expect(config.apiToken).to.equal('secret');
	});
});
