/**
 * learnedAddressDials (issue #1980): an address somebody other than the
 * operator chose is dialed through the proxy or not at all.
 *
 * Whoever supplies a dial target sees where the dial comes from. A channel
 * peer can announce any address it likes in its node_announcement, and the
 * node dials that address after a disconnect. On a node that keeps its own
 * address private, that would be a way to read it.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import net from 'net';
import path from 'path';
import {
	LearnedAddressRefusedError,
	PeerErrorCode,
	PeerManager
} from '../../src/lightning/transport/peer-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type { LearnedAddressDials } from '../../src/lightning/transport/peer-manager';
import { encodeNodeAnnouncementMessage } from '../../src/lightning/gossip/messages';
import { signNodeAnnouncement } from '../../src/lightning/gossip/validation';
import { ADDRESS_TYPE_IPV4 } from '../../src/lightning/gossip/types';

const settle = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

const randomPubkey = (): string =>
	getPublicKey(crypto.randomBytes(32)).toString('hex');

/** A TCP server that only records whether anything connected to it. */
async function flagServer(): Promise<{
	port: number;
	contacted: () => boolean;
	close: () => Promise<void>;
}> {
	let contacted = false;
	const server = net.createServer((socket) => {
		contacted = true;
		socket.destroy();
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		port: (server.address() as net.AddressInfo).port,
		contacted: () => contacted,
		close: () => new Promise<void>((resolve) => server.close(() => resolve()))
	};
}

/**
 * A SOCKS5 proxy that sends every CONNECT to one local port, whatever host
 * was asked for, and records the hosts it was asked for.
 */
async function socksTo(targetPort: number): Promise<{
	port: number;
	requested: string[];
	close: () => Promise<void>;
}> {
	const requested: string[] = [];
	const sockets = new Set<net.Socket>();
	const server = net.createServer((client) => {
		sockets.add(client);
		client.on('error', () => undefined);
		client.on('close', () => sockets.delete(client));
		client.once('data', () => {
			client.write(Buffer.from([0x05, 0x00]));
			client.once('data', (request) => {
				const type = request[3];
				let host = '';
				if (type === 0x03) {
					host = request.subarray(5, 5 + request[4]).toString();
				} else if (type === 0x01) {
					host = Array.from(request.subarray(4, 8)).join('.');
				}
				requested.push(host);
				const target = net.connect(targetPort, '127.0.0.1');
				sockets.add(target);
				target.on('error', () => client.destroy());
				target.on('close', () => sockets.delete(target));
				target.once('connect', () => {
					const reply = Buffer.alloc(10);
					reply[0] = 0x05;
					reply[3] = 0x01;
					client.write(reply);
					client.pipe(target);
					target.pipe(client);
				});
			});
		});
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		port: (server.address() as net.AddressInfo).port,
		requested,
		close: (): Promise<void> => {
			for (const socket of sockets) socket.destroy();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		}
	};
}

async function refusal(dial: Promise<void>): Promise<unknown> {
	try {
		await dial;
	} catch (err) {
		return err;
	}
	return undefined;
}

describe('learnedAddressDials', function () {
	this.timeout(10_000);

	describe("'any' (the default)", function () {
		it('dials a learned public address like any other', async function () {
			const proxy = await flagServer();
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				socks5Proxy: { host: '127.0.0.1', port: proxy.port },
				socks5ProxyScope: 'onion',
				socks5TimeoutMs: 500
			});
			expect(pm.canDialLearnedAddress('203.0.113.1')).to.equal(true);
			// TEST-NET-3 is never routed: the direct dial fails or sits in SYN.
			const dial = pm
				.connectPeer(randomPubkey(), '203.0.113.1', 9735, undefined, {
					timeoutMs: 200,
					reconnect: false,
					learned: true
				})
				.catch((err) => err);
			await settle(300);
			expect(proxy.contacted()).to.equal(false);
			pm.destroy();
			const err = await Promise.race([dial, settle(1000)]);
			expect(err).to.not.be.instanceOf(LearnedAddressRefusedError);
			await proxy.close();
		});
	});

	describe("'proxy-only'", function () {
		it('sends a learned public address through the proxy under scope onion', async function () {
			const proxy = await flagServer();
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				socks5Proxy: { host: '127.0.0.1', port: proxy.port },
				socks5ProxyScope: 'onion',
				socks5TimeoutMs: 500,
				learnedAddressDials: 'proxy-only'
			});
			expect(pm.canDialLearnedAddress('203.0.113.1')).to.equal(true);
			const err = await refusal(
				pm.connectPeer(randomPubkey(), '203.0.113.1', 9735, undefined, {
					timeoutMs: 500,
					reconnect: false,
					learned: true
				})
			);
			// The flag server speaks no SOCKS, so the dial fails; the point is
			// that it was aimed at the proxy rather than at the address.
			expect(proxy.contacted()).to.equal(true);
			expect(err).to.not.be.instanceOf(LearnedAddressRefusedError);
			pm.destroy();
			await proxy.close();
		});

		it('leaves an operator address alone under scope onion', async function () {
			const proxy = await flagServer();
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				socks5Proxy: { host: '127.0.0.1', port: proxy.port },
				socks5ProxyScope: 'onion',
				socks5TimeoutMs: 500,
				learnedAddressDials: 'proxy-only'
			});
			const dial = pm
				.connectPeer(randomPubkey(), '203.0.113.1', 9735, undefined, {
					timeoutMs: 200,
					reconnect: false
				})
				.catch((err) => err);
			await settle(300);
			expect(proxy.contacted()).to.equal(false);
			pm.destroy();
			await Promise.race([dial, settle(1000)]);
			await proxy.close();
		});

		it('refuses a learned public address when there is no proxy', async function () {
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				learnedAddressDials: 'proxy-only'
			});
			expect(pm.canDialLearnedAddress('203.0.113.1')).to.equal(false);
			const pubkey = randomPubkey();
			const err = await refusal(
				pm.connectPeer(pubkey, '203.0.113.1', 9735, undefined, {
					reconnect: false,
					learned: true
				})
			);
			expect(err).to.be.instanceOf(LearnedAddressRefusedError);
			expect((err as LearnedAddressRefusedError).code).to.equal(
				PeerErrorCode.LEARNED_ADDRESS_REFUSED
			);
			expect((err as Error).message).to.include('203.0.113.1:9735');
			expect(pm.getPeerAddress(pubkey)).to.equal(undefined);
			pm.destroy();
		});

		it('refuses a learned loopback address even with a proxy, and never connects to it', async function () {
			const proxy = await flagServer();
			const target = await flagServer();
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				socks5Proxy: { host: '127.0.0.1', port: proxy.port },
				learnedAddressDials: 'proxy-only'
			});
			expect(pm.canDialLearnedAddress('127.0.0.1')).to.equal(false);
			expect(pm.canDialLearnedAddress('192.168.1.20')).to.equal(false);
			const err = await refusal(
				pm.connectPeer(randomPubkey(), '127.0.0.1', target.port, undefined, {
					reconnect: false,
					learned: true
				})
			);
			expect(err).to.be.instanceOf(LearnedAddressRefusedError);
			await settle(50);
			expect(target.contacted()).to.equal(false);
			expect(proxy.contacted()).to.equal(false);
			pm.destroy();
			await proxy.close();
			await target.close();
		});

		it('refuses a learned WebSocket address, which the proxy does not carry', async function () {
			const proxy = await flagServer();
			const target = await flagServer();
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				socks5Proxy: { host: '127.0.0.1', port: proxy.port },
				learnedAddressDials: 'proxy-only'
			});
			const url = `ws://127.0.0.1:${target.port}`;
			const err = await refusal(
				pm.connectPeer(
					randomPubkey(),
					'127.0.0.1',
					target.port,
					{ type: 'ws', url },
					{ reconnect: false, learned: true }
				)
			);
			expect(err).to.be.instanceOf(LearnedAddressRefusedError);
			expect((err as Error).message).to.include(url);
			await settle(50);
			expect(target.contacted()).to.equal(false);
			pm.destroy();
			await proxy.close();
			await target.close();
		});

		it('does not refuse a learned onion address with no proxy configured', async function () {
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				socks5TimeoutMs: 500,
				learnedAddressDials: 'proxy-only'
			});
			// An onion address only resolves through Tor, so it falls back to
			// Tor's default local port and cannot show the node's address.
			expect(pm.canDialLearnedAddress(`${'a'.repeat(56)}.onion`)).to.equal(
				true
			);
			const err = await refusal(
				pm.connectPeer(
					randomPubkey(),
					`${'a'.repeat(56)}.onion`,
					9735,
					undefined,
					{ timeoutMs: 500, reconnect: false, learned: true }
				)
			);
			expect(err).to.not.be.instanceOf(LearnedAddressRefusedError);
			pm.destroy();
		});

		it('never retries an announced address the proxy cannot carry', async function () {
			const target = await flagServer();
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				autoReconnect: true,
				learnedAddressDials: 'proxy-only'
			});
			const pubkey = randomPubkey();
			pm.setAnnouncedAddresses(pubkey, [
				{ host: '203.0.113.1', port: 9735 },
				{ host: '127.0.0.1', port: target.port }
			]);
			const internal = pm as unknown as {
				scheduleReconnect(pubkey: string): void;
				reconnectTimers: Map<string, unknown>;
			};
			internal.scheduleReconnect(pubkey);
			expect(internal.reconnectTimers.has(pubkey)).to.equal(false);
			await settle(50);
			expect(target.contacted()).to.equal(false);
			// The addresses are still held: the rule is applied when dialing.
			expect(pm.getAnnouncedAddresses(pubkey)).to.have.length(2);
			pm.destroy();
			await target.close();
		});

		it('reconnects to an announced address through the proxy and does not keep it as last-known-good', async function () {
			const remoteKey = crypto.randomBytes(32);
			const remotePubkey = getPublicKey(remoteKey).toString('hex');
			const remote = new PeerManager({ localPrivateKey: remoteKey });
			await remote.listen(0, '127.0.0.1');
			const remotePort = (
				(
					remote as unknown as { server: net.Server }
				).server.address() as net.AddressInfo
			).port;
			const proxy = await socksTo(remotePort);
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				autoReconnect: true,
				socks5Proxy: { host: '127.0.0.1', port: proxy.port },
				socks5ProxyScope: 'onion',
				learnedAddressDials: 'proxy-only'
			});
			pm.setAnnouncedAddresses(remotePubkey, [
				{ host: 'peer.example', port: 9735 }
			]);
			const connected = new Promise<void>((resolve) =>
				pm.once('peer:connect', () => resolve())
			);
			(
				pm as unknown as { scheduleReconnect(pubkey: string): void }
			).scheduleReconnect(remotePubkey);
			await connected;

			expect(proxy.requested).to.deep.equal(['peer.example']);
			expect(pm.listPeers().map((p) => p.pubkey)).to.deep.equal([remotePubkey]);
			// Not recorded: the last-known-good slot is redialed under the
			// configured scope, which here would be a direct dial.
			expect(pm.getPeerAddress(remotePubkey)).to.equal(undefined);

			pm.destroy();
			remote.destroy();
			await proxy.close();
		});

		it('keeps an operator dial as last-known-good, as before', async function () {
			const remoteKey = crypto.randomBytes(32);
			const remotePubkey = getPublicKey(remoteKey).toString('hex');
			const remote = new PeerManager({ localPrivateKey: remoteKey });
			await remote.listen(0, '127.0.0.1');
			const remotePort = (
				(
					remote as unknown as { server: net.Server }
				).server.address() as net.AddressInfo
			).port;
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				learnedAddressDials: 'proxy-only'
			});
			await pm.connectPeer(remotePubkey, '127.0.0.1', remotePort);
			expect(pm.getPeerAddress(remotePubkey)).to.deep.equal({
				host: '127.0.0.1',
				port: remotePort
			});
			// A learned dial to a connected peer is a no-op that must not
			// replace the operator's address either.
			await pm.connectPeer(remotePubkey, '198.51.100.9', 9735, undefined, {
				learned: true
			});
			expect(pm.getPeerAddress(remotePubkey)).to.deep.equal({
				host: '127.0.0.1',
				port: remotePort
			});
			pm.destroy();
			remote.destroy();
		});
	});

	describe('a channel peer that announces an address', function () {
		function makeNode(
			privateKey: Buffer,
			learnedAddressDials?: LearnedAddressDials
		): LightningNode {
			return new LightningNode({
				nodePrivateKey: privateKey,
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: {
					fundingPubkey: crypto.randomBytes(33),
					revocationBasepoint: crypto.randomBytes(33),
					paymentBasepoint: crypto.randomBytes(33),
					delayedPaymentBasepoint: crypto.randomBytes(33),
					htlcBasepoint: crypto.randomBytes(33),
					firstPerCommitmentPoint: crypto.randomBytes(33)
				},
				fundingPrivkey: crypto.randomBytes(32),
				enableNetworking: true,
				learnedAddressDials
			});
		}

		function announcement(privkey: Buffer, port: number): Buffer {
			const payload = encodeNodeAnnouncementMessage({
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp: Math.floor(Date.now() / 1000),
				nodeId: getPublicKey(privkey),
				rgbColor: Buffer.from([0, 0, 0]),
				alias: Buffer.alloc(32),
				addresses: [{ type: ADDRESS_TYPE_IPV4, host: '127.0.0.1', port }]
			});
			signNodeAnnouncement(payload, privkey).copy(payload, 0);
			return payload;
		}

		const listenPort = (node: LightningNode): number =>
			(
				node as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;

		it("is not dialed back under 'proxy-only' without a proxy", async function () {
			this.timeout(20_000);
			const hiddenKey = crypto.randomBytes(32);
			const visitorKey = crypto.randomBytes(32);
			const hiddenPub = getPublicKey(hiddenKey).toString('hex');
			const visitorPub = getPublicKey(visitorKey).toString('hex');
			const hidden = makeNode(hiddenKey, 'proxy-only');
			const visitor = makeNode(visitorKey);
			// Where the visitor says it can be reached: anything that connects
			// here has shown the visitor its source address.
			const trap = await flagServer();
			try {
				await hidden.listen(0);
				const internal = hidden as unknown as {
					handleNodeAnnouncement(payload: Buffer): void;
					peerManager: PeerManager;
				};
				await visitor.connectPeer(hiddenPub, '127.0.0.1', listenPort(hidden));
				const deadline = Date.now() + 5_000;
				while (internal.peerManager.listPeers().length !== 1) {
					if (Date.now() > deadline) throw new Error('never connected');
					await settle(25);
				}

				hidden.getChannelManager().hasChannelWithPeer = (pubkey): boolean =>
					pubkey === visitorPub;
				internal.handleNodeAnnouncement(announcement(visitorKey, trap.port));
				expect(
					internal.peerManager.getAnnouncedAddresses(visitorPub)
				).to.deep.equal([{ host: '127.0.0.1', port: trap.port }]);

				visitor.disconnectPeer(hiddenPub);
				// The first reconnect round fires about a second after the drop.
				await settle(3_000);
				expect(trap.contacted()).to.equal(false);
				expect(internal.peerManager.listPeers()).to.have.length(0);
			} finally {
				hidden.destroy();
				visitor.destroy();
				await trap.close();
			}
		});

		it("is dialed back under 'any', which is what the restriction prevents", async function () {
			this.timeout(20_000);
			const hiddenKey = crypto.randomBytes(32);
			const visitorKey = crypto.randomBytes(32);
			const hiddenPub = getPublicKey(hiddenKey).toString('hex');
			const visitorPub = getPublicKey(visitorKey).toString('hex');
			const open = makeNode(hiddenKey);
			const visitor = makeNode(visitorKey);
			const trap = await flagServer();
			try {
				await open.listen(0);
				const internal = open as unknown as {
					handleNodeAnnouncement(payload: Buffer): void;
					peerManager: PeerManager;
				};
				await visitor.connectPeer(hiddenPub, '127.0.0.1', listenPort(open));
				const deadline = Date.now() + 5_000;
				while (internal.peerManager.listPeers().length !== 1) {
					if (Date.now() > deadline) throw new Error('never connected');
					await settle(25);
				}
				open.getChannelManager().hasChannelWithPeer = (pubkey): boolean =>
					pubkey === visitorPub;
				internal.handleNodeAnnouncement(announcement(visitorKey, trap.port));
				visitor.disconnectPeer(hiddenPub);
				const dialed = Date.now() + 10_000;
				while (!trap.contacted()) {
					if (Date.now() > dialed) throw new Error('never dialed back');
					await settle(25);
				}
			} finally {
				open.destroy();
				visitor.destroy();
				await trap.close();
			}
		});
	});

	/**
	 * Every place that dials a Lightning peer, with the arguments it passes
	 * and who chose the address. A new or changed call site fails this until
	 * it is listed here, which is the moment to decide whether it passes
	 * `learned: true`.
	 *
	 * - operator: the address came from the operator (an API call, config, the
	 *   node's own backup, an address stored from an earlier operator dial).
	 * - learned: somebody else chose it; the call marks it.
	 * - forwards: the call passes its own caller's choice through.
	 * - via hook: dials through the node's connectPeer hook, which marks it.
	 */
	describe('dial sites', function () {
		type Kind = 'operator' | 'learned' | 'forwards' | 'via hook';
		const SITES: Array<[file: string, args: string, kind: Kind]> = [
			[
				'src/cli/beignet-node.ts',
				'pubkey, host, port, transport, this._connectTimeoutMs',
				'operator'
			],
			[
				'src/cli/beignet-node.ts',
				'pubkey, host, port, transport, learned ? { learned: true } : undefined',
				'forwards'
			],
			['src/cli/beignet-node.ts', 'pubkey, host, port', 'operator'],
			[
				'src/cli/beignet-node.ts',
				'suggestion.nodeId, addr.host, addr.port, undefined, this._connectTimeoutMs, true',
				'learned'
			],
			[
				'src/cli/beignet-node.ts',
				'candidate.pubkey, host, port, transport, timeoutMs',
				'operator'
			],
			[
				'src/cli/daemon.ts',
				"pubkey, peerHost, peerPort, { type: 'iroh', fallbackOnion, endpointId, relayUrl }",
				'operator'
			],
			[
				'src/cli/daemon.ts',
				"pubkey, peerHost, peerPort, { type: 'ws', url: peerUrl }",
				'operator'
			],
			[
				'src/cli/daemon.ts',
				"pubkey, peerHost, peerPort, { type: 'ws' }",
				'operator'
			],
			['src/cli/daemon.ts', 'pubkey, peerHost, peerPort', 'operator'],
			// The stand-alone payer SDK has no learnedAddressDials mode.
			[
				'src/direct-funding/peer-messaging.ts',
				'id, host, port, remaining, options',
				'operator'
			],
			[
				'src/direct-funding/transports.ts',
				'id, host, port, timeout, { reconnect: false }',
				'operator'
			],
			[
				'src/lightning/direct-funding/transport/index.ts',
				'hex, host, port, timeoutMs, { reconnect: false }',
				'via hook'
			],
			[
				'src/lightning/direct-funding/transport/types.ts',
				'peerHex, host, port, remainingMs',
				'via hook'
			],
			// Start-up reconnect: stored addresses, and announced ones flagged.
			[
				'src/lightning/node/lightning-node.ts',
				'pubkey, host, port, transport, { learned }',
				'forwards'
			],
			[
				'src/lightning/node/lightning-node.ts',
				'pubkey, announced.host, announced.port, undefined, { learned: true }',
				'learned'
			],
			// Recovery peers, from the node's own backup.
			[
				'src/lightning/node/lightning-node.ts',
				'peerNodeId, parsed.host, parsed.port, parsed.transport',
				'operator'
			],
			// The public connectPeer.
			[
				'src/lightning/node/lightning-node.ts',
				'pubkey, endpointId, 0, { ...transport, endpointId, ...(relayUrl ? { relayUrl } : {}) }, options',
				'forwards'
			],
			[
				'src/lightning/node/lightning-node.ts',
				'pubkey, host, port, transport, options',
				'forwards'
			],
			// A node id resolved through the gossip graph, then DNS seeds.
			[
				'src/lightning/node/lightning-node.ts',
				'pubkey, host, port, undefined, learnedOptions',
				'learned'
			],
			[
				'src/lightning/node/lightning-node.ts',
				'pubkey, peer.host, peer.port, undefined, learnedOptions',
				'learned'
			],
			[
				'src/lightning/node/lightning-node.ts',
				'pubkeyHex, peer.host, peer.port, undefined, { learned: true }',
				'learned'
			],
			// The hooks direct-funding lanes and the swap provider dial through.
			[
				'src/lightning/node/lightning-node.ts',
				'peer, host, port, undefined, { ...options, ...(timeoutMs !== undefined ? { timeoutMs } : {}), learned: true }',
				'learned'
			],
			[
				'src/lightning/node/lightning-node.ts',
				'peerHex, host, port, undefined, { learned: true }',
				'learned'
			]
		];

		const CALL = /\.(connectPeer|connectPeerWithin)\(/g;

		function sourceFiles(dir: string): string[] {
			const out: string[] = [];
			for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
				const full = path.join(dir, entry.name);
				if (entry.isDirectory()) out.push(...sourceFiles(full));
				else if (entry.name.endsWith('.ts')) out.push(full);
			}
			return out.sort();
		}

		/** The text between a call's parentheses, whitespace collapsed. */
		function callArguments(text: string, open: number): string {
			let depth = 1;
			let i = open;
			while (depth > 0 && i < text.length) {
				if (text[i] === '(') depth++;
				else if (text[i] === ')') depth--;
				i++;
			}
			return text
				.slice(open, i - 1)
				.split(/\s+/)
				.filter(Boolean)
				.join(' ')
				.replace(/,$/, '');
		}

		function scan(): Array<[string, string]> {
			const root = path.join(__dirname, '..', '..');
			const found: Array<[string, string]> = [];
			for (const file of sourceFiles(path.join(root, 'src'))) {
				const rel = path.relative(root, file).split(path.sep).join('/');
				// The peer manager's own dial plumbing, and the CLI client (it
				// calls the daemon over HTTP), are not dial sites.
				if (
					rel === 'src/lightning/transport/peer-manager.ts' ||
					rel === 'src/cli/cli.ts'
				)
					continue;
				const text = fs.readFileSync(file, 'utf8');
				for (const match of text.matchAll(CALL)) {
					const at = match.index ?? 0;
					const lineStart = text.lastIndexOf('\n', at) + 1;
					const line = text.slice(lineStart, at).trim();
					if (line.startsWith('//') || line.startsWith('*')) continue;
					found.push([rel, callArguments(text, at + match[0].length)]);
				}
			}
			return found;
		}

		it('are all listed with who chose the address', function () {
			const listed = SITES.map(([file, args]) => `${file} :: ${args}`).sort();
			const found = scan()
				.map(([file, args]) => `${file} :: ${args}`)
				.sort();
			expect(found).to.deep.equal(listed);
		});

		it('mark every learned address', function () {
			for (const [file, args, kind] of SITES) {
				const marked = /learned/.test(args) || /, true$/.test(args);
				expect(marked, `${file} :: ${args}`).to.equal(
					kind === 'learned' || (kind === 'forwards' && /learned/.test(args))
				);
			}
		});
	});
});
