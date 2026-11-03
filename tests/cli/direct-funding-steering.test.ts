/**
 * Direct-funding requests bound to a peer (issue #1922, step 2b). The peer
 * `POST /direct-funding/request` names, or the ranked primary it is steered
 * to, is what the envelope's relay descriptors name and what the request
 * record binds, so the receiver negotiates the funding with it whatever the
 * direct-funding policy says by then. A request that names no peer and has
 * no primaries follows the policy, unbound, as before.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import * as sinon from 'sinon';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import type { PeerInfo } from '../../src/cli/types';
import { decodeRequestEnvelope } from '../../src/lightning/direct-funding/envelope';
import {
	DfTransportType,
	DirectFundingErrorCode
} from '../../src/lightning/direct-funding/types';
import type { IDfOnionTransport } from '../../src/lightning/direct-funding/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	mnemonic: MNEMONIC,
	daemonPort: 0
};

// Real curve points: a blinded path is minted through the bound peer.
const point = (fill: number): string =>
	getPublicKey(Buffer.alloc(32, fill)).toString('hex');
const POLICY_PEER = point(0x11);
const REACHABLE = point(0x22);
const UNREACHABLE = point(0x33);
const INBOUND = point(0x44);

function httpCall(
	port: number,
	method: 'GET' | 'POST',
	route: string,
	body?: unknown
): Promise<{ status: number; json: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				host: '127.0.0.1',
				port,
				path: route,
				method,
				headers: { 'content-type': 'application/json' }
			},
			(res) => {
				let raw = '';
				res.on('data', (c) => (raw += c));
				res.on('end', () =>
					resolve({ status: res.statusCode ?? 0, json: JSON.parse(raw) })
				);
			}
		);
		req.on('error', reject);
		req.end(body === undefined ? undefined : JSON.stringify(body));
	});
}

/** The peer a minted request is bound to, read from the node's request store. */
function boundPeerOf(
	daemon: IStartedDaemon,
	paymentHash: string
): string | undefined {
	const inner = (
		daemon.node as unknown as {
			node: {
				directFunding: {
					requests: {
						byReceiptHash(hash: string): { liquidityPeer?: string } | null;
					};
				};
			};
		}
	).node;
	return inner.directFunding.requests.byReceiptHash(paymentHash)?.liquidityPeer;
}

function relayOf(request: string): IDfOnionTransport | undefined {
	return decodeRequestEnvelope(request).transports.find(
		(t) => t.type === DfTransportType.ONION_MESSAGE
	) as IDfOnionTransport | undefined;
}

describe('direct-funding requests bound to a peer (issue #1922)', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: IStartedDaemon;
	let port: number;
	let peers: PeerInfo[] = [];
	/** What this node dialed each peer at; a peer that dialed us has no entry. */
	let dialed: Record<
		string,
		Pick<PeerInfo, 'host' | 'port' | 'transport'>
	> = {};

	const mint = (
		body: Record<string, unknown>
	): Promise<{ status: number; json: Record<string, unknown> }> =>
		httpCall(port, 'POST', '/direct-funding/request', body);

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-df-steer-'));
		daemon = await startDaemon({ ...OFFLINE, dataDir });
		port = (daemon.server.address() as AddressInfo).port;
		// The mint only needs to know where a peer is; nothing is dialed here.
		// listPeers is what a peer is up on, getPeerAddress what this node
		// dialed it at: a peer that connected to us is in the first only.
		sinon.stub(daemon.node, 'listPeers').callsFake(() => peers);
		sinon
			.stub(daemon.node, 'getPeerAddress')
			.callsFake((pubkey: string) => dialed[pubkey]);
	});

	after(async () => {
		sinon.restore();
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('refuses a named peer that is neither a primary nor the policy peer with 400 INVALID_PARAMS', async () => {
		// The route runs at invoice scope, and the peer a direct-funded channel
		// opens with holds every payment it receives: which peers can be named
		// stays with the admin routes that configure the primaries and the
		// policy. Being up, dialed and well formed is not enough.
		peers = [
			{ pubkey: REACHABLE, host: '10.0.0.8', port: 9737, state: 'ready' }
		];
		dialed = { [REACHABLE]: { host: '10.0.0.8', port: 9737 } };
		const { status, json } = await mint({ lspPubkey: REACHABLE });
		expect(status).to.equal(400);
		const error = json.error as { code: string; message: string };
		expect(error.code).to.equal('INVALID_PARAMS');
		expect(error.message).to.contain('neither a configured primary');
	});

	it('follows the policy, unbound, when nothing names a peer and no primaries are configured', async () => {
		daemon.node.configureDirectFunding({
			lspPubkey: POLICY_PEER,
			lspHost: '10.0.0.7',
			lspPort: 9736
		});
		const { status, json } = await mint({});
		expect(status).to.equal(200);
		const result = json.result as Record<string, unknown>;
		expect(result.lspPubkey).to.equal(POLICY_PEER);
		const relay = relayOf(result.request as string);
		expect(relay?.introNodeId.toString('hex')).to.equal(POLICY_PEER);
		expect(relay).to.include({ host: '10.0.0.7', port: 9736 });
		// Unbound: it is negotiated with whatever the policy names at admission.
		expect(boundPeerOf(daemon, result.paymentHash as string)).to.equal(
			undefined
		);
	});

	it('takes the policy address for the policy peer when it is named outright', async () => {
		const { json } = await mint({ lspPubkey: POLICY_PEER });
		const result = json.result as Record<string, unknown>;
		expect(relayOf(result.request as string)).to.include({
			host: '10.0.0.7',
			port: 9736
		});
		expect(boundPeerOf(daemon, result.paymentHash as string)).to.equal(
			POLICY_PEER
		);
	});

	it('binds the request to a primary named outright, at the address this node dialed it at', async () => {
		daemon.node.addPrimary({ pubkey: REACHABLE });
		const { status, json } = await mint({
			amountSats: 50_000,
			lspPubkey: REACHABLE.toUpperCase()
		});
		expect(status).to.equal(200);
		const result = json.result as Record<string, unknown>;
		expect(result.lspPubkey).to.equal(REACHABLE);
		expect(result).to.not.have.property('skipped');
		const relay = relayOf(result.request as string);
		expect(relay?.introNodeId.toString('hex')).to.equal(REACHABLE);
		expect(relay).to.include({ host: '10.0.0.8', port: 9737 });
		expect(boundPeerOf(daemon, result.paymentHash as string)).to.equal(
			REACHABLE
		);
		// The policy was not touched: the request carries its own peer.
		expect(daemon.node.getDirectFundingConfig().lspPubkey).to.equal(
			POLICY_PEER
		);
	});

	it('binds to a primary with no known address, emitting no relay descriptor', async () => {
		daemon.node.addPrimary({ pubkey: UNREACHABLE });
		peers = [];
		dialed = {};
		const { status, json } = await mint({ lspPubkey: UNREACHABLE });
		expect(status).to.equal(200);
		const result = json.result as Record<string, unknown>;
		expect(result.lspPubkey).to.equal(UNREACHABLE);
		expect(
			decodeRequestEnvelope(result.request as string).transports
		).to.have.length(0);
		expect(boundPeerOf(daemon, result.paymentHash as string)).to.equal(
			UNREACHABLE
		);
	});

	it('steers through the primaries ahead of the policy, passing over one with no known address', async () => {
		// Rank order is selection order here: UNREACHABLE first, then REACHABLE
		// re-added with a relay address stored beside it.
		daemon.node.removePrimary(REACHABLE);
		daemon.node.addPrimary({
			pubkey: REACHABLE,
			host: 'relay.example',
			port: 9999
		});
		peers = [
			{ pubkey: REACHABLE, host: '10.0.0.8', port: 9737, state: 'ready' }
		];
		dialed = { [REACHABLE]: { host: '10.0.0.8', port: 9737 } };
		const { status, json } = await mint({ amountSats: 50_000 });
		expect(status).to.equal(200);
		const result = json.result as Record<string, unknown>;
		expect(result.lspPubkey).to.equal(REACHABLE);
		expect(
			(result.skipped as Record<string, unknown>[]).map((s) => [
				s.pubkey,
				s.rank,
				s.stage,
				s.code
			])
		).to.deep.equal([[UNREACHABLE, 1, 'attempt', 'RECEIVE_UNAVAILABLE']]);
		// The address stored with the primary wins over the dialed one.
		const relay = relayOf(result.request as string);
		expect(relay?.introNodeId.toString('hex')).to.equal(REACHABLE);
		expect(relay).to.include({ host: 'relay.example', port: 9999 });
		expect(boundPeerOf(daemon, result.paymentHash as string)).to.equal(
			REACHABLE
		);
		expect(daemon.node.getDirectFundingConfig().lspPubkey).to.equal(
			POLICY_PEER
		);
	});

	it("passes over a primary that dialed us, whose listed port is its socket's source port", async () => {
		// INBOUND connected to this node and was never dialed, so the port
		// listPeers shows for it is its connection's ephemeral source port, where
		// no payer could reach a relay. REACHABLE stores no address this time and
		// is bound at the address this node dialed it at.
		daemon.node.removePrimary(REACHABLE);
		daemon.node.addPrimary({ pubkey: INBOUND });
		daemon.node.addPrimary({ pubkey: REACHABLE });
		peers = [
			{ pubkey: INBOUND, host: '10.0.0.5', port: 54123, state: 'ready' },
			{ pubkey: REACHABLE, host: '10.0.0.8', port: 9737, state: 'ready' }
		];
		dialed = { [REACHABLE]: { host: '10.0.0.8', port: 9737 } };
		const { status, json } = await mint({ amountSats: 50_000 });
		expect(status).to.equal(200);
		const result = json.result as Record<string, unknown>;
		expect(result.lspPubkey).to.equal(REACHABLE);
		expect(
			(result.skipped as Record<string, unknown>[]).map((s) => [
				s.pubkey,
				s.code
			])
		).to.deep.equal([
			[UNREACHABLE, 'RECEIVE_UNAVAILABLE'],
			[INBOUND, 'RECEIVE_UNAVAILABLE']
		]);
		const relay = relayOf(result.request as string);
		expect(relay?.introNodeId.toString('hex')).to.equal(REACHABLE);
		expect(relay).to.include({ host: '10.0.0.8', port: 9737 });
		expect(boundPeerOf(daemon, result.paymentHash as string)).to.equal(
			REACHABLE
		);
	});

	it('answers 503 NO_PRIMARY_AVAILABLE when no primary has an address', async () => {
		daemon.node.removePrimary(REACHABLE);
		peers = [];
		dialed = {};
		const { status, json } = await mint({});
		expect(status).to.equal(503);
		const error = json.error as { code: string; message: string };
		expect(error.code).to.equal('NO_PRIMARY_AVAILABLE');
		expect(error.message).to.contain(UNREACHABLE.slice(0, 16));
		expect(error.message).to.contain('no address is known');
	});

	it('refuses a malformed lspPubkey with 400 INVALID_PARAMS', async () => {
		const { status, json } = await mint({ lspPubkey: 'zz' });
		expect(status).to.equal(400);
		expect((json.error as { code: string }).code).to.equal('INVALID_PARAMS');
	});

	it('refuses an lspPubkey that is not a string with 400 INVALID_PARAMS', async () => {
		// An array holding one key reads as that key under a bare regex test and
		// used to reach the mint, where its first string method threw a 500.
		const { status, json } = await mint({ lspPubkey: [REACHABLE] });
		expect(status).to.equal(400);
		expect((json.error as { code: string }).code).to.equal('INVALID_PARAMS');
	});

	it('refuses a malformed bound peer in the library mint, typed, before any relay is resolved', () => {
		// With a policy peer configured, the relay used to be resolved before
		// the store saw the peer, and a non-string one threw a bare TypeError
		// from a string method. The store's MALFORMED is what a library caller
		// gets now.
		let caught: unknown;
		try {
			daemon.node.getNode().mintDirectFundingRequest({
				liquidityPeer: [REACHABLE] as unknown as string
			});
		} catch (err) {
			caught = err;
		}
		expect((caught as { code?: string } | undefined)?.code).to.equal(
			DirectFundingErrorCode.MALFORMED
		);
	});
});

/**
 * The relay address fallback outlives the dial cache: the address a dial
 * persisted in an earlier run serves a primary stored by pubkey alone after a
 * restart, with nothing stubbed between the route and the wallet's storage.
 */
describe('direct-funding relay address persisted by an earlier dial (issue #1922)', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: IStartedDaemon;
	let port: number;

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-df-saved-'));
		daemon = await startDaemon({ ...OFFLINE, dataDir });
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	/** The row the last successful dial of a peer leaves in the wallet's storage. */
	const savePeerAddress = (
		pubkey: string,
		host: string,
		peerPort: number,
		transport?: { type: 'tcp' | 'ws' | 'iroh' }
	): void => {
		(
			daemon.node.getNode() as unknown as {
				storage: {
					savePeerAddress(
						pubkey: string,
						host: string,
						port: number,
						transport?: { type: 'tcp' | 'ws' | 'iroh' }
					): void;
				};
			}
		).storage.savePeerAddress(pubkey, host, peerPort, transport);
	};

	it('takes the address the last dial persisted when nothing was dialed this run', async () => {
		savePeerAddress(REACHABLE, '10.0.0.8', 9737);
		daemon.node.addPrimary({ pubkey: REACHABLE });
		expect(daemon.node.getPeerAddress(REACHABLE)).to.deep.equal({
			host: '10.0.0.8',
			port: 9737
		});
		const { status, json } = await httpCall(
			port,
			'POST',
			'/direct-funding/request',
			{ amountSats: 50_000 }
		);
		expect(status).to.equal(200);
		const result = json.result as Record<string, unknown>;
		expect(result.lspPubkey).to.equal(REACHABLE);
		expect(relayOf(result.request as string)).to.include({
			host: '10.0.0.8',
			port: 9737
		});
	});

	it('passes over a persisted address that is not TCP', async () => {
		savePeerAddress(UNREACHABLE, 'ws.example', 443, { type: 'ws' });
		daemon.node.addPrimary({ pubkey: UNREACHABLE, rank: 1 });
		expect(daemon.node.getPeerAddress(UNREACHABLE)).to.deep.equal({
			host: 'ws.example',
			port: 443,
			transport: 'ws'
		});
		const { status, json } = await httpCall(
			port,
			'POST',
			'/direct-funding/request',
			{}
		);
		expect(status).to.equal(200);
		const result = json.result as Record<string, unknown>;
		expect(result.lspPubkey).to.equal(REACHABLE);
		expect(
			(result.skipped as Record<string, unknown>[]).map((s) => [
				s.pubkey,
				s.code
			])
		).to.deep.equal([[UNREACHABLE, 'RECEIVE_UNAVAILABLE']]);
	});
});
