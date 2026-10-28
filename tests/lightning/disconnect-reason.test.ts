/**
 * Disconnect diagnostics (issue #1890): an open that dies on a disconnect
 * says who closed the connection and why, peer:disconnect carries that
 * cause, and a peer's tx_abort reason is surfaced.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import { Peer } from '../../src/lightning/transport/peer';
import {
	IPeerDisconnectInfo,
	PeerManager
} from '../../src/lightning/transport/peer-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { ChannelState } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import { encodeTxAbortMessage } from '../../src/lightning/message/interactive-tx';
import { MessageType } from '../../src/lightning/message/types';
import { parseWireTrace } from '../../src/cli/config';
import { COMMIT_ALL } from './helpers/channel-persistence';

const PEER = '02' + '11'.repeat(32);
// Even, so BOLT 1 requires the receiver to close; not a known type.
const UNKNOWN_REQUIRED_TYPE = 20000;

function basepoints(): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(crypto.randomBytes(32)),
		revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
		paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
		firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	};
}

function openingManager(): {
	mgr: ChannelManager;
	errors: string[];
	tempId: Buffer;
} {
	const config = {
		localBasepoints: basepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32),
		localFundingPrivkey: crypto.randomBytes(32),
		persistence: COMMIT_ALL
	};
	const mgr = new ChannelManager(config);
	const errors: string[] = [];
	mgr.on('error', (_id: Buffer | null, message: string) =>
		errors.push(message)
	);
	const params: IDualFundingParams = {
		fundingSatoshis: 100_000n,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 253,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		localBasepoints: config.localBasepoints,
		localPerCommitmentSeed: config.localPerCommitmentSeed,
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
		channelType: Buffer.from('1000', 'hex')
	};
	const channel = mgr.createDualFundedChannel(PEER, params);
	expect(channel.getState()).to.equal(ChannelState.DUAL_FUNDING_V2);
	return { mgr, errors, tempId: channel.getTemporaryChannelId() };
}

async function settle(ms = 20): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, ms));
}

async function until(
	predicate: () => boolean,
	timeoutMs = 3_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() > deadline) throw new Error('condition not met in time');
		await settle(10);
	}
}

describe('Open killed by a disconnect (issue #1890)', () => {
	it('names the closing side and the transport reason', () => {
		const { mgr, errors } = openingManager();
		mgr.handlePeerDisconnected(PEER, {
			initiator: 'remote',
			reason: 'read ECONNRESET'
		});
		expect(errors).to.deep.equal([
			'Peer disconnected during channel open (state: DUAL_FUNDING_V2): closed by peer: read ECONNRESET'
		]);
	});

	it('says when this side closed and no reason is known', () => {
		const { mgr, errors } = openingManager();
		mgr.handlePeerDisconnected(PEER, { initiator: 'local' });
		expect(errors).to.deep.equal([
			'Peer disconnected during channel open (state: DUAL_FUNDING_V2): closed by us'
		]);
	});

	it('keeps the old text when the caller knows nothing about the close', () => {
		const { mgr, errors } = openingManager();
		mgr.handlePeerDisconnected(PEER);
		expect(errors).to.deep.equal([
			'Peer disconnected during channel open (state: DUAL_FUNDING_V2)'
		]);
	});

	it("surfaces a peer's tx_abort reason", () => {
		const { mgr, errors, tempId } = openingManager();
		mgr.handleMessage(
			PEER,
			MessageType.TX_ABORT,
			encodeTxAbortMessage({
				channelId: tempId,
				data: Buffer.from('too many channel-less peers')
			})
		);
		expect(errors[0]).to.equal('Remote tx_abort: too many channel-less peers');
	});

	it('adds nothing for a tx_abort without a reason', () => {
		const { mgr, errors, tempId } = openingManager();
		mgr.handleMessage(
			PEER,
			MessageType.TX_ABORT,
			encodeTxAbortMessage({ channelId: tempId, data: Buffer.alloc(0) })
		);
		expect(errors.filter((e) => e.startsWith('Remote tx_abort'))).to.deep.equal(
			[]
		);
	});
});

describe('peer:disconnect cause (issue #1890)', () => {
	const HOST_SECRET = crypto
		.createHash('sha256')
		.update('disconnect-reason')
		.digest();
	const HOST_ID = getPublicKey(HOST_SECRET);
	let pm: PeerManager | undefined;
	const peers: Peer[] = [];

	afterEach(() => {
		for (const peer of peers.splice(0)) peer.disconnect();
		pm?.destroy();
		pm = undefined;
	});

	async function host(): Promise<{
		port: number;
		disconnects: Array<{ pubkey: string; info: IPeerDisconnectInfo }>;
	}> {
		pm = new PeerManager({
			localPrivateKey: HOST_SECRET,
			autoReconnect: false
		});
		pm.on('peer:error', () => undefined);
		const disconnects: Array<{ pubkey: string; info: IPeerDisconnectInfo }> =
			[];
		pm.on('peer:disconnect', (pubkey: string, info: IPeerDisconnectInfo) =>
			disconnects.push({ pubkey, info })
		);
		await pm.listen(0, '127.0.0.1');
		const port = (
			pm as unknown as { server: { address(): { port: number } } }
		).server.address().port;
		return { port, disconnects };
	}

	async function dial(port: number): Promise<{ peer: Peer; pubkey: string }> {
		const key = crypto.randomBytes(32);
		const peer = new Peer({
			localPrivateKey: key,
			remotePublicKey: HOST_ID,
			host: '127.0.0.1',
			port,
			connectTimeout: 2_000,
			handshakeTimeout: 2_000
		});
		peer.on('error', () => undefined);
		peers.push(peer);
		await peer.connect();
		await until(() => pm!.listPeers().length === 1);
		return { peer, pubkey: getPublicKey(key).toString('hex') };
	}

	it('reports a close by the peer as remote, with the connection age', async () => {
		const { port, disconnects } = await host();
		const { peer, pubkey } = await dial(port);
		const connection = pm!.getConnectionInfo(pubkey);
		expect(connection?.direction).to.equal('inbound');

		peer.disconnect();
		await until(() => disconnects.length === 1);
		expect(disconnects[0].pubkey).to.equal(pubkey);
		expect(disconnects[0].info.initiator).to.equal('remote');
		expect(disconnects[0].info.direction).to.equal('inbound');
		expect(disconnects[0].info.uptimeMs).to.be.a('number');
		expect(pm!.getConnectionInfo(pubkey)).to.equal(undefined);
	});

	it('reports our own disconnectPeer as local', async () => {
		const { port, disconnects } = await host();
		const { pubkey } = await dial(port);
		pm!.disconnectPeer(pubkey);
		expect(disconnects).to.have.length(1);
		expect(disconnects[0].info).to.include({
			initiator: 'local',
			reason: 'disconnect requested',
			direction: 'inbound'
		});
	});

	it('carries the protocol error behind a close this side made', async () => {
		const { port, disconnects } = await host();
		const { peer } = await dial(port);
		peer.sendMessage(UNKNOWN_REQUIRED_TYPE, Buffer.alloc(0));
		await until(() => disconnects.length === 1);
		expect(disconnects[0].info).to.include({
			initiator: 'local',
			reason: `Unknown required message type ${UNKNOWN_REQUIRED_TYPE}`
		});
	});

	it('shows each message to the wire observer by type and length', async () => {
		const { port } = await host();
		const seen: Array<[string, number, number]> = [];
		pm!.setWireObserver((dir, _pubkey, type, length) =>
			seen.push([dir, type, length])
		);
		const { peer } = await dial(port);
		peer.sendMessage(MessageType.WARNING, Buffer.alloc(34));
		await until(() => seen.length > 0);
		expect(seen[0]).to.deep.equal(['in', MessageType.WARNING, 34]);
	});
});

describe('BEIGNET_WIRE_TRACE parsing (issue #1890)', () => {
	it('reads on, off and pubkey lists', () => {
		expect(parseWireTrace(undefined)).to.equal(undefined);
		expect(parseWireTrace('')).to.equal(undefined);
		expect(parseWireTrace('0')).to.equal(undefined);
		expect(parseWireTrace('false')).to.equal(undefined);
		expect(parseWireTrace('1')).to.equal(true);
		expect(parseWireTrace('TRUE')).to.equal(true);
		expect(parseWireTrace(` 02AB, 03cd ,`)).to.deep.equal(['02ab', '03cd']);
	});
});
