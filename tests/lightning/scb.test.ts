/**
 * Static channel backup (SCB) export tests.
 *
 * Covers the encode/decode envelope (AES-256-GCM under an HKDF key from the
 * wallet seed), per-entry and address validation at the decode boundary,
 * LightningNode.buildStaticChannelBackupData channel selection and field
 * mapping, and BeignetNode.exportStaticChannelBackup file output.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as bip39 from 'bip39';
import {
	encodeScb,
	decodeScb,
	parseScbAddress,
	validateScbEntry,
	validateScbEntries,
	SCB_PREFIX,
	IStaticChannelBackup,
	IScbChannelEntry
} from '../../src/lightning/backup/scb';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { BeignetNode } from '../../src/cli/beignet-node';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`scb-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	fundingSatoshis = 1_000_000n
): { channelId: Buffer; fundingTxid: Buffer } {
	const channel = alice.openChannel(bob.getNodeId(), fundingSatoshis);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return { channelId, fundingTxid };
}

/** An entry with every field exactly as the exporter writes it. */
function makeValidScbEntry(): IScbChannelEntry {
	return {
		channelId: 'aa'.repeat(32),
		peerNodeId: getPublicKey(makeSeed(9)).toString('hex'),
		peerAddresses: ['203.0.113.7:9735'],
		fundingTxid: 'cc'.repeat(32),
		fundingOutputIndex: 1,
		fundingSatoshis: '5000000',
		channelKeyIndex: 3,
		channelType: '',
		role: 'OPENER',
		isTaproot: false,
		isAnchor: false
	};
}

function makeFabricatedBackup(): IStaticChannelBackup {
	const entries: IScbChannelEntry[] = [
		{
			channelId: 'aa'.repeat(32),
			peerNodeId: '02' + 'bb'.repeat(32),
			peerAddresses: ['203.0.113.7:9735', 'example.onion:9735'],
			fundingTxid: 'cc'.repeat(32),
			fundingOutputIndex: 1,
			fundingSatoshis: '5000000',
			channelKeyIndex: 3,
			channelType: '',
			role: 'OPENER',
			isTaproot: false,
			isAnchor: false
		},
		{
			channelId: 'dd'.repeat(32),
			peerNodeId: '03' + 'ee'.repeat(32),
			peerAddresses: [],
			fundingTxid: 'ff'.repeat(32),
			fundingOutputIndex: 0,
			fundingSatoshis: '123456789012',
			channelKeyIndex: null,
			channelType: '10100000',
			role: 'ACCEPTOR',
			isTaproot: true,
			isAnchor: true
		}
	];
	return {
		version: 1,
		network: 'bcrt',
		createdAt: 1750000000000,
		channels: entries
	};
}

describe('Static Channel Backup (SCB)', function () {
	describe('encodeScb / decodeScb', function () {
		const seed = crypto
			.createHash('sha512')
			.update('scb-envelope-seed')
			.digest();

		it('round-trips a backup through encrypt + decrypt', function () {
			const backup = makeFabricatedBackup();
			const encoded = encodeScb(backup, seed);
			expect(encoded.startsWith(SCB_PREFIX)).to.be.true;

			const decoded = decodeScb(encoded, seed);
			expect(decoded).to.deep.equal(backup);
			// Taproot/anchor combo survives the round-trip
			expect(decoded.channels[1].isTaproot).to.be.true;
			expect(decoded.channels[1].isAnchor).to.be.true;
			expect(decoded.channels[1].fundingSatoshis).to.equal('123456789012');
		});

		it('produces ciphertext that hides channel data', function () {
			const backup = makeFabricatedBackup();
			const encoded = encodeScb(backup, seed);
			expect(encoded).to.not.include('channelId');
			expect(encoded).to.not.include(backup.channels[0].peerNodeId);
			expect(encoded).to.not.include(backup.channels[0].fundingTxid);
		});

		it('throws on decode with the wrong seed', function () {
			const encoded = encodeScb(makeFabricatedBackup(), seed);
			const wrongSeed = crypto.createHash('sha512').update('wrong').digest();
			expect(() => decodeScb(encoded, wrongSeed)).to.throw(/wrong seed/);
		});

		it('throws on a tampered blob', function () {
			const encoded = encodeScb(makeFabricatedBackup(), seed);
			const payload = Buffer.from(encoded.slice(SCB_PREFIX.length), 'base64');
			// Flip a bit in the ciphertext body (past iv + tag)
			payload[payload.length - 1] ^= 0x01;
			const tampered = SCB_PREFIX + payload.toString('base64');
			expect(() => decodeScb(tampered, seed)).to.throw(
				/corrupted|tampered|wrong seed/
			);
		});

		it('throws on a missing or foreign prefix', function () {
			const encoded = encodeScb(makeFabricatedBackup(), seed);
			const stripped = encoded.slice(SCB_PREFIX.length);
			expect(() => decodeScb(stripped, seed)).to.throw(/prefix/);
			expect(() => decodeScb('enc1:' + stripped, seed)).to.throw(/prefix/);
		});

		it('throws on an unsupported version', function () {
			const bad = {
				...makeFabricatedBackup(),
				version: 2
			} as unknown as IStaticChannelBackup;
			const encoded = encodeScb(bad, seed);
			expect(() => decodeScb(encoded, seed)).to.throw(/version/);
		});

		it('throws when the payload lacks a channels array', function () {
			const bad = {
				version: 1,
				network: 'bcrt',
				createdAt: 0
			} as unknown as IStaticChannelBackup;
			const encoded = encodeScb(bad, seed);
			expect(() => decodeScb(encoded, seed)).to.throw(/channels/);
		});

		it('throws on an envelope with no network or no timestamp', function () {
			const noNetwork = {
				...makeFabricatedBackup(),
				network: ''
			} as unknown as IStaticChannelBackup;
			expect(() => decodeScb(encodeScb(noNetwork, seed), seed)).to.throw(
				/network/
			);
			const noTimestamp = {
				...makeFabricatedBackup(),
				createdAt: 'yesterday'
			} as unknown as IStaticChannelBackup;
			expect(() => decodeScb(encodeScb(noTimestamp, seed), seed)).to.throw(
				/createdAt/
			);
			const notAnObject = [1, 2, 3] as unknown as IStaticChannelBackup;
			expect(() => decodeScb(encodeScb(notAnObject, seed), seed)).to.throw(
				/backup object/
			);
		});

		it('keeps a backup usable when only SOME entries are malformed', function () {
			// The blob is AEAD-authenticated, so a bad entry inside a
			// decryptable backup is a producer bug, not corruption. Refusing
			// the whole backup would forfeit the funds behind every good
			// entry, so decode reports per entry instead of throwing.
			const good = makeValidScbEntry();
			const bad = {
				...makeValidScbEntry(),
				channelId: 'bb'.repeat(32),
				fundingTxid: 'nothex'
			};
			const backup: IStaticChannelBackup = {
				version: 1,
				network: 'bcrt',
				createdAt: 1750000000000,
				channels: [good, bad]
			};
			const decoded = decodeScb(encodeScb(backup, seed), seed);
			expect(decoded.channels).to.have.length(2);
			const problems = validateScbEntries(decoded);
			expect(problems).to.have.length(1);
			expect(problems[0].index).to.equal(1);
			expect(problems[0].channelId).to.equal(bad.channelId);
			expect(problems[0].reason).to.contain('fundingTxid');
		});
	});

	describe('parseScbAddress', function () {
		it('accepts the forms a backup actually carries', function () {
			expect(parseScbAddress('127.0.0.1:9735')).to.deep.equal({
				host: '127.0.0.1',
				port: 9735
			});
			expect(parseScbAddress('[fe80::1]:9735')).to.deep.equal({
				host: 'fe80::1',
				port: 9735
			});
			// Unbracketed IPv6, split on the LAST colon, as written by peers
			// that stored the address that way.
			expect(parseScbAddress('fe80::1:9735')).to.deep.equal({
				host: 'fe80::1',
				port: 9735
			});
			expect(
				parseScbAddress(
					'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9735'
				)
			).to.deep.equal({
				host: 'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion',
				port: 9735
			});
			expect(parseScbAddress('host:1')).to.deep.equal({
				host: 'host',
				port: 1
			});
			expect(parseScbAddress('host:65535')).to.deep.equal({
				host: 'host',
				port: 65535
			});
		});

		it('refuses everything a permissive parseInt would have accepted', function () {
			// parseInt('9735junk') is 9735: a persisted dial candidate built
			// from a port nobody wrote is worse than having none.
			expect(parseScbAddress('127.0.0.1:9735junk')).to.equal(null);
			expect(parseScbAddress('127.0.0.1:0x26')).to.equal(null);
			expect(parseScbAddress('127.0.0.1: 9735')).to.equal(null);
			expect(parseScbAddress('127.0.0.1:+9735')).to.equal(null);
			expect(parseScbAddress('127.0.0.1:97.35')).to.equal(null);
			// Out of range at both ends.
			expect(parseScbAddress('127.0.0.1:0')).to.equal(null);
			expect(parseScbAddress('127.0.0.1:65536')).to.equal(null);
			expect(parseScbAddress('127.0.0.1:99999')).to.equal(null);
			// No host, no port, no separator.
			expect(parseScbAddress(':9735')).to.equal(null);
			expect(parseScbAddress('127.0.0.1:')).to.equal(null);
			expect(parseScbAddress('127.0.0.1')).to.equal(null);
			expect(parseScbAddress('[]:9735')).to.equal(null);
			// A stray bracket is malformed, never something to strip.
			expect(parseScbAddress('[fe80::1:9735')).to.equal(null);
			expect(parseScbAddress('fe80::1]:9735')).to.equal(null);
			// Whitespace and non-strings.
			expect(parseScbAddress('local host:9735')).to.equal(null);
			expect(parseScbAddress('')).to.equal(null);
			expect(parseScbAddress(undefined)).to.equal(null);
			expect(parseScbAddress(9735)).to.equal(null);
		});
	});

	describe('validateScbEntry', function () {
		const validEntry = makeValidScbEntry;

		it('accepts a well-formed entry, with and without the lease fields', function () {
			expect(validateScbEntry(validEntry())).to.equal(null);
			expect(
				validateScbEntry({
					...validEntry(),
					channelKeyIndex: null,
					channelType: '10100000',
					role: 'ACCEPTOR',
					isTaproot: true,
					isAnchor: true,
					leaseExpiry: 900_000,
					isLessor: true,
					leaseCommitBlockheight: 800_000
				})
			).to.equal(null);
		});

		it('tolerates advisory absence and the LEGACY shape, never absent recovery material', function () {
			// Advisory: recovery is passive without addresses, and it reads the
			// channel type rather than the taproot/anchor booleans, so their
			// absence must not forfeit a channel's funds.
			const advisory = { ...makeValidScbEntry() } as Record<string, unknown>;
			delete advisory.peerAddresses;
			delete advisory.isTaproot;
			delete advisory.isAnchor;
			expect(validateScbEntry(advisory)).to.equal(null);

			// LEGACY, not advisory: a missing channelKeyIndex means the
			// node-level basepoints and a missing channelType means the
			// untyped static_remotekey channel. Both are accepted because
			// backups predating per-channel keys and channel types are still
			// recoverable, not because the fields do not matter.
			const legacy = { ...makeValidScbEntry() } as Record<string, unknown>;
			delete legacy.channelKeyIndex;
			delete legacy.channelType;
			expect(validateScbEntry(legacy)).to.equal(null);

			// A modern entry cannot claim the legacy shape AND a modern
			// commitment format: reconstructing it would look for a
			// static_remotekey P2WPKH its commitment never pays.
			for (const claim of [{ isAnchor: true }, { isTaproot: true }]) {
				expect(
					validateScbEntry({ ...legacy, ...claim }),
					JSON.stringify(claim)
				).to.match(/channelType is required/);
				expect(
					validateScbEntry({
						...makeValidScbEntry(),
						...claim,
						channelType: ''
					})
				).to.match(/channelType is required/);
			}

			// A hardened BIP32 path component stops at 2^31 - 1; a larger
			// index is not a legacy channel, it is an underivable one.
			expect(
				validateScbEntry({
					...makeValidScbEntry(),
					channelKeyIndex: 0x80000000
				})
			).to.equal('invalid channelKeyIndex');
			expect(
				validateScbEntry({
					...makeValidScbEntry(),
					channelKeyIndex: 0x7fffffff
				})
			).to.equal(null);

			for (const field of [
				'channelId',
				'peerNodeId',
				'fundingTxid',
				'fundingOutputIndex',
				'fundingSatoshis',
				'role'
			]) {
				const missing = { ...makeValidScbEntry() } as Record<string, unknown>;
				delete missing[field];
				expect(validateScbEntry(missing), field).to.not.equal(null);
			}
		});

		it('names the field that makes an entry unusable', function () {
			const cases: Array<[Partial<Record<string, unknown>>, RegExp]> = [
				[{ channelId: 'aa'.repeat(31) }, /channelId/],
				[{ channelId: 'zz'.repeat(32) }, /channelId/],
				[{ peerNodeId: '02' + 'bb'.repeat(31) }, /peerNodeId/],
				// Well-shaped 33-byte hex that is not a point on the curve:
				// recovery would persist it as a peer and dial it forever.
				[{ peerNodeId: '02' + 'bb'.repeat(32) }, /valid public key/],
				[{ peerAddresses: '203.0.113.7:9735' }, /peerAddresses/],
				[{ peerAddresses: [9735] }, /peerAddresses/],
				[{ fundingTxid: 'nothex' }, /fundingTxid/],
				[{ fundingOutputIndex: -1 }, /fundingOutputIndex/],
				[{ fundingOutputIndex: 1.5 }, /fundingOutputIndex/],
				[{ fundingSatoshis: 5_000_000 }, /fundingSatoshis/],
				[{ fundingSatoshis: '5_000_000' }, /fundingSatoshis/],
				[{ fundingSatoshis: '0' }, /range/],
				[{ fundingSatoshis: '2100000100000000' }, /range/],
				[{ channelKeyIndex: -3 }, /channelKeyIndex/],
				[{ channelType: 'abc' }, /channelType/],
				[{ role: 'INITIATOR' }, /role/],
				[{ isTaproot: 'yes' }, /booleans/],
				[{ isAnchor: null }, /booleans/],
				[{ leaseExpiry: -1 }, /leaseExpiry/],
				[{ leaseCommitBlockheight: 'soon' }, /leaseCommitBlockheight/],
				[{ isLessor: 1 }, /isLessor/]
			];
			for (const [patch, expected] of cases) {
				const reason = validateScbEntry({ ...validEntry(), ...patch });
				expect(reason, JSON.stringify(patch)).to.match(expected);
			}
			expect(validateScbEntry(null)).to.match(/not an object/);
			expect(validateScbEntry('channel')).to.match(/not an object/);
		});
	});

	describe('LightningNode.buildStaticChannelBackupData', function () {
		function createNodePair(): { alice: LightningNode; bob: LightningNode } {
			const alice = new LightningNode(makeNodeConfig(1));
			const bob = new LightningNode(makeNodeConfig(2));
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodes(alice, bob);
			return { alice, bob };
		}

		it('includes a NORMAL channel with correct fields on both sides', function () {
			const { alice, bob } = createNodePair();
			try {
				const { channelId } = openReadyChannel(alice, bob);
				const aliceChannel = alice.getChannelManager().getChannel(channelId)!;
				const state = aliceChannel.getFullState();
				expect(state.state).to.equal(ChannelState.NORMAL);

				const data = alice.buildStaticChannelBackupData();
				expect(data.network).to.equal(Network.REGTEST);
				expect(data.channels).to.have.length(1);

				const entry = data.channels[0];
				expect(entry.channelId).to.equal(channelId.toString('hex'));
				expect(entry.peerNodeId).to.equal(bob.getNodeId());
				// Funding txid must stay in INTERNAL byte order (no reverse)
				expect(entry.fundingTxid).to.equal(state.fundingTxid!.toString('hex'));
				expect(entry.fundingOutputIndex).to.equal(state.fundingOutputIndex);
				expect(entry.fundingSatoshis).to.equal('1000000');
				expect(entry.role).to.equal('OPENER');
				// Entry mirrors whatever key index the channel carries (opener
				// assignment happens even without a channelKeyDeriver)
				expect(entry.channelKeyIndex).to.equal(aliceChannel.channelKeyIndex);
				expect(entry.peerAddresses).to.deep.equal([]);
				expect(entry.isTaproot).to.be.false;

				// Bob sees the same channel from the ACCEPTOR side
				const bobData = bob.buildStaticChannelBackupData();
				expect(bobData.channels).to.have.length(1);
				expect(bobData.channels[0].role).to.equal('ACCEPTOR');
				expect(bobData.channels[0].channelId).to.equal(
					channelId.toString('hex')
				);
				expect(bobData.channels[0].peerNodeId).to.equal(alice.getNodeId());
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});

		it('carries the per-channel key index when one is assigned', function () {
			const { alice, bob } = createNodePair();
			try {
				const { channelId } = openReadyChannel(alice, bob);
				const channel = alice.getChannelManager().getChannel(channelId)!;
				channel.channelKeyIndex = 7;
				expect(
					alice.buildStaticChannelBackupData().channels[0].channelKeyIndex
				).to.equal(7);
				// Legacy channels restored without a key index export null
				channel.channelKeyIndex = null;
				expect(
					alice.buildStaticChannelBackupData().channels[0].channelKeyIndex
				).to.equal(null);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});

		it('excludes channels without a funding outpoint', function () {
			const { alice, bob } = createNodePair();
			try {
				// Opened but no funding created: nothing on chain to recover
				alice.openChannel(bob.getNodeId(), 500_000n);
				const data = alice.buildStaticChannelBackupData();
				expect(data.channels).to.have.length(0);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});

		it('excludes CLOSED channels but keeps ERRORED ones', function () {
			const { alice, bob } = createNodePair();
			try {
				const { channelId } = openReadyChannel(alice, bob);
				const state = alice
					.getChannelManager()
					.getChannel(channelId)!
					.getFullState();

				state.state = ChannelState.ERRORED;
				expect(alice.buildStaticChannelBackupData().channels).to.have.length(1);

				state.state = ChannelState.CLOSED;
				expect(alice.buildStaticChannelBackupData().channels).to.have.length(0);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});

		it('includes persisted peer addresses as host:port strings', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const alice = new LightningNode({ ...makeNodeConfig(1), storage });
			const bob = new LightningNode(makeNodeConfig(2));
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodes(alice, bob);
			try {
				const { channelId } = openReadyChannel(alice, bob);
				storage.savePeerAddress(bob.getNodeId(), '203.0.113.5', 9735);

				const data = alice.buildStaticChannelBackupData();
				expect(data.channels).to.have.length(1);
				expect(data.channels[0].channelId).to.equal(channelId.toString('hex'));
				expect(data.channels[0].peerAddresses).to.deep.equal([
					'203.0.113.5:9735'
				]);
			} finally {
				alice.destroy();
				bob.destroy();
				storage.close();
			}
		});
	});

	describe('BeignetNode.exportStaticChannelBackup', function () {
		const MNEMONIC =
			'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
		let tmpDir: string;

		beforeEach(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-scb-'));
		});

		afterEach(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('writes an encrypted channels.scb decodable with the wallet seed', async function () {
			this.timeout(60_000);
			const node = await BeignetNode.create({
				mnemonic: MNEMONIC,
				network: 'regtest',
				dataDir: tmpDir,
				logLevel: 'silent',
				rapidGossipSync: false,
				autoGossipSync: false
			});
			let result: { encoded: string; channelCount: number; path: string };
			try {
				result = node.exportStaticChannelBackup();
			} finally {
				await node.destroy();
			}

			expect(result.channelCount).to.equal(0);
			expect(result.path).to.equal(path.join(tmpDir, 'channels.scb'));
			expect(fs.existsSync(result.path)).to.be.true;

			const raw = fs.readFileSync(result.path, 'utf8');
			expect(raw).to.equal(result.encoded);
			expect(raw.startsWith(SCB_PREFIX)).to.be.true;
			// The on-disk blob must not leak backup structure in plaintext
			expect(raw).to.not.include('channelId');
			expect(raw).to.not.include('"version"');

			const seed = bip39.mnemonicToSeedSync(MNEMONIC);
			const decoded = decodeScb(raw, seed);
			expect(decoded.version).to.equal(1);
			expect(decoded.network).to.equal('bcrt');
			expect(decoded.channels).to.deep.equal([]);
			expect(decoded.createdAt).to.be.a('number');
		});
	});
});
