/**
 * Asset channels and the daemon's recovery mode (issue #2093, step 14).
 *
 * A wallet whose recovery mode is a guardian mode (`async-remote` or
 * `quorum`) neither opens nor accepts an asset channel; one in a mode
 * without guardians does. A restore that holds asset channels is refused
 * under a code of the daemon's own.
 *
 * The guardian mode is a real one: three daemons serve the reference
 * guardian and a fourth pins them in quorum mode, the pattern of
 * tests/cli/guardian-host-surface.test.ts. Boots offline (unreachable
 * Electrum).
 */

import Database from 'better-sqlite3';
import { expect } from 'chai';
import { createHash } from 'crypto';
import * as bip39 from 'bip39';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import { AddressInfo } from 'net';
import * as os from 'os';
import * as path from 'path';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import {
	BeignetNode,
	BeignetNodeOptions,
	restoreOmittedAssetChannels
} from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import {
	EXTENSION_API_VERSION,
	IBeignetExtension
} from '../../src/cli/extension';
import type { IStaticChannelBackup } from '../../src/lightning/backup/scb';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	LnCoinType,
	deriveLightningKeysFromMnemonic
} from '../../src/lightning/keys/wallet-keys';
import { PaymentStatus } from '../../src/lightning/node/payment-types';
import { AuxiliaryProviderRequiredError } from '../../src/lightning/node/types';
import {
	AuxiliaryGuardianModeError,
	AuxiliaryGuardianRestoreError,
	AuxiliaryRestoreRefusedError,
	decodeRecoveryCapsuleBlob
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	payAssetUnits,
	turns,
	withAssetOpens
} from '../lightning/helpers/auxiliary-nodes';
import {
	ASSET_FUNDING_ROOT,
	referenceProvider
} from '../lightning/helpers/auxiliary-pair';

const MNEMONICS = [
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
	'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
	'legal winner thank year wave sausage worth useful legal winner thank yellow',
	'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'
];

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	daemonPort: 0
};

const PEER = `02${'11'.repeat(32)}`;

function tmpDir(tag: string): string {
	return fs.mkdtempSync(
		path.join(os.tmpdir(), `beignet-recovery-auxiliary-${tag}-`)
	);
}

/** Every row of every table of a database file, as text, by table. */
function tables(file: string): Map<string, string[]> {
	const db = new Database(file, { readonly: true });
	const out = new Map<string, string[]>();
	const names = db
		.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
		.all() as Array<{ name: string }>;
	for (const { name } of names) {
		const rows = db.prepare(`SELECT * FROM "${name}"`).all() as object[];
		out.set(
			name,
			rows.map((row) =>
				JSON.stringify(row, (_key, value: unknown) =>
					Buffer.isBuffer(value) ? value.toString('hex') : value
				)
			)
		);
	}
	db.close();
	return out;
}

function portOf(daemon: IStartedDaemon): number {
	return (daemon.server.address() as AddressInfo).port;
}

async function freePort(): Promise<number> {
	return new Promise((resolve) => {
		const probe = net.createServer();
		probe.listen(0, '127.0.0.1', () => {
			const port = (probe.address() as AddressInfo).port;
			probe.close(() => resolve(port));
		});
	});
}

function request(
	port: number,
	method: string,
	urlPath: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {};
		if (payload) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(payload);
		}
		const req = http.request(
			{ hostname: '127.0.0.1', port, path: urlPath, method, headers },
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve({
							status: res.statusCode!,
							body: JSON.parse(Buffer.concat(chunks).toString())
						});
					} catch {
						resolve({ status: res.statusCode!, body: {} });
					}
				});
			}
		);
		req.on('error', reject);
		if (payload) req.write(payload);
		req.end();
	});
}

/** An extension that supplies the node's asset channels, and nothing else. */
const assets = (given: IAuxiliaryChannelConfig): IBeignetExtension => ({
	id: 'assets',
	version: '1.0.0',
	api: EXTENSION_API_VERSION,
	attach: () => ({ auxiliaryChannels: given })
});

const auxiliaryChannels = (): IAuxiliaryChannelConfig => ({
	provider: referenceProvider(),
	resolveIncoming: (): undefined => undefined
});

/** What opening an asset channel to a peer throws on this daemon's node. */
const openRefusal = (daemon: IStartedDaemon): unknown => {
	try {
		daemon.node.getNode().openAuxiliaryChannel(PEER, 2_000_000n, {
			temporaryChannelId: Buffer.alloc(32, 7),
			fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
			channelData: Buffer.from('proposed asset funding'),
			localBalance: 900n,
			remoteBalance: 100n
		});
	} catch (err) {
		return err;
	}
	return undefined;
};

describe('Recovery modes and asset channels, over the daemon', function () {
	this.timeout(180_000);
	withAssetOpens();

	let daemons: IStartedDaemon[];
	let dirs: string[];

	beforeEach(() => {
		daemons = [];
		dirs = [];
	});

	afterEach(async () => {
		for (const daemon of daemons.reverse()) {
			try {
				await daemon.stop();
			} catch {
				// Already stopped.
			}
		}
		for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
	});

	const boot = async (
		tag: string,
		options: Record<string, unknown>
	): Promise<IStartedDaemon> => {
		const dataDir = tmpDir(tag);
		dirs.push(dataDir);
		const daemon = await startDaemon({ ...OFFLINE, dataDir, ...options });
		daemons.push(daemon);
		return daemon;
	};

	it('refuses to open an asset channel while the recovery mode is a guardian mode, and not in a mode without guardians', async () => {
		// Three guardians, served by three daemons at their Lightning
		// addresses.
		const uris: string[] = [];
		for (let index = 0; index < 3; index++) {
			const listenPort = await freePort();
			const host = await boot(`host-${index}`, {
				mnemonic: MNEMONICS[index],
				listenPort,
				guardianServe: true
			});
			const info = await request(portOf(host), 'GET', '/info');
			const nodeId = (info.body.result as { nodeId: string }).nodeId;
			uris.push(`${nodeId}@127.0.0.1:${listenPort}`);
		}
		const entries: string[] = [];
		for (const uri of uris) {
			const resolved = await request(
				portOf(daemons[0]),
				'POST',
				'/recovery/resolve-guardian',
				{ uri }
			);
			expect(resolved.status, JSON.stringify(resolved.body)).to.equal(200);
			entries.push((resolved.body.result as { entry: string }).entry);
		}

		// A wallet in a guardian mode, with the extension that supplies its
		// asset channels.
		const given = auxiliaryChannels();
		const guarded = await boot('guarded', {
			mnemonic: MNEMONICS[3],
			recoveryMode: 'quorum',
			recoveryGuardians: entries,
			recoveryLeaseCheckIntervalMs: 200,
			extensions: [assets(given)]
		});
		const status = await request(portOf(guarded), 'GET', '/recovery/status');
		expect((status.body.result as { mode: string }).mode).to.equal('quorum');
		expect(guarded.node.getNode()).to.have.property('auxiliaryChannels', given);
		const refusal = openRefusal(guarded);
		expect(refusal).to.be.instanceOf(AuxiliaryGuardianModeError);
		expect((refusal as AuxiliaryGuardianModeError).code).to.equal(
			'AUXILIARY_GUARDIAN_MODE'
		);
		expect((refusal as Error).message).to.match(
			/^Asset channels cannot be opened or accepted while this node replicates its recovery journal to guardians/
		);
		expect(guarded.node.getNode().listChannels()).to.have.length(0);

		// The same extension on wallets without guardians: whatever the
		// opening meets there, it is not this refusal.
		for (const recoveryMode of ['peer-storage', 'off']) {
			const plain = await boot(`plain-${recoveryMode}`, {
				mnemonic: bip39.generateMnemonic(),
				recoveryMode,
				extensions: [assets(auxiliaryChannels())]
			});
			const met = openRefusal(plain);
			expect(met, recoveryMode).to.not.be.instanceOf(
				AuxiliaryGuardianModeError
			);
			expect(
				String((met as Error | undefined)?.message),
				recoveryMode
			).to.not.match(/AUXILIARY_GUARDIAN_MODE/);
		}
	});

	it('gives a refused restore a code of its own, and the code of a missing provider when there is none', async () => {
		const daemon = await boot('codes', {
			mnemonic: MNEMONICS[0],
			recoveryMode: 'peer-storage'
		});
		const refusalFor = (
			daemon.node as unknown as {
				assetRestoreRefusal(err: unknown): BeignetError | undefined;
			}
		).assetRestoreRefusal.bind(daemon.node);
		const id = 'ab'.repeat(32);

		const refused = refusalFor(new AuxiliaryRestoreRefusedError([id]));
		expect(refused).to.be.instanceOf(BeignetError);
		expect(refused?.code).to.equal('ASSET_RESTORE_REFUSED');
		expect(refused?.message).to.equal(
			new AuxiliaryRestoreRefusedError([id]).message
		);

		const required = refusalFor(new AuxiliaryProviderRequiredError([id]));
		expect(required?.code).to.equal('ASSET_PROVIDER_REQUIRED');
		expect(required?.message).to.equal(
			'This restore holds 1 asset channel and no extension attached to ' +
				'this wallet can run them, so nothing was restored. Restore it ' +
				'with the extension that opened them.'
		);

		// Any other failure of a restore is left to the code it had.
		expect(refusalFor(new Error('disk full'))).to.equal(undefined);

		// Neither says more than it did: a refusal that names no channel
		// has no details, in the object or in the answer.
		expect(refused).to.not.have.property('details');
		expect(refused?.toJSON()).to.deep.equal({
			code: 'ASSET_RESTORE_REFUSED',
			message: new AuxiliaryRestoreRefusedError([id]).message
		});
		expect(required?.toJSON()).to.not.have.property('details');
	});

	it('answers a refused capsule restore with the asset channels it holds, and takes omitAssetChannels only as a boolean', async () => {
		const daemon = await boot('omit', {
			mnemonic: MNEMONICS[0],
			recoveryMode: 'peer-storage'
		});
		const refusalFor = (
			daemon.node as unknown as {
				assetRestoreRefusal(err: unknown): BeignetError | undefined;
			}
		).assetRestoreRefusal.bind(daemon.node);
		const id = 'ab'.repeat(32);
		const held = [
			{ channelId: id, peerPubkey: PEER, capacitySatoshis: 2_000_000n }
		];
		const assetChannels = [
			{ channelId: id, peerPubkey: PEER, capacitySats: 2_000_000 }
		];
		// As the engine's capsule restore throws them.
		const required = refusalFor(
			Object.assign(new AuxiliaryProviderRequiredError([id]), {
				channels: held
			})
		);
		expect(required?.code).to.equal('ASSET_PROVIDER_REQUIRED');
		expect(required?.toJSON()).to.deep.equal({
			code: 'ASSET_PROVIDER_REQUIRED',
			message:
				'This restore holds 1 asset channel and no extension attached to ' +
				'this wallet can run them, so nothing was restored. Restore it ' +
				'with the extension that opened them.',
			details: { assetChannels }
		});
		const refused = refusalFor(
			Object.assign(new AuxiliaryRestoreRefusedError([id]), { channels: held })
		);
		expect(refused?.code).to.equal('ASSET_RESTORE_REFUSED');
		expect(refused?.details).to.deep.equal({ assetChannels });
		// The answer is JSON as it stands.
		expect(JSON.parse(JSON.stringify(refused?.toJSON())).details).to.deep.equal(
			{ assetChannels }
		);

		// The option, on the route and on the call.
		const port = portOf(daemon);
		for (const given of ['true', 1, null]) {
			const answer = await request(port, 'POST', '/recovery/restore-capsule', {
				confirm: true,
				omitAssetChannels: given
			});
			expect(answer.status, String(given)).to.equal(400);
			expect(answer.body.error).to.deep.equal({
				code: 'INVALID_PARAMS',
				message: 'omitAssetChannels must be a boolean'
			});
		}
		let thrown: unknown;
		try {
			await daemon.node.restoreFromCapsules({
				omitAssetChannels: 'true' as unknown as boolean
			});
		} catch (err) {
			thrown = err;
		}
		expect((thrown as BeignetError).code).to.equal('INVALID_PARAMS');
		expect((thrown as BeignetError).message).to.equal(
			'omitAssetChannels must be a boolean'
		);
		// A boolean passes the check and reaches the restore itself, which
		// has no capsule here: the same answer with the option and without.
		const without = await request(port, 'POST', '/recovery/restore-capsule', {
			confirm: true
		});
		for (const given of [true, false]) {
			const answer = await request(port, 'POST', '/recovery/restore-capsule', {
				confirm: true,
				omitAssetChannels: given
			});
			expect(answer.status).to.equal(without.status);
			expect(answer.body).to.deep.equal(without.body);
			expect((answer.body.error as { code: string }).code).to.not.equal(
				'INVALID_PARAMS'
			);
		}
	});

	/**
	 * The wallet that was lost and the capsule it handed its peers: a node
	 * with the key of MNEMONICS[0], an asset channel and a payment its payee
	 * holds. Answers the capsule, the channel, its peer and the payment.
	 * Without `inline` the capsule is the one of a run that took no snapshot
	 * since the channel opened: its journal is too large for a peer to
	 * store, so it holds the backup only and restores at Tier 1.
	 */
	const lostWallet = async (
		tag: string,
		inline = true
	): Promise<{ blob: Buffer; id: string; peerId: string; hash: Buffer }> => {
		// The wallet that was lost: a node with this daemon's own key, an
		// asset channel, a payment its payee holds, and the capsule it
		// handed its peers.
		const secret = deriveLightningKeysFromMnemonic(
			MNEMONICS[0],
			undefined,
			LnCoinType.REGTEST
		).nodePrivateKey;
		const journal = new SqliteStorage(':memory:');
		journal.open();
		const valued: Partial<IAuxiliaryChannelConfig> = {
			valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n
		};
		const lost = assetHost(tag, 1, valued, {
			extra: {
				nodePrivateKey: secret,
				storage: journal,
				recovery: { enabled: true }
			}
		});
		const peer = assetHost(tag, 2, valued);
		let blob: Buffer | null;
		let id: string;
		let peerId: string;
		const hash = createHash('sha256')
			.update(`${tag} held by the payee`)
			.digest();
		try {
			connectHosts(lost, peer);
			const channelId = await openAssetChannel(lost, peer, {
				tag: tag,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			id = channelId.toString('hex');
			peerId = peer.node.getNodeId();
			const invoice = peer.node.createInvoice({
				amountMsat: 3_000_000n,
				description: 'held by the payee',
				hold: true,
				paymentHash: hash
			});
			payAssetUnits(lost, peer, channelId, invoice, 3_000_000n, 3000n);
			await turns(200);
			expect(lost.node.getPayment(hash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			// As after a restart of that wallet: the first capsule of a run
			// follows a snapshot of the tables, which is what keeps the
			// journal small enough for a peer to store.
			const node = lost.node as unknown as {
				recoveryJournal: { rebasedThisRun: boolean };
				composeRecoveryCapsuleBlob: () => Buffer | null;
			};
			if (inline) node.recoveryJournal.rebasedThisRun = false;
			blob = node.composeRecoveryCapsuleBlob();
		} finally {
			lost.node.destroy();
			peer.node.destroy();
			try {
				journal.close();
			} catch {
				// Closed with its node.
			}
		}
		expect(blob).to.not.equal(null);
		const capsule = decodeRecoveryCapsuleBlob(blob!, secret);
		expect(capsule, "the capsule is this wallet's").to.not.equal(null);
		expect(
			capsule!.inlineRecoveryState !== undefined,
			'the journal is inline for a Tier 2 restore, and left out for Tier 1'
		).to.equal(inline);
		return { blob: blob!, id, peerId, hash };
	};

	it('restores a real capsule that holds an asset channel, over HTTP: refused by default with the channels listed and nothing installed, and with omitAssetChannels restored without them, the payment in flight left unresolved', async () => {
		const { blob, id, peerId, hash } = await lostWallet('capsule over http');

		// The same seed on a fresh database, with no extension attached.
		const daemon = await boot('capsule-http', {
			mnemonic: MNEMONICS[0],
			recoveryMode: 'peer-storage'
		});
		const dataDir = dirs[dirs.length - 1];
		const port = portOf(daemon);
		daemon.node.getNode().emit('peer_storage:retrieved', PEER, blob);
		const listed = [
			{ channelId: id, peerPubkey: peerId, capacitySats: 2_000_000 }
		];

		// By default it is refused, with the channels, and nothing is
		// installed: the daemon answers on as the empty wallet it was.
		const refused = await request(port, 'POST', '/recovery/restore-capsule', {
			confirm: true
		});
		expect(refused.status, JSON.stringify(refused.body)).to.equal(409);
		expect(refused.body.ok).to.equal(false);
		const error = refused.body.error as {
			code: string;
			message: string;
			details?: unknown;
		};
		expect(error.code).to.equal('ASSET_PROVIDER_REQUIRED');
		expect(error.details).to.deep.equal({ assetChannels: listed });
		expect((await request(port, 'GET', '/info')).status).to.equal(200);
		expect((await request(port, 'GET', '/channels')).body.result).to.deep.equal(
			[]
		);
		expect((await request(port, 'GET', '/payments')).body.result).to.deep.equal(
			[]
		);

		// Asked to leave them out, it restores the rest and says what it
		// left out and which payment it can no longer follow.
		const restored = await request(port, 'POST', '/recovery/restore-capsule', {
			confirm: true,
			omitAssetChannels: true
		});
		expect(restored.status, JSON.stringify(restored.body)).to.equal(200);
		expect(restored.body.ok).to.equal(true);
		const result = restored.body.result as {
			tier: number;
			restartRequired?: boolean;
			omittedAssetChannels?: unknown;
			unresolvedPayments?: unknown;
		};
		expect(result.tier).to.equal(2);
		expect(result.omittedAssetChannels).to.deep.equal(listed);
		expect(result.unresolvedPayments).to.deep.equal([hash.toString('hex')]);
		expect(result.restartRequired).to.equal(true);
		await daemon.stop();

		// After the restart the wallet runs with no asset channel and no
		// extension, and shows the payment as it is: PENDING, unresolved.
		const again = await boot('capsule-http-again', {
			dataDir,
			mnemonic: MNEMONICS[0],
			recoveryMode: 'peer-storage'
		});
		const portAgain = portOf(again);
		expect((await request(portAgain, 'GET', '/info')).status).to.equal(200);
		expect(
			(await request(portAgain, 'GET', '/channels')).body.result
		).to.deep.equal([]);
		const rows = (await request(portAgain, 'GET', '/payments')).body
			.result as Array<Record<string, unknown>>;
		expect(rows.map((row) => row.paymentHash)).to.deep.equal([
			hash.toString('hex')
		]);
		expect(rows[0].status).to.equal('PENDING');
		expect(rows[0].direction).to.equal('OUTGOING');
		expect(rows[0].auxiliary).to.equal(true);
		expect(rows[0].unresolved).to.deep.equal({
			code: 'CHANNEL_OMITTED_AT_RESTORE',
			channelIds: [id]
		});
		expect(rows[0]).to.not.have.property('preimage');
		expect(rows[0]).to.not.have.property('failureDescription');
		const cancel = await request(portAgain, 'POST', '/payment/cancel', {
			paymentHash: hash.toString('hex')
		});
		expect(cancel.status).to.equal(409);
		expect((cancel.body.error as { code: string }).code).to.equal(
			'PAYMENT_UNRESOLVED'
		);
		const after = (await request(portAgain, 'GET', '/payments')).body
			.result as Array<Record<string, unknown>>;
		expect(after[0].status).to.equal('PENDING');
	});

	/** A wallet set to apply a peer's checkpoint without asking. */
	const AUTO = {
		recoveryMode: 'peer-storage' as const,
		recoveryAutoApply: true,
		recoveryAutoApplySettleMs: 300,
		recoveryAutoApplyMaxWaitMs: 3000
	};

	interface IAutoStatus {
		state: string;
		capsules: { candidates: number; best: unknown };
		restore?: { inProgress: boolean; lastEvent?: { type: string } };
		autoApply: {
			enabled: boolean;
			phase: string;
			settleUntil: number | null;
			lastReason: string | null;
			refusal?: { code: string; assetChannels: unknown[] };
			skippedAssetChannels?: unknown[];
		};
	}

	const statusOf = async (port: number): Promise<IAutoStatus> => {
		const res = await request(port, 'GET', '/recovery/status');
		expect(res.status).to.equal(200);
		return res.body.result as unknown as IAutoStatus;
	};

	/** The automatic apply has decided: what the status then says. */
	const decided = async (port: number): Promise<IAutoStatus> => {
		const deadline = Date.now() + 20_000;
		for (;;) {
			const status = await statusOf(port);
			const phase = status.autoApply.phase;
			if (phase === 'applied' || phase === 'refused') return status;
			if (Date.now() > deadline) {
				throw new Error(`the automatic apply stayed ${phase}`);
			}
			await new Promise((resolve) => setTimeout(resolve, 50));
		}
	};

	it('refuses the automatic apply of a capsule that holds an asset channel as the route does: nothing is installed, no channel is left out, GET /recovery/status says so with the channels, and the confirmed call then leaves them out', async () => {
		const { blob, id, peerId, hash } = await lostWallet('capsule applied');
		const daemon = await boot('capsule-auto', {
			mnemonic: MNEMONICS[0],
			...AUTO
		});
		const dataDir = dirs[dirs.length - 1];
		const port = portOf(daemon);
		const listed = [
			{ channelId: id, peerPubkey: peerId, capacitySats: 2_000_000 }
		];
		const progress: Array<Record<string, unknown>> = [];
		daemon.node.on('recovery:restore-progress', (data) => {
			progress.push(data as Record<string, unknown>);
		});
		expect((await statusOf(port)).autoApply).to.deep.equal({
			enabled: true,
			phase: 'idle',
			settleUntil: null,
			lastReason: null
		});
		daemon.node.getNode().emit('peer_storage:retrieved', PEER, blob);

		// Refused, by the code the route answers with, and the wallet runs
		// on as the empty wallet it was, with the checkpoint still waiting.
		const status = await decided(port);
		expect(status.autoApply.phase).to.equal('refused');
		expect(status.autoApply.lastReason).to.match(/^ASSET_PROVIDER_REQUIRED: /);
		expect(status.state).to.equal('running');
		expect(status.capsules.candidates).to.equal(1);
		expect(status.capsules.best).to.not.equal(null);
		expect(status.restore?.lastEvent?.type).to.equal('capsule:auto-refused');
		expect((await request(port, 'GET', '/info')).status).to.equal(200);
		expect((await request(port, 'GET', '/channels')).body.result).to.deep.equal(
			[]
		);
		expect((await request(port, 'GET', '/payments')).body.result).to.deep.equal(
			[]
		);
		expect(
			fs.readdirSync(dataDir).filter((name) => name.includes('capsule-restore'))
		).to.deep.equal([]);

		// The status and the event name the channels, which is what a client
		// shows before it asks for them to be left out.
		expect(status.autoApply.refusal).to.deep.equal({
			code: 'ASSET_PROVIDER_REQUIRED',
			assetChannels: listed
		});
		const event = progress.find(
			(entry) => entry.type === 'capsule:auto-refused'
		);
		expect(event).to.not.equal(undefined);
		expect(event!.detail).to.equal(status.autoApply.lastReason);
		expect(event!.refusal).to.deep.equal(status.autoApply.refusal);

		// A second capsule arrival does not run it again, and nothing was
		// left out by the wallet itself.
		daemon.node.getNode().emit('peer_storage:retrieved', PEER, blob);
		await new Promise((resolve) => setTimeout(resolve, 600));
		expect((await statusOf(port)).autoApply).to.deep.equal(status.autoApply);
		expect(
			progress.filter((entry) => entry.type === 'capsule:auto-refused')
		).to.have.length(1);

		// The route answers the same refusal, and the confirmed call with
		// omitAssetChannels restores the rest.
		const refused = await request(port, 'POST', '/recovery/restore-capsule', {
			confirm: true
		});
		expect(refused.status, JSON.stringify(refused.body)).to.equal(409);
		expect(refused.body.error).to.include({ code: 'ASSET_PROVIDER_REQUIRED' });
		expect((refused.body.error as { details?: unknown }).details).to.deep.equal(
			{ assetChannels: listed }
		);
		const restored = await request(port, 'POST', '/recovery/restore-capsule', {
			confirm: true,
			omitAssetChannels: true
		});
		expect(restored.status, JSON.stringify(restored.body)).to.equal(200);
		const result = restored.body.result as Record<string, unknown>;
		expect(result.tier).to.equal(2);
		expect(result.omittedAssetChannels).to.deep.equal(listed);
		expect(result.unresolvedPayments).to.deep.equal([hash.toString('hex')]);
		expect(result.restartRequired).to.equal(true);

		// Restored, the refusal is no longer what the status says.
		const after = await statusOf(port);
		expect(after.state).to.equal('restart-required');
		expect(after.autoApply).to.not.have.property('refusal');
	});

	it('refuses the automatic apply by the code of a provider that cannot restore, and applies a capsule its provider can restore with its channels', async () => {
		const { blob, id, peerId } = await lostWallet('capsule with a provider');
		const listed = [
			{ channelId: id, peerPubkey: peerId, capacitySats: 2_000_000 }
		];

		// An extension is attached, and its provider does not say it can
		// restore these channels.
		const unable = await boot('capsule-auto-unable', {
			mnemonic: MNEMONICS[0],
			...AUTO,
			extensions: [assets(auxiliaryChannels())]
		});
		unable.node.getNode().emit('peer_storage:retrieved', PEER, blob);
		const refused = await decided(portOf(unable));
		expect(refused.autoApply.phase).to.equal('refused');
		expect(refused.autoApply.lastReason).to.match(/^ASSET_RESTORE_REFUSED: /);
		expect(refused.autoApply.refusal).to.deep.equal({
			code: 'ASSET_RESTORE_REFUSED',
			assetChannels: listed
		});
		expect(
			(await request(portOf(unable), 'GET', '/channels')).body.result
		).to.deep.equal([]);
		await unable.stop();

		// One that says it can: the capsule is applied, with its channel,
		// and there is no refusal to read.
		const able = await boot('capsule-auto-able', {
			mnemonic: MNEMONICS[0],
			...AUTO,
			extensions: [
				assets({ ...auxiliaryChannels(), canRestore: (): boolean => true })
			]
		});
		able.node.getNode().emit('peer_storage:retrieved', PEER, blob);
		const applied = await decided(portOf(able));
		expect(
			applied.autoApply.phase,
			String(applied.autoApply.lastReason)
		).to.equal('applied');
		expect(applied.autoApply).to.not.have.property('refusal');
		const channels = (await request(portOf(able), 'GET', '/channels')).body
			.result as Array<Record<string, unknown>>;
		expect(channels.map((channel) => channel.channelId)).to.deep.equal([id]);
		expect(channels[0].auxiliary).to.equal(true);
	});

	it('skips the asset entry of a capsule that is a backup only, by the route and by the automatic apply alike, and lists it where each is read', async () => {
		const { blob, id, peerId } = await lostWallet('capsule backup only', false);
		const listed = [
			{ channelId: id, peerPubkey: peerId, capacitySats: 2_000_000 }
		];

		// The route: Tier 1 refuses nothing. The entry is skipped with its
		// reason, and listed as an asset channel beside it.
		const manual = await boot('capsule-tier1', {
			mnemonic: MNEMONICS[0],
			recoveryMode: 'peer-storage'
		});
		manual.node.getNode().emit('peer_storage:retrieved', PEER, blob);
		const answer = await request(
			portOf(manual),
			'POST',
			'/recovery/restore-capsule',
			{ confirm: true }
		);
		expect(answer.status, JSON.stringify(answer.body)).to.equal(200);
		const result = answer.body.result as {
			tier: number;
			recovering: string[];
			skipped: Array<{ channelId: string; reason: string }>;
			skippedAssetChannels?: unknown;
		};
		expect(result.tier).to.equal(1);
		expect(result.recovering).to.deep.equal([]);
		expect(result.skipped.map((entry) => entry.channelId)).to.deep.equal([id]);
		expect(result.skippedAssetChannels).to.deep.equal(listed);
		expect(result).to.not.have.property('omittedAssetChannels');
		expect(
			(await request(portOf(manual), 'GET', '/channels')).body.result
		).to.deep.equal([]);
		await manual.stop();

		// The automatic apply does the same, and the status keeps the list
		// nobody was there to be answered with.
		const auto = await boot('capsule-tier1-auto', {
			mnemonic: MNEMONICS[0],
			...AUTO
		});
		auto.node.getNode().emit('peer_storage:retrieved', PEER, blob);
		const status = await decided(portOf(auto));
		expect(
			status.autoApply.phase,
			String(status.autoApply.lastReason)
		).to.equal('applied');
		expect(status.autoApply.skippedAssetChannels).to.deep.equal(listed);
		expect(status.autoApply).to.not.have.property('refusal');
		expect(
			(await request(portOf(auto), 'GET', '/channels')).body.result
		).to.deep.equal([]);
	});

	it('says nothing of asset channels on a refusal that is not about them: the status and the event are the bytes they were', async () => {
		const methods = BeignetNode.prototype as unknown as Record<
			string,
			(this: unknown, ...args: unknown[]) => unknown
		>;
		expect(
			JSON.stringify(
				methods.describeAutoApply.call({
					_recoveryAutoApply: true,
					_bootTargetEmpty: true,
					_restartRequired: false,
					_autoApply: {
						phase: 'refused',
						lastReason: 'CAPSULE_RESTORE_TARGET_DIRTY: holds state'
					}
				})
			)
		).to.equal(
			'{"enabled":true,"phase":"refused","settleUntil":null,' +
				'"lastReason":"CAPSULE_RESTORE_TARGET_DIRTY: holds state"}'
		);

		// A database that is not empty when the capsule comes: refused as
		// the route refuses it, with no word of asset channels.
		const { blob } = await lostWallet('capsule on a wallet in use');
		const daemon = await boot('capsule-auto-dirty', {
			mnemonic: MNEMONICS[0],
			...AUTO
		});
		const port = portOf(daemon);
		const progress: Array<Record<string, unknown>> = [];
		daemon.node.on('recovery:restore-progress', (data) => {
			progress.push(data as Record<string, unknown>);
		});
		const own = await request(port, 'POST', '/invoice/create', {
			amountSats: 1,
			description: 'local state'
		});
		expect(own.body.ok).to.equal(true);
		daemon.node.getNode().emit('peer_storage:retrieved', PEER, blob);
		const status = await decided(port);
		expect(status.autoApply.phase).to.equal('refused');
		expect(status.autoApply.lastReason).to.match(
			/^CAPSULE_RESTORE_TARGET_DIRTY: /
		);
		expect(Object.keys(status.autoApply)).to.deep.equal([
			'enabled',
			'phase',
			'settleUntil',
			'lastReason'
		]);
		const event = progress.find(
			(entry) => entry.type === 'capsule:auto-refused'
		);
		expect(Object.keys(event!)).to.deep.equal(['type', 'detail']);
	});

	it('lists what a restore left out: the channels the engine skipped at Tier 2, and the asset entries of the backup at Tier 1', () => {
		const overlay = new FeatureFlags();
		overlay.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
		const taproot = new FeatureFlags();
		taproot.setCompulsory(Feature.OPTION_TAPROOT);
		const entry = (
			channelId: string,
			channelType: string
		): IStaticChannelBackup['channels'][number] =>
			({
				channelId,
				peerNodeId: PEER,
				peerAddresses: [],
				fundingTxid: '00'.repeat(32),
				fundingOutputIndex: 0,
				fundingSatoshis: '250000',
				channelKeyIndex: 1,
				channelType
			}) as unknown as IStaticChannelBackup['channels'][number];
		const asset = 'aa'.repeat(32);
		const scb = {
			version: 1,
			network: 'regtest',
			createdAt: 1,
			channels: [
				entry(asset, overlay.toBuffer().toString('hex')),
				entry('bb'.repeat(32), taproot.toBuffer().toString('hex')),
				entry('cc'.repeat(32), ''),
				entry('dd'.repeat(32), 'not hex')
			]
		} as unknown as IStaticChannelBackup;

		expect(restoreOmittedAssetChannels({ tier: 1, scb })).to.deep.equal([
			{ channelId: asset, peerPubkey: PEER, capacitySats: 250_000 }
		]);
		// At Tier 2 the engine's word is the list, whatever the backup names.
		expect(restoreOmittedAssetChannels({ tier: 2, scb })).to.deep.equal([]);
		expect(
			restoreOmittedAssetChannels({
				tier: 2,
				scb,
				omittedAuxiliaryChannels: [
					{
						channelId: 'ee'.repeat(32),
						peerPubkey: PEER,
						capacitySatoshis: 1_000_000n
					}
				]
			})
		).to.deep.equal([
			{ channelId: 'ee'.repeat(32), peerPubkey: PEER, capacitySats: 1_000_000 }
		]);
	});

	it('hands a guardian restore no provider, and gives a journal that holds an asset channel the refusal of one this build never replicates', async () => {
		// The boot decision of a guardian mode is made before any extension
		// is attached, so the restore it builds cannot be handed one. It is
		// not meant to be: no guardian journal holds an asset channel.
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		const assembly = require('../../src/lightning/recovery/assembly') as {
			buildGuardianRecovery: (
				config: Record<string, unknown>
			) => Promise<unknown>;
		};
		const original = assembly.buildGuardianRecovery;
		const seen: Array<{ keys: string[]; attached: number }> = [];
		let attached = 0;
		let asked = 0;
		const id = 'cd'.repeat(32);
		const given: IAuxiliaryChannelConfig = {
			...auxiliaryChannels(),
			canRestore: (): boolean => {
				asked++;
				return true;
			}
		};
		assembly.buildGuardianRecovery = async (config): Promise<unknown> => {
			seen.push({ keys: Object.keys(config), attached });
			return {
				kind: 'restore-required',
				buildRestoreDriver: () => ({
					// What the driver throws after it replayed such a journal.
					restore: async (): Promise<never> => {
						throw new AuxiliaryGuardianRestoreError([id]);
					}
				})
			};
		};
		const dataDir = tmpDir('guardian-restore');
		dirs.push(dataDir);
		let node: BeignetNode | undefined;
		try {
			node = await BeignetNode.create({
				...OFFLINE,
				dataDir,
				mnemonic: MNEMONICS[0],
				recoveryMode: 'quorum',
				// x coordinates of G, 2G and 3G.
				recoveryGuardians: [
					'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798@https://g1.example.com',
					'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5@https://g2.example.com',
					'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9@https://g3.example.com'
				],
				extensions: [
					{
						id: 'assets',
						version: '1.0.0',
						api: EXTENSION_API_VERSION,
						attach: (): { auxiliaryChannels: IAuxiliaryChannelConfig } => {
							attached++;
							return { auxiliaryChannels: given };
						}
					}
				]
			} as BeignetNodeOptions);
			let refusal: unknown;
			try {
				await node.restoreFromGuardians();
			} catch (err) {
				refusal = err;
			}
			expect(seen).to.have.length(1);
			expect(seen[0].attached).to.equal(0);
			expect(seen[0].keys).to.not.include('auxiliaryChannels');
			expect(asked).to.equal(0);
			expect(refusal).to.be.instanceOf(BeignetError);
			expect((refusal as BeignetError).code).to.equal('ASSET_RESTORE_REFUSED');
			expect((refusal as BeignetError).message).to.equal(
				`The journal the guardians hold for this wallet carries 1 asset channel (${id}). ` +
					'This build never replicates an asset channel to guardians and ' +
					'cannot restore one from them, so nothing of the journal was ' +
					'installed (AUXILIARY_GUARDIAN_RESTORE_REFUSED).'
			);
		} finally {
			assembly.buildGuardianRecovery = original;
			await node?.destroy();
		}
	});

	it('does not start in a guardian mode over a stored asset channel: nothing is built, no guardian hears of it, and the database is as it was', async () => {
		// Three guardians to pin, resolved while their daemons run.
		const ports: number[] = [];
		const entries: string[] = [];
		const guardians: IStartedDaemon[] = [];
		for (let index = 0; index < 3; index++) {
			const listenPort = await freePort();
			ports.push(listenPort);
			guardians.push(
				await boot(`start-host-${index}`, {
					mnemonic: MNEMONICS[index],
					listenPort,
					guardianServe: true
				})
			);
		}
		for (let index = 0; index < 3; index++) {
			const info = await request(portOf(guardians[index]), 'GET', '/info');
			const nodeId = (info.body.result as { nodeId: string }).nodeId;
			const resolved = await request(
				portOf(guardians[0]),
				'POST',
				'/recovery/resolve-guardian',
				{ uri: `${nodeId}@127.0.0.1:${ports[index]}` }
			);
			expect(resolved.status, JSON.stringify(resolved.body)).to.equal(200);
			entries.push((resolved.body.result as { entry: string }).entry);
		}
		// In their place, listeners that count whoever reaches them.
		for (const guardian of guardians) await guardian.stop();
		let contacts = 0;
		const listeners: net.Server[] = [];
		for (const port of ports) {
			const listener = net.createServer((socket) => {
				contacts++;
				socket.destroy();
			});
			await new Promise<void>((resolve) =>
				listener.listen(port, '127.0.0.1', resolve)
			);
			listeners.push(listener);
		}

		try {
			// A wallet's database that holds an asset channel.
			const tag = 'guardian-start';
			const alice = assetHost(tag, 1, {}, { sqlite: true });
			const bob = assetHost(tag, 2);
			connectHosts(alice, bob);
			const channelId = await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 700n,
				acceptorUnits: 300n
			});
			const hex = channelId.toString('hex');
			const row = alice.storage!.loadChannel(hex)!;
			alice.node.destroy();
			bob.node.destroy();
			const dataDir = tmpDir('guardian-start');
			dirs.push(dataDir);
			const file = path.join(dataDir, 'regtest.db');
			const seeded = new SqliteStorage(file);
			seeded.open();
			seeded.saveChannel(hex, row.state, row.peerPubkey);
			seeded.close();
			// The wallet runs with it while it has no guardian backup, and
			// stores it as the daemon stores every row.
			const listsIt = async (): Promise<void> => {
				const plain = await startDaemon({
					...OFFLINE,
					dataDir,
					mnemonic: MNEMONICS[3],
					recoveryMode: 'off',
					extensions: [assets(auxiliaryChannels())]
				});
				daemons.push(plain);
				const listed = await request(portOf(plain), 'GET', '/channels');
				expect(
					(
						listed.body.result as Array<{
							channelId: string;
							auxiliary?: boolean;
						}>
					).map((channel) => [channel.channelId, channel.auxiliary])
				).to.deep.equal([[hex, true]]);
				await plain.stop();
			};
			await listsIt();
			const before = Object.fromEntries(tables(file));
			expect(before.channels).to.have.length(1);

			for (const recoveryMode of ['quorum', 'async-remote']) {
				let refusal: unknown;
				try {
					daemons.push(
						await startDaemon({
							...OFFLINE,
							dataDir,
							mnemonic: MNEMONICS[3],
							recoveryMode,
							recoveryGuardians: entries,
							extensions: [assets(auxiliaryChannels())]
						})
					);
				} catch (err) {
					refusal = err;
				}
				expect(refusal, recoveryMode).to.be.instanceOf(BeignetError);
				expect((refusal as BeignetError).code).to.equal(
					'ASSET_GUARDIAN_START_REFUSED'
				);
				expect((refusal as BeignetError).message).to.equal(
					`This wallet holds 1 asset channel (${hex}) and its recovery ` +
						`mode is ${recoveryMode}, which backs it up to guardians. A ` +
						'guardian backup cannot restore an asset channel, so the ' +
						'wallet was not started and nothing was sent to a guardian. ' +
						'Close the asset channel, or start without the guardian ' +
						'backup (recovery mode peer-storage or off).'
				);
				// Nothing reached a guardian, and nothing was written: no
				// journal, no frame, and the channel's row as it was.
				expect(contacts, recoveryMode).to.equal(0);
				expect(Object.fromEntries(tables(file))).to.deep.equal(before);
			}

			// Without the guardian backup the same database starts again, and
			// the channel is there to be closed.
			await listsIt();
		} finally {
			for (const listener of listeners) {
				await new Promise<void>((resolve) => listener.close(() => resolve()));
			}
		}
	});
});
