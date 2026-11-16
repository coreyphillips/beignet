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

import { expect } from 'chai';
import * as bip39 from 'bip39';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import { AddressInfo } from 'net';
import * as os from 'os';
import * as path from 'path';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';
import {
	EXTENSION_API_VERSION,
	IBeignetExtension
} from '../../src/cli/extension';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { AuxiliaryProviderRequiredError } from '../../src/lightning/node/types';
import {
	AuxiliaryGuardianModeError,
	AuxiliaryRestoreRefusedError
} from '../../src/lightning/recovery';
import { withAssetOpens } from '../lightning/helpers/auxiliary-nodes';
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
	});
});
