/**
 * Recovery Phase 7: the direct-funding payer's transient state
 * (docs/RECOVERY-PROTOCOL.md 5.10, issue #613).
 *
 * The payer holds one piece of state 5.10 has to classify: the record of a
 * funding it is about to sign for. Its disposition is **D1, persist before
 * emit** — the attestation, the negotiated transaction and our own witness are
 * journaled in the same transition as the message that exposes them, which
 * here is the witness frame itself. 5.10 says prose classification is not
 * acceptance, so each boundary is killed and the outcome asserted.
 *
 * The victim is a real process with a real SQLite file and a real encryption
 * key, SIGKILLed at the boundary (the exit signal is asserted, so no graceful
 * path ever runs) and then judged from the file it left behind. Three
 * boundaries:
 *
 *   pre-persist    the record must hold no witness, and none may have left
 *   post-persist   the record must hold the whole commitment, witness included
 *   post-witness   the same, with the witness on the wire
 *
 * And the half that makes D1 worth having: a second life against the same file
 * must resume the SAME offer over the SAME coin rather than committing a second
 * one, which is the fork's defect D6 under a crash.
 */

import { expect } from 'chai';
import { ChildProcess, spawn } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { DirectFundingPaymentStore } from '../../src/lightning/direct-funding/sender/records';
import { IDfPaymentRecord } from '../../src/lightning/direct-funding/sender/types';
import { DF_CRASH_DB_KEY, DfKillLabel } from './helpers/df-sender-crash-child';

const CHILD = path.join(__dirname, 'helpers', 'df-sender-crash-child.ts');
const REPO_ROOT = path.join(__dirname, '..', '..');

interface IChildRun {
	lines: string[];
	/** The signal the process died from; null when it exited on its own. */
	signal: NodeJS.Signals | null;
}

/**
 * Run one life. When `killAt` is a boundary, the child announces it, and this
 * SIGKILLs the process there; with `none` the life runs to completion.
 */
function runLife(
	dbPath: string,
	seed: Buffer,
	killAt: DfKillLabel,
	timeoutMs = 30_000
): Promise<IChildRun> {
	return new Promise((resolve, reject) => {
		const proc: ChildProcess = spawn(
			process.execPath,
			['-r', 'ts-node/register', CHILD, dbPath, seed.toString('hex'), killAt],
			{ cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'inherit'] }
		);
		const lines: string[] = [];
		let killed = false;
		const timer = setTimeout(() => {
			proc.kill('SIGKILL');
			reject(new Error(`child did not reach ${killAt}: ${lines.join(' | ')}`));
		}, timeoutMs);
		readline.createInterface({ input: proc.stdout! }).on('line', (line) => {
			lines.push(line);
			if (killAt !== 'none' && line === `reached:${killAt}`) {
				killed = true;
				proc.kill('SIGKILL');
			}
		});
		proc.on('exit', (_code, signal) => {
			clearTimeout(timer);
			if (killAt !== 'none' && !killed) {
				reject(new Error(`child settled without reaching ${killAt}`));
				return;
			}
			resolve({ lines, signal });
		});
		proc.on('error', reject);
	});
}

/** What the file holds now, read the way a restarted payer reads it. */
function recordsOnDisk(dbPath: string): IDfPaymentRecord[] {
	const storage = new SqliteStorage(dbPath, undefined, {
		encryptionKey: DF_CRASH_DB_KEY
	});
	storage.open();
	try {
		const store = new DirectFundingPaymentStore({
			storage: {
				saveWalletData: (key, value): void =>
					storage.saveWalletData(key, value),
				loadWalletData: (key): string | null => storage.loadWalletData(key)
			}
		});
		store.restore();
		return store.list();
	} finally {
		storage.close();
	}
}

const valueOf = (lines: string[], prefix: string): string | undefined =>
	lines.find((l) => l.startsWith(prefix))?.slice(prefix.length);

describe('Recovery phase 7: direct funding payer (5.10 D1)', function () {
	this.timeout(120_000);

	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-df-kill-'));
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('killed BEFORE the persist, no witness exists anywhere', async () => {
		const dbPath = path.join(dir, 'pre.db');
		const seed = crypto.randomBytes(32);
		const run = await runLife(dbPath, seed, 'pre-persist');
		expect(run.signal, 'the life ended gracefully').to.equal('SIGKILL');
		expect(run.lines, 'a witness left before the record landed').to.not.include(
			'witness-seen'
		);
		const records = recordsOnDisk(dbPath);
		expect(records, 'the offer itself was never recorded').to.have.length(1);
		// The record exists, because it is opened before the FIRST frame goes
		// out, and it holds nothing about a witness because none was made.
		expect(records[0].status).to.equal('OFFERED');
		expect(records[0].witness).to.equal(undefined);
		expect(records[0].attestation).to.equal(undefined);
		expect(records[0].negotiatedTx).to.equal(undefined);
	});

	it('killed AFTER the persist, the whole commitment survived the kill', async () => {
		const dbPath = path.join(dir, 'post.db');
		const seed = crypto.randomBytes(32);
		const run = await runLife(dbPath, seed, 'post-persist');
		expect(run.signal).to.equal('SIGKILL');
		// The persist is what the witness send waits on, so nothing left the
		// device: this is the ordering the disposition is named for.
		expect(run.lines).to.not.include('witness-seen');
		const records = recordsOnDisk(dbPath);
		expect(records).to.have.length(1);
		const record = records[0];
		expect(record.status).to.equal('SIGNED_PENDING');
		expect(record.attestation, 'the attestation did not survive').to.not.equal(
			undefined
		);
		expect(record.negotiatedTx, 'the transaction did not survive').to.be.a(
			'string'
		);
		expect(record.witness, 'our own witness did not survive').to.have.length(2);
		expect(record.fundingTxid).to.be.a('string');
		expect(record.frozen).to.equal(true);
	});

	it('killed AFTER the witness, the record already describes what left', async () => {
		const dbPath = path.join(dir, 'witness.db');
		const seed = crypto.randomBytes(32);
		const run = await runLife(dbPath, seed, 'post-witness');
		expect(run.signal).to.equal('SIGKILL');
		expect(run.lines).to.include('witness-seen');
		const record = recordsOnDisk(dbPath)[0];
		// The scenario the whole disposition exists for: a crash between the
		// witness leaving and the caller hearing about it. The fork lost every
		// trace of a payment that may already be on chain (defect D7).
		expect(record.status).to.equal('SIGNED_PENDING');
		expect(record.witness).to.have.length(2);
		expect(record.negotiatedTx).to.be.a('string');
		expect(record.fundingTxid).to.be.a('string');
	});

	it('a second life resumes the recorded attempt, never a second coin', async () => {
		const dbPath = path.join(dir, 'resume.db');
		const seed = crypto.randomBytes(32);
		const first = await runLife(dbPath, seed, 'post-witness');
		const before = recordsOnDisk(dbPath)[0];
		const second = await runLife(dbPath, seed, 'none');
		expect(second.signal, 'the second life should settle on its own').to.equal(
			null
		);
		// It replays the record rather than re-running the exchange, so the
		// receiver never sees a second witness for the same request.
		expect(second.lines).to.not.include('witness-seen');
		expect(second.lines).to.include('settled:SIGNED_PENDING');
		const after = recordsOnDisk(dbPath);
		expect(after, 'a second attempt was opened').to.have.length(1);
		expect(after[0].offerId).to.equal(before.offerId);
		expect(after[0].spentTxid).to.equal(before.spentTxid);
		expect(valueOf(first.lines, 'coin:')).to.equal(
			valueOf(second.lines, 'coin:')
		);
	});
});
