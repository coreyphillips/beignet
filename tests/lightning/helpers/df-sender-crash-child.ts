/**
 * Crash child for the direct-funding persist-before-emit kill points (issue
 * #613, RECOVERY-PROTOCOL 5.10 disposition D1). NOT a test file: spawned by
 * recovery-phase7-direct-funding.test.ts as
 *
 *   node -r ts-node/register df-sender-crash-child.ts <dbPath> <seed> <label>
 *
 * and killed with SIGKILL at the named boundary. Protocol on stdout, one line
 * each:
 *
 *   request:<base64url>   the envelope this life will pay
 *   coin:<txid>:<vout>    the outpoint it selected
 *   reached:<label>       the boundary is here; the parent kills now
 *   witness-seen          the receiver got the payer's witness
 *   settled:<status>      the send resolved (label `none` only)
 *   error:<code>          the send was refused
 *
 * The storage is a real SQLite file with a real encryption key, so a record
 * the parent finds after the kill is one that genuinely survived it. The
 * receiver is scripted in-process: what is under test is the payer's ordering,
 * not a channel.
 */

import crypto from 'crypto';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { DirectFundingSender } from '../../../src/lightning/direct-funding/sender/engine';
import { DirectFundingPaymentStore } from '../../../src/lightning/direct-funding/sender/records';
import { chainHashForNetwork } from '../../../src/lightning/direct-funding/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	acceptingReceiver,
	FakeSenderWallet,
	makeCoin,
	mintRequest,
	registryWith,
	ScriptedReceiverLane
} from './df-sender';

export const DF_CRASH_DB_KEY = Buffer.alloc(32, 0x5d);

/** Where a life may be killed. `none` runs to completion. */
export type DfKillLabel =
	| 'pre-persist'
	| 'post-persist'
	| 'post-witness'
	| 'none';

function spinForever(): never {
	// Busy-spin rather than exit: the parent's SIGKILL is what ends this
	// process, so no graceful path ever runs.
	for (;;) {
		Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
	}
}

async function main(): Promise<void> {
	const [dbPath, seedHex, label] = process.argv.slice(2) as [
		string,
		string,
		DfKillLabel
	];
	if (!dbPath || !seedHex || !label) {
		process.stderr.write('usage: df-sender-crash-child <db> <seed> <label>\n');
		process.exit(2);
	}
	const seed = Buffer.from(seedHex, 'hex');
	const storage = new SqliteStorage(dbPath, undefined, {
		encryptionKey: DF_CRASH_DB_KEY
	});
	storage.open();

	// Everything about the request is derived from the seed, so a second life
	// against the same database pays the SAME request.
	const request = mintRequest({
		nodePrivkey: crypto.createHash('sha256').update(seed).digest(),
		amountSat: 100_000n
	});
	const persisted = storage.loadWalletData('df:test-request');
	const encoded = persisted ?? request.encoded;
	if (!persisted) storage.saveWalletData('df:test-request', encoded);
	// The coin is derived too: a resumed life must find the same outpoint the
	// record pinned.
	const coin = makeCoin(200_000);
	const coinSeed = storage.loadWalletData('df:test-coin');
	if (coinSeed) {
		const kept = JSON.parse(coinSeed) as { hex: string; privkey: string };
		coin.prevTx = require('bitcoinjs-lib').Transaction.fromHex(kept.hex);
		coin.txidHex = coin.prevTx.getId();
		coin.privkey = Buffer.from(kept.privkey, 'hex');
	} else {
		storage.saveWalletData(
			'df:test-coin',
			JSON.stringify({
				hex: coin.prevTx.toHex(),
				privkey: coin.privkey.toString('hex')
			})
		);
	}
	process.stdout.write(`request:${encoded}\n`);
	process.stdout.write(`coin:${coin.txidHex}:${coin.vout}\n`);

	const wallet = new FakeSenderWallet([coin]);
	const payments = new DirectFundingPaymentStore({
		storage: {
			saveWalletData: (key, value): void => {
				// The persist that records the witness. Killing BEFORE it must leave
				// no witness anywhere; killing AFTER it must leave the whole record.
				if (
					key === 'df:payments' &&
					value.includes('SIGNED_PENDING') &&
					label === 'pre-persist'
				) {
					process.stdout.write('reached:pre-persist\n');
					spinForever();
				}
				storage.saveWalletData(key, value);
				if (
					key === 'df:payments' &&
					value.includes('SIGNED_PENDING') &&
					label === 'post-persist'
				) {
					process.stdout.write('reached:post-persist\n');
					spinForever();
				}
			},
			loadWalletData: (key): string | null => storage.loadWalletData(key)
		}
	});
	payments.restore();

	const lane = new ScriptedReceiverLane(
		request,
		acceptingReceiver(request, {
			noReceipt: true,
			onWitness: (): void => {
				process.stdout.write('witness-seen\n');
				if (label === 'post-witness') {
					process.stdout.write('reached:post-witness\n');
					spinForever();
				}
			}
		})
	);
	const sender = new DirectFundingSender(
		{
			wallet,
			registry: registryWith(lane),
			payments,
			chainHash: (): Buffer => chainHashForNetwork(Network.REGTEST)
		},
		{ offerResendDelaysMs: [], offerTimeoutMs: 4_000, receiptTimeoutMs: 200 }
	);
	try {
		const result = await sender.send(encoded, {});
		process.stdout.write(`settled:${result.status}\n`);
	} catch (err) {
		const code = (err as { code?: string }).code ?? 'UNKNOWN';
		process.stdout.write(`error:${code}\n`);
	}
	storage.close();
}

void main();
