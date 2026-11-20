/**
 * A released build over a forwarding history that holds a forward with an
 * asset leg (issue #2098, step 7).
 *
 * From this build the SQLite database is at schema 21: forwarding_events
 * gains auxiliary_json, what marks a forward with an asset leg, empty for
 * every ordinary forward. This suite drives the published beignet 0.43.6
 * (schema 20) over a database written by this build and holds it to what
 * the downgrade promises: the release opens the database (it runs no
 * migration at or above its own version, and its required columns are all
 * there), lists a forward with an asset leg as an ordinary one at what its
 * legs were worth and counts it in its totals, and writes its own rows with
 * the column empty, which this build reads back as ordinary forwards.
 *
 * The released build is not a dependency of this repository. The suite runs
 * when BEIGNET_RELEASED_0_43_6 names an installed copy of it, and is skipped
 * without it:
 *
 *   npm install --prefix "$DIR" beignet@0.43.6
 *   BEIGNET_RELEASED_0_43_6="$DIR/node_modules/beignet" \
 *     npx mocha -r ts-node/register tests/lightning/forwarding-history-downgrade.test.ts
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const RELEASED = process.env.BEIGNET_RELEASED_0_43_6;

/** What this suite uses of the released build's storage. */
interface IReleasedStorage {
	open(): void;
	close(): void;
	getSchemaVersion(): number;
	saveForwardingEvent(event: {
		settledAt: number;
		inChannelId: string;
		outChannelId: string;
		amountInMsat: bigint;
		amountOutMsat: bigint;
		feeMsat: bigint;
	}): void;
	listForwardingEvents(): Array<Record<string, unknown>>;
	getForwardingSummary(): {
		count: number;
		volumeOutMsat: bigint;
		feesEarnedMsat: bigint;
	};
}

const releasedStorage = (file: string): IReleasedStorage => {
	const { SqliteStorage: Released } =
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		require(path.join(
			RELEASED as string,
			'dist',
			'lightning',
			'storage',
			'sqlite-storage.js'
		)) as { SqliteStorage: new (file: string) => IReleasedStorage };
	return new Released(file);
};

(RELEASED ? describe : describe.skip)(
	'beignet 0.43.6 over a forwarding history with a forward with an asset leg (#2098, step 7)',
	() => {
		let directory: string;

		beforeEach(() => {
			directory = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-fwd-down-'));
		});

		afterEach(() => {
			fs.rmSync(directory, { recursive: true, force: true });
		});

		it('opens the database, lists the forward as an ordinary one at what its legs were worth, and writes rows this build reads as ordinary', () => {
			const file = path.join(directory, 'node.db');
			const current = new SqliteStorage(file);
			current.open();
			current.saveForwardingEvent({
				settledAt: 200,
				inChannelId: 'aa'.repeat(32),
				outChannelId: 'bb'.repeat(32),
				amountInMsat: 5_010_000n,
				amountOutMsat: 5_000_000n,
				feeMsat: 10_000n,
				auxiliary: true,
				inAuxiliaryAmount: 5_010n,
				inWireAmountMsat: 354_000n,
				nextHopScid: '0102030405060708'
			});
			current.close();

			const old = releasedStorage(file);
			old.open();
			try {
				expect(old.getSchemaVersion()).to.equal(21);
				const listed = old.listForwardingEvents();
				expect(listed).to.have.length(1);
				expect(listed[0]).to.deep.include({
					settledAt: 200,
					amountInMsat: 5_010_000n,
					amountOutMsat: 5_000_000n,
					feeMsat: 10_000n
				});
				expect(listed[0].auxiliary).to.equal(undefined);
				expect(old.getForwardingSummary()).to.deep.equal({
					count: 1,
					volumeOutMsat: 5_000_000n,
					feesEarnedMsat: 10_000n
				});
				old.saveForwardingEvent({
					settledAt: 300,
					inChannelId: 'cc'.repeat(32),
					outChannelId: 'dd'.repeat(32),
					amountInMsat: 1_005n,
					amountOutMsat: 1_000n,
					feeMsat: 5n
				});
			} finally {
				old.close();
			}

			const again = new SqliteStorage(file);
			again.open();
			try {
				const [ordinary, marked] = again.listForwardingEvents();
				expect(ordinary.settledAt).to.equal(300);
				expect(ordinary.auxiliary).to.equal(undefined);
				expect(marked).to.deep.include({
					settledAt: 200,
					auxiliary: true,
					inAuxiliaryAmount: 5_010n,
					nextHopScid: '0102030405060708'
				});
				expect(again.getForwardingSummary()).to.deep.equal({
					count: 1,
					volumeOutMsat: 1_000n,
					feesEarnedMsat: 5n,
					auxiliary: {
						count: 1,
						volumeOutMsat: 5_000_000n,
						feesEarnedMsat: 10_000n
					}
				});
			} finally {
				again.close();
			}
		});
	}
);
