/**
 * Issue #1203: the autoRebalance timer is held to the drain and the daily
 * limit.
 *
 * The timer ran inside the engine and called executeRebalanceRecommendations
 * itself, so a draining node or an exhausted daily limit did not stop it, and
 * the fees it paid never reached the shared ledger. A real node boots here
 * (over an unreachable Electrum) with the advisor run stubbed, so what is
 * under test is the timer the node starts and the admission it goes through.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { IRebalanceExecutionSummary } from '../../src/lightning/node/types';

const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

async function until(check: () => boolean): Promise<void> {
	const deadline = Date.now() + 5_000;
	while (!check()) {
		if (Date.now() > deadline) throw new Error('condition not reached');
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
}

describe('Issue #1203: automatic rebalances under the shared rails', function () {
	this.timeout(30_000);

	let dir: string;
	let node: BeignetNode;
	/** The ledger while each stubbed advisor run was in flight. */
	const spentDuringRun: number[] = [];
	let stopRequested: (() => boolean) | undefined;
	let feeSpentMsat = 250_000n;
	const refusals: string[] = [];

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1203-'));
		node = await BeignetNode.create({
			network: 'regtest',
			dataDir: dir,
			logLevel: 'warn',
			...OFFLINE_ELECTRUM,
			dailySpendLimitSats: 10_000,
			autoRebalance: { enabled: true, budgetSatsPerDay: 1_000, intervalMs: 20 }
		});
		node.on('log', (entry) => {
			if (entry.message === 'Automatic rebalance failed') {
				refusals.push(String(entry.data?.error));
			}
		});
		node.getNode().executeRebalanceRecommendations = async (options?: {
			stopRequested?: () => boolean;
		}): Promise<IRebalanceExecutionSummary> => {
			spentDuringRun.push(node.getDailySpendInfo().spentSats);
			stopRequested = options?.stopRequested;
			return {
				attempts: [],
				succeeded: 1,
				failed: 0,
				skippedBudget: 0,
				feeSpentMsat,
				budgetRemainingMsat: 0n
			};
		};
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('leaves the engine timer off and runs the node one', () => {
		const engine = node.getNode() as unknown as { autoRebalanceTimer: unknown };
		expect(engine.autoRebalanceTimer).to.equal(null);
		const facade = node as unknown as { _autoRebalanceTimer: unknown };
		expect(facade._autoRebalanceTimer).to.not.equal(undefined);
	});

	it('charges each run the day budget up front and keeps the fees it paid', async () => {
		await until(() => spentDuringRun.length >= 2);
		expect(spentDuringRun[0]).to.equal(1_000);
		// Each later run starts from the one before, less what it gave back.
		expect(spentDuringRun[1] - spentDuringRun[0]).to.equal(250);
	});

	it('stops at the drain, inside a run and before the next', async () => {
		expect(stopRequested?.()).to.equal(false);
		node.setDraining(true);
		try {
			expect(stopRequested?.()).to.equal(true);
			const runs = spentDuringRun.length;
			const seen = refusals.length;
			await until(() => refusals.length >= seen + 3);
			expect(refusals[refusals.length - 1]).to.match(/draining/i);
			expect(spentDuringRun.length).to.equal(runs);
		} finally {
			node.setDraining(false);
		}
	});

	it('stops once the daily limit cannot hold the day budget', async () => {
		feeSpentMsat = 1_000_000n;
		await until(() => refusals.some((r) => /Daily spend limit/.test(r)));
		const runs = spentDuringRun.length;
		const seen = refusals.length;
		await until(() => refusals.length >= seen + 3);
		expect(spentDuringRun.length).to.equal(runs);
		expect(node.getDailySpendInfo().spentSats).to.be.at.most(10_000);
	});

	it('clears the timer on destroy', async () => {
		await node.destroy();
		const facade = node as unknown as { _autoRebalanceTimer: unknown };
		expect(facade._autoRebalanceTimer).to.equal(undefined);
	});
});
