import { expect } from 'chai';
import { FforState } from '../../src/lightning/ffor/types';
import { Feature } from '../../src/lightning/features/flags';
import {
	activate,
	AMOUNTS,
	createPair,
	expectHealthy,
	pay,
	record,
	restart,
	settleSlot
} from './helpers/ffor-concurrent-pair';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';

describe('Concurrent receive defaults', function () {
	this.timeout(120000);
	for (const version of [1, 2] as const) {
		for (const policy of [{ enabled: true }, null]) {
			it(`accepts version ${version} with ${
				policy ? 'omitted acceptance switch' : 'no settlement policy'
			}`, () => {
				const pair = createPair({ sPolicy: policy });
				activate(pair, AMOUNTS, true, version);
				expectHealthy(pair);
			});
		}
		it(`retains live version ${version} sync and payments after new-book acceptance is disabled at restart`, () => {
			const pair = createPair({ pushSat: 200000n, sPolicy: { enabled: true } });
			activate(pair, AMOUNTS, true, version);
			pair.sPolicy = { enabled: true, allowConcurrent: false };
			restart(pair, 'S');
			restart(pair, 'R');
			pair.link.reconnect();
			settleSlot(pair, 1);
			expect(pair.rManager.fforSync(pair.channelId).ok).to.equal(true);
			expect(record(pair.rChannel).voucherOutcomes?.[0]?.outcome).to.equal(
				'fulfilled'
			);
			expect(record(pair.rChannel).concurrentVersion).to.equal(version);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			pay(pair, 'R', 1000000n);
			pay(pair, 'S', 2000000n);
			expectHealthy(pair);
		});
		it(`negotiates version ${version} with omitted node and settlement switches`, () => {
			const w = createConcurrentWorld({
				sExtra: { fforConcurrent: undefined, fforSettle: { enabled: true } },
				rExtra: { fforConcurrent: undefined }
			});
			expect(
				w.s.getLocalFeatures().hasFeature(Feature.OPTION_FF_CONCURRENT)
			).to.equal(true);
			expect(
				w.r.getLocalFeatures().hasFeature(Feature.OPTION_FF_CONCURRENT)
			).to.equal(true);
			activateWorld(w, true, undefined, version);
		});
	}
});
