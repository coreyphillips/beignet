/**
 * FFOR concurrent receive, version 1: the durable selected version
 * (specs/CONCURRENT-RECEIVE.md sections 1.1 and 8).
 *
 * The selected version is persisted with the setup transcript and compared
 * with the stored ff_init and ff_accept bytes on load. A baseline record
 * serializes to exactly the JSON it did before the extension existed, and a
 * row written before the field existed loads as a baseline epoch. A row
 * whose field and transcript disagree is never read as a baseline epoch.
 */

import { expect } from 'chai';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	deserializeChannelState,
	deserializeFforEpoch,
	ISerializedFforEpoch,
	serializeChannelState,
	serializeFforEpoch
} from '../../src/lightning/storage/serialization';
import { FforState } from '../../src/lightning/ffor/types';
import {
	BASELINE_FIXTURE,
	fixtureRecord,
	fixtureTranscript
} from './helpers/ffor-concurrent-fixture';
import {
	activate,
	AMOUNTS,
	createPair,
	IPair,
	offer,
	pay,
	record,
	Side,
	TIP,
	vouchers,
	why
} from './helpers/ffor-concurrent-pair';

function stored(json: string): ISerializedFforEpoch {
	return JSON.parse(json);
}

/**
 * Restart one side from a serialized state a test has edited, the way a
 * row another build rewrote would come back.
 */
function restartFrom(
	pair: IPair,
	side: Side,
	edit: (ffor: ISerializedFforEpoch) => void
): { manager: ChannelManager; channel: Channel; enforce: number } {
	pair.link.disconnect();
	const old = side === 'S' ? pair.sChannel : pair.rChannel;
	const row = JSON.parse(
		JSON.stringify(serializeChannelState(old.getFullState()))
	);
	edit(row.ffor);
	const manager = new ChannelManager(
		side === 'S' ? pair.sConfig : pair.rConfig
	);
	const channel = new Channel(deserializeChannelState(row));
	const seen = { enforce: 0 };
	manager.on('ffor:enforce', () => seen.enforce++);
	manager.on('error', () => undefined);
	manager.restoreChannel(channel, side === 'S' ? pair.rPub : pair.sPub);
	manager.handleNewBlock(TIP);
	return {
		manager,
		channel,
		get enforce(): number {
			return seen.enforce;
		}
	};
}

describe('FFOR concurrent receive: persistence (CONCURRENT-RECEIVE.md 1.1, 8)', function () {
	this.timeout(60_000);

	describe('a baseline record is byte for byte what it was', () => {
		for (const role of ['R', 'S'] as const) {
			it(`role ${role}: serializes to the pinned pre-extension JSON`, () => {
				const json = JSON.stringify(serializeFforEpoch(fixtureRecord(role)));
				expect(json).to.equal(
					role === 'R' ? BASELINE_FIXTURE.record_r : BASELINE_FIXTURE.record_s
				);
				expect(json).to.not.include('concurrentVersion');
			});

			it(`role ${role}: the pinned row loads as a baseline epoch and writes back unchanged`, () => {
				const pinned =
					role === 'R' ? BASELINE_FIXTURE.record_r : BASELINE_FIXTURE.record_s;
				const loaded = deserializeFforEpoch(stored(pinned));
				expect(loaded).to.not.have.property('concurrentVersion');
				expect(loaded.params).to.not.have.property('concurrentVersion');
				expect(loaded.activationMismatch).to.equal(false);
				expect(JSON.stringify(serializeFforEpoch(loaded))).to.equal(pinned);
			});
		}

		it('a live baseline epoch writes no new key on either side', () => {
			const pair = createPair();
			activate(pair, AMOUNTS, false);
			for (const ch of [pair.sChannel, pair.rChannel]) {
				const json = JSON.stringify(
					serializeChannelState(ch.getFullState()).ffor
				);
				expect(json).to.not.include('concurrentVersion');
				expect(Object.keys(JSON.parse(json))).to.deep.equal(
					Object.keys(stored(BASELINE_FIXTURE.record_r))
				);
			}
		});

		it('a record given an explicit version 0 serializes as baseline', () => {
			const rec = fixtureRecord('R');
			rec.concurrentVersion = 0;
			expect(JSON.stringify(serializeFforEpoch(rec))).to.equal(
				BASELINE_FIXTURE.record_r
			);
		});
	});

	describe('a concurrent record', () => {
		for (const role of ['R', 'S'] as const) {
			it(`role ${role}: adds only the request and the selection, and round-trips`, () => {
				const rec = fixtureRecord(role, 1, 1);
				rec.concurrentVersion = 1;
				const out = serializeFforEpoch(rec);
				expect(out.concurrentVersion).to.equal(1);
				expect(out.params.concurrentVersion).to.equal(1);
				const baseline = stored(
					role === 'R' ? BASELINE_FIXTURE.record_r : BASELINE_FIXTURE.record_s
				);
				expect(Object.keys(out)).to.deep.equal([
					...Object.keys(baseline),
					'concurrentVersion'
				]);
				expect(Object.keys(out.params)).to.deep.equal([
					...Object.keys(baseline.params),
					'concurrentVersion'
				]);
				const back = deserializeFforEpoch(JSON.parse(JSON.stringify(out)));
				expect(back.concurrentVersion).to.equal(1);
				expect(back.params.concurrentVersion).to.equal(1);
				expect(back.activationMismatch).to.equal(false);
				expect(JSON.stringify(serializeFforEpoch(back))).to.equal(
					JSON.stringify(out)
				);
			});
		}

		it('R before ff_accept: the request is stored, nothing is selected yet', () => {
			const rec = fixtureRecord('R', 1);
			rec.state = FforState.NEGOTIATING;
			rec.acceptWire = null;
			rec.tSetup = null;
			const out = serializeFforEpoch(rec);
			expect(out.params.concurrentVersion).to.equal(1);
			expect(out).to.not.have.property('concurrentVersion');
			const back = deserializeFforEpoch(JSON.parse(JSON.stringify(out)));
			expect(back).to.not.have.property('concurrentVersion');
			expect(back.activationMismatch).to.equal(false);
		});

		it('a live concurrent epoch round-trips through the channel row on both sides', () => {
			const pair = createPair();
			activate(pair, AMOUNTS, true);
			for (const ch of [pair.sChannel, pair.rChannel]) {
				const row = JSON.parse(
					JSON.stringify(serializeChannelState(ch.getFullState()))
				);
				expect(row.ffor.concurrentVersion).to.equal(1);
				const back = deserializeChannelState(row).ffor!;
				expect(back.concurrentVersion).to.equal(1);
				expect(back.activationMismatch).to.equal(false);
				expect(back.state).to.equal(FforState.ACTIVE);
			}
		});
	});

	describe('the field is checked against the stored transcript on load', () => {
		function load(
			request: number | undefined,
			echo: number | undefined,
			edit: (row: ISerializedFforEpoch) => void
		): ReturnType<typeof deserializeFforEpoch> {
			const rec = fixtureRecord('S', request, echo);
			if (request === 1 && echo === 1) rec.concurrentVersion = 1;
			const row: ISerializedFforEpoch = JSON.parse(
				JSON.stringify(serializeFforEpoch(rec))
			);
			edit(row);
			return deserializeFforEpoch(row);
		}

		it('field and transcript agree on concurrent: no mismatch', () => {
			const back = load(1, 1, () => undefined);
			expect(back.concurrentVersion).to.equal(1);
			expect(back.activationMismatch).to.equal(false);
		});

		it('field and transcript agree on baseline: no mismatch', () => {
			const back = load(undefined, undefined, () => undefined);
			expect(back).to.not.have.property('concurrentVersion');
			expect(back.activationMismatch).to.equal(false);
		});

		it('the field was dropped from a concurrent row: still concurrent, and in dispute', () => {
			const back = load(1, 1, (row) => {
				delete row.concurrentVersion;
			});
			expect(back.concurrentVersion).to.equal(1);
			expect(back.activationMismatch).to.equal(true);
		});

		it('the field says concurrent over a baseline transcript: concurrent, and in dispute', () => {
			const back = load(undefined, undefined, (row) => {
				row.concurrentVersion = 1;
			});
			expect(back.concurrentVersion).to.equal(1);
			expect(back.activationMismatch).to.equal(true);
		});

		it('the stored request differs from the ff_init bytes: in dispute', () => {
			const dropped = load(1, 1, (row) => {
				delete row.params.concurrentVersion;
			});
			expect(dropped.concurrentVersion).to.equal(1);
			expect(dropped.activationMismatch).to.equal(true);
			const added = load(undefined, undefined, (row) => {
				row.params.concurrentVersion = 1;
			});
			expect(added.activationMismatch).to.equal(true);
		});

		it('an ff_accept without the echo stored beside a request: in dispute', () => {
			// No honest path stores this: R aborts on a missing echo.
			const back = load(1, undefined, () => undefined);
			expect(back.activationMismatch).to.equal(true);
		});

		it('the field says concurrent and the transcript does not decode: in dispute', () => {
			const back = load(1, 1, (row) => {
				row.initWire = '';
			});
			expect(back.concurrentVersion).to.equal(1);
			expect(back.activationMismatch).to.equal(true);
			const truncated = load(1, 1, (row) => {
				row.acceptWire = row.acceptWire!.slice(0, 200);
			});
			expect(truncated.concurrentVersion).to.equal(1);
			expect(truncated.activationMismatch).to.equal(true);
		});

		it('no field and a transcript that does not decode: left alone as baseline', () => {
			// Fixture rows and rows that predate the transcript checks.
			const back = load(undefined, undefined, (row) => {
				row.initWire = '';
			});
			expect(back).to.not.have.property('concurrentVersion');
			expect(back.activationMismatch).to.equal(false);
		});

		it('an existing dispute is kept', () => {
			const back = load(1, 1, (row) => {
				row.activationMismatch = true;
			});
			expect(back.activationMismatch).to.equal(true);
		});

		it('the transcript itself is untouched by loading', () => {
			const tx = fixtureTranscript(1, 1);
			const back = load(1, 1, () => undefined);
			expect(back.initWire.equals(tx.initWire)).to.equal(true);
			expect(back.acceptWire!.equals(tx.acceptWire)).to.equal(true);
		});
	});

	describe('a restart never falls back to baseline', () => {
		for (const side of ['S', 'R'] as const) {
			it(`${side}: a concurrent row whose field was dropped comes back concurrent and holds new work`, () => {
				const pair = createPair();
				activate(pair, AMOUNTS, true);
				// Ordinary traffic has moved the commitments past the activation.
				pay(pair, 'S', 20_000_000n);
				pay(pair, 'R', 3_000_000n);
				expect(pair.sErrors, why(pair)).to.deep.equal([]);
				const restored = restartFrom(pair, side, (ffor) => {
					delete ffor.concurrentVersion;
				});
				const f = record(restored.channel);
				expect(f.state).to.equal(FforState.ACTIVE);
				expect(f.concurrentVersion).to.equal(1);
				expect(f.activationMismatch).to.equal(true);
				// The vouchers are all still there.
				expect(vouchers(restored.channel).length).to.equal(AMOUNTS.length);
				// S settles nothing new under the dispute.
				if (side === 'S') {
					expect(restored.channel.fforSettlementRefusal(1, TIP)).to.match(
						/activation hash mismatch/
					);
				}
				expect(restored.channel.fforAdmissionHold()).to.match(/in dispute/);
			});
		}

		it('a baseline row loaded by this build is still a frozen baseline epoch', () => {
			const pair = createPair();
			activate(pair, AMOUNTS, false);
			const restored = restartFrom(pair, 'S', () => undefined);
			const f = record(restored.channel);
			expect(f).to.not.have.property('concurrentVersion');
			expect(f.activationMismatch).to.equal(false);
			expect(restored.channel.fforIsFrozen()).to.equal(true);
			expect(restored.channel.fforAdmissionHold()).to.equal(null);
			expect(restored.enforce).to.equal(0);
		});

		it('the concurrent epoch itself is not frozen, and says so only from the record', () => {
			const pair = createPair();
			activate(pair, AMOUNTS, true);
			expect(pair.sChannel.fforIsFrozen()).to.equal(false);
			expect(pair.rChannel.fforIsFrozen()).to.equal(false);
			const add = offer(pair, 'S', 5_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
		});
	});
});
