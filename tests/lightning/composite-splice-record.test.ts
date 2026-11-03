/**
 * The composite splice record (issue #1922): what storage and the recovery
 * frame codec accept, and the stage order the engine reasons with.
 */

import { expect } from 'chai';
import {
	COMPOSITE_SPLICE_STAGES,
	ICompositeSpliceRecord,
	compositeSpliceStageAtLeast,
	compositeSpliceStageIsTerminal,
	validateCompositeSpliceRecord
} from '../../src/lightning/channel/composite-splice-record';

function record(): ICompositeSpliceRecord {
	return {
		id: '11'.repeat(32),
		stage: 'COMMITTED',
		channels: [
			{
				channelId: '22'.repeat(32),
				peerPubkey: '02' + '33'.repeat(32),
				fundingTxid: '44'.repeat(32),
				fundingOutputIndex: 1,
				debitSats: '600000',
				feeSats: '300',
				oldCapacitySats: '1000000',
				newCapacitySats: '399700',
				inputSerialId: '0',
				fundingOutputSerialId: '4'
			},
			{
				channelId: '55'.repeat(32),
				peerPubkey: '03' + '66'.repeat(32),
				fundingTxid: '77'.repeat(32),
				fundingOutputIndex: 0,
				debitSats: '400000',
				feeSats: '200',
				oldCapacitySats: '700000',
				newCapacitySats: '299800',
				inputSerialId: '2',
				fundingOutputSerialId: '6'
			}
		],
		destinationScript: '0014' + '88'.repeat(20),
		destinationSerialId: '8',
		amountSats: '1000000',
		feeSats: '500',
		feeratePerkw: 1000,
		locktime: 123,
		txid: '99'.repeat(32),
		txHex: '0200000000',
		createdAt: 1_700_000_000_000,
		updatedAt: 1_700_000_000_001
	};
}

describe('Composite splice record (issue #1922)', function () {
	it('validates a well-formed record and returns a copy with only the known fields', function () {
		const r = record();
		const valid = validateCompositeSpliceRecord({ ...r, extra: 'dropped' });
		expect(valid).to.deep.equal(r);
		expect(valid).to.not.equal(r);
		// Optional fields stay absent rather than becoming undefined keys.
		const bare = validateCompositeSpliceRecord({
			...r,
			txid: undefined,
			txHex: undefined,
			reason: undefined
		});
		expect(Object.keys(bare)).to.not.include.members([
			'txid',
			'txHex',
			'reason'
		]);
		// JSON round trip is the storage form.
		expect(
			validateCompositeSpliceRecord(JSON.parse(JSON.stringify(r)))
		).to.deep.equal(r);
	});

	it('refuses every malformed field', function () {
		const bad = (
			mutate: (r: ICompositeSpliceRecord) => void,
			what: string
		): void => {
			const r = record();
			mutate(r);
			expect(() => validateCompositeSpliceRecord(r), what).to.throw(
				/Invalid composite splice record/
			);
		};
		bad((r) => (r.id = 'zz'.repeat(32)), 'non-hex id');
		bad((r) => (r.id = '11'.repeat(31)), 'short id');
		bad((r) => (r.stage = 'DONE' as 'LOCKED'), 'unknown stage');
		bad((r) => (r.channels = []), 'no channels');
		bad(
			(r) => (r.channels[1].channelId = r.channels[0].channelId),
			'repeated channel'
		);
		bad(
			(r) => (r.channels[0].peerPubkey = '02' + '33'.repeat(31)),
			'short pubkey'
		);
		bad((r) => (r.channels[0].debitSats = '-1'), 'negative sats');
		bad((r) => (r.channels[0].debitSats = '1.5'), 'fractional sats');
		bad((r) => (r.channels[0].fundingOutputIndex = -1), 'negative vout');
		bad((r) => (r.channels[0].inputSerialId = 'a'), 'non-decimal serial');
		bad((r) => (r.destinationScript = ''), 'empty destination');
		bad((r) => (r.destinationScript = '001'), 'odd-length destination');
		bad((r) => (r.amountSats = '18446744073709551616'), 'amount above u64');
		bad((r) => (r.feeratePerkw = 1.5), 'fractional feerate');
		bad((r) => (r.locktime = 0x1_0000_0000), 'locktime above u32');
		bad((r) => (r.txid = 'abc'), 'bad txid');
		bad((r) => (r.txHex = ''), 'empty tx hex');
		bad(
			(r) => ((r as unknown as { reason: number }).reason = 5),
			'non-string reason'
		);
		bad(
			(r) => ((r as unknown as { createdAt: string }).createdAt = 'now'),
			'non-numeric time'
		);
		expect(() => validateCompositeSpliceRecord(null)).to.throw(
			/Invalid composite splice record/
		);
		expect(() => validateCompositeSpliceRecord('record')).to.throw(
			/Invalid composite splice record/
		);
	});

	it('orders the stages and knows the terminal ones', function () {
		expect(COMPOSITE_SPLICE_STAGES).to.deep.equal([
			'PLANNED',
			'NEGOTIATING',
			'COMMITTED',
			'PEERS_SIGNED',
			'RELEASED',
			'BROADCAST',
			'LOCKED',
			'ABORTED',
			'CONFLICTED'
		]);
		expect(compositeSpliceStageAtLeast('RELEASED', 'COMMITTED')).to.equal(true);
		expect(compositeSpliceStageAtLeast('COMMITTED', 'RELEASED')).to.equal(
			false
		);
		expect(compositeSpliceStageAtLeast('BROADCAST', 'RELEASED')).to.equal(true);
		expect(compositeSpliceStageAtLeast('LOCKED', 'PLANNED')).to.equal(true);
		// ABORTED sits outside the forward path.
		expect(compositeSpliceStageAtLeast('ABORTED', 'RELEASED')).to.equal(false);
		expect(compositeSpliceStageAtLeast('ABORTED', 'PLANNED')).to.equal(false);
		expect(compositeSpliceStageAtLeast('LOCKED', 'ABORTED')).to.equal(false);
		expect(compositeSpliceStageAtLeast('ABORTED', 'ABORTED')).to.equal(true);
		expect(compositeSpliceStageAtLeast('CONFLICTED', 'RELEASED')).to.equal(
			false
		);
		expect(compositeSpliceStageAtLeast('LOCKED', 'CONFLICTED')).to.equal(false);
		expect(compositeSpliceStageAtLeast('CONFLICTED', 'CONFLICTED')).to.equal(
			true
		);
		for (const stage of COMPOSITE_SPLICE_STAGES) {
			expect(compositeSpliceStageIsTerminal(stage)).to.equal(
				stage === 'LOCKED' || stage === 'ABORTED' || stage === 'CONFLICTED'
			);
		}
	});
});
