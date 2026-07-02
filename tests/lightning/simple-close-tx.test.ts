/**
 * option_simple_close: closing tx builder, dust table, OP_RETURN handling,
 * and shutdown-script OP_RETURN grammar.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	SimpleCloseVariant,
	buildSimpleClosingTx,
	isDustOutput,
	isOpReturnScript,
	estimateSimpleCloseFee,
	calculateClosingFee
} from '../../src/lightning/chain/closing';
import { isValidShutdownScript } from '../../src/lightning/channel/validation';

const CLOSER_SCRIPT = Buffer.from('0014' + 'aa'.repeat(20), 'hex'); // P2WPKH
const CLOSEE_SCRIPT = Buffer.from('0014' + 'bb'.repeat(20), 'hex'); // P2WPKH
const OP_RETURN_SCRIPT = Buffer.concat([
	Buffer.from([0x6a, 0x06]),
	Buffer.from('burned', 'ascii')
]);

function baseParams(): Parameters<typeof buildSimpleClosingTx>[0] {
	return {
		fundingTxid: crypto.randomBytes(32).toString('hex'),
		fundingOutputIndex: 1,
		closerScriptPubkey: CLOSER_SCRIPT,
		closeeScriptPubkey: CLOSEE_SCRIPT,
		closerAmount: 600_000n,
		closeeAmount: 400_000n,
		feeSatoshis: 1_000n,
		locktime: 850_123,
		variant: SimpleCloseVariant.CLOSER_AND_CLOSEE
	};
}

describe('option_simple_close closing tx builder', function () {
	it('builds version-2, RBF-signalling tx with the given locktime', function () {
		const { tx } = buildSimpleClosingTx(baseParams());
		expect(tx.version).to.equal(2);
		expect(tx.locktime).to.equal(850_123);
		expect(tx.ins).to.have.length(1);
		expect(tx.ins[0].sequence).to.equal(0xfffffffd);
	});

	it('closer pays the entire fee from its own output', function () {
		const { tx, outputMap } = buildSimpleClosingTx(baseParams());
		expect(tx.outs).to.have.length(2);
		expect(tx.outs[outputMap.closer!].value).to.equal(599_000); // 600k - 1k fee
		expect(tx.outs[outputMap.closee!].value).to.equal(400_000); // untouched
	});

	it('variant selects which outputs are present', function () {
		const closerOnly = buildSimpleClosingTx({
			...baseParams(),
			variant: SimpleCloseVariant.CLOSER_OUTPUT_ONLY
		});
		expect(closerOnly.tx.outs).to.have.length(1);
		expect(closerOnly.outputMap.closer).to.equal(0);
		expect(closerOnly.outputMap.closee).to.equal(undefined);

		const closeeOnly = buildSimpleClosingTx({
			...baseParams(),
			variant: SimpleCloseVariant.CLOSEE_OUTPUT_ONLY
		});
		expect(closeeOnly.tx.outs).to.have.length(1);
		expect(closeeOnly.outputMap.closee).to.equal(0);
		expect(closeeOnly.tx.outs[0].value).to.equal(400_000);
	});

	it('sorts outputs per BIP 69 (value, then script)', function () {
		// closee (400k) < closer post-fee (599k) → closee first
		const { outputMap } = buildSimpleClosingTx(baseParams());
		expect(outputMap.closee).to.equal(0);
		expect(outputMap.closer).to.equal(1);

		// Equal values → script tiebreak (aa.. > bb.. is false: aa < bb)
		const equal = buildSimpleClosingTx({
			...baseParams(),
			closerAmount: 401_000n, // post-fee 400k == closee 400k
			feeSatoshis: 1_000n
		});
		expect(equal.outputMap.closer).to.equal(0); // aa.. sorts before bb..
		expect(equal.outputMap.closee).to.equal(1);
	});

	it('forces OP_RETURN output amounts to 0', function () {
		const { tx, outputMap } = buildSimpleClosingTx({
			...baseParams(),
			closerScriptPubkey: OP_RETURN_SCRIPT,
			closerAmount: 100n,
			feeSatoshis: 100n
		});
		expect(tx.outs[outputMap.closer!].value).to.equal(0);
		expect(
			isOpReturnScript(tx.outs[outputMap.closer!].script as Buffer)
		).to.equal(true);
	});

	it('throws when the fee exceeds the closer balance', function () {
		expect(() =>
			buildSimpleClosingTx({
				...baseParams(),
				closerAmount: 500n,
				feeSatoshis: 501n
			})
		).to.throw(/exceeds closer balance/);
	});

	it('estimateSimpleCloseFee matches the legacy weight model', function () {
		expect(estimateSimpleCloseFee(1000, 22, 22)).to.equal(
			calculateClosingFee(1000, 22, 22)
		);
		expect(estimateSimpleCloseFee(1000, 22, 0) > 0n).to.equal(true);
	});
});

describe('isDustOutput', function () {
	const P2PKH = Buffer.from('76a914' + '11'.repeat(20) + '88ac', 'hex');
	const P2SH = Buffer.from('a914' + '11'.repeat(20) + '87', 'hex');
	const P2WPKH = Buffer.from('0014' + '11'.repeat(20), 'hex');
	const P2WSH = Buffer.from('0020' + '11'.repeat(32), 'hex');
	const P2TR = Buffer.from('5120' + '11'.repeat(32), 'hex');

	it('applies the BOLT 3 threshold table', function () {
		expect(isDustOutput(P2PKH, 545n)).to.equal(true);
		expect(isDustOutput(P2PKH, 546n)).to.equal(false);
		expect(isDustOutput(P2SH, 539n)).to.equal(true);
		expect(isDustOutput(P2SH, 540n)).to.equal(false);
		expect(isDustOutput(P2WPKH, 293n)).to.equal(true);
		expect(isDustOutput(P2WPKH, 294n)).to.equal(false);
		expect(isDustOutput(P2WSH, 329n)).to.equal(true);
		expect(isDustOutput(P2WSH, 330n)).to.equal(false);
		expect(isDustOutput(P2TR, 353n)).to.equal(true);
		expect(isDustOutput(P2TR, 354n)).to.equal(false);
	});

	it('never treats OP_RETURN as dust', function () {
		expect(isDustOutput(OP_RETURN_SCRIPT, 0n)).to.equal(false);
	});
});

describe('shutdown script OP_RETURN grammar (option_simple_close)', function () {
	function opReturnPush(len: number): Buffer {
		return Buffer.concat([Buffer.from([0x6a, len]), Buffer.alloc(len, 7)]);
	}
	function opReturnPushdata1(len: number): Buffer {
		return Buffer.concat([
			Buffer.from([0x6a, 0x4c, len]),
			Buffer.alloc(len, 7)
		]);
	}

	it('accepts 6..75-byte pushes only with allowOpReturn', function () {
		expect(isValidShutdownScript(opReturnPush(6), true, true)).to.equal(true);
		expect(isValidShutdownScript(opReturnPush(75), true, true)).to.equal(true);
		expect(isValidShutdownScript(opReturnPush(6), true, false)).to.equal(false);
		expect(isValidShutdownScript(opReturnPush(6), true)).to.equal(false);
	});

	it('rejects pushes below 6 bytes', function () {
		expect(isValidShutdownScript(opReturnPush(5), true, true)).to.equal(false);
	});

	it('accepts PUSHDATA1 76..80 and rejects outside the range', function () {
		expect(isValidShutdownScript(opReturnPushdata1(76), true, true)).to.equal(
			true
		);
		expect(isValidShutdownScript(opReturnPushdata1(80), true, true)).to.equal(
			true
		);
		expect(isValidShutdownScript(opReturnPushdata1(81), true, true)).to.equal(
			false
		);
		expect(isValidShutdownScript(opReturnPushdata1(75), true, true)).to.equal(
			false
		);
	});

	it('rejects length mismatches', function () {
		const truncated = opReturnPush(20).subarray(0, 10);
		expect(isValidShutdownScript(truncated, true, true)).to.equal(false);
		const extra = Buffer.concat([opReturnPush(20), Buffer.from([0])]);
		expect(isValidShutdownScript(extra, true, true)).to.equal(false);
	});

	it('does not affect existing forms', function () {
		expect(isValidShutdownScript(CLOSER_SCRIPT, true, true)).to.equal(true);
		expect(isValidShutdownScript(CLOSER_SCRIPT, false, false)).to.equal(true);
	});
});
