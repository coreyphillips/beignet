import { strict as assert } from 'assert';
import { createHash } from 'crypto';
import { assetPayoutRevocationKey } from '../../src/lightning/channel';
import { ecc } from '../../src/utils/ecc';

describe('asset payout revocation public keys', () => {
	const id = 'ac'.repeat(32);
	const base = Buffer.from(ecc.pointFromScalar(Buffer.alloc(32, 3), true)!);
	const scope = {
		channelId: '17'.repeat(32),
		fundingTxid: Buffer.from(
			Array.from({ length: 32 }, (_, index) => index)
		).toString('hex'),
		fundingOutputIndex: 0x1020304,
		stateNumber: '4328719365',
		revocationPubkey: base
	};
	it('binds the compressed basepoint, displayed txid, big-endian vout and height, and whole issuance ID', () => {
		const tag = createHash('sha256')
			.update('Beignet/AssetPayoutRevocation/v1')
			.digest();
		const tweak = createHash('sha256')
			.update(
				Buffer.concat([
					tag,
					tag,
					base,
					Buffer.from(scope.channelId, 'hex'),
					Buffer.from(scope.fundingTxid, 'hex'),
					Buffer.from('010203040000000102030405', 'hex'),
					Buffer.from(id, 'hex')
				])
			)
			.digest();
		const expected = Buffer.from(ecc.pointAddScalar(base, tweak, true)!);
		assert.deepEqual(assetPayoutRevocationKey(scope, id), expected);
		for (const other of [
			{ channelId: '16'.repeat(32) },
			{ fundingTxid: '82'.repeat(32) },
			{ fundingOutputIndex: scope.fundingOutputIndex - 1 },
			{ stateNumber: '4328719364' },
			{
				revocationPubkey: Buffer.concat([
					Buffer.of(base[0] ^ 1),
					base.subarray(1)
				])
			}
		])
			assert.notDeepEqual(
				assetPayoutRevocationKey({ ...scope, ...other }, id),
				expected
			);
		assert.notDeepEqual(
			assetPayoutRevocationKey(scope, 'ad'.repeat(32)),
			expected
		);
	});
	it('rejects invalid lengths, points and integer fields', () => {
		for (const invalid of [
			{ channelId: '00' },
			{ fundingTxid: 'zz'.repeat(32) },
			{ revocationPubkey: Buffer.alloc(33) },
			{ fundingOutputIndex: -1 },
			{ fundingOutputIndex: 0x100000000 },
			{ stateNumber: '-1' },
			{ stateNumber: String(1n << 64n) }
		])
			assert.throws(() =>
				assetPayoutRevocationKey({ ...scope, ...invalid }, id)
			);
		assert.throws(() => assetPayoutRevocationKey(scope, 'ac'.repeat(31)));
	});
});
