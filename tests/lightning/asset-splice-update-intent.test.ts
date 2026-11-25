import { strict as assert } from 'assert';
import {
	decodeAssetUpdateIntent,
	encodeAssetUpdateIntent
} from '../../src/lightning/channel/asset-splice-update-intent';
import type { AssetUpdateChange } from '../../src/lightning/channel/asset-splice-update-provider';
describe('asset update operations over the peer channel', () => {
	const channel = 'ab'.repeat(32),
		A = '10'.repeat(32),
		B = '31'.repeat(32);
	const updates: AssetUpdateChange[] = [
		{
			kind: 'add',
			htlc: {
				id: 9n,
				offeredBy: 'local',
				amountMsat: 10000n,
				paymentHash: Buffer.alloc(32, 88),
				cltvExpiry: 555121,
				allocations: [
					{ assetId: B, units: 17n },
					{ assetId: A, units: 4n }
				]
			}
		},
		{
			kind: 'fulfill',
			id: 2n,
			offeredBy: 'peer',
			preimage: Buffer.alloc(32, 99)
		},
		{
			kind: 'fail',
			id: 8n,
			offeredBy: 'local',
			reason: Buffer.from('010502', 'hex')
		},
		{ kind: 'fee', feeratePerKw: 690 }
	];
	it('preserves payment and failure bytes, sorts issuance IDs and reverses local orientation on the other device', () => {
		const wire = encodeAssetUpdateIntent(channel, true, updates),
			peer = decodeAssetUpdateIntent(channel, false, wire);
		assert.deepEqual(encodeAssetUpdateIntent(channel, false, peer), wire);
		assert.deepEqual(peer[0], {
			kind: 'add',
			htlc: {
				...(updates[0] as Extract<AssetUpdateChange, { kind: 'add' }>).htlc,
				offeredBy: 'peer',
				allocations: [
					{ assetId: A, units: 4n },
					{ assetId: B, units: 17n }
				]
			}
		});
		assert.deepEqual(peer[1], { ...updates[1], offeredBy: 'local' });
		assert.deepEqual(peer[2], { ...updates[2], offeredBy: 'peer' });
		assert.deepEqual(peer[3], updates[3]);
	});
	it('refuses a changed channel, extra fields, repeated allocations, invalid units, noncanonical encodings and oversized messages', () => {
		const wire = encodeAssetUpdateIntent(channel, true, updates),
			row = JSON.parse(wire.toString())[2][0];
		assert.throws(() => decodeAssetUpdateIntent('bc'.repeat(32), true, wire));
		const incoming = (r: unknown[]) =>
			decodeAssetUpdateIntent(
				channel,
				true,
				Buffer.from(JSON.stringify([1, channel, [r]]))
			);
		for (const pair of [
			[[A, '0']],
			[[A, '01']],
			[[A, '18446744073709551616']],
			[
				[A, '4'],
				[A, '4']
			],
			[
				[B, '9'],
				[A, '4']
			]
		])
			assert.throws(() => incoming([...row.slice(0, 6), pair]));
		assert.throws(() => incoming([...row, 42]));
		assert.throws(() => incoming(['fail', 'peer', '2', 'abcd']));
		assert.throws(() =>
			decodeAssetUpdateIntent(
				channel,
				true,
				Buffer.concat([wire, Buffer.of(32)])
			)
		);
		assert.throws(() =>
			decodeAssetUpdateIntent(channel, true, Buffer.alloc(65536))
		);
	});
});
