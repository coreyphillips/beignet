import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import type {
	AssetUpdateChange,
	IAssetUpdateAmount
} from './asset-splice-update-provider';

const hash = /^[a-f0-9]{64}$/;
function decimal(value: unknown, positive = false): bigint {
	if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value))
		throw new Error('Invalid asset update amount');
	const n = BigInt(value);
	if (n > 0xffffffffffffffffn || (positive && n === 0n))
		throw new Error('Asset update amount out of range');
	return n;
}
function raw(value: unknown, exact?: number) {
	if (
		typeof value !== 'string' ||
		!/^(?:[a-f0-9]{2})+$/.test(value) ||
		(exact !== undefined && value.length !== 2 * exact)
	)
		throw new Error('Invalid asset update value');
	return Buffer.from(value, 'hex');
}
function stringify(
	id: string,
	initiator: boolean,
	changes: readonly AssetUpdateChange[]
): Buffer {
	if (
		!hash.test(id) ||
		typeof initiator !== 'boolean' ||
		!Array.isArray(changes) ||
		!changes.length ||
		changes.length > 967
	)
		throw new Error('Invalid asset update intent');
	const role = (dir: 'local' | 'peer') => {
		if (dir !== 'local' && dir !== 'peer')
			throw new Error('Unknown asset update sender');
		return (dir === 'local') === initiator ? 'initiator' : 'acceptor';
	};
	const list = changes.map((change) => {
		if (change.kind === 'add') {
			const h = change.htlc;
			return [
				'add',
				role(h.offeredBy),
				String(h.id),
				String(h.amountMsat),
				h.paymentHash.toString('hex'),
				h.cltvExpiry,
				h.allocations
					.map((a: IAssetUpdateAmount) => [a.assetId, String(a.units)])
					.sort((a: string[], b: string[]) => a[0].localeCompare(b[0]))
			];
		}
		if (change.kind === 'fee') return ['fee', change.feeratePerKw];
		if (change.kind !== 'fulfill' && change.kind !== 'fail')
			throw new Error('Unknown asset update operation');
		return [
			change.kind,
			role(change.offeredBy),
			String(change.id),
			(change.kind === 'fulfill' ? change.preimage : change.reason).toString(
				'hex'
			)
		];
	});
	const bytes = Buffer.from(JSON.stringify([1, id, list]));
	if (bytes.length > MAX_LIGHTNING_PAYLOAD)
		throw new Error('Asset update intent exceeds its wire limit');
	return bytes;
}
export function decodeAssetUpdateIntent(
	id: string,
	isOriginalInitiator: boolean,
	bytes: Buffer
): AssetUpdateChange[] {
	if (
		!Buffer.isBuffer(bytes) ||
		!bytes.length ||
		bytes.length > MAX_LIGHTNING_PAYLOAD
	)
		throw new Error('Invalid asset update intent bytes');
	const v: unknown = JSON.parse(bytes.toString('utf8'));
	if (
		!Array.isArray(v) ||
		v.length !== 3 ||
		v[0] !== 1 ||
		v[1] !== id ||
		!Array.isArray(v[2]) ||
		!v[2].length ||
		v[2].length > 967
	)
		throw new Error('Wrong asset update intent or channel');
	const ops: AssetUpdateChange[] = v[2].map((r: unknown): AssetUpdateChange => {
		if (!Array.isArray(r)) throw new Error('Malformed asset update operation');
		if (
			r[0] === 'fee' &&
			r.length === 2 &&
			Number.isSafeInteger(r[1]) &&
			r[1] >= 253 &&
			r[1] <= 100000
		)
			return { kind: 'fee', feeratePerKw: r[1] };
		if (r[1] !== 'initiator' && r[1] !== 'acceptor')
			throw new Error('Invalid asset update participant');
		const offeredBy =
				(r[1] === 'initiator') === isOriginalInitiator ? 'local' : 'peer',
			htlcId = decimal(r[2]);
		if (
			r[0] === 'add' &&
			r.length === 7 &&
			Number.isSafeInteger(r[5]) &&
			r[5] > 0 &&
			r[5] < 500000000 &&
			Array.isArray(r[6]) &&
			r[6].length <= 483
		) {
			const seen = new Set<string>();
			const allocations = r[6].map((pair: unknown) => {
				if (
					!Array.isArray(pair) ||
					pair.length !== 2 ||
					typeof pair[0] !== 'string' ||
					!hash.test(pair[0]) ||
					seen.has(pair[0])
				)
					throw new Error('Invalid or duplicate HTLC issuance');
				seen.add(pair[0]);
				return { assetId: pair[0], units: decimal(pair[1], true) };
			});
			return {
				kind: 'add',
				htlc: {
					offeredBy,
					id: htlcId,
					amountMsat: decimal(r[3], true),
					paymentHash: raw(r[4], 32),
					cltvExpiry: r[5],
					allocations
				}
			};
		}
		if (r[0] === 'fulfill' && r.length === 4)
			return {
				kind: 'fulfill',
				offeredBy,
				id: htlcId,
				preimage: raw(r[3], 32)
			};
		if (r[0] === 'fail' && r.length === 4)
			return { kind: 'fail', offeredBy, id: htlcId, reason: raw(r[3]) };
		throw new Error('Unknown or malformed asset update operation');
	});
	if (!stringify(id, isOriginalInitiator, ops).equals(bytes))
		throw new Error('Noncanonical asset update intent');
	return ops;
}
export function encodeAssetUpdateIntent(
	id: string,
	isOriginalInitiator: boolean,
	changes: readonly AssetUpdateChange[]
): Buffer {
	const exact = stringify(id, isOriginalInitiator, changes);
	decodeAssetUpdateIntent(id, isOriginalInitiator, exact);
	return exact;
}
