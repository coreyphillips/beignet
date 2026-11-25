import { ecc } from '../../utils/ecc';
import { isValidPublicKey } from '../crypto/ecdh';
import { taggedHash } from '../crypto/hash';

export interface IAssetPayoutScope {
	channelId: string;
	fundingTxid: string;
	fundingOutputIndex: number;
	stateNumber: string;
	revocationPubkey: Buffer;
}

/** Separate a virtual balance key from the Bitcoin revocation key, per funding, state and issuance. */
export function assetPayoutRevocationTweak(
	scope: IAssetPayoutScope,
	assetId: string
): Buffer {
	const {
		channelId,
		fundingTxid,
		fundingOutputIndex,
		stateNumber,
		revocationPubkey
	} = scope;
	if (
		![channelId, fundingTxid, assetId].every(
			(id) => typeof id === 'string' && /^[0-9a-f]{64}$/.test(id)
		) ||
		!Number.isInteger(fundingOutputIndex) ||
		fundingOutputIndex < 0 ||
		fundingOutputIndex > 0xffffffff ||
		typeof stateNumber !== 'string' ||
		!/^(?:0|[1-9][0-9]{0,19})$/.test(stateNumber) ||
		BigInt(stateNumber) > 0xffffffffffffffffn ||
		!Buffer.isBuffer(revocationPubkey) ||
		!isValidPublicKey(revocationPubkey)
	)
		throw Error('Invalid asset payout revocation scope');
	const index = Buffer.alloc(4),
		height = Buffer.alloc(8);
	index.writeUInt32BE(fundingOutputIndex);
	height.writeBigUInt64BE(BigInt(stateNumber));
	const tweak = taggedHash(
		'Beignet/AssetPayoutRevocation/v1',
		revocationPubkey,
		Buffer.from(channelId, 'hex'),
		Buffer.from(fundingTxid, 'hex'),
		index,
		height,
		Buffer.from(assetId, 'hex')
	);
	if (!ecc.isPrivate(tweak))
		throw Error('Invalid asset payout revocation tweak');
	return tweak;
}

export function assetPayoutRevocationKey(
	scope: IAssetPayoutScope,
	assetId: string
): Buffer {
	const tweak = assetPayoutRevocationTweak(scope, assetId);
	const key = ecc.pointAddScalar(scope.revocationPubkey, tweak, true);
	if (!key) throw Error('Invalid asset payout revocation key');
	return Buffer.from(key);
}
