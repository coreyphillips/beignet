import type * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import { hmacSha256 } from '../crypto/provider';
import {
	deriveRevocationPrivkey,
	deriveRevocationPubkey,
	perCommitmentPointFromSecret
} from '../keys/derivation';
import type { CustomRecords } from '../message/custom-records';
import type { IChannelState } from './channel-state';
import type { IAuxiliaryCommitmentData } from './auxiliary';
import { isRevokedChildCustodyChannel } from './types';

/** Versioned commitment_signed authorization for the independently scoped child key. */
export const CHILD_REVOCATION_RECORD = 65553n;
const DOMAIN = Buffer.from('beignet/asset-child-custody/base/v1', 'utf8');

/** Independent secret for one exact commitment, including its funding epoch and allocation. */
function baseSecret(
	seed: Buffer,
	transaction: bitcoin.Transaction | string
): Buffer {
	if (
		seed.length !== 32 ||
		(typeof transaction === 'string'
			? !/^[0-9a-f]{64}$/.test(transaction)
			: transaction.ins.length !== 1)
	)
		throw new Error('Invalid scoped child revocation context');
	const transactionHash =
		typeof transaction === 'string'
			? Buffer.from(transaction, 'hex').reverse()
			: transaction.getHash();
	for (let counter = 0; counter < 256; counter++) {
		const secret = hmacSha256(
			seed,
			Buffer.concat([DOMAIN, transactionHash, Buffer.from([counter])])
		);
		if (ecc.isPrivate(secret)) return secret;
	}
	throw new Error('Unable to derive scoped child revocation key');
}

export function childRevocationBasepoint(
	seed: Buffer,
	transaction: bitcoin.Transaction
): Buffer {
	return Buffer.from(ecc.pointFromScalar(baseSecret(seed, transaction), true)!);
}

/** Only call after authenticating the reveal for this exact revoked remote commitment. */
export function revokedChildPrivateKey(
	seed: Buffer,
	transaction: bitcoin.Transaction | string,
	perCommitmentSecret: Buffer
): Buffer {
	const secret = baseSecret(seed, transaction);
	return deriveRevocationPrivkey(
		secret,
		perCommitmentSecret,
		Buffer.from(ecc.pointFromScalar(secret, true)!),
		perCommitmentPointFromSecret(perCommitmentSecret)
	);
}

/** Installs only a source-bound public point; no private delegation occurs on this wire. */
export function acceptChildRevocationRecord(
	state: IChannelState,
	records?: CustomRecords,
	transaction?: bitcoin.Transaction
): void {
	const raw = records?.get(CHILD_REVOCATION_RECORD);
	if (!isRevokedChildCustodyChannel(state.channelType)) {
		if (raw) throw new Error('Unnegotiated child custody record');
		return;
	}
	if (!state.auxiliaryState || !raw || raw.length !== 66 || raw[0] !== 1)
		throw new Error('Missing or invalid child custody record');
	const txid = raw.subarray(1, 33).toString('hex');
	if (transaction && txid !== transaction.getId())
		throw new Error(
			'Child custody record does not identify the signed commitment'
		);
	const point = raw.subarray(33);
	if (!ecc.isPoint(point)) throw new Error('Invalid child custody basepoint');
	const points = (state.auxiliaryState.childRevocationBasepoints ??= new Map());
	const previous = points.get(txid);
	if (previous && !previous.equals(point))
		throw new Error('Child custody basepoint changed for a signed commitment');
	points.set(txid, Buffer.from(point));
}

/** Resolve after first-level asset output scripts are final, before building child outputs. */
export function resolveChildRevocationKey(
	state: IChannelState,
	side: 'local' | 'remote',
	perCommitmentPoint: Buffer,
	transaction: bitcoin.Transaction
): { basepoint: Buffer; publicKey: Buffer } | undefined {
	if (!isRevokedChildCustodyChannel(state.channelType)) return undefined;
	const basepoint =
		side === 'remote'
			? childRevocationBasepoint(state.localPerCommitmentSeed, transaction)
			: state.auxiliaryState?.childRevocationBasepoints?.get(
					transaction.getId()
			  );
	if (!basepoint) return undefined;
	return {
		basepoint: Buffer.from(basepoint),
		publicKey: deriveRevocationPubkey(basepoint, perCommitmentPoint)
	};
}

export function addChildRevocationRecord(
	state: IChannelState,
	transaction: bitcoin.Transaction,
	data: IAuxiliaryCommitmentData | undefined,
	records?: CustomRecords
): CustomRecords | undefined {
	if (!isRevokedChildCustodyChannel(state.channelType)) return records;
	if (
		!data?.secondLevelRevocationBasepoint ||
		data.secondLevelCommitmentTxid !== transaction.getId()
	)
		throw new Error('Missing source-bound child custody key');
	const result = new Map(records);
	if (result.has(CHILD_REVOCATION_RECORD))
		throw new Error('Auxiliary provider reserved the child custody record');
	result.set(
		CHILD_REVOCATION_RECORD,
		Buffer.concat([
			Buffer.from([1]),
			Buffer.from(transaction.getId(), 'hex'),
			data.secondLevelRevocationBasepoint
		])
	);
	return result;
}

/** Ordinary Bitcoin HTLCs keep their existing keys even in the optional custody mode. */
export function secondLevelRevocationKey(
	state: IChannelState,
	data: IAuxiliaryCommitmentData | undefined,
	fallback: Buffer,
	assetAmount: bigint | undefined,
	transaction?: bitcoin.Transaction
): Buffer {
	if (!isRevokedChildCustodyChannel(state.channelType) || !assetAmount)
		return fallback;
	if (
		!data?.secondLevelRevocationKey ||
		(transaction && data.secondLevelCommitmentTxid !== transaction.getId())
	)
		throw new Error('Missing authenticated child custody key');
	return data.secondLevelRevocationKey;
}
