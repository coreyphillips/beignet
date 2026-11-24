import type { BIP32Interface } from 'bip32';
import { Transaction } from 'bitcoinjs-lib';
import type { IFinalOpeningTerms } from '../../../src/lightning/channel/final-opening-commitment';
import type { IFinalWalletBinding } from '../../../src/lightning/storage/final-wallet-format';
import path from 'path';
import { deriveV2ChannelId } from '../../../src/lightning/channel/validation';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	generateFromSeed,
	MAX_INDEX
} from '../../../src/lightning/keys/shachain';
import {
	bip32RootFromSeed,
	deriveChannelKeys,
	deriveLightningKeys,
	type IChannelKeys
} from '../../../src/lightning/keys/wallet-keys';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { type Candidate, opening } from './final-opening';
import { otherOpeningView } from './final-opening-commitment';
import { seedFor } from './taproot-revoked-fixture';

export function participant(
	seed: number,
	index: number
): {
	root: BIP32Interface;
	index: number;
	keys: IChannelKeys;
	binding: IFinalWalletBinding;
	points: IFinalOpeningTerms['localBasepoints'];
} {
	const root = bip32RootFromSeed(seedFor(seed));
	const keys = deriveChannelKeys(root, 1, index);
	const bp = keys.channelBasepoints;
	return {
		root,
		index,
		keys,
		binding: {
			encryptionKey: seedFor(seed + 20),
			network: 'regtest' as const,
			nodeId: deriveLightningKeys(root, 1).nodePublicKey.toString('hex')
		},
		points: {
			fundingPubkey: bp.fundingPubkey.toString('hex'),
			revocationBasepoint: bp.revocationBasepoint.toString('hex'),
			paymentBasepoint: bp.paymentBasepoint.toString('hex'),
			delayedPaymentBasepoint: bp.delayedPaymentBasepoint.toString('hex'),
			htlcBasepoint: bp.htlcBasepoint.toString('hex'),
			firstPerCommitmentPoint: getPublicKey(
				generateFromSeed(keys.perCommitmentSeed, MAX_INDEX)
			).toString('hex')
		}
	};
}
export const alice = participant(840, 2);
export const bob = participant(841, 4);

export function signingFixture(
	oneSided = false,
	left = alice,
	right = bob
): {
	candidate: Candidate;
	terms: IFinalOpeningTerms;
	counterpart: ReturnType<typeof otherOpeningView>;
	id: string;
	funding: Transaction;
} {
	const terms = {
		localBasepoints: left.points,
		remoteBasepoints: right.points,
		localToSelfDelay: 17,
		remoteToSelfDelay: 61,
		localDustLimitSatoshis: 354,
		remoteDustLimitSatoshis: 1000,
		commitmentFeeratePerKw: 253
	};
	const candidate = opening(oneSided);
	const id = deriveV2ChannelId(
		left.keys.channelBasepoints.revocationBasepoint,
		right.keys.channelBasepoints.revocationBasepoint
	).toString('hex');
	Object.assign(candidate, {
		channelId: id,
		localFundingPubkey: left.points.fundingPubkey,
		remoteFundingPubkey: right.points.fundingPubkey
	});
	if (oneSided) {
		candidate.isInitiator = true;
		candidate.localContributionSats = 140_000;
		candidate.remoteContributionSats = 0;
		candidate.inputs[0].isLocal = true;
	}
	const funding = Transaction.fromHex(candidate.fundingTxHex);
	funding.outs[candidate.fundingOutputIndex].script =
		createTaprootFundingScript(
			left.keys.channelBasepoints.fundingPubkey,
			right.keys.channelBasepoints.fundingPubkey
		).p2trOutput;
	candidate.fundingTxHex = funding.toHex();
	const counterpart = otherOpeningView(candidate, terms);
	return { candidate, terms, counterpart, id, funding };
}

export function peers(
	directory: string,
	oneSided = false
): {
	a: SqliteStorage;
	b: SqliteStorage;
	terms: IFinalOpeningTerms;
	bTerms: IFinalOpeningTerms;
	id: string;
	funding: Transaction;
	aFile: string;
	bFile: string;
} {
	const aFile = path.join(directory, 'alice.db');
	const bFile = path.join(directory, 'bob.db');
	const a = SqliteStorage.createFinalWallet(aFile, alice.binding);
	const b = SqliteStorage.createFinalWallet(bFile, bob.binding);
	const { candidate, terms, counterpart, id, funding } =
		signingFixture(oneSided);
	a.rememberFinalOpening(candidate);
	b.rememberFinalOpening(counterpart.candidate);
	const aNonce = a.finalOpeningTxComplete(id, alice.keys.fundingPrivkey);
	const bNonce = b.finalOpeningTxComplete(id, bob.keys.fundingPrivkey);
	a.rememberFinalPeerTxComplete(id, bNonce);
	b.rememberFinalPeerTxComplete(id, aNonce);
	return { a, b, terms, bTerms: counterpart.terms, id, funding, aFile, bFile };
}
