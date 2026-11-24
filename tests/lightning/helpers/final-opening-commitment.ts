import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { deriveV2ChannelId } from '../../../src/lightning/channel/validation';
import type { IFinalOpeningTerms } from '../../../src/lightning/channel/final-opening-commitment';
import { Candidate, opening } from './final-opening';
import { basepointsOf, privAt, seedFor } from './taproot-revoked-fixture';

export function openingPoints(
	seedId: number
): IFinalOpeningTerms['localBasepoints'] {
	const seed = seedFor(seedId);
	const points = basepointsOf(seed);
	points.firstPerCommitmentPoint = getPublicKey(privAt(seed, 5));
	return {
		fundingPubkey: points.fundingPubkey.toString('hex'),
		revocationBasepoint: points.revocationBasepoint.toString('hex'),
		paymentBasepoint: points.paymentBasepoint.toString('hex'),
		delayedPaymentBasepoint: points.delayedPaymentBasepoint.toString('hex'),
		htlcBasepoint: points.htlcBasepoint.toString('hex'),
		firstPerCommitmentPoint: points.firstPerCommitmentPoint.toString('hex')
	};
}

export function commitmentFixture(): {
	candidate: Candidate;
	terms: IFinalOpeningTerms;
} {
	const localBasepoints = openingPoints(171);
	const remoteBasepoints = openingPoints(172);
	const candidate = opening();
	candidate.channelId = deriveV2ChannelId(
		Buffer.from(localBasepoints.revocationBasepoint, 'hex'),
		Buffer.from(remoteBasepoints.revocationBasepoint, 'hex')
	).toString('hex');
	return {
		candidate,
		terms: {
			localBasepoints,
			remoteBasepoints,
			localToSelfDelay: 17,
			remoteToSelfDelay: 61,
			localDustLimitSatoshis: 354,
			remoteDustLimitSatoshis: 1000,
			commitmentFeeratePerKw: 253
		}
	};
}

export function otherOpeningView(
	c: Candidate,
	t: IFinalOpeningTerms
): { candidate: Candidate; terms: IFinalOpeningTerms } {
	return {
		candidate: {
			...c,
			isInitiator: !c.isInitiator,
			localFundingPubkey: c.remoteFundingPubkey,
			remoteFundingPubkey: c.localFundingPubkey,
			localContributionSats: c.remoteContributionSats,
			remoteContributionSats: c.localContributionSats,
			inputs: c.inputs.map((input) => ({ ...input, isLocal: !input.isLocal }))
		},
		terms: {
			localBasepoints: t.remoteBasepoints,
			remoteBasepoints: t.localBasepoints,
			localToSelfDelay: t.remoteToSelfDelay,
			remoteToSelfDelay: t.localToSelfDelay,
			localDustLimitSatoshis: t.remoteDustLimitSatoshis,
			remoteDustLimitSatoshis: t.localDustLimitSatoshis,
			commitmentFeeratePerKw: t.commitmentFeeratePerKw
		}
	};
}
