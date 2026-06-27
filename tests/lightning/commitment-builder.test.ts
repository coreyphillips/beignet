import { expect } from 'chai';
import crypto from 'crypto';
import {
	deriveCommitmentKeys,
	buildLocalCommitment,
	buildRemoteCommitment,
	signRemoteCommitment,
	verifyRemoteCommitmentSig
} from '../../src/lightning/channel/commitment-builder';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { deriveChannelId } from '../../src/lightning/channel/validation';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}

	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function getFundingPrivkey(seed: Buffer): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
}

function getPerCommitmentPoint(seed: Buffer, commitmentNumber: bigint): Buffer {
	const index = MAX_INDEX - commitmentNumber;
	const secret = generateFromSeed(seed, index);
	return perCommitmentPointFromSecret(secret);
}

function createReadyState() {
	const openerSeed = makeSeed(1);
	const acceptorSeed = makeSeed(2);
	const openerCommitSeed = makeSeed(3);
	const acceptorCommitSeed = makeSeed(4);

	const openerBasepoints = makeBasepoints(openerSeed);
	const acceptorBasepoints = makeBasepoints(acceptorSeed);

	// Set first per-commitment points
	openerBasepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
		openerCommitSeed,
		0n
	);
	acceptorBasepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
		acceptorCommitSeed,
		0n
	);

	const fundingTxid = crypto
		.createHash('sha256')
		.update(Buffer.from('funding-tx'))
		.digest();
	const fundingOutputIndex = 0;
	const channelId = deriveChannelId(fundingTxid, fundingOutputIndex);

	const fundingSatoshis = 1_000_000n;

	const openerState = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitSeed
	});

	openerState.remoteBasepoints = acceptorBasepoints;
	openerState.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
	openerState.fundingTxid = fundingTxid;
	openerState.fundingOutputIndex = fundingOutputIndex;
	openerState.channelId = channelId;
	openerState.state = ChannelState.NORMAL;
	openerState.remoteCurrentPerCommitmentPoint =
		acceptorBasepoints.firstPerCommitmentPoint;

	const acceptorState = createAcceptorState({
		temporaryChannelId: openerState.temporaryChannelId,
		fundingSatoshis,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBasepoints,
		localPerCommitmentSeed: acceptorCommitSeed,
		remoteBasepoints: openerBasepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});

	acceptorState.fundingTxid = fundingTxid;
	acceptorState.fundingOutputIndex = fundingOutputIndex;
	acceptorState.channelId = channelId;
	acceptorState.state = ChannelState.NORMAL;
	acceptorState.remoteCurrentPerCommitmentPoint =
		openerBasepoints.firstPerCommitmentPoint;
	acceptorState.localBalanceMsat = 0n;
	acceptorState.remoteBalanceMsat = fundingSatoshis * 1000n;

	return {
		openerState,
		acceptorState,
		openerSeed,
		acceptorSeed,
		openerCommitSeed,
		acceptorCommitSeed,
		fundingTxid
	};
}

describe('Commitment Builder', function () {
	describe('deriveCommitmentKeys', function () {
		it('should derive keys for local commitment', function () {
			const localBasepoints = makeBasepoints(makeSeed(1));
			const remoteBasepoints = makeBasepoints(makeSeed(2));
			const perCommitmentPoint = getPerCommitmentPoint(makeSeed(3), 0n);

			const keys = deriveCommitmentKeys(
				localBasepoints,
				remoteBasepoints,
				perCommitmentPoint,
				true
			);

			expect(keys.revocationPubkey).to.have.length(33);
			expect(keys.localDelayedPubkey).to.have.length(33);
			expect(keys.remotePaymentPubkey).to.have.length(33);
			expect(keys.localHtlcPubkey).to.have.length(33);
			expect(keys.remoteHtlcPubkey).to.have.length(33);
		});

		it('should derive keys for remote commitment', function () {
			const localBasepoints = makeBasepoints(makeSeed(1));
			const remoteBasepoints = makeBasepoints(makeSeed(2));
			const perCommitmentPoint = getPerCommitmentPoint(makeSeed(3), 0n);

			const keys = deriveCommitmentKeys(
				localBasepoints,
				remoteBasepoints,
				perCommitmentPoint,
				false
			);

			expect(keys.revocationPubkey).to.have.length(33);
			expect(keys.localDelayedPubkey).to.have.length(33);
		});

		it('should produce different keys for local vs remote', function () {
			const localBasepoints = makeBasepoints(makeSeed(1));
			const remoteBasepoints = makeBasepoints(makeSeed(2));
			const perCommitmentPoint = getPerCommitmentPoint(makeSeed(3), 0n);

			const localKeys = deriveCommitmentKeys(
				localBasepoints,
				remoteBasepoints,
				perCommitmentPoint,
				true
			);
			const remoteKeys = deriveCommitmentKeys(
				localBasepoints,
				remoteBasepoints,
				perCommitmentPoint,
				false
			);

			// Keys should be different (different derivation paths)
			expect(localKeys.revocationPubkey.equals(remoteKeys.revocationPubkey)).to
				.be.false;
		});
	});

	describe('buildLocalCommitment', function () {
		it('should build a valid local commitment transaction', function () {
			const { openerState, openerCommitSeed } = createReadyState();
			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);
			const built = buildLocalCommitment(openerState, perCommitPoint);

			expect(built.result.tx).to.exist;
			expect(built.result.tx.version).to.equal(2);
			expect(built.result.tx.ins).to.have.length(1);
			// Should have at least a to_local output (opener has all funds)
			expect(built.result.tx.outs.length).to.be.greaterThanOrEqual(1);
		});

		it('should include both to_local and to_remote with push_msat', function () {
			const { openerState, openerCommitSeed } = createReadyState();
			// Give some balance to remote
			openerState.localBalanceMsat = 800_000_000n;
			openerState.remoteBalanceMsat = 200_000_000n;

			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);
			const built = buildLocalCommitment(openerState, perCommitPoint);

			// Should have 2 outputs: to_local and to_remote
			expect(built.result.tx.outs).to.have.length(2);
			expect(built.result.outputMap.toLocal).to.not.be.undefined;
			expect(built.result.outputMap.toRemote).to.not.be.undefined;
		});

		it('should trim dust outputs', function () {
			const { openerState, openerCommitSeed } = createReadyState();
			// Set remote balance below dust
			openerState.remoteBalanceMsat = 100_000n; // 100 sat - below P2WPKH dust

			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);
			const built = buildLocalCommitment(openerState, perCommitPoint);

			// Should only have to_local output
			expect(built.result.outputMap.toRemote).to.be.undefined;
		});

		it('should include HTLC outputs', function () {
			const { openerState, openerCommitSeed } = createReadyState();
			openerState.localBalanceMsat = 900_000_000n;
			openerState.remoteBalanceMsat = 100_000_000n;

			// Add an offered HTLC
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});

			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);
			const built = buildLocalCommitment(openerState, perCommitPoint);

			// Should have to_local, to_remote, and 1 HTLC output
			expect(built.result.outputMap.htlcs).to.have.length(1);
		});
	});

	describe('buildRemoteCommitment', function () {
		it('should build a valid remote commitment transaction', function () {
			const { openerState } = createReadyState();
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const built = buildRemoteCommitment(openerState, remotePoint);

			expect(built.result.tx).to.exist;
			expect(built.result.tx.version).to.equal(2);
		});

		it('should mirror local commitment (to_local ↔ to_remote)', function () {
			const { openerState, openerCommitSeed } = createReadyState();
			openerState.localBalanceMsat = 600_000_000n;
			openerState.remoteBalanceMsat = 400_000_000n;

			const localPoint = getPerCommitmentPoint(openerCommitSeed, 0n);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;

			const localBuilt = buildLocalCommitment(openerState, localPoint);
			const remoteBuilt = buildRemoteCommitment(openerState, remotePoint);

			// Local tx: to_local = 600k sat, to_remote = 400k sat
			// Remote tx: to_local = 400k sat (their balance), to_remote = 600k sat (our balance)
			const localToLocalIdx = localBuilt.result.outputMap.toLocal!;
			const localToRemoteIdx = localBuilt.result.outputMap.toRemote!;
			const remoteToLocalIdx = remoteBuilt.result.outputMap.toLocal!;
			const remoteToRemoteIdx = remoteBuilt.result.outputMap.toRemote!;

			const localToLocalValue =
				localBuilt.result.tx.outs[localToLocalIdx].value;
			const localToRemoteValue =
				localBuilt.result.tx.outs[localToRemoteIdx].value;
			const remoteToLocalValue =
				remoteBuilt.result.tx.outs[remoteToLocalIdx].value;
			const remoteToRemoteValue =
				remoteBuilt.result.tx.outs[remoteToRemoteIdx].value;

			// Our local balance = their remote balance
			expect(localToLocalValue).to.equal(remoteToRemoteValue);
			// Our remote balance = their local balance
			expect(localToRemoteValue).to.equal(remoteToLocalValue);
		});
	});

	describe('Signing and Verification', function () {
		it('should sign and verify commitment transaction', function () {
			const {
				openerState,
				acceptorState,
				openerSeed,
				acceptorSeed,
				acceptorCommitSeed
			} = createReadyState();

			const openerFundingPrivkey = getFundingPrivkey(openerSeed);
			const acceptorFundingPrivkey = getFundingPrivkey(acceptorSeed);
			const openerSigner = new ChannelSigner(openerFundingPrivkey);
			const acceptorSigner = new ChannelSigner(acceptorFundingPrivkey);

			// Opener signs acceptor's (remote) commitment
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { signature } = signRemoteCommitment(
				openerState,
				openerSigner,
				remotePoint
			);
			expect(signature).to.have.length(64);

			// Acceptor verifies the signature on their local commitment
			const localPoint = getPerCommitmentPoint(acceptorCommitSeed, 0n);
			const valid = verifyRemoteCommitmentSig(
				acceptorState,
				acceptorSigner,
				localPoint,
				signature
			);
			expect(valid).to.be.true;
		});

		it('should reject invalid signature', function () {
			const { acceptorState, acceptorSeed, acceptorCommitSeed } =
				createReadyState();
			const acceptorFundingPrivkey = getFundingPrivkey(acceptorSeed);
			const acceptorSigner = new ChannelSigner(acceptorFundingPrivkey);

			const localPoint = getPerCommitmentPoint(acceptorCommitSeed, 0n);
			const badSig = crypto.randomBytes(64);
			const valid = verifyRemoteCommitmentSig(
				acceptorState,
				acceptorSigner,
				localPoint,
				badSig
			);
			expect(valid).to.be.false;
		});

		it('should sign commitment with HTLCs', function () {
			const {
				openerState,
				acceptorState,
				openerSeed,
				acceptorSeed,
				acceptorCommitSeed
			} = createReadyState();

			// Add an HTLC to both states
			const htlcEntry = {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			};

			openerState.htlcs.set('offered-0', { ...htlcEntry });
			openerState.localBalanceMsat -= htlcEntry.amountMsat;

			// In acceptor state, this is a received HTLC
			acceptorState.htlcs.set('received-0', {
				...htlcEntry,
				direction: HtlcDirection.RECEIVED
			});
			acceptorState.remoteBalanceMsat -= htlcEntry.amountMsat;

			const openerSigner = new ChannelSigner(getFundingPrivkey(openerSeed));
			const acceptorSigner = new ChannelSigner(getFundingPrivkey(acceptorSeed));

			// Opener signs acceptor's commitment
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { signature } = signRemoteCommitment(
				openerState,
				openerSigner,
				remotePoint
			);

			// Acceptor verifies
			const localPoint = getPerCommitmentPoint(acceptorCommitSeed, 0n);
			const valid = verifyRemoteCommitmentSig(
				acceptorState,
				acceptorSigner,
				localPoint,
				signature
			);
			expect(valid).to.be.true;
		});
	});

	describe('Commitment Number Obscuring', function () {
		it('should encode commitment number in locktime and sequence', function () {
			const { openerState, openerCommitSeed } = createReadyState();
			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);
			const built = buildLocalCommitment(openerState, perCommitPoint);

			// Locktime should have 0x20000000 bit set
			expect(built.result.tx.locktime & 0x20000000).to.equal(0x20000000);

			// Sequence should have 0x80000000 bit set
			expect((built.result.tx.ins[0].sequence & 0x80000000) >>> 0).to.equal(
				0x80000000 >>> 0
			);
		});

		it('should produce different locktime for different commitment numbers', function () {
			const { openerState, openerCommitSeed } = createReadyState();

			const point0 = getPerCommitmentPoint(openerCommitSeed, 0n);
			const built0 = buildLocalCommitment(openerState, point0);

			openerState.localCommitmentNumber = 1n;
			const point1 = getPerCommitmentPoint(openerCommitSeed, 1n);
			const built1 = buildLocalCommitment(openerState, point1);

			// Different commitment numbers should produce different locktimes
			expect(built0.result.tx.locktime).to.not.equal(built1.result.tx.locktime);
		});
	});
});
