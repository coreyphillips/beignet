/**
 * What an ordinary channel's commitment round is made of, reduced to values
 * a test can pin (issue #2093, step 6).
 *
 * Everything here is computed from constants through the same functions a
 * channel signs with. The values were taken with the code as it stood before
 * auxiliary leaves reached the script and commitment builders; the tests
 * hold the builders to them.
 */

import crypto from 'crypto';
import {
	buildLocalCommitment,
	buildRemoteCommitment,
	signRemoteCommitment,
	signRemoteHtlcSignaturesTaproot
} from '../../../src/lightning/channel/commitment-builder';
import { getPerCommitmentPoint } from '../../../src/lightning/channel/channel-helpers';
import type { IChannelState } from '../../../src/lightning/channel/channel-state';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { deriveTaprootFundingKey } from '../../../src/lightning/crypto/musig';
import { ChannelSigner } from '../../../src/lightning/keys/signer';
import { encodeCommitmentSignedMessage } from '../../../src/lightning/message/channel-commitment';
import {
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput,
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput
} from '../../../src/lightning/script/commitment-taproot';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import {
	buildTaprootHtlcSuccessTx,
	buildTaprootHtlcTimeoutTx,
	taprootHtlcLeafSighash
} from '../../../src/lightning/script/htlc-taproot';
import { ordinaryChannelState } from './auxiliary-state-fixture';

const sha256 = (data: Buffer | string): string =>
	crypto.createHash('sha256').update(data).digest('hex');

const key = (n: number): Buffer => getPublicKey(Buffer.alloc(32, n));

/** The first byte the fixture state of each kind fills its keys from. */
export const FIXTURE_FILL = { taproot: 0x10, anchors: 0x20 } as const;

/** The signer that holds the fixture state's funding and HTLC keys. */
export function fixtureSigner(kind: 'taproot' | 'anchors'): ChannelSigner {
	const fill = FIXTURE_FILL[kind];
	return new ChannelSigner(
		Buffer.alloc(32, fill + 2),
		Buffer.alloc(32, fill + 6)
	);
}

export interface ICommitmentDigests {
	localTx: string;
	remoteTx: string;
	/** Output index of each HTLC, in the order the signatures are sent. */
	localHtlcOutputs: number[];
	remoteHtlcOutputs: number[];
	/** sha256 over the signatures we send for the peer's commitment. */
	signatures: string;
}

/** Both commitments of the fixture channel and what we sign for the peer's. */
export function commitmentDigests(
	kind: 'taproot' | 'anchors',
	state: IChannelState = ordinaryChannelState(kind)
): ICommitmentDigests {
	const localPoint = getPerCommitmentPoint(state.localPerCommitmentSeed, 5n);
	const remotePoint = state.remoteCurrentPerCommitmentPoint!;
	const local = buildLocalCommitment(state, localPoint, 5n);
	const remote = buildRemoteCommitment(state, remotePoint, 5n);
	const signer = fixtureSigner(kind);
	const signatures =
		kind === 'taproot'
			? signRemoteHtlcSignaturesTaproot(state, signer, remotePoint, 5n)
			: ((): Buffer[] => {
					const signed = signRemoteCommitment(state, signer, remotePoint, 5n);
					return [signed.signature, ...signed.htlcSignatures];
			  })();
	return {
		localTx: local.result.tx.toHex(),
		remoteTx: remote.result.tx.toHex(),
		localHtlcOutputs: [...local.result.outputMap.htlcs],
		remoteHtlcOutputs: [...remote.result.outputMap.htlcs],
		signatures: sha256(Buffer.concat(signatures))
	};
}

/** Every taproot output and second-level transaction, built with no auxiliary leaf. */
export function taprootScriptDigest(): string {
	const hash = Buffer.alloc(32, 0x42);
	const toLocal = buildTaprootToLocalOutput(key(1), key(2), 144);
	const toRemote = buildTaprootToRemoteOutput(key(3));
	const offered = buildTaprootOfferedHtlcOutput(key(1), key(4), key(5), hash);
	const received = buildTaprootReceivedHtlcOutput(
		key(1),
		key(4),
		key(5),
		hash,
		800_000
	);
	const secondLevel = buildTaprootSecondLevelOutput(key(1), key(2), 144);
	const funding = createTaprootFundingScript(key(6), key(7));
	const fundingKey = deriveTaprootFundingKey(key(6), key(7));
	const txid = 'ab'.repeat(32);
	const success = buildTaprootHtlcSuccessTx(
		txid,
		2,
		20_000n,
		key(1),
		key(2),
		144
	);
	const timeout = buildTaprootHtlcTimeoutTx(
		txid,
		3,
		40_000n,
		800_000,
		key(1),
		key(2),
		144
	);
	const parts: Buffer[] = [
		toLocal.output,
		toLocal.delay.script,
		toLocal.delay.controlBlock,
		toLocal.revoke.script,
		toLocal.revoke.controlBlock,
		toRemote.output,
		toRemote.spend.controlBlock,
		offered.output,
		offered.merkleRoot,
		offered.success.controlBlock,
		offered.timeout.controlBlock,
		received.output,
		received.merkleRoot,
		received.success.controlBlock,
		received.timeout.controlBlock,
		secondLevel.output,
		secondLevel.delay.controlBlock,
		funding.p2trOutput,
		funding.tweak,
		fundingKey.outputKey,
		success.toBuffer(),
		timeout.toBuffer(),
		taprootHtlcLeafSighash(
			success,
			received.output,
			20_000,
			received.success.script
		),
		taprootHtlcLeafSighash(
			timeout,
			offered.output,
			40_000,
			offered.timeout.script
		)
	];
	return sha256(Buffer.concat(parts));
}

/** commitment_signed with every standard field, as it is put on the wire. */
export function commitmentSignedDigest(): string {
	return sha256(
		Buffer.concat([
			encodeCommitmentSignedMessage({
				channelId: Buffer.alloc(32, 0x31),
				signature: Buffer.alloc(64, 0x32),
				htlcSignatures: [Buffer.alloc(64, 0x33), Buffer.alloc(64, 0x34)]
			}),
			encodeCommitmentSignedMessage({
				channelId: Buffer.alloc(32, 0x31),
				signature: Buffer.alloc(64),
				htlcSignatures: [Buffer.alloc(64, 0x33)],
				fundingTxid: Buffer.alloc(32, 0x35),
				partialSignatureWithNonce: Buffer.alloc(98, 0x36)
			})
		])
	);
}
