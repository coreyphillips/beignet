import { payments } from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import type {
	IAssetHtlcVirtualSpend,
	IAssetOpeningHtlcPayout
} from '../channel/asset-opening-provider';
import type { IFinalCommitmentView } from '../channel/final-opening-commitment';
import { privateAdd } from '../crypto/ecdh';
import { taggedHash } from '../crypto/hash';
import { sha256 } from '../crypto/provider';
import {
	buildTaprootSecondLevelOutput,
	tweakTaprootKeyPathPrivkey
} from '../script/commitment-taproot';
import { tapleafHash, signTaprootHtlcLeaf } from '../script/htlc-taproot';

function u32(n: number): Buffer {
	const result = Buffer.alloc(4);
	result.writeUInt32LE(n);
	return result;
}
function u64(n: bigint, bigEndian = false): Buffer {
	const result = Buffer.alloc(8);
	if (bigEndian) result.writeBigUInt64BE(n);
	else result.writeBigUInt64LE(n);
	return result;
}

/** A virtual asset input commits to a root and its sum. Reconstruct the full
 * BIP341 digest here so channel keys cannot sign an arbitrary supplied hash. */
export function assetHtlcVirtualSigner(
	ctx: Pick<
		IAssetOpeningHtlcPayout,
		| 'kind'
		| 'htlc'
		| 'keys'
		| 'toSelfDelay'
		| 'transaction'
		| 'secondLevelTemplate'
	>,
	output: IFinalCommitmentView['htlcs'][number],
	htlcKey: Buffer,
	delayedKey: Buffer,
	revoked: Buffer | undefined
) {
	const indexTweak = Buffer.alloc(32);
	indexTweak.writeBigUInt64BE(
		ctx.htlc.id === 0xffffffffffffffffn ? 1n : ctx.htlc.id + 1n,
		24
	);
	const internal = ecc.pointAddScalar(
		ctx.keys.revocationPubkey,
		indexTweak,
		true
	);
	if (!internal) throw Error('Invalid virtual HTLC internal key');
	const child = buildTaprootSecondLevelOutput(
		ctx.keys.revocationPubkey,
		ctx.keys.localDelayedPubkey,
		ctx.toSelfDelay,
		undefined,
		'final'
	);
	const seen = new Map<string, Buffer>();
	const unitsByAsset = new Map(
		ctx.htlc.allocations.map((a) => [a.assetId, a.units])
	);
	const timelocks = [ctx.transaction, ctx.secondLevelTemplate].map((tx) => ({
		lockTime: tx.locktime,
		sequence: tx.ins[0].sequence < 0x80000000 ? tx.ins[0].sequence : 0
	}));
	return (spend: IAssetHtlcVirtualSpend): Buffer => {
		const second = spend.stage === 'second-level',
			childSpend = ctx.kind.startsWith('second_level_');
		if (
			(!second && spend.stage !== 'commitment') ||
			(second && !childSpend) ||
			!Buffer.isBuffer(spend.inputRoot) ||
			spend.inputRoot.length !== 32 ||
			!Buffer.isBuffer(spend.outputRoot) ||
			spend.outputRoot.length !== 32
		)
			throw Error('Invalid virtual HTLC signing stage or asset root');
		const units = unitsByAsset.get(spend.assetId);
		if (!units || units < 1n)
			throw Error('Virtual HTLC signature needs a committed issuance');
		const { lockTime, sequence } = timelocks[!second && childSpend ? 1 : 0];
		if (lockTime !== spend.lockTime || sequence !== spend.sequence)
			throw Error('Wrong virtual HTLC timelocks');
		const source = payments.p2tr({
			internalPubkey: Buffer.from(internal).subarray(1),
			scriptTree: second
				? { output: child.delay.script }
				: [
						{ output: output.tree.success.script },
						{ output: output.tree.timeout.script }
				  ]
		});
		const leaf = second
			? child.delay
			: ctx.kind.includes('second_level')
			? output.leaf
			: ctx.kind === 'htlc_success'
			? output.tree.success
			: output.tree.timeout;
		const revocation = ctx.kind.endsWith('revocation');
		if (revocation && !revoked)
			throw Error('Missing HTLC revocation authority');
		const key = revocation
			? tweakTaprootKeyPathPrivkey(
					privateAdd(revoked!, indexTweak),
					source.hash!
			  )
			: second
			? delayedKey
			: htlcKey;
		const single =
			!second &&
			!revocation &&
			(ctx.kind.startsWith('htlc_second_level_') || childSpend);
		const amount = u64(units);
		const prevout = Buffer.concat([
			sha256(Buffer.concat([spend.inputRoot, u64(units, true)])),
			u32(0)
		]);
		const script = Buffer.concat([Buffer.of(34), source.output!]);
		const destination = sha256(
			Buffer.concat([amount, Buffer.of(34, 0x51, 0x20), spend.outputRoot])
		);
		const ext = Buffer.of(revocation ? 0 : 2);
		const digest = taggedHash(
			'TapSighash',
			Buffer.of(0, single ? 0x83 : 0),
			u32(2),
			u32(spend.lockTime),
			...(single
				? [ext, prevout, amount, script, u32(sequence), destination]
				: [
						sha256(prevout),
						sha256(amount),
						sha256(script),
						sha256(u32(sequence)),
						destination,
						ext,
						u32(0)
				  ]),
			...(revocation
				? []
				: [
						tapleafHash(leaf.script, leaf.leafVersion),
						Buffer.of(0),
						u32(0xffffffff)
				  ])
		);
		const slot = spend.stage + '/' + spend.assetId,
			prior = seen.get(slot);
		if (prior && !prior.equals(digest))
			throw Error('Virtual HTLC spend changed during recovery');
		seen.set(slot, digest);
		return signTaprootHtlcLeaf(digest, key);
	};
}
