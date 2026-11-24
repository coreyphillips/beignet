import type { Transaction } from 'bitcoinjs-lib';
import { sha256 } from '../crypto/provider';
import {
	DUST_LIMIT_SATS,
	MAX_INTERACTIVE_TX_INPUTS,
	MAX_INTERACTIVE_TX_OUTPUTS,
	MAX_INTERACTIVE_TX_SEQUENCE,
	MAX_MONEY_SATS,
	MAX_STANDARD_TX_WEIGHT
} from '../interactive-tx/validation';

export interface IAssetOpenLayout {
	attempt: Buffer;
	chainHash: Buffer;
	channelId: Buffer;
	openHash: Buffer;
	acceptHash: Buffer;
	initiatorProposalHash: Buffer;
	acceptorProposalHash: Buffer;
	locktime: number;
	inputs: readonly {
		serialId: bigint;
		txid: Buffer;
		vout: number;
		sequence: number;
	}[];
	outputs: readonly {
		serialId: bigint;
		kind: 'funding' | 'change';
		valueSats: bigint;
		descriptorHash: Buffer;
	}[];
}

function hash32(value: Buffer): Buffer {
	if (!Buffer.isBuffer(value) || value.length !== 32)
		throw new Error('Expected a 32-byte opening manifest field');
	return value;
}

function u32(value: number, maximum = 0xffffffff): Buffer {
	if (!Number.isInteger(value) || value < 0 || value > maximum)
		throw new Error('Invalid opening manifest uint32');
	const bytes = Buffer.allocUnsafe(4);
	bytes.writeUInt32BE(value);
	return bytes;
}

function u64(value: bigint): Buffer {
	if (typeof value !== 'bigint' || value < 0n || value > 0xffffffffffffffffn)
		throw new Error('Invalid opening manifest uint64');
	const bytes = Buffer.allocUnsafe(8);
	bytes.writeBigUInt64BE(value);
	return bytes;
}

function checkSerials(
	items: readonly { serialId: bigint }[],
	limit: number,
	used: Set<bigint>
): number[] {
	if (!Array.isArray(items) || items.length < 1 || items.length > 2 * limit)
		throw new Error('Invalid opening manifest item count');
	const counts = [0, 0];
	let previous = -1n;
	for (const { serialId } of items) {
		if (
			typeof serialId !== 'bigint' ||
			serialId <= previous ||
			serialId > 0xffffffffffffffffn ||
			used.has(serialId) ||
			++counts[Number(serialId & 1n)] > limit
		)
			throw new Error('Invalid opening manifest serial IDs');
		used.add(serialId);
		previous = serialId;
	}
	return counts;
}

/** Preauthorization digest. All positions and peers are in initiator wire order. */
export function layoutDigest(layout: IAssetOpenLayout): Buffer {
	const serials = new Set<bigint>();
	const owners = checkSerials(
		layout.inputs,
		MAX_INTERACTIVE_TX_INPUTS,
		serials
	);
	if (owners.includes(0))
		throw new Error('Asset opening requires two contributors');
	checkSerials(layout.outputs, MAX_INTERACTIVE_TX_OUTPUTS, serials);
	const parts = [
		Buffer.from('beignet/asset-opening/layout/v1\0'),
		...[
			layout.attempt,
			layout.chainHash,
			layout.channelId,
			layout.openHash,
			layout.acceptHash,
			layout.initiatorProposalHash,
			layout.acceptorProposalHash
		].map(hash32),
		u32(layout.locktime),
		u32(layout.inputs.length)
	];
	const prevouts = new Set<string>();
	for (const input of layout.inputs) {
		parts.push(
			u64(input.serialId),
			hash32(input.txid),
			u32(input.vout),
			u32(input.sequence, MAX_INTERACTIVE_TX_SEQUENCE)
		);
		const outpoint = input.txid.toString('hex') + ':' + input.vout;
		if (prevouts.has(outpoint))
			throw new Error('Duplicate opening manifest input');
		prevouts.add(outpoint);
	}
	parts.push(u32(layout.outputs.length));
	let funding = 0;
	let sats = 0n;
	for (const output of layout.outputs) {
		if (output.kind === 'funding') {
			if (output.serialId & 1n || ++funding !== 1)
				throw new Error('Invalid shared funding output');
		} else if (output.kind !== 'change')
			throw new Error('Invalid opening output role');
		if (
			typeof output.valueSats !== 'bigint' ||
			output.valueSats < DUST_LIMIT_SATS ||
			(sats += output.valueSats) > MAX_MONEY_SATS
		)
			throw new Error('Invalid opening output amount');
		parts.push(
			u64(output.serialId),
			Buffer.of(output.kind === 'funding' ? 0 : 1),
			u64(output.valueSats),
			hash32(output.descriptorHash)
		);
	}
	if (!funding) throw new Error('Missing shared funding output');
	return sha256(Buffer.concat(parts));
}

/** Binds the frozen transaction and both signed virtual transfers after tx_complete. */
export function finalManifestDigest(
	layout: IAssetOpenLayout,
	fundingTx: Transaction,
	fundingRoot: Buffer,
	authorizedObjects: readonly [Buffer, Buffer],
	finalProofHash: Buffer
): Buffer {
	const layoutHash = layoutDigest(layout);
	if (
		fundingTx.version !== 2 ||
		fundingTx.locktime !== layout.locktime ||
		fundingTx.hasWitnesses() ||
		fundingTx.ins.length !== layout.inputs.length ||
		fundingTx.outs.length !== layout.outputs.length ||
		fundingTx.weight() > MAX_STANDARD_TX_WEIGHT ||
		!Array.isArray(authorizedObjects) ||
		authorizedObjects.length !== 2
	)
		throw new Error('Invalid frozen asset opening');
	for (const [i, input] of fundingTx.ins.entries()) {
		const planned = layout.inputs[i];
		if (
			input.script.length ||
			input.index !== planned.vout ||
			input.sequence !== planned.sequence ||
			!input.hash.equals(planned.txid)
		)
			throw new Error('Opening input disagrees with the layout');
	}
	for (const [i, output] of fundingTx.outs.entries()) {
		if (BigInt(output.value) !== layout.outputs[i].valueSats)
			throw new Error('Opening output disagrees with the layout');
	}
	return sha256(
		Buffer.concat([
			Buffer.from('beignet/asset-opening/final/v1\0'),
			layoutHash,
			fundingTx.getHash(),
			hash32(fundingRoot),
			...authorizedObjects.map(hash32),
			hash32(finalProofHash)
		])
	);
}
