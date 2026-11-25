import { Transaction } from 'bitcoinjs-lib';
import { isAssetOpeningType } from '../features/asset-opening';
import { isFinalTaprootTypeHex } from '../channel/commitment-profile';
import { MAX_MINIMUM_DEPTH } from '../channel/types';
import { isValidPublicKey } from '../crypto/ecdh';
import {
	DUST_LIMIT_SATS,
	MAX_INTERACTIVE_TX_INPUTS,
	MAX_INTERACTIVE_TX_OUTPUTS,
	MAX_INTERACTIVE_TX_SEQUENCE,
	MAX_MONEY_SATS,
	MAX_PEER_PREVTX_BYTES_PER_SESSION,
	MAX_STANDARD_TX_WEIGHT,
	checkFeeSufficiency
} from '../interactive-tx/validation';
import { createTaprootFundingScript } from '../script/funding-taproot';

/** The agreed unsigned first funding transaction, in Bitcoin input/output order. */
export interface IFinalOpeningCandidate {
	channelId: string;
	channelType: string;
	localFundingPubkey: string;
	remoteFundingPubkey: string;
	fundingTxHex: string;
	fundingOutputIndex: number;
	isInitiator: boolean;
	fundingFeeratePerKw: number;
	minimumDepth: number;
	localContributionSats: number;
	remoteContributionSats: number;
	inputs: Array<{ prevTxHex: string; isLocal: boolean; serialId: string }>;
	outputSerialIds: string[];
}

/** Local wallet inputs reserved by authenticated final opening candidates. */
export function finalOpeningWalletOutpoints(
	candidates: readonly IFinalOpeningCandidate[]
): Set<string> {
	const result = new Set<string>();
	for (const candidate of candidates) {
		const tx = Transaction.fromHex(candidate.fundingTxHex);
		for (const [i, input] of tx.ins.entries()) {
			if (candidate.inputs[i].isLocal)
				result.add(
					Buffer.from(input.hash).reverse().toString('hex') + ':' + input.index
				);
		}
	}
	return result;
}

function requireCandidate(
	condition: boolean,
	field: string
): asserts condition {
	if (!condition) throw new Error('Invalid final opening candidate: ' + field);
}

function uint(value: number, maximum: number, minimum = 0): boolean {
	return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function readTransaction(hex: string, maxBytes: number): Transaction {
	requireCandidate(
		typeof hex === 'string' &&
			hex.length > 0 &&
			hex.length <= maxBytes * 2 &&
			hex.length % 2 === 0 &&
			/^[0-9a-f]+$/.test(hex),
		'transaction hex'
	);
	const tx = Transaction.fromHex(hex);
	requireCandidate(
		tx.ins.length > 0 && tx.outs.length > 0 && tx.toHex() === hex,
		'canonical transaction'
	);
	return tx;
}

function fundingKey(hex: string): Buffer {
	requireCandidate(
		typeof hex === 'string' && /^(02|03)[0-9a-f]{64}$/.test(hex),
		'funding key'
	);
	const key = Buffer.from(hex, 'hex');
	requireCandidate(isValidPublicKey(key), 'funding key point');
	return key;
}

/** Serial IDs are unsigned u64s, unique across the entire interactive transaction. */
function serialIds(values: string[], used: Set<string>): bigint[] {
	let previous = -1n;
	return Array.from(values, (value) => {
		requireCandidate(
			typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value),
			'serial id'
		);
		const serial = BigInt(value);
		requireCandidate(
			serial <= 0xffffffffffffffffn && serial > previous && !used.has(value),
			'serial id order or reuse'
		);
		used.add(value);
		previous = serial;
		return serial;
	});
}

export function validateFinalOpening(c: IFinalOpeningCandidate): {
	encoded: string;
	fundingOutpoint: string;
} {
	requireCandidate(isFinalTaprootTypeHex(c.channelType), 'channel type');
	return validateOpening(c);
}

export function validateAssetOpening(
	c: IFinalOpeningCandidate,
	fundingRoot: Buffer
) {
	requireCandidate(isAssetOpeningType(c.channelType), 'asset channel type');
	requireCandidate(
		Buffer.isBuffer(fundingRoot) && fundingRoot.length === 32,
		'asset funding root'
	);
	const checked = validateOpening(c, fundingRoot);
	requireCandidate(
		c.inputs.some((i) => i.isLocal) && c.inputs.some((i) => !i.isLocal),
		'two contributors'
	);
	return checked;
}

function validateOpening(c: IFinalOpeningCandidate, fundingRoot?: Buffer) {
	requireCandidate(
		typeof c.channelId === 'string' && /^[0-9a-f]{64}$/.test(c.channelId),
		'channel id'
	);
	requireCandidate(typeof c.isInitiator === 'boolean', 'role');
	requireCandidate(
		uint(c.minimumDepth, MAX_MINIMUM_DEPTH, 1),
		'positive confirmation depth'
	);
	requireCandidate(
		uint(c.fundingFeeratePerKw, 0xffffffff, 1),
		'funding feerate'
	);
	requireCandidate(
		uint(c.localContributionSats, Number(MAX_MONEY_SATS)) &&
			uint(c.remoteContributionSats, Number(MAX_MONEY_SATS)),
		'contributions'
	);
	const capacity =
		BigInt(c.localContributionSats) + BigInt(c.remoteContributionSats);
	requireCandidate(
		capacity >= DUST_LIMIT_SATS && capacity <= MAX_MONEY_SATS,
		'funding capacity'
	);
	requireCandidate(
		c.localFundingPubkey !== c.remoteFundingPubkey,
		'distinct funding keys'
	);
	const fundingScript = createTaprootFundingScript(
		fundingKey(c.localFundingPubkey),
		fundingKey(c.remoteFundingPubkey),
		undefined,
		fundingRoot
	).p2trOutput;
	const tx = readTransaction(c.fundingTxHex, MAX_STANDARD_TX_WEIGHT / 4);
	requireCandidate(
		tx.version === 2 && !tx.hasWitnesses(),
		'unsigned version 2 funding transaction'
	);
	requireCandidate(
		uint(c.fundingOutputIndex, tx.outs.length - 1),
		'funding output index'
	);
	requireCandidate(
		Array.isArray(c.inputs) &&
			c.inputs.length === tx.ins.length &&
			c.inputs.length <= 2 * MAX_INTERACTIVE_TX_INPUTS,
		'input count'
	);
	requireCandidate(
		Array.isArray(c.outputSerialIds) &&
			c.outputSerialIds.length === tx.outs.length &&
			c.outputSerialIds.length <= 2 * MAX_INTERACTIVE_TX_OUTPUTS,
		'output count'
	);

	const used = new Set<string>();
	const inputIds = serialIds(
		Array.from(c.inputs, (input) => input.serialId),
		used
	);
	const outputIds = serialIds(c.outputSerialIds, used);
	const prevouts = new Set<string>();
	const sides = [0, 1].map(() => ({
		satsIn: 0n,
		change: 0n,
		prevBytes: 0,
		inputs: 0,
		outputs: 0
	}));
	let weight = tx.weight() + 2; // Segwit marker and flag.
	const inputs = c.inputs.map(({ prevTxHex, isLocal, serialId }, i) => {
		const fromInitiator = inputIds[i] % 2n === 0n;
		requireCandidate(
			typeof isLocal === 'boolean' &&
				isLocal === (fromInitiator === c.isInitiator),
			'input owner'
		);
		const side = sides[isLocal ? 0 : 1];
		const prev = readTransaction(prevTxHex, 0xffff); // tx_add_input carries a u16 prev_tx length.
		side.prevBytes += prevTxHex.length / 2;
		requireCandidate(
			++side.inputs <= MAX_INTERACTIVE_TX_INPUTS &&
				side.prevBytes <= MAX_PEER_PREVTX_BYTES_PER_SESSION,
			'input budget'
		);
		const input = tx.ins[i];
		requireCandidate(
			input.script.length === 0 &&
				input.sequence <= MAX_INTERACTIVE_TX_SEQUENCE,
			'funding input script or sequence'
		);
		requireCandidate(
			input.hash.equals(prev.getHash()) && input.index < prev.outs.length,
			'funding prevout'
		);
		const key = prev.getId() + ':' + input.index;
		requireCandidate(!prevouts.has(key), 'duplicate funding input');
		prevouts.add(key);
		const { script, value } = prev.outs[input.index];
		const p2wpkh = script.length === 22 && script[0] === 0 && script[1] === 20;
		const p2tr = script.length === 34 && script[0] === 0x51 && script[1] === 32;
		requireCandidate(p2wpkh || p2tr, 'wallet input script');
		requireCandidate(uint(value, Number(MAX_MONEY_SATS)), 'prevout amount');
		side.satsIn += BigInt(value);
		weight += p2tr ? 66 : 107; // Default key spend or a low-R P2WPKH witness.
		return { prevTxHex, isLocal, serialId };
	});

	for (const [i, output] of tx.outs.entries()) {
		const fromInitiator = outputIds[i] % 2n === 0n;
		const side = sides[fromInitiator === c.isInitiator ? 0 : 1];
		requireCandidate(
			++side.outputs <= MAX_INTERACTIVE_TX_OUTPUTS,
			'output count by owner'
		);
		requireCandidate(
			uint(output.value, Number(MAX_MONEY_SATS), Number(DUST_LIMIT_SATS)),
			'output amount'
		);
		if (i === c.fundingOutputIndex) {
			requireCandidate(
				fromInitiator &&
					output.script.equals(fundingScript) &&
					BigInt(output.value) === capacity,
				'funding output script, owner or capacity'
			);
		} else {
			requireCandidate(
				!output.script.equals(fundingScript),
				'ambiguous funding output'
			);
			side.change += BigInt(output.value);
		}
	}
	const [local, remote] = sides;
	const contributed = local.satsIn + remote.satsIn;
	requireCandidate(
		contributed <= MAX_MONEY_SATS && weight <= MAX_STANDARD_TX_WEIGHT,
		'funding transaction size or amount'
	);
	requireCandidate(
		local.satsIn - local.change >= BigInt(c.localContributionSats) &&
			remote.satsIn - remote.change >= BigInt(c.remoteContributionSats),
		'net channel contributions'
	);
	const fee = contributed - local.change - remote.change - capacity;
	const feeError = checkFeeSufficiency(fee, weight, c.fundingFeeratePerKw);
	if (feeError) throw new Error(feeError);

	// Explicit field order makes exact replay independent of caller property order.
	const record: IFinalOpeningCandidate = {
		channelId: c.channelId,
		channelType: c.channelType,
		localFundingPubkey: c.localFundingPubkey,
		remoteFundingPubkey: c.remoteFundingPubkey,
		fundingTxHex: c.fundingTxHex,
		fundingOutputIndex: c.fundingOutputIndex,
		isInitiator: c.isInitiator,
		fundingFeeratePerKw: c.fundingFeeratePerKw,
		minimumDepth: c.minimumDepth,
		localContributionSats: c.localContributionSats,
		remoteContributionSats: c.remoteContributionSats,
		inputs,
		outputSerialIds: [...c.outputSerialIds]
	};
	requireCandidate(
		Object.keys(c).length === Object.keys(record).length &&
			c.inputs.every((input) => Object.keys(input).length === 3),
		'unexpected candidate field'
	);
	return {
		encoded: JSON.stringify(record),
		fundingOutpoint: tx.getId() + ':' + c.fundingOutputIndex
	};
}
