import { Block, crypto } from 'bitcoinjs-lib';
import { ChainBackendUnavailableError } from './chain-watcher';
import type { SqliteStorage } from '../storage/sqlite-storage';
import { loadAssetSpliceExitProofs } from '../storage/asset-splice-exit-proofs';
import type { IHeader } from '../../types/electrum';
import type { IAssetSpliceAnchor } from '../channel/asset-splice-lock';

const hashHex = /^[0-9a-f]{64}$/;
const headerHex = /^[0-9a-f]{160}$/;
const MAX_HEADERS = 2016;
const HEADERS_PER_REQUEST_GROUP = 16;

function regtestHeader(hex: string): Block {
	if (typeof hex !== 'string' || hex.length !== 160 || !headerHex.test(hex))
		throw new Error('Invalid asset splice block header');
	const block = Block.fromHex(hex);
	if (block.bits !== 0x207fffff || !block.checkProofOfWork())
		throw new Error('Invalid regtest proof of work for asset splice funding');
	return block;
}

interface IMerkleBranch {
	block_height?: unknown;
	merkle?: unknown;
	pos?: unknown;
}
function checkMerkleBranch(
	txid: string,
	height: number,
	response: unknown,
	root: Buffer
): void {
	if (
		!response ||
		typeof response !== 'object' ||
		('error' in response && response.error)
	)
		throw new Error('Asset splice transaction proof unavailable');
	const body = (
		'data' in response ? response.data : response
	) as IMerkleBranch | null;
	if (
		!body ||
		body.block_height !== height ||
		typeof body.pos !== 'number' ||
		!Number.isSafeInteger(body.pos) ||
		body.pos <= 0 ||
		!Array.isArray(body.merkle) ||
		body.merkle.length > 32 ||
		body.pos >= 2 ** body.merkle.length
	)
		throw new Error('Invalid asset splice transaction proof position');
	let node = Buffer.from(txid, 'hex').reverse(),
		position = body.pos;
	for (const sibling of body.merkle) {
		if (
			typeof sibling !== 'string' ||
			sibling.length !== 64 ||
			!hashHex.test(sibling)
		)
			throw new Error('Invalid asset splice transaction proof branch');
		const hash = Buffer.from(sibling, 'hex').reverse();
		node = crypto.hash256(
			Buffer.concat(position % 2 === 0 ? [node, hash] : [hash, node])
		);
		position = Math.floor(position / 2);
	}
	if (!node.equals(root))
		throw new Error(
			'Asset splice transaction proof differs from the funding block'
		);
}

export interface IAssetSpliceInclusionRecovery {
	store: SqliteStorage;
	channelId: string;
	finalDigest: string;
}

interface InclusionCursor {
	kind: 'inclusion-progress';
	finalDigest: string;
	txid: string;
	fundingHeight: number;
	tipHash: string;
	tipHeight: number;
	nextHash: string;
	nextHeight: number;
}

const HISTORICAL_STEP = 128;

async function historicalInclusion(
	recovery: IAssetSpliceInclusionRecovery,
	txid: string,
	height: number,
	tip: IHeader,
	read: (height: number) => Promise<Block>,
	getBranch: () => Promise<unknown>,
	assertCurrent: () => void
): Promise<IAssetSpliceAnchor> {
	const { store, channelId, finalDigest } = recovery;
	if (!store.canSpliceDualFundedAssets)
		throw new Error(
			'Historical asset inclusion requires the original splice wallet'
		);
	const evidence = loadAssetSpliceExitProofs(store, channelId, finalDigest);
	if (evidence.candidate.fundingTxid !== txid)
		throw new Error(
			'Historical proof is for a different retained funding candidate'
		);
	const head = store.readAssetSpliceJournal<InclusionCursor>(channelId);
	const prior = head.records
		.filter(
			(r) =>
				r.kind === 'inclusion-progress' &&
				r.finalDigest === finalDigest &&
				r.txid === txid &&
				r.fundingHeight === height
		)
		.pop();

	// Every expected hash comes from the accepted tip or a header already linked to it.
	async function descend(
		start: number,
		stop: number,
		expected: string
	): Promise<string> {
		for (let high = start; high > stop; high -= HEADERS_PER_REQUEST_GROUP) {
			const length = Math.min(HEADERS_PER_REQUEST_GROUP, high - stop);
			const blocks = await Promise.all(
				Array.from({ length }, (_, i) => read(high - i))
			);
			assertCurrent();
			for (const block of blocks) {
				if (block.getId() !== expected)
					throw new Error(
						'Asset splice funding block is outside the accepted header chain'
					);
				expected = Buffer.from(block.prevHash!).reverse().toString('hex');
			}
		}
		return expected;
	}
	await read(tip.height);
	assertCurrent();
	let start = tip.height,
		expected = tip.hash;
	if (prior) {
		if (
			!Number.isSafeInteger(prior.tipHeight) ||
			!Number.isSafeInteger(prior.nextHeight) ||
			prior.nextHeight < height ||
			prior.nextHeight > prior.tipHeight ||
			prior.tipHeight > 0xffffffff ||
			!hashHex.test(prior.tipHash) ||
			!hashHex.test(prior.nextHash)
		)
			throw new Error('Invalid historical asset inclusion checkpoint');
		if (
			tip.height >= prior.tipHeight &&
			tip.height - prior.tipHeight <= HISTORICAL_STEP &&
			(await descend(tip.height, prior.tipHeight, tip.hash)) === prior.tipHash
		) {
			start = prior.nextHeight;
			expected = prior.nextHash;
		}
	}
	const nextHeight = Math.max(height, start - HISTORICAL_STEP);
	const nextHash = await descend(start, nextHeight, expected);
	assertCurrent();
	const cursor: InclusionCursor = {
		kind: 'inclusion-progress',
		finalDigest,
		txid,
		fundingHeight: height,
		tipHash: tip.hash,
		tipHeight: tip.height,
		nextHash,
		nextHeight
	};
	if (nextHeight > height) {
		store.appendAssetSpliceEvent(channelId, head, cursor);
		throw new ChainBackendUnavailableError(
			'Historical asset splice header verification is in progress'
		);
	}
	const [funding, branch] = await Promise.all([read(height), getBranch()]);
	assertCurrent();
	if (funding.getId() !== nextHash)
		throw new Error(
			'Asset splice funding block is outside the accepted header chain'
		);
	checkMerkleBranch(txid, height, branch, funding.merkleRoot!);
	if (
		!prior ||
		prior.nextHeight !== height ||
		prior.nextHash !== nextHash ||
		prior.tipHash !== tip.hash
	)
		store.appendAssetSpliceEvent(channelId, head, cursor);
	return { txid, blockHash: nextHash, confirmations: tip.height - height + 1 };
}

/** Follow header hashes up to the wallet's accepted tip, which must remain current throughout the lookup. */
export async function verifyAssetSpliceInclusion(
	txid: string,
	height: number,
	tip: IHeader,
	getHeader: (height: number) => Promise<string>,
	getBranch: () => Promise<unknown>,
	assertCurrent: () => void,
	recovery?: IAssetSpliceInclusionRecovery
): Promise<IAssetSpliceAnchor> {
	if (
		typeof txid !== 'string' ||
		txid.length !== 64 ||
		!hashHex.test(txid) ||
		!Number.isSafeInteger(height) ||
		height < 1 ||
		!Number.isSafeInteger(tip.height) ||
		tip.height > 0xffffffff ||
		tip.height < height ||
		(!recovery && tip.height - height + 1 > MAX_HEADERS)
	)
		throw new Error('Invalid or unsupported asset splice funding height');
	const accepted = regtestHeader(tip.hex);
	if (accepted.getId() !== tip.hash)
		throw new Error('Asset splice tip hash disagrees with the accepted header');
	const read = async (requestedHeight: number): Promise<Block> => {
		const block = regtestHeader(await getHeader(requestedHeight));
		if (
			requestedHeight === tip.height &&
			!block.getHash().equals(accepted.getHash())
		)
			throw new Error(
				'Serving peer does not corroborate the accepted splice tip'
			);
		return block;
	};
	if (tip.height - height + 1 > MAX_HEADERS && recovery)
		return historicalInclusion(
			recovery,
			txid,
			height,
			tip,
			read,
			getBranch,
			assertCurrent
		);
	const [fundingBlock, branch] = await Promise.all([read(height), getBranch()]);
	assertCurrent();
	checkMerkleBranch(txid, height, branch, fundingBlock.merkleRoot!);
	let previous = fundingBlock;
	for (
		let start = height + 1;
		start <= tip.height;
		start += HEADERS_PER_REQUEST_GROUP
	) {
		const count = Math.min(HEADERS_PER_REQUEST_GROUP, tip.height - start + 1);
		const headers = await Promise.all(
			Array.from({ length: count }, (_, index) => read(start + index))
		);
		assertCurrent();
		for (const header of headers) {
			if (!header.prevHash!.equals(previous.getHash()))
				throw new Error(
					'Asset splice funding block is outside the accepted header chain'
				);
			previous = header;
		}
	}
	return {
		txid,
		blockHash: fundingBlock.getId(),
		confirmations: tip.height - height + 1
	};
}
