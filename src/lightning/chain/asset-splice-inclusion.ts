import { Block, crypto } from 'bitcoinjs-lib';
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

/** Follow header hashes up to the wallet's accepted tip, which must remain current throughout the lookup. */
export async function verifyAssetSpliceInclusion(
	txid: string,
	height: number,
	tip: IHeader,
	getHeader: (height: number) => Promise<string>,
	getBranch: () => Promise<unknown>,
	assertCurrent: () => void
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
		tip.height - height + 1 > MAX_HEADERS
	)
		throw new Error('Invalid or unsupported asset splice funding height');
	const accepted = regtestHeader(tip.hex);
	if (accepted.getId() !== tip.hash)
		throw new Error('Asset splice tip hash disagrees with the accepted header');
	const read = async (height: number) => {
		const block = regtestHeader(await getHeader(height));
		if (height === tip.height && !block.getHash().equals(accepted.getHash()))
			throw new Error(
				'Serving peer does not corroborate the accepted splice tip'
			);
		return block;
	};
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
