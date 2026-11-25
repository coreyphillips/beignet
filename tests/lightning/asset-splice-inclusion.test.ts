import { strict as assert } from 'assert';
import { Block, crypto, Transaction } from 'bitcoinjs-lib';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';

const fundingHeight = 101;
const display = (hash: Buffer) => Buffer.from(hash).reverse().toString('hex');
const parent = (left: Buffer, right: Buffer) =>
	crypto.hash256(Buffer.concat([left, right]));
function transaction(n: number) {
	const tx = new Transaction();
	tx.version = 2;
	tx.addInput(
		Buffer.alloc(32, n),
		n === 0 ? 0xffffffff : 0,
		0xfffffffd,
		n === 0 ? Buffer.from([1, 1]) : undefined
	);
	tx.addOutput(
		Buffer.concat([Buffer.from([0, 20]), Buffer.alloc(20, n)]),
		6000 + n
	);
	return tx;
}
const transactions = [0, 1, 2, 3].map(transaction);
function mine(previous: Buffer, merkleRoot: Buffer, timestamp: number) {
	const b = new Block();
	b.version = 4;
	b.prevHash = previous;
	b.merkleRoot = merkleRoot;
	b.timestamp = timestamp;
	b.bits = 0x207fffff;
	b.nonce = 0;
	while (!b.checkProofOfWork()) b.nonce++;
	return b;
}
function chain(stamp = 1700000101) {
	const first = mine(
		Buffer.alloc(32, 99),
		Block.calculateMerkleRoot(transactions),
		stamp
	);
	const next = mine(first.getHash(), Buffer.alloc(32, 22), stamp + 1);
	const tip = mine(next.getHash(), Buffer.alloc(32, 33), stamp + 2);
	return [first, next, tip];
}
function fixture(pos = 1) {
	const blocks = chain();
	const txid = transactions[pos].getId();
	const opposite = pos < 2 ? 2 : 0;
	const branch = {
		merkle: [
			transactions[pos ^ 1].getId(),
			display(
				parent(
					transactions[opposite].getHash(),
					transactions[opposite + 1].getHash()
				)
			)
		],
		pos,
		block_height: fundingHeight
	};
	const current = {
		height: fundingHeight + 2,
		hash: blocks[2].getId(),
		hex: blocks[2].toHex(true)
	};
	const server = {
		electrumNetwork: 'bitcoinRegtest',
		getBlockHeader: () => ({ ...current }),
		getBlockHex: async ({ height }: { height: number }) => ({
			isErr: () => false,
			value: blocks[height - fundingHeight].toHex(true)
		}),
		getTransactionMerkle: async (q: {
			tx_hash: string;
			height: number;
		}): Promise<unknown> => {
			assert.deepEqual(q, { tx_hash: txid, height: fundingHeight });
			return { error: false, data: branch };
		}
	};
	return {
		txid,
		blocks,
		branch,
		current,
		server,
		backend: new ElectrumBackend(server as never, 2000)
	};
}

describe('Electrum inclusion for an asset splice candidate', () => {
	it('proves the actual transaction on either branch of the merkle tree and returns the funding block at its current depth', async () => {
		for (const pos of [1, 2]) {
			const { txid, blocks, backend, server, branch } = fixture(pos);
			if (pos === 2) server.getTransactionMerkle = async () => branch;
			assert.deepEqual(
				await backend.getAssetSpliceInclusion(txid, fundingHeight),
				{
					txid,
					blockHash: blocks[0].getId(),
					confirmations: 3
				}
			);
		}
	});

	it('reports a different funding block when the same transaction is mined again at the same height', async () => {
		const { txid, blocks, backend, current } = fixture();
		const before = await backend.getAssetSpliceInclusion(txid, fundingHeight);
		blocks.splice(0, blocks.length, ...chain(1700000111));
		current.hex = blocks[2].toHex(true);
		current.hash = blocks[2].getId();
		const after = await backend.getAssetSpliceInclusion(txid, fundingHeight);
		assert.notEqual(before.blockHash, after.blockHash);
		assert.equal(after.blockHash, blocks[0].getId());
		assert.equal(after.confirmations, 3);
	});

	it('rejects incorrect, malformed or oversized merkle information, including unused high position bits', async () => {
		const { txid, branch, server, backend } = fixture();
		for (const wrong of [
			{ ...branch, block_height: fundingHeight - 1 },
			{ ...branch, pos: 0 },
			{ ...branch, pos: branch.pos + 2 ** branch.merkle.length },
			{ ...branch, pos: 2 ** 40 + branch.pos },
			{ ...branch, pos: 1.2 },
			{ ...branch, merkle: [branch.merkle[1], branch.merkle[0]] },
			{ ...branch, merkle: ['bad', branch.merkle[1]] },
			{ ...branch, merkle: Array(33).fill('11'.repeat(32)) },
			{ error: true, data: branch }
		]) {
			server.getTransactionMerkle = async () => wrong;
			await assert.rejects(
				backend.getAssetSpliceInclusion(txid, fundingHeight)
			);
		}
	});

	it('rejects a proof from a disconnected funding block, a malformed header, or an inconsistent local tip', async () => {
		const { txid, blocks, server, backend, current } = fixture();
		const old = blocks[0];
		blocks[0] = chain(1700000110)[0];
		await assert.rejects(backend.getAssetSpliceInclusion(txid, fundingHeight));
		blocks[0] = old;
		const correct = server.getBlockHex;
		server.getBlockHex = async ({ height }) => ({
			isErr: () => false,
			value: (await correct({ height })).value + '00'
		});
		await assert.rejects(backend.getAssetSpliceInclusion(txid, fundingHeight));
		server.getBlockHex = correct;
		current.hash = 'ee'.repeat(32);
		await assert.rejects(backend.getAssetSpliceInclusion(txid, fundingHeight));
	});

	it('requires the serving peer to corroborate the wallet tip even when it can prove the funding block', async () => {
		const { txid, blocks, backend } = fixture();
		blocks[2] = mine(blocks[1].getHash(), Buffer.alloc(32, 91), 1700000700);
		await assert.rejects(backend.getAssetSpliceInclusion(txid, fundingHeight));
	});

	it('does not return inclusion from a proof callback that crosses a tip replacement or backend failover', async () => {
		for (const change of ['tip', 'server']) {
			const { txid, branch, server, backend, current } = fixture();
			let start!: () => void, finish!: () => void;
			const started = new Promise<void>((r) => {
				start = r;
			});
			const done = new Promise<void>((r) => {
				finish = r;
			});
			server.getTransactionMerkle = async () => {
				start();
				await done;
				return branch;
			};
			const result = backend.getAssetSpliceInclusion(txid, fundingHeight);
			await started;
			if (change === 'tip') {
				const replaced = chain(1700000999)[2];
				current.hash = replaced.getId();
				current.hex = replaced.toHex(true);
			} else backend.setElectrum(fixture().server as never);
			finish();
			await assert.rejects(result);
		}
	});

	it('refuses historical scans beyond its resource limit before fetching proof material', async () => {
		const { txid, current, server, backend } = fixture();
		current.height = 5_000_000;
		let lookups = 0;
		server.getTransactionMerkle = async () => {
			lookups++;
			return {};
		};
		server.getBlockHex = async () => {
			lookups++;
			return { isErr: () => false, value: '' };
		};
		await assert.rejects(backend.getAssetSpliceInclusion(txid, fundingHeight));
		assert.equal(lookups, 0);
	});

	it('requires the regtest backend and valid regtest work in every linked header', async () => {
		const { txid, blocks, server, backend, current } = fixture();
		server.electrumNetwork = 'bitcoin';
		await assert.rejects(backend.getAssetSpliceInclusion(txid, fundingHeight));
		server.electrumNetwork = 'bitcoinRegtest';
		const bad = Block.fromHex(blocks[1].toHex(true));
		while (bad.checkProofOfWork()) bad.nonce++;
		blocks[1] = bad;
		blocks[2] = mine(bad.getHash(), Buffer.alloc(32, 33), bad.timestamp + 1);
		current.hex = blocks[2].toHex(true);
		current.hash = blocks[2].getId();
		await assert.rejects(backend.getAssetSpliceInclusion(txid, fundingHeight));
	});
});
