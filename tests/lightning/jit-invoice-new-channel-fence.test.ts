/**
 * A JIT receive invoice is a promise that an LSP may open a channel to us.
 *
 * The LSP's engine serves an intercepted HTLC by opening a channel and
 * forwarding onto it, and it has no confirmed fallback: if our acceptor
 * refuses the open, openZeroConfChannelAndWait throws and the held parts fail
 * back upstream. Issue #906's fence makes that refusal a normal thing to do:
 * a bare-seed boot refuses every brand-new channel, inbound accepts included,
 * until it has learned a chain tip, and a daemon refuses one while a Recovery
 * Capsule restore is unresolved.
 *
 * Nothing connected the two. createJitInvoice happily minted an invoice at
 * height zero, and the payer found out it could not be served only when its
 * payment failed back at the LSP. A fenced node now refuses at the mint, and
 * says which condition holds, because every one of them lifts on its own.
 *
 * The carve-out matters as much: over an existing usable channel the payment
 * needs no new channel at all, so nothing here applies. That is the same
 * predicate the invoice already uses to decide whether to carry the LSP's
 * intercept hint.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { LnCoinType } from '../../src/lightning/keys/wallet-keys';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const TIP = 850_000;
const LSP_PUBKEY = '02' + 'ab'.repeat(32);
const noop = (): void => {};

function fixture(): { dir: string; node: LightningNode } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-jitfence-'));
	const storage = new SqliteStorage(path.join(dir, 'wallet.db'));
	storage.open();
	const node = LightningNode.fromMnemonic(MNEMONIC, {
		coinType: LnCoinType.REGTEST,
		storage,
		enableNetworking: false
	});
	node.on('error', noop);
	node.on('node:error', noop);
	return { dir, node };
}

/** Stand in for a usable channel with the LSP, the invoice's own predicate. */
function pretendChannelWith(node: LightningNode, pubkey: string): void {
	(
		node as unknown as {
			usableChannelWith(peer: string): unknown;
		}
	).usableChannelWith = (peer: string): unknown =>
		peer === pubkey ? { id: 'stand-in' } : null;
}

async function rejection(promise: Promise<unknown>): Promise<string> {
	try {
		await promise;
	} catch (err) {
		return err instanceof Error ? err.message : String(err);
	}
	return '(resolved)';
}

describe('JIT invoice against the new-channel fence (issue #906)', () => {
	it('refuses to mint while a bare-seed boot has no chain tip', async () => {
		const { dir, node } = fixture();
		try {
			expect(
				node.getChannelManager().channelIndexTipFloorArmed,
				'a birth boot arms the floor'
			).to.equal(true);
			const message = await rejection(
				node.createJitInvoice({
					lspPubkeyHex: LSP_PUBKEY,
					amountMsat: 100_000_000n
				})
			);
			expect(message).to.contain(
				'JIT receive needs a new channel from the LSP'
			);
			// The condition names itself, because it is the thing that lifts.
			expect(message).to.contain('chain tip');
		} finally {
			node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('mints once the first header has fired the floor', async () => {
		const { dir, node } = fixture();
		try {
			node.handleNewBlock(TIP);
			expect(node.getChannelManager().channelIndexTipFloorArmed).to.equal(
				false
			);
			// Past the fence, the request reaches the LSP, which is not connected
			// in this fixture, and answers that it cannot be reached. Reaching THAT
			// is the assertion.
			const message = await rejection(
				node.createJitInvoice({
					lspPubkeyHex: LSP_PUBKEY,
					amountMsat: 100_000_000n
				})
			);
			expect(message).to.not.contain('JIT receive needs a new channel');
			expect(message).to.contain('Networking is not enabled');
		} finally {
			node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('never refuses when the payment would route over an existing channel', async () => {
		const { dir, node } = fixture();
		try {
			pretendChannelWith(node, LSP_PUBKEY);
			expect(
				node.getChannelManager().channelIndexTipFloorArmed,
				'the fence is still armed'
			).to.equal(true);
			const message = await rejection(
				node.createJitInvoice({
					lspPubkeyHex: LSP_PUBKEY,
					amountMsat: 100_000_000n
				})
			);
			expect(message).to.not.contain('JIT receive needs a new channel');
			expect(message).to.contain('Networking is not enabled');
		} finally {
			node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('reports the same refusal the acceptors would answer the wire with', () => {
		const { dir, node } = fixture();
		try {
			const manager = node.getChannelManager();
			expect(manager.newChannelRefusal()).to.contain('chain tip');
			node.handleNewBlock(TIP);
			expect(manager.newChannelRefusal()).to.equal(null);
		} finally {
			node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
