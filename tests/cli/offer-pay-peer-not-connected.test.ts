/**
 * Issue #1974: an invoice_request the node has no link to send is a typed
 * PEER_NOT_CONNECTED refusal (409), not a scrubbed INTERNAL_ERROR.
 *
 * Offline suite: the engine's requestInvoice is stubbed to refuse the way the
 * peer link does, so nothing needs a chain, a peer or a channel.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import { statusForErrorCode } from '../../src/cli/daemon';
import {
	PeerError,
	PeerErrorCode
} from '../../src/lightning/transport/peer-manager';

const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('payOffer with no link to the first hop (#1974)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1974-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			...OFFLINE_ELECTRUM
		});
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('answers PEER_NOT_CONNECTED', async () => {
		const offer = node.createOffer({ description: 'x' }).encoded!;
		const engine = (
			node as unknown as {
				node: { requestInvoice: () => Promise<unknown> };
			}
		).node;
		engine.requestInvoice = async (): Promise<never> => {
			throw new PeerError(
				PeerErrorCode.NOT_CONNECTED,
				'Not connected to peer 02aa'
			);
		};

		let err: unknown;
		try {
			await node.payOffer(offer, 1_234);
		} catch (e) {
			err = e;
		}

		expect(err).to.be.instanceOf(BeignetError);
		expect((err as BeignetError).code).to.equal('PEER_NOT_CONNECTED');
		expect((err as BeignetError).message).to.equal(
			'Not connected to peer 02aa'
		);
		expect(statusForErrorCode('PEER_NOT_CONNECTED')).to.equal(409);
		expect(node.listPayments()).to.have.length(0);
	});
});
