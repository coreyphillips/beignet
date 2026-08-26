/**
 * Interop smoke: a live CLN ignores beignet's custom odd type 44069
 * (issue #546, LFBW port #532 workstream 1E).
 *
 * The whole fallback-safety story of the custom surface rests on BOLT 1
 * "it's OK to be odd": a peer that does not speak the protocol must ignore
 * the message rather than erroring or disconnecting. This sends real
 * envelopes (a known subtype, an unknown subtype, and a large payload) to a
 * live CLN and asserts the connection survives.
 *
 * Requires the `cln` container; auto-skips otherwise.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	createInteropNode,
	sleep,
	CLN_P2P_HOST,
	CLN_P2P_PORT
} from './cln-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	BeignetCustomSubtype,
	BEIGNET_CUSTOM_PROTOCOL_VERSION
} from '../../../src/lightning/message/custom';

describe('Interop: CLN ignores the beignet custom odd type (44069)', function () {
	this.timeout(120_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let skipAll = false;
	let node: LightningNode | undefined;

	before(async function () {
		this.timeout(60_000);
		if (!(await isClnAvailable())) {
			skipAll = true;
			console.log('    [skip] CLN container not reachable');
			this.skip();
			return;
		}
		cln = (await createClnClient())!;
		await waitForClnSync(cln);
		const info = (await cln.getInfo()) as unknown as { id: string };
		clnPubkey = info.id;
	});

	after(function () {
		if (node) {
			try {
				node.disconnectPeer(clnPubkey);
			} catch {
				/* ignore */
			}
			try {
				node.destroy();
			} catch {
				/* ignore */
			}
		}
	});

	it('stays connected through known, unknown and large custom envelopes', async function () {
		if (skipAll) this.skip();

		node = createInteropNode(946);
		node.on('node:error', () => {
			/* absorb */
		});
		await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(1500);

		// A reserved subtype, an unknown future subtype, and a chunky payload:
		// all must be silently ignored (BOLT 1 odd-type tolerance).
		node.sendCustomMessage(
			clnPubkey,
			BeignetCustomSubtype.JIT_RECEIVE_AUTHORIZATION,
			Buffer.from('smoke')
		);
		node.sendCustomMessage(clnPubkey, 40_000, crypto.randomBytes(1024));
		node.sendCustomMessage(
			clnPubkey,
			BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
			crypto.randomBytes(16_384)
		);
		await sleep(2000);

		// Our side still lists the peer ready (no error/disconnect came back)...
		const peers = node.listPeers();
		expect(peers.length).to.equal(1);
		expect(peers[0].pubkey).to.equal(clnPubkey);
		expect(peers[0].state).to.equal('ready');

		// ...and CLN still lists us connected.
		const beignetNodeId = node.getNodeId();
		let found = false;
		for (let i = 0; i < 5; i++) {
			const { peers: clnPeers } = await cln.listPeers();
			found = (clnPeers || []).some(
				(p) => p.id === beignetNodeId && p.connected
			);
			if (found) break;
			await sleep(500);
		}
		expect(found, 'CLN still lists us connected').to.equal(true);

		// The envelope version constant is what receivers key tolerance on;
		// pin it so a bump is a deliberate act.
		expect(BEIGNET_CUSTOM_PROTOCOL_VERSION).to.equal(1);
	});
});
