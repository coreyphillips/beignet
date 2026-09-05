/**
 * The M9.0 gate (spec section 15.3): R provisions a receipt witness for an
 * ACTIVE epoch, the witness restarts over its database with R offline, R
 * fetches an empty mailbox, and a mailbox nobody provisioned answers the
 * same way. Once on the in-process world (the witness is a fourth node on a
 * loopback link), once over a real BOLT 8 socket between two PeerManagers.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { Feature } from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FforState } from '../../src/lightning/ffor/types';
import {
	FF_WITNESS_FETCH_RESP_TYPE,
	FF_WITNESS_FETCH_TYPE
} from '../../src/lightning/ffor/witness-types';
import {
	decodeWitnessFetchResp,
	encodeWitnessFetch
} from '../../src/lightning/ffor/witness-messages';
import {
	NodeLink,
	TIP,
	activate,
	createWorld,
	makeBasepoints,
	makeNodeConfig,
	record,
	sha
} from './helpers/ffor-world';

function tmpDb(files: string[]): string {
	const f = path.join(
		os.tmpdir(),
		`ffor-w-${crypto.randomBytes(4).toString('hex')}.db`
	);
	files.push(f);
	return f;
}

async function waitFor(
	cond: () => boolean,
	label: string,
	timeoutMs = 15_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!cond()) {
		if (Date.now() > deadline)
			throw new Error(`Timed out waiting for ${label}`);
		await new Promise((r) => setTimeout(r, 25));
	}
}

describe('FFOR receipt witness transport (M9.0)', function () {
	this.timeout(60_000);
	const files: string[] = [];
	after(() => {
		for (const f of files) fs.rmSync(f, { force: true });
	});

	it('in-process: provision, witness restart, fetch empty, unknown mailbox identical, invoices gated on the ack', async () => {
		const w = createWorld();
		activate(w);
		const file = tmpDb(files);
		const storage1 = new SqliteStorage(file);
		storage1.open();
		const wConfig = makeNodeConfig(777, storage1, {
			fforWitness: { enabled: true }
		});
		const witness1 = new LightningNode(wConfig);
		witness1.on('node:error', () => {});
		const rw = new NodeLink(w.r, witness1);
		witness1.handleNewBlock(TIP);

		const { mailboxId, retentionUntil } = await w.r.provisionFforWitness(
			w.srHex,
			witness1.getNodeId()
		);
		expect(retentionUntil).to.equal(
			record(w.r, w.srHex).params.voucherExpiry + 288
		);
		const rRec = record(w.r, w.srHex);
		expect(rRec.witnesses).to.have.length(1);
		expect(rRec.witnesses[0].mailboxId.equals(mailboxId)).to.be.true;
		expect(rRec.witnesses[0].ackedAt).to.not.equal(null);
		expect(witness1.getFforWitnessService()!.listMailboxes()).to.have.length(1);
		// The mailbox knows the epoch's H_act and its hashes, and no key of R's.
		const mailbox = witness1.getFforWitnessService()!.listMailboxes()[0];
		expect(mailbox.hActHex).to.equal(rRec.hAct!.toString('hex'));
		expect(mailbox.entries.map((e) => e.hashHex)).to.deep.equal(
			rRec.paymentHashes.map((h) => h.toString('hex'))
		);
		expect(JSON.stringify(mailbox)).to.not.include(w.r.getNodeId());

		// The witness restarts over its database; R is offline throughout.
		rw.disconnect();
		storage1.close();
		const storage2 = new SqliteStorage(file);
		storage2.open();
		const witness2 = new LightningNode({ ...wConfig, storage: storage2 });
		witness2.on('node:error', () => {});
		witness2.handleNewBlock(TIP);
		expect(witness2.getFforWitnessService()!.listMailboxes()).to.have.length(1);

		// R returns and fetches: empty, verified against its own keys.
		const rw2 = new NodeLink(w.r, witness2);
		void rw2;
		const fetched = await w.r.fetchFforWitnessRecords(w.srHex);
		expect(fetched).to.have.length(1);
		expect(fetched[0].ok).to.be.true;
		expect(fetched[0].records).to.have.length(0);
		expect(fetched[0].credited).to.equal(0);

		// A mailbox nobody provisioned answers exactly like the empty one.
		const responses: Buffer[] = [];
		w.r.on('message:outbound', () => undefined);
		witness2.on(
			'message:outbound',
			(_pk: string, type: number, payload: Buffer) => {
				if (type === FF_WITNESS_FETCH_RESP_TYPE) responses.push(payload);
			}
		);
		const ghostId = crypto.randomBytes(16);
		witness2.handlePeerMessage(
			w.r.getNodeId(),
			FF_WITNESS_FETCH_TYPE,
			encodeWitnessFetch(
				ghostId,
				crypto.randomBytes(32),
				crypto.randomBytes(32),
				crypto.randomBytes(32)
			)
		);
		const realId = crypto.randomBytes(16);
		witness2.handlePeerMessage(
			w.r.getNodeId(),
			FF_WITNESS_FETCH_TYPE,
			encodeWitnessFetch(
				realId,
				mailboxId,
				crypto.randomBytes(32),
				rRec.witnesses[0].fetchPrivkey
			)
		);
		expect(responses).to.have.length(2);
		const ghost = decodeWitnessFetchResp(responses[0]);
		const real = decodeWitnessFetchResp(responses[1]);
		expect(ghost.ok).to.equal(real.ok);
		expect(ghost.records).to.deep.equal(real.records);
		expect(
			responses[0].subarray(16).equals(responses[1].subarray(16)),
			'byte-identical after the id'
		).to.be.true;

		// Close is advisory: acknowledged with the record count.
		const closed = await w.r.closeFforWitnesses(w.srHex);
		expect(closed[0].ok).to.be.true;
		expect(closed[0].held).to.equal(0);
		expect(witness2.getFforWitnessService()!.listMailboxes()[0].state).to.equal(
			'CLOSED'
		);
		storage2.close();
	});

	it('a witness that refuses is dropped, and an unacknowledged witness blocks invoice exposure', async () => {
		const w = createWorld();
		activate(w);
		// A witness with room for nothing.
		const full = new LightningNode(
			makeNodeConfig(778, undefined, {
				fforWitness: { enabled: true, maxMailboxes: 0 }
			})
		);
		full.on('node:error', () => {});
		new NodeLink(w.r, full);
		let refused: Error | null = null;
		try {
			await w.r.provisionFforWitness(w.srHex, full.getNodeId());
		} catch (err) {
			refused = err as Error;
		}
		expect(refused?.message).to.match(/cannot reserve/);
		expect(
			record(w.r, w.srHex).witnesses,
			'a refused witness is not counted'
		).to.have.length(0);
		expect(w.r.createFforVoucherInvoice(w.srHex, 1).bolt11).to.be.a('string');

		// A witness that never answers: the provision stays owed, no invoice.
		const silent = new LightningNode(makeNodeConfig(779));
		silent.on('node:error', () => {});
		new NodeLink(w.r, silent); // no witness service: the request is ignored
		const pending = w.r.provisionFforWitness(w.srHex, silent.getNodeId(), {
			timeoutMs: 200
		});
		expect(record(w.r, w.srHex).witnesses).to.have.length(1);
		expect(record(w.r, w.srHex).witnesses[0].ackedAt).to.equal(null);
		expect(() => w.r.createFforVoucherInvoice(w.srHex, 2)).to.throw(
			/has not acknowledged/
		);
		let timedOut: Error | null = null;
		try {
			await pending;
		} catch (err) {
			timedOut = err as Error;
		}
		expect(timedOut?.message).to.match(/did not answer/);
		expect(record(w.r, w.srHex).witnesses).to.have.length(0);
	});

	it('over a real BOLT 8 socket: provision and fetch between two PeerManagers', async () => {
		const mk = (
			seedId: number,
			extra: Partial<INodeConfig> = {}
		): LightningNode => {
			const seed = sha(`ffor-w-net-${seedId}`);
			const features = LightningNode.defaultFeatures();
			features.clearBit(Feature.DUAL_FUND + 1);
			const node = new LightningNode({
				nodePrivateKey: sha(seed, 'node-identity'),
				network: Network.REGTEST,
				channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
				channelBasepoints: makeBasepoints(seed),
				perCommitmentSeed: sha(seed, 'per-commitment'),
				fundingPrivkey: sha(seed, Buffer.from([0])),
				htlcBasepointSecret: sha(seed, Buffer.from([4])),
				enableNetworking: true,
				localFeatures: features,
				...extra
			});
			node.on('error', () => {});
			node.on('node:error', () => {});
			return node;
		};
		// R's epoch lives on the in-process world; only the witness lane is
		// on the socket, which is exactly the production shape: a witness is
		// any node R can dial, unrelated to the channel.
		const w = createWorld();
		activate(w);
		const witness = mk(1, { fforWitness: { enabled: true } });
		const rNet = mk(2);
		try {
			await witness.listen(0, '127.0.0.1');
			const port = (
				witness.getPeerManager() as unknown as {
					server: { address(): { port: number } };
				}
			).server.address().port;
			await rNet.connectPeer(witness.getNodeId(), '127.0.0.1', port);
			await waitFor(
				() => witness.listPeers().length === 1,
				'the witness sees R'
			);
			witness.handleNewBlock(TIP);

			// R's node on the socket relays for the world's R: it forwards the
			// lane messages both ways, so the manifest R signs travels over
			// TCP and the ack comes back the same way.
			const worldR = w.r;
			worldR.on(
				'message:outbound',
				(pk: string, type: number, payload: Buffer) => {
					if (pk === witness.getNodeId()) {
						rNet
							.getPeerManager()!
							.sendToPeer(witness.getNodeId(), type, payload);
					}
				}
			);
			rNet
				.getPeerManager()!
				.on('message', (pk: string, type: number, payload: Buffer) => {
					if (pk === witness.getNodeId())
						worldR.handlePeerMessage(pk, type, payload);
				});

			const { mailboxId } = await worldR.provisionFforWitness(
				w.srHex,
				witness.getNodeId()
			);
			expect(witness.getFforWitnessService()!.listMailboxes()[0].id).to.equal(
				mailboxId.toString('hex')
			);
			const fetched = await worldR.fetchFforWitnessRecords(w.srHex);
			expect(fetched[0].ok).to.be.true;
			expect(fetched[0].records).to.have.length(0);
			expect(record(worldR, w.srHex).state).to.equal(FforState.ACTIVE);
		} finally {
			rNet.destroy();
			witness.destroy();
		}
	});
});

export const unused = getPublicKey;
