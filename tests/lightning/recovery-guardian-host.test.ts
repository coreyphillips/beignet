/**
 * The guardian host (wire 2.7, issue #699 D4 and D5): one node serving the
 * reference guardian to many sets over bolt8 sessions. Registration carries
 * the member list and is refused when the list does not hash to the set id
 * or does not name this guardian; sets are isolated in their own stores and
 * survive a host restart through the index; quotas refuse rather than
 * delete; a bearer token gates the transport.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { Peer } from '../../src/lightning/transport/peer';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	decodeCustomMessage,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import {
	CRASH_V1_PROFILE,
	GuardianBolt8FrameError,
	GuardianClient,
	GuardianHost,
	GuardianState,
	GuardianStatus,
	GuardianTransportError,
	IGuardianHostEvent,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	bolt8GuardianTransport,
	computeGuardianSetId,
	deriveGuardianRoot,
	deriveRecoveryRoot,
	genesisLogHead,
	recordTranscriptHash,
	registerTranscriptHash,
	signTranscript,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

/** The host node: its identity key derives its guardian key (D4). */
const HOST_NODE_SECRET = sha('host-node-secret');
const HOST_NODE_ID = getPublicKey(HOST_NODE_SECRET);
const HOST = deriveGuardianRoot(HOST_NODE_SECRET);

/** Two other guardians per set, so two distinct sets both include the host. */
const OTHERS_A = [sha('other-a-1'), sha('other-a-2')].map(xOnlyFromSecret);
const OTHERS_B = [sha('other-b-1'), sha('other-b-2')].map(xOnlyFromSecret);
const SET_A = [HOST.guardianId, ...OTHERS_A];
const SET_B = [HOST.guardianId, ...OTHERS_B];
const setIdOf = (members: Buffer[]): Buffer =>
	computeGuardianSetId({ ...CRASH_V1_PROFILE, guardianIds: members });

interface IWriter {
	root: { rootSecret: Buffer; recoveryId: Buffer };
	writer: { secret: Buffer; pub: Buffer };
}

function makeWriter(tag: string): IWriter {
	const writerSecret = sha(`${tag}-writer`);
	return {
		root: deriveRecoveryRoot(sha(`${tag}-node`)),
		writer: { secret: writerSecret, pub: xOnlyFromSecret(writerSecret) }
	};
}

function registration(
	who: IWriter,
	members: Buffer[],
	overrides: Partial<IGuardianRegisterNodeRequest> = {}
): IGuardianRegisterNodeRequest {
	const setId = setIdOf(members);
	const initialState: GuardianState = {
		recoveryId: who.root.recoveryId,
		lease: { epoch: 1n, writerPublicKey: who.writer.pub },
		origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
		logHead: genesisLogHead()
	};
	return {
		protocolVersion: 1,
		guardianSetId: setId,
		guardianMembers: members,
		initialState,
		rootSignature: signTranscript(
			registerTranscriptHash(setId, initialState),
			who.root.rootSecret
		),
		...overrides
	};
}

function record(
	who: IWriter,
	members: Buffer[],
	sequence: bigint,
	previousHash: Buffer,
	ciphertext = sha(`ct-${sequence}`)
): IGuardianRecord {
	const setId = setIdOf(members);
	const frameHash = sha(
		`fh-${who.root.recoveryId.toString('hex')}-${sequence}`
	);
	return {
		protocolVersion: 1,
		guardianSetId: setId,
		recoveryId: who.root.recoveryId,
		epoch: 1n,
		sequence,
		previousHash,
		frameHash,
		ciphertext,
		writerSignature: signTranscript(
			recordTranscriptHash(setId, {
				recoveryId: who.root.recoveryId,
				epoch: 1n,
				sequence,
				previousHash,
				frameHash,
				ciphertextHash: sha256(ciphertext)
			}),
			who.writer.secret
		)
	};
}

/** A TCP listener that speaks BOLT 8 as the host node and routes to the host. */
interface IHostServer {
	url: string;
	events: IGuardianHostEvent[];
	host: GuardianHost;
	close(): Promise<void>;
}

async function serve(
	dir: string,
	options: Partial<ConstructorParameters<typeof GuardianHost>[0]> = {}
): Promise<IHostServer> {
	const events: IGuardianHostEvent[] = [];
	const host = new GuardianHost({
		path: dir,
		guardianSecret: HOST.guardianSecret,
		onEvent: (event): void => {
			events.push(event);
		},
		...options
	});
	const peers: Peer[] = [];
	const server = net.createServer((socket) => {
		const peer = new Peer({
			localPrivateKey: HOST_NODE_SECRET,
			remotePublicKey: Buffer.alloc(33, 0),
			host: '127.0.0.1',
			port: 0
		});
		peers.push(peer);
		peer.on('error', () => undefined);
		peer.on('message', (type: number, payload: Buffer) => {
			if (type !== BEIGNET_CUSTOM_MESSAGE_TYPE) return;
			const envelope = decodeCustomMessage(payload);
			if (envelope.subtype !== BeignetCustomSubtype.GUARDIAN_REQUEST) return;
			const pubkey = peer.remotePublicKey.toString('hex');
			let frames: Buffer[];
			try {
				frames = host.handle(pubkey, envelope.payload);
			} catch (error) {
				expect(error).to.be.instanceOf(GuardianBolt8FrameError);
				peer.disconnect();
				return;
			}
			for (const frame of frames) {
				peer.sendMessage(
					BEIGNET_CUSTOM_MESSAGE_TYPE,
					encodeCustomMessage(BeignetCustomSubtype.GUARDIAN_RESPONSE, frame)
				);
			}
		});
		peer.on('close', () =>
			host.sessionClosed(peer.remotePublicKey.toString('hex'))
		);
		void peer.acceptInbound(socket).catch(() => socket.destroy());
	});
	const port = await new Promise<number>((resolve) => {
		server.listen(0, '127.0.0.1', () => {
			resolve((server.address() as net.AddressInfo).port);
		});
	});
	return {
		url: `bolt8://${HOST_NODE_ID.toString('hex')}@127.0.0.1:${port}`,
		events,
		host,
		close: (): Promise<void> =>
			new Promise((resolve) => {
				for (const peer of peers) peer.disconnect();
				host.close();
				server.close(() => resolve());
			})
	};
}

function clientFor(
	served: IHostServer,
	members: Buffer[],
	auth?: { type: 'bearer'; token: string }
): { client: GuardianClient; close: () => void } {
	const transport = bolt8GuardianTransport({
		session: { reconnectMinMs: 1, reconnectMaxMs: 2 }
	});
	return {
		client: new GuardianClient({
			url: served.url,
			guardianSetId: setIdOf(members),
			transport,
			timeoutMs: 5_000,
			auth
		}),
		close: (): void => transport.close()
	};
}

describe('guardian host', () => {
	let dir: string;
	let served: IHostServer;
	const closers: Array<() => void> = [];

	beforeEach(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-guardian-host-'));
		served = await serve(dir);
	});

	afterEach(async () => {
		for (const close of closers.splice(0)) close();
		await served.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('derives its guardian id from the node secret, never the node id', () => {
		expect(HOST.guardianId).to.have.length(32);
		expect(HOST.guardianId.equals(HOST_NODE_ID.subarray(1))).to.equal(false);
		expect(served.host.guardianId.equals(HOST.guardianId)).to.equal(true);
		expect(
			deriveGuardianRoot(HOST_NODE_SECRET).guardianId.equals(HOST.guardianId)
		).to.equal(true);
	});

	it('serves two sets from one directory, each in its own store', async () => {
		const alice = makeWriter('alice');
		const bob = makeWriter('bob');
		const a = clientFor(served, SET_A);
		const b = clientFor(served, SET_B);
		closers.push(a.close, b.close);

		expect((await a.client.info()).guardianSetIds).to.have.length(0);
		expect(
			(await a.client.register(registration(alice, SET_A))).status
		).to.equal(GuardianStatus.OK);
		expect((await b.client.register(registration(bob, SET_B))).status).to.equal(
			GuardianStatus.OK
		);
		const putA = await a.client.putState(
			record(alice, SET_A, 1n, Buffer.alloc(32))
		);
		expect(putA.status).to.equal(GuardianStatus.OK);
		const headB = await b.client.getHead(bob.root.recoveryId);
		expect(headB.status).to.equal(GuardianStatus.OK);
		expect(headB.receipt!.state.logHead.sequence).to.equal(0n);

		const info = await a.client.info();
		expect(
			info.guardianSetIds.map((id) => id.toString('hex')).sort()
		).to.deep.equal(
			[setIdOf(SET_A), setIdOf(SET_B)].map((id) => id.toString('hex')).sort()
		);
		const files = fs.readdirSync(dir).sort();
		expect(files).to.include(`${setIdOf(SET_A).toString('hex')}.sqlite`);
		expect(files).to.include(`${setIdOf(SET_B).toString('hex')}.sqlite`);
		expect(files).to.include('sets.json');

		const status = served.host.status();
		expect(status.sets).to.have.length(2);
		expect(
			status.sets.find((s) => s.setId === setIdOf(SET_A).toString('hex'))!
				.namespaces
		).to.equal(1);
		expect(status.authRequired).to.equal(false);
		expect(
			served.events.filter((e) => e.type === 'guardian:set-registered')
		).to.have.length(2);
	});

	it('refuses a registration whose members do not hash to the set id or omit this guardian', async () => {
		const alice = makeWriter('alice');
		const a = clientFor(served, SET_A);
		closers.push(a.close);
		// Members disagree with the set id the request names.
		const mismatch = await a.client.register(
			registration(alice, SET_A, { guardianMembers: SET_B })
		);
		expect(mismatch.status).to.equal(GuardianStatus.ERR_MALFORMED);
		expect(mismatch.detail).to.match(/do not hash/);
		// A set that does not include this host, consistently named.
		const strangers = [sha('s1'), sha('s2'), sha('s3')].map(xOnlyFromSecret);
		const strangerClient = clientFor(served, strangers);
		closers.push(strangerClient.close);
		const outsider = await strangerClient.client.register(
			registration(alice, strangers)
		);
		expect(outsider.status).to.equal(GuardianStatus.ERR_UNKNOWN_SET);
		// Two members only.
		const short = await a.client.register(
			registration(alice, SET_A, { guardianMembers: SET_A.slice(0, 2) })
		);
		expect(short.status).to.equal(GuardianStatus.ERR_MALFORMED);
		expect(served.host.servedSetIds()).to.have.length(0);
	});

	it('answers ERR_UNKNOWN_SET to a write for a set nobody registered', async () => {
		const alice = makeWriter('alice');
		const a = clientFor(served, SET_A);
		closers.push(a.close);
		const put = await a.client.putState(
			record(alice, SET_A, 1n, Buffer.alloc(32))
		);
		expect(put.status).to.equal(GuardianStatus.ERR_UNKNOWN_SET);
		const head = await a.client.getHead(alice.root.recoveryId);
		expect(head.status).to.equal(GuardianStatus.ERR_UNKNOWN_SET);
	});

	it('caps the number of sets and the bytes per set, refusing rather than deleting', async () => {
		await served.close();
		served = await serve(dir, { maxSets: 1, maxBytesPerSet: 160 * 1024 });
		const alice = makeWriter('alice');
		const bob = makeWriter('bob');
		const a = clientFor(served, SET_A);
		const b = clientFor(served, SET_B);
		closers.push(a.close, b.close);
		expect(
			(await a.client.register(registration(alice, SET_A))).status
		).to.equal(GuardianStatus.OK);
		const second = await b.client.register(registration(bob, SET_B));
		expect(second.status).to.equal(GuardianStatus.ERR_QUOTA_EXCEEDED);

		// Fill set A past its byte quota; the store is a SQLite file, so the
		// first records fit inside the initial pages and later ones do not.
		let previous = Buffer.alloc(32);
		let refused = false;
		for (let sequence = 1n; sequence <= 40n; sequence++) {
			const rec = record(
				alice,
				SET_A,
				sequence,
				previous,
				crypto.randomBytes(8192)
			);
			const put = await a.client.putState(rec);
			if (put.status === GuardianStatus.ERR_QUOTA_EXCEEDED) {
				refused = true;
				break;
			}
			expect(put.status).to.equal(GuardianStatus.OK);
			previous = rec.frameHash;
		}
		expect(refused).to.equal(true);
		// Reads still work: the quota refuses writes, it never removes state.
		const head = await a.client.getHead(alice.root.recoveryId);
		expect(head.status).to.equal(GuardianStatus.OK);
		expect(head.receipt!.state.logHead.sequence > 0n).to.equal(true);
		expect(
			served.events.some((e) => e.type === 'guardian:quota-refused')
		).to.equal(true);
	});

	it('reopens every served set from the index after a restart', async () => {
		const alice = makeWriter('alice');
		const a = clientFor(served, SET_A);
		closers.push(a.close);
		await a.client.register(registration(alice, SET_A));
		const rec = record(alice, SET_A, 1n, Buffer.alloc(32));
		expect((await a.client.putState(rec)).status).to.equal(GuardianStatus.OK);
		a.close();
		await served.close();

		served = await serve(dir);
		const again = clientFor(served, SET_A);
		closers.push(again.close);
		const info = await again.client.info();
		expect(info.guardianSetIds.map((id) => id.toString('hex'))).to.deep.equal([
			setIdOf(SET_A).toString('hex')
		]);
		const head = await again.client.getHead(alice.root.recoveryId);
		expect(head.status).to.equal(GuardianStatus.OK);
		expect(
			head.receipt!.state.logHead.frameHash.equals(rec.frameHash)
		).to.equal(true);
		// Re-registering the same genesis is the idempotent duplicate.
		expect(
			(await again.client.register(registration(alice, SET_A))).status
		).to.equal(GuardianStatus.OK_DUPLICATE);
	});

	it('refuses to start on an index naming a set it is not a member of', async () => {
		await served.close();
		const strangers = [sha('s1'), sha('s2'), sha('s3')].map(xOnlyFromSecret);
		fs.writeFileSync(
			path.join(dir, 'sets.json'),
			JSON.stringify({
				version: 1,
				sets: {
					[setIdOf(strangers).toString('hex')]: {
						members: strangers.map((m) => m.toString('hex')),
						registeredAt: 1
					}
				}
			})
		);
		expect(
			() => new GuardianHost({ path: dir, guardianSecret: HOST.guardianSecret })
		).to.throw(/cannot serve/);
		// Leave a usable host behind for afterEach.
		fs.unlinkSync(path.join(dir, 'sets.json'));
		served = await serve(dir);
	});

	it('gates every session on the bearer token when one is configured', async () => {
		await served.close();
		served = await serve(dir, { token: 'pool-secret' });
		const anonymous = clientFor(served, SET_A);
		const wrong = clientFor(served, SET_A, { type: 'bearer', token: 'nope' });
		const right = clientFor(served, SET_A, {
			type: 'bearer',
			token: 'pool-secret'
		});
		closers.push(anonymous.close, wrong.close, right.close);
		for (const client of [anonymous.client, wrong.client]) {
			let failure: unknown;
			try {
				await client.info();
			} catch (error) {
				failure = error;
			}
			expect(failure).to.be.instanceOf(GuardianTransportError);
			expect((failure as GuardianTransportError).httpStatus).to.equal(401);
		}
		expect(
			(await right.client.info()).guardianId.equals(HOST.guardianId)
		).to.equal(true);
		expect(served.host.status().authRequired).to.equal(true);
	});

	it('keeps one session per peer and forgets it when the peer leaves', async () => {
		const a = clientFor(served, SET_A);
		closers.push(a.close);
		await a.client.info();
		expect(served.host.status().sessions).to.equal(1);
		a.close();
		for (let i = 0; i < 100 && served.host.status().sessions > 0; i++) {
			await new Promise((resolve) => setTimeout(resolve, 10));
		}
		expect(served.host.status().sessions).to.equal(0);
	});
});
