/**
 * bolt8 guardian sessions (wire 2.7, issue #699): the bolt8 address form,
 * the chunked frame codec and its reassembly rules, endpoint selection with
 * a fourth transport, and a loopback session driving the UNCHANGED
 * GuardianClient through every verb against a node-hosted guardian, with
 * the answers compared byte for byte against the HTTP transport.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as net from 'net';
import { Peer } from '../../src/lightning/transport/peer';
import {
	BEIGNET_CUSTOM_MAX_PAYLOAD,
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	decodeCustomMessage,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import {
	CRASH_V1_PROFILE,
	GUARDIAN_BOLT8_CHUNK_BODY_BYTES,
	GUARDIAN_BOLT8_FRAME_HEADER_BYTES,
	GuardianBolt8Assembler,
	GuardianBolt8FrameError,
	GuardianBolt8Responder,
	GuardianBolt8Status,
	GuardianBolt8Verb,
	GuardianClient,
	GuardianDescriptor,
	GuardianHttpServer,
	GuardianState,
	GuardianStatus,
	GuardianTransportError,
	IGuardianBolt8Request,
	IGuardianBolt8Response,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	ReferenceGuardian,
	assertGuardianDescriptors,
	bearerAuthenticator,
	bolt8BearerAuthenticator,
	bolt8GuardianTransport,
	computeGuardianSetId,
	decodeGuardianBolt8Frame,
	deriveRecoveryRoot,
	encodeGuardianBolt8Request,
	encodeGuardianBolt8Response,
	genesisLogHead,
	guardianBolt8VerbCode,
	guardianBolt8VerbName,
	guardianDescriptorFor,
	parseBolt8GuardianUrl,
	parseGuardianUri,
	recordTranscriptHash,
	registerTranscriptHash,
	selectGuardianEndpoint,
	signTranscript,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`bolt8-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const ROOT = deriveRecoveryRoot(sha('bolt8-node-secret'));
const WRITER = {
	secret: sha('bolt8-writer'),
	pub: xOnlyFromSecret(sha('bolt8-writer'))
};

/** The node identity of the guardian HOST (what the URL's userinfo names). */
const HOST_NODE_SECRET = sha('bolt8-host-node-secret');
const HOST_NODE_ID = getPublicKey(HOST_NODE_SECRET);
const HOST_NODE_HEX = HOST_NODE_ID.toString('hex');

function makeGuardian(startClock: bigint): ReferenceGuardian {
	let now = startClock;
	return new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[0],
		members: GUARDIAN_IDS,
		clock: (): bigint => ++now
	});
}

function buildRegistration(): IGuardianRegisterNodeRequest {
	const initialState: GuardianState = {
		recoveryId: ROOT.recoveryId,
		lease: { epoch: 1n, writerPublicKey: WRITER.pub },
		origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
		logHead: genesisLogHead()
	};
	return {
		protocolVersion: 1,
		guardianSetId: SET_ID,
		guardianMembers: GUARDIAN_IDS,
		initialState,
		rootSignature: signTranscript(
			registerTranscriptHash(SET_ID, initialState),
			ROOT.rootSecret
		)
	};
}

function buildRecord(opts: {
	sequence: bigint;
	previousHash: Buffer;
	ciphertext?: Buffer;
}): IGuardianRecord {
	const ciphertext =
		opts.ciphertext ?? sha(`bolt8-ciphertext-${opts.sequence}`);
	const frameHash = sha(`bolt8-frame-${opts.sequence}`);
	return {
		protocolVersion: 1,
		guardianSetId: SET_ID,
		recoveryId: ROOT.recoveryId,
		epoch: 1n,
		sequence: opts.sequence,
		previousHash: opts.previousHash,
		frameHash,
		ciphertext,
		writerSignature: signTranscript(
			recordTranscriptHash(SET_ID, {
				recoveryId: ROOT.recoveryId,
				epoch: 1n,
				sequence: opts.sequence,
				previousHash: opts.previousHash,
				frameHash,
				ciphertextHash: sha256(ciphertext)
			}),
			WRITER.secret
		)
	};
}

/**
 * A minimal node-hosted guardian: a TCP listener that runs the BOLT 8
 * handshake as the host node and routes GUARDIAN_REQUEST envelopes to one
 * responder per session. This is the shape the Phase B host inside the
 * node takes; here it is a raw Peer so the transport is tested alone.
 */
interface IBolt8Host {
	port: number;
	url: string;
	sessions: Peer[];
	close(): Promise<void>;
}

async function startHost(
	guardian: ReferenceGuardian,
	options: {
		authenticate?: (auth: Buffer | undefined) => boolean;
		maxBodyBytes?: number;
	} = {}
): Promise<IBolt8Host> {
	const sessions: Peer[] = [];
	const server = net.createServer((socket) => {
		const peer = new Peer({
			localPrivateKey: HOST_NODE_SECRET,
			remotePublicKey: Buffer.alloc(33, 0),
			host: '127.0.0.1',
			port: 0
		});
		const responder = new GuardianBolt8Responder({
			guardian,
			authenticate: options.authenticate,
			maxBodyBytes: options.maxBodyBytes
		});
		peer.on('message', (type: number, payload: Buffer) => {
			if (type !== BEIGNET_CUSTOM_MESSAGE_TYPE) return;
			const envelope = decodeCustomMessage(payload);
			if (envelope.subtype !== BeignetCustomSubtype.GUARDIAN_REQUEST) return;
			let frames: Buffer[];
			try {
				frames = responder.handle(envelope.payload);
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
		peer.on('error', () => undefined);
		sessions.push(peer);
		void peer.acceptInbound(socket).catch(() => socket.destroy());
	});
	const port = await new Promise<number>((resolve, reject) => {
		server.once('error', reject);
		server.listen(0, '127.0.0.1', () => {
			const address = server.address();
			if (address === null || typeof address === 'string') {
				reject(new Error('no address'));
				return;
			}
			resolve(address.port);
		});
	});
	return {
		port,
		url: `bolt8://${HOST_NODE_HEX}@127.0.0.1:${port}`,
		sessions,
		close: (): Promise<void> =>
			new Promise((resolve) => {
				for (const peer of sessions) peer.disconnect();
				server.close(() => resolve());
			})
	};
}

describe('bolt8 guardian address', () => {
	const good = `bolt8://${HOST_NODE_HEX}@guardian.example:9735`;

	it('parses the canonical form and lowercases the node id', () => {
		const target = parseBolt8GuardianUrl(
			good.toUpperCase().replace('BOLT8', 'bolt8')
		);
		expect(target.nodeId.equals(HOST_NODE_ID)).to.equal(true);
		expect(target.host).to.equal('guardian.example');
		expect(target.port).to.equal(9735);
		expect(target.url).to.equal(good);
	});

	it('strips IPv6 brackets from the host it dials', () => {
		const target = parseBolt8GuardianUrl(`bolt8://${HOST_NODE_HEX}@[::1]:9735`);
		expect(target.host).to.equal('::1');
		expect(target.url).to.equal(`bolt8://${HOST_NODE_HEX}@[::1]:9735`);
	});

	it('refuses the wrong key length, a password, a missing port, a path', () => {
		const xonly = HOST_NODE_HEX.slice(2);
		expect(() => parseBolt8GuardianUrl(`bolt8://${xonly}@h:1`)).to.throw(
			/66-hex compressed node id/
		);
		expect(() =>
			parseBolt8GuardianUrl(`bolt8://${HOST_NODE_HEX}:secret@h:1`)
		).to.throw(/nothing else/);
		expect(() => parseBolt8GuardianUrl(`bolt8://${HOST_NODE_HEX}@h`)).to.throw(
			/no port/
		);
		expect(() =>
			parseBolt8GuardianUrl(`bolt8://${HOST_NODE_HEX}@h:1/beignet-guardian/v1`)
		).to.throw(/must not carry a path/);
		expect(() => parseBolt8GuardianUrl(`http://${HOST_NODE_HEX}@h:1`)).to.throw(
			/not a bolt8 URL/
		);
		expect(() =>
			parseBolt8GuardianUrl(`bolt8://${'ff'.repeat(33)}@h:1`)
		).to.throw(/not a valid compressed secp256k1 point/);
	});

	it('is accepted by parseGuardianUri with the guardian id in front', () => {
		const entry = `${GUARDIAN_IDS[0].toString('hex')}@${good}`;
		const parsed = parseGuardianUri(entry);
		expect(parsed.guardianId.equals(GUARDIAN_IDS[0])).to.equal(true);
		expect(parsed.url).to.equal(good);
		// The http rule against userinfo is untouched.
		expect(() =>
			parseGuardianUri(`${GUARDIAN_IDS[0].toString('hex')}@https://u@h`)
		).to.throw(/must not carry credentials/);
	});

	it('classifies as a bolt8 descriptor that the capsule validator accepts', () => {
		const descriptor = guardianDescriptorFor(
			parseGuardianUri(`${GUARDIAN_IDS[0].toString('hex')}@${good}`)
		);
		expect(descriptor.transports).to.deep.equal([{ type: 'bolt8', url: good }]);
		const roundTripped = assertGuardianDescriptors([descriptor]);
		expect(roundTripped).to.deep.equal([descriptor]);
	});

	it('is selected after https, needs Tor for an onion host, beats local-http', () => {
		const onion = `bolt8://${HOST_NODE_HEX}@${'a'.repeat(56)}.onion:9735`;
		const withHttps: GuardianDescriptor = {
			guardianId: GUARDIAN_IDS[0].toString('hex'),
			transports: [
				{ type: 'local-http', url: 'http://127.0.0.1:8080' },
				{ type: 'bolt8', url: good },
				{ type: 'https', url: 'https://g.example' }
			]
		};
		expect(
			selectGuardianEndpoint(withHttps, {
				torEnabled: false,
				allowLocalHttp: true
			})
		).to.deep.equal({ url: 'https://g.example', transportType: 'https' });
		const onlyBolt8: GuardianDescriptor = {
			guardianId: GUARDIAN_IDS[0].toString('hex'),
			transports: [
				{ type: 'local-http', url: 'http://127.0.0.1:8080' },
				{ type: 'bolt8', url: good }
			]
		};
		expect(
			selectGuardianEndpoint(onlyBolt8, {
				torEnabled: false,
				allowLocalHttp: true
			})
		).to.deep.equal({ url: good, transportType: 'bolt8' });
		const onionOnly: GuardianDescriptor = {
			guardianId: GUARDIAN_IDS[0].toString('hex'),
			transports: [{ type: 'bolt8', url: onion }]
		};
		expect(() =>
			selectGuardianEndpoint(onionOnly, { torEnabled: false })
		).to.throw(GuardianTransportError);
		expect(
			selectGuardianEndpoint(onionOnly, { torEnabled: true })
		).to.deep.equal({
			url: onion,
			transportType: 'bolt8'
		});
	});

	it('maps verb names and codes both ways', () => {
		expect(guardianBolt8VerbCode('info')).to.equal(GuardianBolt8Verb.INFO);
		expect(guardianBolt8VerbCode('put_state')).to.equal(
			GuardianBolt8Verb.PUT_STATE
		);
		expect(guardianBolt8VerbCode('nope')).to.equal(null);
		expect(guardianBolt8VerbName(GuardianBolt8Verb.SYNC_EPOCH)).to.equal(
			'sync_epoch'
		);
		expect(guardianBolt8VerbName(200)).to.equal(null);
	});
});

describe('bolt8 guardian frames', () => {
	const firstBodyCapacity = (prefixLength: number): number =>
		BEIGNET_CUSTOM_MAX_PAYLOAD -
		GUARDIAN_BOLT8_FRAME_HEADER_BYTES -
		prefixLength;

	function reassemble(
		frames: Buffer[],
		kind: 'request' | 'response'
	): IGuardianBolt8Request | IGuardianBolt8Response {
		const assembler = new GuardianBolt8Assembler({
			kind,
			maxBodyBytes: 64 * 1024 * 1024
		});
		let complete: IGuardianBolt8Request | IGuardianBolt8Response | null = null;
		for (const frame of frames) {
			const result = assembler.push(frame);
			if (result?.kind === 'complete') complete = result.message;
		}
		expect(complete).to.not.equal(null);
		expect(assembler.inFlight).to.equal(0);
		return complete!;
	}

	it('round-trips an empty body, a one-chunk body, and the exact boundary', () => {
		const auth = Buffer.from('Bearer t', 'utf8');
		for (const length of [0, 1, firstBodyCapacity(2 + auth.length)]) {
			const body = crypto.randomBytes(length);
			const frames = encodeGuardianBolt8Request({
				requestId: 7,
				verb: GuardianBolt8Verb.PUT_STATE,
				auth,
				body
			});
			expect(frames).to.have.length(1);
			expect(frames[0].length).to.be.at.most(BEIGNET_CUSTOM_MAX_PAYLOAD);
			const back = reassemble(frames, 'request') as IGuardianBolt8Request;
			expect(back.requestId).to.equal(7);
			expect(back.verb).to.equal(GuardianBolt8Verb.PUT_STATE);
			expect(back.auth!.equals(auth)).to.equal(true);
			expect(back.body.equals(body)).to.equal(true);
		}
	});

	it('splits a large response into ordered chunks that reassemble exactly', () => {
		const body = crypto.randomBytes(
			firstBodyCapacity(2) + 3 * GUARDIAN_BOLT8_CHUNK_BODY_BYTES + 1
		);
		const frames = encodeGuardianBolt8Response({
			requestId: 0xffffffff,
			verb: GuardianBolt8Verb.GET_STATE,
			status: 200,
			body
		});
		expect(frames).to.have.length(5);
		for (const frame of frames) {
			expect(frame.length).to.be.at.most(BEIGNET_CUSTOM_MAX_PAYLOAD);
		}
		const headers = frames.map(
			(f) => decodeGuardianBolt8Frame(f, 'response').header
		);
		expect(headers.map((h) => h.chunkIndex)).to.deep.equal([0, 1, 2, 3, 4]);
		expect(new Set(headers.map((h) => h.chunkCount))).to.deep.equal(
			new Set([5])
		);
		const back = reassemble(frames, 'response') as IGuardianBolt8Response;
		expect(back.status).to.equal(200);
		expect(back.requestId).to.equal(0xffffffff);
		expect(back.body.equals(body)).to.equal(true);
	});

	it('omits the auth field when running open and refuses an oversized one', () => {
		const [frame] = encodeGuardianBolt8Request({
			requestId: 1,
			verb: GuardianBolt8Verb.INFO,
			body: Buffer.alloc(0)
		});
		const decoded = decodeGuardianBolt8Frame(frame, 'request');
		expect(decoded.auth).to.equal(undefined);
		expect(decoded.chunk).to.have.length(0);
		expect(() =>
			encodeGuardianBolt8Request({
				requestId: 1,
				verb: GuardianBolt8Verb.INFO,
				auth: Buffer.alloc(4097),
				body: Buffer.alloc(0)
			})
		).to.throw(GuardianBolt8FrameError);
	});

	it('lets requests interleave but refuses chunks out of order', () => {
		const big = (id: number): Buffer[] =>
			encodeGuardianBolt8Request({
				requestId: id,
				verb: GuardianBolt8Verb.PUT_STATE,
				body: crypto.randomBytes(
					firstBodyCapacity(2) + 2 * GUARDIAN_BOLT8_CHUNK_BODY_BYTES
				)
			});
		const a = big(1);
		const b = big(2);
		const assembler = new GuardianBolt8Assembler({
			kind: 'request',
			maxBodyBytes: 1 << 24
		});
		expect(assembler.push(a[0])).to.equal(null);
		expect(assembler.push(b[0])).to.equal(null);
		expect(assembler.push(a[1])).to.equal(null);
		expect(assembler.push(b[1])).to.equal(null);
		expect(assembler.inFlight).to.equal(2);
		expect(assembler.push(b[2])?.kind).to.equal('complete');
		expect(assembler.push(a[2])?.kind).to.equal('complete');
		expect(assembler.inFlight).to.equal(0);

		const strict = new GuardianBolt8Assembler({
			kind: 'request',
			maxBodyBytes: 1 << 24
		});
		strict.push(a[0]);
		expect(() => strict.push(a[2])).to.throw(
			GuardianBolt8FrameError,
			/out of order/
		);
		expect(() => strict.push(b[1])).to.throw(
			GuardianBolt8FrameError,
			/unknown request/
		);
		strict.push(b[0]);
		expect(() => strict.push(b[0])).to.throw(
			GuardianBolt8FrameError,
			/still in flight/
		);
	});

	it('reports a too-large body once and swallows the rest of its chunks', () => {
		const frames = encodeGuardianBolt8Request({
			requestId: 9,
			verb: GuardianBolt8Verb.PUT_STATE,
			body: crypto.randomBytes(200_000)
		});
		const assembler = new GuardianBolt8Assembler({
			kind: 'request',
			maxBodyBytes: 100_000
		});
		const first = assembler.push(frames[0]);
		expect(first).to.deep.equal({
			kind: 'too-large',
			requestId: 9,
			verb: GuardianBolt8Verb.PUT_STATE,
			totalLength: 200_000
		});
		for (const frame of frames.slice(1))
			expect(assembler.push(frame)).to.equal(null);
		expect(assembler.inFlight).to.equal(0);
		// The id is free again once every chunk has been swallowed.
		const small = encodeGuardianBolt8Request({
			requestId: 9,
			verb: GuardianBolt8Verb.GET_HEAD,
			body: Buffer.alloc(10)
		});
		expect(assembler.push(small[0])?.kind).to.equal('complete');
	});

	it('evicts partial messages that went stale and caps the in-flight count', () => {
		let now = 1000;
		const assembler = new GuardianBolt8Assembler({
			kind: 'request',
			maxBodyBytes: 1 << 24,
			maxInFlight: 2,
			staleMs: 500,
			clock: (): number => now
		});
		const big = (id: number): Buffer[] =>
			encodeGuardianBolt8Request({
				requestId: id,
				verb: GuardianBolt8Verb.PUT_STATE,
				body: crypto.randomBytes(firstBodyCapacity(2) + 10)
			});
		assembler.push(big(1)[0]);
		assembler.push(big(2)[0]);
		expect(() => assembler.push(big(3)[0])).to.throw(
			/too many guardian requests/
		);
		now += 600;
		expect(assembler.evictStale()).to.equal(2);
		expect(assembler.inFlight).to.equal(0);
		expect(assembler.push(big(3)[0])).to.equal(null);
	});

	it('refuses a header that lies about its body', () => {
		const [frame] = encodeGuardianBolt8Request({
			requestId: 4,
			verb: GuardianBolt8Verb.GET_HEAD,
			body: Buffer.alloc(32)
		});
		const lying = Buffer.from(frame);
		lying.writeUInt32BE(31, 5); // totalLength disagrees with the chunk
		const assembler = new GuardianBolt8Assembler({
			kind: 'request',
			maxBodyBytes: 1 << 20
		});
		expect(() => assembler.push(lying)).to.throw(/disagrees/);
		expect(() => decodeGuardianBolt8Frame(Buffer.alloc(5), 'request')).to.throw(
			/shorter than its header/
		);
		const zeroChunks = Buffer.from(frame);
		zeroChunks.writeUInt16BE(0, 11);
		expect(() => decodeGuardianBolt8Frame(zeroChunks, 'request')).to.throw(
			/zero chunks/
		);
	});
});

describe('bolt8 guardian session end to end', () => {
	let guardian: ReferenceGuardian;
	let host: IBolt8Host;
	let transport: ReturnType<typeof bolt8GuardianTransport>;
	let client: GuardianClient;

	beforeEach(async () => {
		guardian = makeGuardian(1_800_000_000_000n);
		host = await startHost(guardian);
		transport = bolt8GuardianTransport({
			session: { reconnectMinMs: 1, reconnectMaxMs: 2 }
		});
		client = new GuardianClient({
			url: host.url,
			guardianSetId: SET_ID,
			transport,
			timeoutMs: 5_000
		});
	});

	afterEach(async () => {
		transport.close();
		await host.close();
		guardian.close();
	});

	it('runs discovery and every signed verb over one session', async () => {
		const info = await client.info();
		expect(info.guardianId.equals(GUARDIAN_IDS[0])).to.equal(true);
		expect(transport.sessions().size).to.equal(1);

		const registered = await client.register(buildRegistration());
		expect(registered.status).to.equal(GuardianStatus.OK);

		const first = buildRecord({ sequence: 1n, previousHash: Buffer.alloc(32) });
		const put = await client.putState(first);
		expect(put.status).to.equal(GuardianStatus.OK);
		expect(put.receipt!.state.logHead.sequence).to.equal(1n);

		const head = await client.getHead(ROOT.recoveryId);
		expect(head.status).to.equal(GuardianStatus.OK);
		expect(
			head.receipt!.state.logHead.frameHash.equals(first.frameHash)
		).to.equal(true);

		const state = await client.getState(ROOT.recoveryId, 0n, 10);
		expect(state.status).to.equal(GuardianStatus.OK);
		expect(state.records!).to.have.length(1);
		expect(state.records![0].ciphertext.equals(first.ciphertext)).to.equal(
			true
		);

		// The whole exchange rode ONE session, as a stranger.
		expect(host.sessions).to.have.length(1);
		expect(host.sessions[0].remotePublicKey.equals(HOST_NODE_ID)).to.equal(
			false
		);
		expect(transport.sessions().get(host.url)!.inFlight).to.equal(0);
	});

	it('answers exactly what the HTTP transport answers', async () => {
		const twin = makeGuardian(1_800_000_000_000n);
		const httpServer = new GuardianHttpServer({ guardian: twin });
		const port = await httpServer.listen(0);
		const httpClient = new GuardianClient({
			url: `http://127.0.0.1:${port}`,
			guardianSetId: SET_ID
		});
		try {
			const registration = buildRegistration();
			const record = buildRecord({
				sequence: 1n,
				previousHash: Buffer.alloc(32)
			});
			const overBolt8 = [
				await client.info(),
				await client.register(registration),
				await client.putState(record),
				await client.getHead(ROOT.recoveryId),
				await client.getState(ROOT.recoveryId, 0n, 10)
			];
			const overHttp = [
				await httpClient.info(),
				await httpClient.register(registration),
				await httpClient.putState(record),
				await httpClient.getHead(ROOT.recoveryId),
				await httpClient.getState(ROOT.recoveryId, 0n, 10)
			];
			expect(overBolt8).to.deep.equal(overHttp);
		} finally {
			await httpServer.close();
			twin.close();
		}
	});

	it('carries a multi-chunk record both ways', async () => {
		await client.register(buildRegistration());
		const ciphertext = crypto.randomBytes(3 * BEIGNET_CUSTOM_MAX_PAYLOAD + 123);
		const record = buildRecord({
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			ciphertext
		});
		const put = await client.putState(record);
		expect(put.status).to.equal(GuardianStatus.OK);
		const state = await client.getState(ROOT.recoveryId, 0n, 10);
		expect(state.status).to.equal(GuardianStatus.OK);
		expect(state.records![0].ciphertext.equals(ciphertext)).to.equal(true);
	});

	it('overlaps requests on one session', async () => {
		await client.register(buildRegistration());
		const results = await Promise.all([
			client.info(),
			client.getHead(ROOT.recoveryId),
			client.info(),
			client.getState(ROOT.recoveryId, 0n, 10)
		]);
		expect(results[1].status).to.equal(GuardianStatus.OK);
		expect(results[3].status).to.equal(GuardianStatus.OK);
		expect(transport.sessions().size).to.equal(1);
	});

	it('reconnects on the next request after the host drops the session', async () => {
		await client.info();
		const session = transport.sessions().get(host.url)!;
		expect(session.connected).to.equal(true);
		// disconnect() emits no local close; the CLIENT observes the drop.
		host.sessions[0].disconnect();
		for (let i = 0; i < 100 && session.connected; i++) {
			await new Promise((resolve) => setTimeout(resolve, 10));
		}
		expect(session.connected).to.equal(false);
		const info = await client.info();
		expect(info.guardianId.equals(GUARDIAN_IDS[0])).to.equal(true);
		expect(session.connected).to.equal(true);
		expect(host.sessions).to.have.length(2);
	});

	it('fails a request in flight when the session drops, without hanging', async () => {
		await client.info();
		const session = transport.sessions().get(host.url)!;
		const pending = session.request(
			GuardianBolt8Verb.GET_HEAD,
			Buffer.alloc(0),
			{
				timeoutMs: 5_000,
				maxResponseBytes: 1 << 20
			}
		);
		// Drop before the host can answer by tearing down from the client.
		session.close();
		let failure: unknown;
		try {
			await pending;
		} catch (error) {
			failure = error;
		}
		expect(failure).to.be.instanceOf(GuardianTransportError);
	});

	it('backs off after a failed dial and reports it as a transport error', async () => {
		const dead = bolt8GuardianTransport({
			session: {
				reconnectMinMs: 60_000,
				reconnectMaxMs: 60_000,
				connectTimeoutMs: 500
			}
		});
		const deadClient = new GuardianClient({
			url: `bolt8://${HOST_NODE_HEX}@127.0.0.1:1`,
			guardianSetId: SET_ID,
			transport: dead,
			timeoutMs: 2_000
		});
		try {
			let first: unknown;
			try {
				await deadClient.info();
			} catch (error) {
				first = error;
			}
			expect(first).to.be.instanceOf(GuardianTransportError);
			expect(String((first as Error).message)).to.match(/dial .* failed/);
			let second: unknown;
			try {
				await deadClient.info();
			} catch (error) {
				second = error;
			}
			expect(String((second as Error).message)).to.match(/backing off/);
		} finally {
			dead.close();
		}
	});
});

describe('bolt8 guardian transport-level statuses', () => {
	it('answers 401 to a missing or wrong credential and 200 to the right one', async () => {
		const guardian = makeGuardian(1_800_000_000_000n);
		const host = await startHost(guardian, {
			authenticate: bolt8BearerAuthenticator('s3cret')
		});
		const open = bolt8GuardianTransport();
		const secured = bolt8GuardianTransport();
		try {
			const anonymous = new GuardianClient({
				url: host.url,
				guardianSetId: SET_ID,
				transport: open
			});
			let failure: unknown;
			try {
				await anonymous.info();
			} catch (error) {
				failure = error;
			}
			expect(failure).to.be.instanceOf(GuardianTransportError);
			expect((failure as GuardianTransportError).httpStatus).to.equal(401);

			const wrong = new GuardianClient({
				url: host.url,
				guardianSetId: SET_ID,
				transport: secured,
				auth: { type: 'bearer', token: 'wrong' }
			});
			let wrongFailure: unknown;
			try {
				await wrong.info();
			} catch (error) {
				wrongFailure = error;
			}
			expect((wrongFailure as GuardianTransportError).httpStatus).to.equal(401);

			const right = new GuardianClient({
				url: host.url,
				guardianSetId: SET_ID,
				transport: secured,
				auth: { type: 'bearer', token: 's3cret' }
			});
			const info = await right.info();
			expect(info.guardianId.equals(GUARDIAN_IDS[0])).to.equal(true);
			// The same token check the HTTP listener applies (wire 9).
			expect(
				bearerAuthenticator('s3cret')({
					headers: { authorization: 'Bearer s3cret' }
				} as never)
			).to.equal(true);
		} finally {
			open.close();
			secured.close();
			await host.close();
			guardian.close();
		}
	});

	it('answers 413 to a body over the host cap without dropping the session', async () => {
		const guardian = makeGuardian(1_800_000_000_000n);
		const host = await startHost(guardian, { maxBodyBytes: 4096 });
		const transport = bolt8GuardianTransport();
		try {
			const client = new GuardianClient({
				url: host.url,
				guardianSetId: SET_ID,
				transport
			});
			await client.register(buildRegistration());
			const record = buildRecord({
				sequence: 1n,
				previousHash: Buffer.alloc(32),
				ciphertext: crypto.randomBytes(200_000)
			});
			let failure: unknown;
			try {
				await client.putState(record);
			} catch (error) {
				failure = error;
			}
			expect((failure as GuardianTransportError).httpStatus).to.equal(
				GuardianBolt8Status.TOO_LARGE
			);
			// The session survived and the id space is clean.
			const head = await client.getHead(ROOT.recoveryId);
			expect(head.status).to.equal(GuardianStatus.OK);
			expect(host.sessions).to.have.length(1);
		} finally {
			transport.close();
			await host.close();
			guardian.close();
		}
	});

	it('answers 404 to an unknown verb code and caps the response it will accept', async () => {
		const guardian = makeGuardian(1_800_000_000_000n);
		const host = await startHost(guardian);
		const transport = bolt8GuardianTransport();
		try {
			const client = new GuardianClient({
				url: host.url,
				guardianSetId: SET_ID,
				transport
			});
			await client.info();
			const session = transport.sessions().get(host.url)!;
			const unknown = await session.request(250, Buffer.alloc(0), {
				timeoutMs: 2_000,
				maxResponseBytes: 1 << 20
			});
			expect(unknown.status).to.equal(GuardianBolt8Status.NOT_FOUND);
			let failure: unknown;
			try {
				await session.request(GuardianBolt8Verb.INFO, Buffer.alloc(0), {
					timeoutMs: 2_000,
					maxResponseBytes: 4
				});
			} catch (error) {
				failure = error;
			}
			expect(String((failure as Error).message)).to.match(/exceeds size cap/);
			// The client refuses paths GuardianClient would never compose.
			let bad: unknown;
			try {
				await transport(`${host.url}/beignet-guardian/v1/nope`, {
					method: 'POST',
					headers: {},
					timeoutMs: 1000,
					maxResponseBytes: 10
				});
			} catch (error) {
				bad = error;
			}
			expect(String((bad as Error).message)).to.match(/unknown guardian verb/);
		} finally {
			transport.close();
			await host.close();
			guardian.close();
		}
	});
});
