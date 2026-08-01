/**
 * Guardian transports and client (wire spec sections 2, 6, 9, 10): the
 * hand-rolled proto3 envelope with frozen field numbers, the HTTP verb
 * mapping with in-body protocol statuses, transport authentication, version
 * gating against InfoResponse, endpoint selection over capsule descriptors,
 * and the quorum fan-out primitives.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianClient,
	GuardianDescriptor,
	GuardianHttpServer,
	GuardianState,
	GuardianStatus,
	GuardianTransportError,
	IGuardianAcquireEpochRequest,
	IGuardianReceipt,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	IGuardianTakeoverCertificate,
	ReferenceGuardian,
	acquireTranscriptHash,
	bearerAuthenticator,
	computeGuardianSetId,
	countReceiptQuorum,
	decodeAcquireEpochResponse,
	decodeGetHeadRequest,
	decodeGetHeadResponse,
	decodeGetStateRequest,
	decodeGuardianState,
	decodeInfoResponse,
	decodeRecord,
	decodeRegisterNodeRequest,
	decodeSyncEpochRequest,
	deriveRecoveryRoot,
	encodeAcquireEpochResponse,
	encodeGetHeadRequest,
	encodeGetStateRequest,
	encodeGetHeadResponse,
	encodeGuardianState,
	encodeInfoResponse,
	encodePutStateResponse,
	encodeRecord,
	encodeRegisterNodeRequest,
	encodeSyncEpochRequest,
	genesisLogHead,
	guardianFanOut,
	nodeGuardianTransport,
	recordTranscriptHash,
	registerTranscriptHash,
	selectGuardianEndpoint,
	signTranscript,
	statesEqual,
	xOnlyFromSecret
} from '../../src/lightning/recovery';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`transport-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const ROOT = deriveRecoveryRoot(sha('transport-node-secret'));

function makeWriter(name: string): { secret: Buffer; pub: Buffer } {
	const secret = sha(name);
	return { secret, pub: xOnlyFromSecret(secret) };
}
const WRITER_1 = makeWriter('transport-writer-1');
const WRITER_2 = makeWriter('transport-writer-2');

let now = 1_800_000_000_000n;
const clock = (): bigint => ++now;

function makeGuardian(index: number): ReferenceGuardian {
	return new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[index],
		members: GUARDIAN_IDS,
		clock
	});
}

function buildRegistration(): IGuardianRegisterNodeRequest {
	const initialState: GuardianState = {
		recoveryId: ROOT.recoveryId,
		lease: { epoch: 1n, writerPublicKey: WRITER_1.pub },
		origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
		logHead: genesisLogHead()
	};
	return {
		protocolVersion: 1,
		guardianSetId: SET_ID,
		initialState,
		rootSignature: signTranscript(
			registerTranscriptHash(SET_ID, initialState),
			ROOT.rootSecret
		)
	};
}

function buildRecord(opts: {
	epoch: bigint;
	sequence: bigint;
	previousHash: Buffer;
	writerSecret: Buffer;
}): IGuardianRecord {
	const ciphertext = sha(`t-ciphertext-${opts.epoch}-${opts.sequence}`);
	const frameHash = sha(`t-frame-${opts.epoch}-${opts.sequence}`);
	return {
		protocolVersion: 1,
		guardianSetId: SET_ID,
		recoveryId: ROOT.recoveryId,
		epoch: opts.epoch,
		sequence: opts.sequence,
		previousHash: opts.previousHash,
		frameHash,
		ciphertext,
		writerSignature: signTranscript(
			recordTranscriptHash(SET_ID, {
				recoveryId: ROOT.recoveryId,
				epoch: opts.epoch,
				sequence: opts.sequence,
				previousHash: opts.previousHash,
				frameHash,
				ciphertextHash: sha256(ciphertext)
			}),
			opts.writerSecret
		)
	};
}

function buildAcquire(
	expectedState: GuardianState,
	newWriter: { secret: Buffer; pub: Buffer }
): IGuardianAcquireEpochRequest {
	const newEpoch = expectedState.lease.epoch + 1n;
	const hash = acquireTranscriptHash(
		SET_ID,
		expectedState,
		newEpoch,
		newWriter.pub
	);
	return {
		protocolVersion: 1,
		guardianSetId: SET_ID,
		expectedState,
		newEpoch,
		newWriterPublicKey: newWriter.pub,
		rootSignature: signTranscript(hash, ROOT.rootSecret),
		newWriterSignature: signTranscript(hash, newWriter.secret)
	};
}

describe('Guardian proto: envelope codec', () => {
	it('round-trips GuardianState including genesis defaults and u64 extremes', () => {
		const genesis = buildRegistration().initialState;
		expect(
			statesEqual(decodeGuardianState(encodeGuardianState(genesis)), genesis)
		).to.equal(true);

		const extreme: GuardianState = {
			recoveryId: sha('extreme-id'),
			lease: { epoch: 0xffffffffffffffffn, writerPublicKey: sha('w') },
			origin: { firstSequence: 0xfffffffffffffffen, previousHash: sha('p') },
			logHead: {
				sequence: 0xffffffffffffff00n,
				frameHash: sha('f'),
				ciphertextHash: sha('c'),
				recordEpoch: 12345678901234567n
			}
		};
		expect(
			statesEqual(decodeGuardianState(encodeGuardianState(extreme)), extreme)
		).to.equal(true);
	});

	it('round-trips every request message', () => {
		const registration = buildRegistration();
		const decodedRegistration = decodeRegisterNodeRequest(
			encodeRegisterNodeRequest(registration)
		);
		expect(decodedRegistration.protocolVersion).to.equal(1);
		expect(decodedRegistration.guardianSetId.equals(SET_ID)).to.equal(true);
		expect(
			statesEqual(decodedRegistration.initialState, registration.initialState)
		).to.equal(true);
		expect(
			decodedRegistration.rootSignature.equals(registration.rootSignature)
		).to.equal(true);

		const record = buildRecord({
			epoch: 3n,
			sequence: 41n,
			previousHash: sha('prev'),
			writerSecret: WRITER_1.secret
		});
		const decodedRecord = decodeRecord(encodeRecord(record));
		expect(decodedRecord.epoch).to.equal(3n);
		expect(decodedRecord.sequence).to.equal(41n);
		expect(decodedRecord.ciphertext.equals(record.ciphertext)).to.equal(true);
		expect(
			decodedRecord.writerSignature.equals(record.writerSignature)
		).to.equal(true);

		const getHead = decodeGetHeadRequest(
			encodeGetHeadRequest({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				recoveryId: ROOT.recoveryId
			})
		);
		expect(getHead.recoveryId.equals(ROOT.recoveryId)).to.equal(true);

		const getState = decodeGetStateRequest(
			encodeGetStateRequest({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				recoveryId: ROOT.recoveryId,
				fromSequence: 7n,
				maxRecords: 128
			})
		);
		expect(getState.fromSequence).to.equal(7n);
		expect(getState.maxRecords).to.equal(128);
	});

	it('preserves certificate bundles and response optionality', () => {
		const guardian = makeGuardian(0);
		guardian.register(buildRegistration());
		const record = buildRecord({
			epoch: 1n,
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			writerSecret: WRITER_1.secret
		});
		guardian.putState({ record });
		const head = guardian.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		const acquired = guardian.acquireEpoch(
			buildAcquire(head.state as GuardianState, WRITER_2)
		);
		expect(acquired.status).to.equal(GuardianStatus.OK);

		const bundle = {
			certificates: [
				acquired.certificate as IGuardianTakeoverCertificate,
				acquired.certificate as IGuardianTakeoverCertificate
			]
		};
		const decodedBundle = decodeSyncEpochRequest(
			encodeSyncEpochRequest(bundle)
		);
		expect(decodedBundle.certificates.length).to.equal(2);
		expect(
			decodedBundle.certificates[0].signature.equals(
				(acquired.certificate as IGuardianTakeoverCertificate).signature
			)
		).to.equal(true);

		const encodedAcquire = encodeAcquireEpochResponse(acquired);
		const decodedAcquire = decodeAcquireEpochResponse(encodedAcquire);
		expect(decodedAcquire.status).to.equal(GuardianStatus.OK);
		expect(decodedAcquire.certificate === undefined).to.equal(false);
		expect(decodedAcquire.receipt === undefined).to.equal(false);
		expect(decodedAcquire.current === undefined).to.equal(true);
		expect(
			statesEqual(
				(decodedAcquire.receipt as IGuardianReceipt).state,
				(acquired.receipt as IGuardianReceipt).state
			)
		).to.equal(true);

		const fullHead = guardian.getHead({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		const decodedHead = decodeGetHeadResponse(encodeGetHeadResponse(fullHead));
		expect(decodedHead.status).to.equal(GuardianStatus.OK);
		expect((decodedHead.certificates ?? []).length).to.equal(1);
		expect(decodedHead.registration === undefined).to.equal(false);
		expect(
			statesEqual(
				(decodedHead.registration as IGuardianRegisterNodeRequest).initialState,
				buildRegistration().initialState
			)
		).to.equal(true);
		guardian.close();
	});

	it('freezes the wire field numbers', () => {
		// GetHeadRequest: field 1 varint, fields 2 and 3 length-delimited.
		const encoded = encodeGetHeadRequest({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		const expected = Buffer.concat([
			Buffer.from([0x08, 0x01, 0x12, 0x20]),
			SET_ID,
			Buffer.from([0x1a, 0x20]),
			ROOT.recoveryId
		]);
		expect(encoded.equals(expected)).to.equal(true);

		// GuardianState nests recovery_id(1), lease(2), origin(3), log_head(4).
		const genesis = buildRegistration().initialState;
		const state = encodeGuardianState(genesis);
		expect(state[0]).to.equal(0x0a);
		expect(state[1]).to.equal(0x20);
		const afterRecoveryId = 2 + 32;
		expect(state[afterRecoveryId]).to.equal(0x12);
	});

	it('skips unknown fields and throws on truncation', () => {
		const encoded = encodeGetHeadRequest({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			recoveryId: ROOT.recoveryId
		});
		// Append unknown field 15 (varint) and unknown field 16 (bytes).
		const extended = Buffer.concat([
			encoded,
			Buffer.from([0x78, 0x2a]),
			Buffer.from([0x82, 0x01, 0x03, 0xaa, 0xbb, 0xcc])
		]);
		const decoded = decodeGetHeadRequest(extended);
		expect(decoded.recoveryId.equals(ROOT.recoveryId)).to.equal(true);

		expect(() =>
			decodeGetHeadRequest(encoded.subarray(0, encoded.length - 1))
		).to.throw(/truncated/);
		expect(() => decodeInfoResponse(Buffer.alloc(12, 0xff))).to.throw(/varint/);
	});
});

describe('Guardian transport: HTTP server and client', () => {
	let guardian: ReferenceGuardian;
	let server: GuardianHttpServer;
	let client: GuardianClient;
	let baseUrl: string;

	before(async () => {
		guardian = makeGuardian(0);
		server = new GuardianHttpServer({ guardian });
		const port = await server.listen(0);
		baseUrl = `http://127.0.0.1:${port}`;
		client = new GuardianClient({ url: baseUrl, guardianSetId: SET_ID });
	});

	after(async () => {
		await server.close();
		guardian.close();
	});

	it('serves INFO and passes version gating', async () => {
		const info = await client.checkVersion();
		expect(info.guardianId.equals(GUARDIAN_IDS[0])).to.equal(true);
		expect(info.guardianSetIds[0].equals(SET_ID)).to.equal(true);
		expect(info.maxRecordsPerGet).to.equal(256);
	});

	it('runs the whole verb matrix over the wire', async () => {
		const registration = buildRegistration();
		const registered = await client.register(registration);
		expect(registered.status).to.equal(GuardianStatus.OK);
		expect(
			statesEqual(
				(registered.receipt as IGuardianReceipt).state,
				registration.initialState
			)
		).to.equal(true);

		const record = buildRecord({
			epoch: 1n,
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			writerSecret: WRITER_1.secret
		});
		const put = await client.putState(record);
		expect(put.status).to.equal(GuardianStatus.OK);
		const replay = await client.putState(record);
		expect(replay.status).to.equal(GuardianStatus.OK_DUPLICATE);
		expect(
			(replay.receipt as IGuardianReceipt).signature.equals(
				(put.receipt as IGuardianReceipt).signature
			)
		).to.equal(true);

		const head = await client.getHead(ROOT.recoveryId);
		expect(head.status).to.equal(GuardianStatus.OK);
		expect((head.state as GuardianState).logHead.sequence).to.equal(1n);
		expect(head.registration === undefined).to.equal(false);
		expect(head.possiblyStale).to.equal(false);

		const page = await client.getState(ROOT.recoveryId, 0n);
		expect(page.status).to.equal(GuardianStatus.OK);
		expect((page.records as IGuardianRecord[]).length).to.equal(1);
		expect(
			(page.records as IGuardianRecord[])[0].ciphertext.equals(
				record.ciphertext
			)
		).to.equal(true);

		const acquired = await client.acquireEpoch(
			buildAcquire(head.state as GuardianState, WRITER_2)
		);
		expect(acquired.status).to.equal(GuardianStatus.OK);

		const record2 = buildRecord({
			epoch: 2n,
			sequence: 2n,
			previousHash: record.frameHash,
			writerSecret: WRITER_2.secret
		});
		const synced = await client.syncRecord(record2);
		expect(synced.status).to.equal(GuardianStatus.OK);
		expect(
			(synced.receipt as IGuardianReceipt).state.logHead.sequence
		).to.equal(2n);

		const stale = await client.syncEpoch([
			acquired.certificate as IGuardianTakeoverCertificate,
			acquired.certificate as IGuardianTakeoverCertificate
		]);
		expect(stale.status).to.equal(GuardianStatus.ERR_CERT_MISMATCH);
	});

	it('answers 404 for unknown paths and methods', async () => {
		const transport = nodeGuardianTransport();
		const wrongVerb = await transport(
			`${baseUrl}/beignet-guardian/v1/no_such_verb`,
			{
				method: 'POST',
				headers: {},
				body: Buffer.alloc(0),
				timeoutMs: 5000,
				maxResponseBytes: 1024
			}
		);
		expect(wrongVerb.status).to.equal(404);
		const wrongMethod = await transport(
			`${baseUrl}/beignet-guardian/v1/put_state`,
			{
				method: 'GET',
				headers: {},
				timeoutMs: 5000,
				maxResponseBytes: 1024
			}
		);
		expect(wrongMethod.status).to.equal(404);
	});

	it('rejects an undecodable body inside a 200 with ERR_MALFORMED', async () => {
		const transport = nodeGuardianTransport();
		const response = await transport(
			`${baseUrl}/beignet-guardian/v1/put_state`,
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/x-protobuf' },
				body: Buffer.alloc(12, 0xff),
				timeoutMs: 5000,
				maxResponseBytes: 4096
			}
		);
		expect(response.status).to.equal(200);
		const decoded = decodeGetHeadResponse(response.body);
		expect(decoded.status).to.equal(GuardianStatus.ERR_MALFORMED);
	});

	it('enforces the body cap with 413', async () => {
		const small = makeGuardian(1);
		const smallServer = new GuardianHttpServer({
			guardian: small,
			maxBodyBytes: 128
		});
		const port = await smallServer.listen(0);
		const transport = nodeGuardianTransport();
		const response = await transport(
			`http://127.0.0.1:${port}/beignet-guardian/v1/put_state`,
			{
				method: 'POST',
				headers: {},
				body: Buffer.alloc(4096, 1),
				timeoutMs: 5000,
				maxResponseBytes: 1024
			}
		);
		expect(response.status).to.equal(413);
		await smallServer.close();
		small.close();
	});

	it('demands the transport credential when configured', async () => {
		const secured = makeGuardian(2);
		const securedServer = new GuardianHttpServer({
			guardian: secured,
			authenticate: bearerAuthenticator('transport-secret')
		});
		const port = await securedServer.listen(0);
		const url = `http://127.0.0.1:${port}`;

		const anonymous = new GuardianClient({ url, guardianSetId: SET_ID });
		try {
			await anonymous.info();
			expect.fail('unauthenticated request must not pass');
		} catch (error) {
			expect(error).to.be.instanceOf(GuardianTransportError);
			expect((error as GuardianTransportError).httpStatus).to.equal(401);
		}

		const authed = new GuardianClient({
			url,
			guardianSetId: SET_ID,
			auth: { type: 'bearer', token: 'transport-secret' }
		});
		const info = await authed.info();
		expect(info.guardianId.equals(GUARDIAN_IDS[2])).to.equal(true);

		await securedServer.close();
		secured.close();
	});

	it('rejects a guardian outside the protocol version range', async () => {
		const stub: GuardianClient = new GuardianClient({
			url: 'http://stub.invalid',
			guardianSetId: SET_ID,
			transport: async (): Promise<{ status: number; body: Buffer }> => ({
				status: 200,
				body: encodeInfoResponse({
					guardianId: GUARDIAN_IDS[0],
					minProtocolVersion: 2,
					maxProtocolVersion: 3,
					guardianSetIds: [SET_ID],
					maxCiphertextBytes: 1024,
					maxRecordsPerGet: 16,
					rateLimitPerMinute: 0
				})
			})
		});
		try {
			await stub.checkVersion();
			expect.fail('version gate must reject');
		} catch (error) {
			expect(error).to.be.instanceOf(GuardianTransportError);
			expect(String((error as Error).message)).to.match(/protocol 2\.\.3/);
		}
	});
});

describe('Guardian transport: endpoint selection', () => {
	const onion = {
		type: 'onion-http' as const,
		url: 'http://abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.onion'
	};
	const https = { type: 'https' as const, url: 'https://guardian.example.com' };
	const local = { type: 'local-http' as const, url: 'http://127.0.0.1:9911' };

	function descriptor(
		transports: GuardianDescriptor['transports']
	): GuardianDescriptor {
		return { guardianId: GUARDIAN_IDS[0].toString('hex'), transports };
	}

	it('prefers onion under Tor, https otherwise, local only when allowed', () => {
		expect(
			selectGuardianEndpoint(descriptor([https, onion]), { torEnabled: true })
				.transportType
		).to.equal('onion-http');
		expect(
			selectGuardianEndpoint(descriptor([https, onion]), { torEnabled: false })
				.transportType
		).to.equal('https');
		expect(
			selectGuardianEndpoint(descriptor([https]), { torEnabled: true })
				.transportType
		).to.equal('https');
		expect(
			selectGuardianEndpoint(descriptor([local]), {
				torEnabled: false,
				allowLocalHttp: true
			}).transportType
		).to.equal('local-http');
	});

	it('surfaces an unusable descriptor as an error, never a silent skip', () => {
		expect(() =>
			selectGuardianEndpoint(descriptor([local]), { torEnabled: false })
		).to.throw(/no usable transport/);
		expect(() =>
			selectGuardianEndpoint(descriptor([onion]), { torEnabled: false })
		).to.throw(/no usable transport/);
		// A transport whose URL does not match its declared type is unusable.
		expect(() =>
			selectGuardianEndpoint(
				descriptor([{ type: 'https', url: 'http://not-tls.example.com' }]),
				{ torEnabled: false }
			)
		).to.throw(/no usable transport/);
		expect(() =>
			selectGuardianEndpoint(
				descriptor([
					{ type: 'onion-http', url: 'http://clearnet.example.com' }
				]),
				{ torEnabled: true }
			)
		).to.throw(/no usable transport/);
	});

	it('confines local-http to loopback and individually approved hosts', () => {
		// A stale or hostile descriptor labelling a clearnet URL local-http
		// must never be selected: the client would attach its credential to
		// plaintext HTTP (wire 2.3: a general LAN address does not qualify).
		const clearnetLocal = {
			type: 'local-http' as const,
			url: 'http://public-host.example'
		};
		expect(() =>
			selectGuardianEndpoint(descriptor([clearnetLocal]), {
				torEnabled: false,
				allowLocalHttp: true
			})
		).to.throw(/no usable transport/);
		// An isolated-container hostname needs explicit, per-host approval.
		const container = {
			type: 'local-http' as const,
			url: 'http://guardian-container:3000'
		};
		expect(() =>
			selectGuardianEndpoint(descriptor([container]), {
				torEnabled: false,
				allowLocalHttp: true
			})
		).to.throw(/no usable transport/);
		expect(
			selectGuardianEndpoint(descriptor([container]), {
				torEnabled: false,
				allowLocalHttpHost: (hostname) => hostname === 'guardian-container'
			}).transportType
		).to.equal('local-http');
		// Providing the approval callback also enables plain loopback.
		expect(
			selectGuardianEndpoint(descriptor([local]), {
				torEnabled: false,
				allowLocalHttpHost: () => false
			}).transportType
		).to.equal('local-http');
	});

	it('requires a plausible v3 onion hostname and the http scheme', () => {
		expect(() =>
			selectGuardianEndpoint(
				descriptor([{ type: 'onion-http', url: 'http://abc.onion' }]),
				{ torEnabled: true }
			)
		).to.throw(/no usable transport/);
		expect(() =>
			selectGuardianEndpoint(
				descriptor([
					{ type: 'onion-http', url: `https://${'a'.repeat(56)}.onion` }
				]),
				{ torEnabled: true }
			)
		).to.throw(/no usable transport/);
	});
});

describe('Guardian transport: client hardening', () => {
	it('gates every verb on the advertised version range, once', async () => {
		const calls: string[] = [];
		const incompatible = new GuardianClient({
			url: 'http://127.0.0.1:1',
			guardianSetId: SET_ID,
			transport: async (url): Promise<{ status: number; body: Buffer }> => {
				calls.push(url);
				return {
					status: 200,
					body: encodeInfoResponse({
						guardianId: GUARDIAN_IDS[0],
						minProtocolVersion: 2,
						maxProtocolVersion: 3,
						guardianSetIds: [SET_ID],
						maxCiphertextBytes: 1024,
						maxRecordsPerGet: 16,
						rateLimitPerMinute: 0
					})
				};
			}
		});
		const record = buildRecord({
			epoch: 1n,
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			writerSecret: WRITER_1.secret
		});
		try {
			await incompatible.putState(record);
			expect.fail('signed material must not reach an incompatible guardian');
		} catch (error) {
			expect(error).to.be.instanceOf(GuardianTransportError);
		}
		expect(calls.length).to.equal(1);
		expect(calls[0].endsWith('/info')).to.equal(true);

		// A compatible guardian is probed exactly once across many verbs.
		const okCalls: string[] = [];
		const compatible = new GuardianClient({
			url: 'http://127.0.0.1:1',
			guardianSetId: SET_ID,
			transport: async (url): Promise<{ status: number; body: Buffer }> => {
				okCalls.push(url);
				if (url.endsWith('/info')) {
					return {
						status: 200,
						body: encodeInfoResponse({
							guardianId: GUARDIAN_IDS[0],
							minProtocolVersion: 1,
							maxProtocolVersion: 1,
							guardianSetIds: [SET_ID],
							maxCiphertextBytes: 1024,
							maxRecordsPerGet: 16,
							rateLimitPerMinute: 0
						})
					};
				}
				return {
					status: 200,
					body: encodePutStateResponse({ status: GuardianStatus.OK })
				};
			}
		});
		expect((await compatible.putState(record)).status).to.equal(
			GuardianStatus.OK
		);
		expect((await compatible.putState(record)).status).to.equal(
			GuardianStatus.OK
		);
		expect(okCalls.filter((u) => u.endsWith('/info')).length).to.equal(1);
	});

	it('refuses plaintext credentials to non-local hosts unless explicitly allowed', () => {
		expect(
			() =>
				new GuardianClient({
					url: 'http://203.0.113.9:8080',
					guardianSetId: SET_ID,
					auth: { type: 'bearer', token: 'leaky' }
				})
		).to.throw(/plaintext/);
		// Loopback and onion targets are not plaintext-to-network.
		const loopback = new GuardianClient({
			url: 'http://127.0.0.1:9911',
			guardianSetId: SET_ID,
			auth: { type: 'bearer', token: 'fine' }
		});
		expect(loopback.url).to.contain('127.0.0.1');
		// An isolated container network is an explicit, named exception.
		const container = new GuardianClient({
			url: 'http://guardian-container:3000',
			guardianSetId: SET_ID,
			auth: { type: 'macaroon', macaroon: 'AA==' },
			allowUnencryptedAuth: true
		});
		expect(container.url).to.contain('guardian-container');
	});
});

describe('Guardian transport: quorum fan-out', () => {
	it('collects receipts across guardians and counts the durable quorum', async () => {
		const guardians = [0, 1, 2].map((i) => makeGuardian(i));
		const servers = await Promise.all(
			guardians.map(async (g) => {
				const s = new GuardianHttpServer({ guardian: g });
				const port = await s.listen(0);
				return { server: s, port };
			})
		);
		const clients = servers.map(
			({ port }) =>
				new GuardianClient({
					url: `http://127.0.0.1:${port}`,
					guardianSetId: SET_ID
				})
		);
		const context = { guardianSetId: SET_ID, members: GUARDIAN_IDS };

		const registration = buildRegistration();
		const registrations = await guardianFanOut(clients, (c) =>
			c.register(registration)
		);
		expect(
			registrations.filter((r) => r.result?.status === GuardianStatus.OK).length
		).to.equal(3);

		const record1 = buildRecord({
			epoch: 1n,
			sequence: 1n,
			previousHash: Buffer.alloc(32),
			writerSecret: WRITER_1.secret
		});
		const firstAppend = await guardianFanOut(clients, (c) =>
			c.putState(record1)
		);
		expect(
			countReceiptQuorum(
				firstAppend,
				context,
				(state) => state.logHead.sequence >= 1n
			)
		).to.equal(3);

		// One guardian down is the normal case a 2-of-3 deployment absorbs:
		// the barrier still clears on the surviving quorum.
		await servers[2].server.close();
		const record2 = buildRecord({
			epoch: 1n,
			sequence: 2n,
			previousHash: record1.frameHash,
			writerSecret: WRITER_1.secret
		});
		const secondAppend = await guardianFanOut(clients, (c) =>
			c.putState(record2)
		);
		expect(secondAppend.filter((r) => r.error !== undefined).length).to.equal(
			1
		);
		expect(
			countReceiptQuorum(
				secondAppend,
				context,
				(state) => state.logHead.sequence >= 2n
			)
		).to.equal(2);

		await servers[0].server.close();
		await servers[1].server.close();
		for (const g of guardians) g.close();
	});
});
