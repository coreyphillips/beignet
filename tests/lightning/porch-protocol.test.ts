/**
 * Porch protocol v1 (docs/PORCH-PROTOCOL.md): keys, route ids, relay addresses,
 * the registration a host signs and a relay checks, and the control
 * messages. The vectors here are the ones the specification prints.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey, sign } from '../../src/lightning/crypto/ecdh';
import { deriveIrohSecretKey } from '../../src/lightning/transport/iroh';
import { parsePeerUri } from '../../src/lightning/transport/peer-uri';
import {
	PORCH_HOST_PATH,
	PORCH_MAX_CONTROL_BYTES,
	PORCH_MAX_TAGS,
	PORCH_VERSION,
	IPorchRegister,
	PorchControlMessage,
	checkPorchRegister,
	createPorchRegister,
	decodePorchControl,
	derivePorchDefaultTag,
	derivePorchHostSecret,
	encodePorchControl,
	isPorchRouteId,
	parsePorchRelayUrl,
	porchHostUrl,
	porchLink,
	porchRegisterDigest,
	porchRouteId
} from '../../src/lightning/transport/porch';

const SEED = Buffer.from(Array.from({ length: 64 }, (_, i) => i));
const HOST_SECRET =
	'21ce437d6976c0d44a33bf9420f9fc120fb34c1faa823826a43f9ae6ddacd01d';
const HOST_KEY =
	'028e05ee420254452db894ac055e819662eb6546f80054ee6f54f37fa9eadc6aa4';
const DEFAULT_TAG = 'de536d1efe0d10a770774b67b5b9fe4d';
const ROUTE_ID = '3v465neydi7h3siyohv7auvakelndu37';
const NONCE = Buffer.alloc(32, 0x11);
const AUTHORITY = 'relay.example';

const secret = Buffer.from(HOST_SECRET, 'hex');
const hostKey = Buffer.from(HOST_KEY, 'hex');
const tagA = Buffer.from(DEFAULT_TAG, 'hex');
const tagB = Buffer.alloc(16, 0xab);

/** RFC 4648 base32 the slow way, to check the module's against. */
function base32(bytes: Buffer): string {
	const bits = [...bytes].map((b) => b.toString(2).padStart(8, '0')).join('');
	let out = '';
	for (let i = 0; i < bits.length; i += 5) {
		out += 'abcdefghijklmnopqrstuvwxyz234567'[
			parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)
		];
	}
	return out;
}

function hkdf(info: string, length: number): Buffer {
	return Buffer.from(
		crypto.hkdfSync('sha256', SEED, Buffer.alloc(32), info, length)
	);
}

function register(
	overrides: Partial<Parameters<typeof createPorchRegister>[0]> = {}
): IPorchRegister {
	return createPorchRegister({
		hostSecret: secret,
		nonce: NONCE,
		authority: AUTHORITY,
		tags: [tagA, tagB],
		...overrides
	});
}

describe('Porch protocol v1', function () {
	describe('keys', function () {
		it('derives the host key and the default link from the seed', function () {
			expect(derivePorchHostSecret(SEED).toString('hex')).to.equal(HOST_SECRET);
			expect(getPublicKey(secret).toString('hex')).to.equal(HOST_KEY);
			expect(derivePorchDefaultTag(SEED).toString('hex')).to.equal(DEFAULT_TAG);
			// The same values from Node's own HKDF.
			expect(derivePorchHostSecret(SEED)).to.deep.equal(
				hkdf('beignet/porch/host/v1', 32)
			);
			expect(derivePorchDefaultTag(SEED)).to.deep.equal(
				hkdf('beignet/porch/link/default/v1', 16)
			);
		});

		it('shares nothing with the Iroh identity derived from the same seed', function () {
			expect(derivePorchHostSecret(SEED)).to.not.deep.equal(
				deriveIrohSecretKey(SEED)
			);
		});

		it('refuses a seed too short to be one', function () {
			expect(() => derivePorchHostSecret(Buffer.alloc(15))).to.throw(/seed/);
			expect(() => derivePorchDefaultTag(Buffer.alloc(0))).to.throw(/seed/);
		});
	});

	describe('route ids', function () {
		it('is the first 20 bytes of a hash of the host key and the tag, in base32', function () {
			expect(porchRouteId(hostKey, tagA)).to.equal(ROUTE_ID);
			const hash = crypto
				.createHash('sha256')
				.update(Buffer.concat([Buffer.from('porch/route/v1'), hostKey, tagA]))
				.digest();
			expect(porchRouteId(hostKey, tagA)).to.equal(
				base32(hash.subarray(0, 20))
			);
			expect(porchRouteId(hostKey, tagB)).to.equal(
				'a2a6afyvl6pnykc7eqno5ny2aye3waud'
			);
		});

		it('differs for another link of the same host and for another host', function () {
			const other = getPublicKey(Buffer.alloc(32, 9));
			const ids = new Set([
				porchRouteId(hostKey, tagA),
				porchRouteId(hostKey, tagB),
				porchRouteId(other, tagA)
			]);
			expect(ids.size).to.equal(3);
			for (const id of ids) expect(isPorchRouteId(id)).to.equal(true);
		});

		it('refuses a key or tag of the wrong length', function () {
			expect(() => porchRouteId(hostKey.subarray(1), tagA)).to.throw(/33/);
			expect(() => porchRouteId(hostKey, Buffer.alloc(15))).to.throw(/16/);
		});

		it('recognises a route id by its shape', function () {
			expect(isPorchRouteId(ROUTE_ID)).to.equal(true);
			for (const bad of [
				ROUTE_ID.slice(1),
				ROUTE_ID + 'a',
				ROUTE_ID.toUpperCase(),
				ROUTE_ID.replace('3', '1'),
				'',
				undefined,
				7
			]) {
				expect(isPorchRouteId(bad), String(bad)).to.equal(false);
			}
		});
	});

	describe('relay addresses', function () {
		it('names a relay by host, and by port when it is not the default', function () {
			expect(parsePorchRelayUrl('wss://relay.example')).to.deep.equal({
				secure: true,
				host: 'relay.example',
				port: 443,
				authority: 'relay.example',
				origin: 'wss://relay.example'
			});
			// Case, a trailing slash and a spelled-out default port are noise.
			expect(parsePorchRelayUrl('WSS://Relay.Example:443/').authority).to.equal(
				'relay.example'
			);
			expect(parsePorchRelayUrl('wss://relay.example:8443')).to.include({
				port: 8443,
				authority: 'relay.example:8443',
				origin: 'wss://relay.example:8443'
			});
			expect(parsePorchRelayUrl('ws://relayonionaddress.onion')).to.include({
				secure: false,
				port: 80,
				authority: 'relayonionaddress.onion'
			});
			expect(parsePorchRelayUrl('ws://relay.example:443').authority).to.equal(
				'relay.example:443'
			);
			expect(parsePorchRelayUrl('ws://[::1]:8787')).to.include({
				host: '::1',
				port: 8787,
				authority: '[::1]:8787'
			});
		});

		it('refuses anything more than a scheme, host and port', function () {
			for (const bad of [
				'https://relay.example',
				'relay.example',
				'wss://relay.example/v1/host',
				'wss://relay.example/?x=1',
				'wss://relay.example/#x',
				'wss://user:pass@relay.example',
				'wss://',
				''
			]) {
				expect(() => parsePorchRelayUrl(bad), bad).to.throw(/Porch relay/);
			}
		});

		it('builds the standby URL and a link the peer URI parser already reads', function () {
			const relay = parsePorchRelayUrl('wss://relay.example:8443');
			expect(porchHostUrl(relay)).to.equal(
				'wss://relay.example:8443' + PORCH_HOST_PATH
			);
			const nodeId = '03' + 'ab'.repeat(32);
			const link = porchLink(nodeId, relay, ROUTE_ID);
			expect(link).to.equal(
				`${nodeId}@wss://relay.example:8443/v1/p/${ROUTE_ID}`
			);
			const parsed = parsePeerUri(link);
			expect(parsed.pubkey).to.equal(nodeId);
			expect(parsed.transport).to.deep.equal({
				type: 'ws',
				url: `wss://relay.example:8443/v1/p/${ROUTE_ID}`
			});
			expect(() => porchLink('nope', relay, ROUTE_ID)).to.throw(/node id/);
			expect(() => porchLink(nodeId, relay, 'short')).to.throw(/route id/);
		});
	});

	describe('registration', function () {
		it('signs the nonce, the relay name and the sorted tag list', function () {
			const digest = porchRegisterDigest(NONCE, AUTHORITY, [tagB, tagA]);
			expect(digest.toString('hex')).to.equal(
				'b556dfbed6a42a764b637f73287b9c9e83d55be6a81a680dce661a5e8dd3590d'
			);
			const name = Buffer.from(AUTHORITY);
			expect(digest).to.deep.equal(
				crypto
					.createHash('sha256')
					.update(
						Buffer.concat([
							Buffer.from('porch/register/v1'),
							NONCE,
							Buffer.from([name.length]),
							name,
							crypto
								.createHash('sha256')
								.update(Buffer.concat([tagB, tagA]))
								.digest()
						])
					)
					.digest()
			);
		});

		it('builds a registration a relay accepts, whatever order the tags came in', function () {
			const message = register({ tags: [tagA, tagB] });
			expect(message).to.deep.equal(register({ tags: [tagB, tagA] }));
			expect(message).to.deep.include({
				t: 'register',
				v: PORCH_VERSION,
				key: HOST_KEY,
				tags: [tagB.toString('hex'), DEFAULT_TAG]
			});
			expect(message).to.not.have.property('token');
			const checked = checkPorchRegister(message, {
				nonce: NONCE,
				authority: AUTHORITY
			});
			expect(checked).to.deep.equal({
				hostKey,
				tags: [tagB, tagA],
				routeIds: [porchRouteId(hostKey, tagB), ROUTE_ID]
			});
		});

		it('carries a token outside the signature', function () {
			const message = register({ token: 'let me in' });
			expect(message.token).to.equal('let me in');
			expect(message.sig).to.equal(register().sig);
			expect(
				checkPorchRegister(message, { nonce: NONCE, authority: AUTHORITY })
			).to.include({ token: 'let me in' });
		});

		it('refuses to build one with no link, too many, a duplicate or a short tag', function () {
			expect(() => register({ tags: [] })).to.throw(/1 to 256/);
			expect(() =>
				register({
					tags: Array.from({ length: PORCH_MAX_TAGS + 1 }, (_, i) => {
						const tag = Buffer.alloc(16);
						tag.writeUInt16BE(i, 0);
						return tag;
					})
				})
			).to.throw(/1 to 256/);
			expect(() => register({ tags: [tagA, Buffer.from(tagA)] })).to.throw(
				/distinct/
			);
			expect(() => register({ tags: [Buffer.alloc(15)] })).to.throw(/16 bytes/);
		});

		const refusal = (
			message: IPorchRegister,
			challenge = { nonce: NONCE, authority: AUTHORITY },
			maxTags?: number
		): string => {
			const checked = checkPorchRegister(message, challenge, maxTags);
			return 'refused' in checked ? checked.refused : 'accepted';
		};

		it('is refused under another nonce: a recorded registration cannot be replayed', function () {
			expect(
				refusal(register(), {
					nonce: Buffer.alloc(32, 0x12),
					authority: AUTHORITY
				})
			).to.equal('bad signature');
		});

		it('is refused under another relay name: one relay cannot register the host at another', function () {
			expect(
				refusal(register(), { nonce: NONCE, authority: 'other.example' })
			).to.equal('bad signature');
			// The name is length-prefixed, so it cannot borrow from the tags.
			expect(
				refusal(register({ authority: 'relay.exampl' }), {
					nonce: NONCE,
					authority: AUTHORITY
				})
			).to.equal('bad signature');
		});

		it('is refused when the tag list is not the one that was signed', function () {
			const message = register();
			expect(refusal({ ...message, tags: [message.tags[1]] })).to.equal(
				'bad signature'
			);
			expect(
				refusal({ ...message, tags: [...message.tags, 'ff'.repeat(16)] })
			).to.equal('bad signature');
			expect(
				refusal({ ...message, tags: [...message.tags].reverse() })
			).to.equal('links are not sorted and distinct');
			expect(
				refusal({ ...message, tags: [message.tags[0], message.tags[0]] })
			).to.equal('links are not sorted and distinct');
		});

		it('is refused when another key signed it, or the signature is not canonical', function () {
			const message = register();
			expect(
				refusal({
					...message,
					key: getPublicKey(Buffer.alloc(32, 9)).toString('hex')
				})
			).to.equal('bad signature');
			expect(refusal({ ...message, sig: '00'.repeat(64) })).to.equal(
				'bad signature'
			);
			// The same signature with s replaced by n - s verifies in a lax
			// check; a relay takes only the low-s form.
			const n = BigInt(
				'0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
			);
			const s = BigInt('0x' + message.sig.slice(64));
			const highS =
				message.sig.slice(0, 64) + (n - s).toString(16).padStart(64, '0');
			expect(refusal({ ...message, sig: highS })).to.equal('bad signature');
		});

		it('is refused for a version or a link count the relay does not take', function () {
			const tags = [tagB, tagA];
			const v2: IPorchRegister = {
				...register(),
				v: 2,
				sig: sign(porchRegisterDigest(NONCE, AUTHORITY, tags), secret).toString(
					'hex'
				)
			};
			expect(refusal(v2)).to.equal('unsupported version');
			expect(refusal(register(), undefined, 1)).to.equal('too many links');
			expect(refusal(register(), undefined, 2)).to.equal('accepted');
		});
	});

	describe('control messages', function () {
		const valid: PorchControlMessage[] = [
			{ t: 'challenge', v: 1, nonce: '11'.repeat(32), authority: AUTHORITY },
			register(),
			register({ token: 'secret' }),
			{ t: 'ready' },
			{ t: 'paired', tag: DEFAULT_TAG },
			{ t: 'ping' },
			{ t: 'pong' }
		];

		it('round-trips every message', function () {
			for (const message of valid) {
				expect(decodePorchControl(encodePorchControl(message))).to.deep.equal(
					message
				);
			}
		});

		it('drops fields it does not know and keeps the ones it does', function () {
			expect(
				decodePorchControl('{"t":"ready","later":true,"v":9}')
			).to.deep.equal({ t: 'ready' });
			expect(
				decodePorchControl(
					JSON.stringify({ t: 'paired', tag: DEFAULT_TAG, extra: [1] })
				)
			).to.deep.equal({ t: 'paired', tag: DEFAULT_TAG });
		});

		it('returns undefined for anything that is not exactly a message', function () {
			const challenge = valid[0];
			const good = register();
			const bad: unknown[] = [
				'',
				'not json',
				'null',
				'[]',
				'7',
				'"ready"',
				{},
				{ t: 'unknown' },
				{ t: 7 },
				{ t: 'paired' },
				{ t: 'paired', tag: DEFAULT_TAG.slice(2) },
				{ t: 'paired', tag: DEFAULT_TAG.toUpperCase() },
				{ t: 'paired', tag: 7 },
				{ ...challenge, v: '1' },
				{ ...challenge, v: 1.5 },
				{ ...challenge, nonce: '11'.repeat(31) },
				{ ...challenge, nonce: 'zz'.repeat(32) },
				{ ...challenge, authority: '' },
				{ ...challenge, authority: 'a'.repeat(256) },
				{ ...challenge, authority: 7 },
				{ ...good, v: null },
				{ ...good, key: good.key.slice(2) },
				{ ...good, key: good.key.toUpperCase() },
				{ ...good, sig: good.sig.slice(2) },
				{ ...good, tags: [] },
				{ ...good, tags: 'ab'.repeat(16) },
				{ ...good, tags: [...good.tags, 'ab'.repeat(15)] },
				{ ...good, tags: [...good.tags, 7] },
				{
					...good,
					tags: Array.from({ length: PORCH_MAX_TAGS + 1 }, () => DEFAULT_TAG)
				},
				{ ...good, token: 7 },
				{ ...good, token: 'x'.repeat(257) }
			];
			for (const value of bad) {
				const text = typeof value === 'string' ? value : JSON.stringify(value);
				expect(decodePorchControl(text), text.slice(0, 60)).to.equal(undefined);
			}
		});

		it('reads a registration at the link cap and refuses text past the size cap', function () {
			const tags = Array.from({ length: PORCH_MAX_TAGS }, (_, i) => {
				const tag = Buffer.alloc(16);
				tag.writeUInt16BE(i, 0);
				return tag;
			});
			const full = encodePorchControl(register({ tags }));
			expect(full.length).to.be.lessThan(PORCH_MAX_CONTROL_BYTES);
			expect(decodePorchControl(full)).to.have.property('t', 'register');
			expect(
				decodePorchControl(
					JSON.stringify({
						t: 'ready',
						pad: 'x'.repeat(PORCH_MAX_CONTROL_BYTES)
					})
				)
			).to.equal(undefined);
			expect(decodePorchControl(7 as unknown as string)).to.equal(undefined);
		});
	});
});
