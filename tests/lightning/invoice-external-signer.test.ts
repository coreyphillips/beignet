import assert from 'assert/strict';
import { createHash } from 'crypto';
import * as secp from '@noble/secp256k1';
import {
	decode,
	encode,
	encodeWithSigner,
	ensureHmac,
	IInvoiceCreationOptions,
	Network
} from '../../src/lightning/invoice';

ensureHmac();
const key = Buffer.alloc(32, 1);
const publicKey = Buffer.from(secp.getPublicKey(key, true));
const options = (): Omit<IInvoiceCreationOptions, 'privateKey'> => ({
	network: Network.REGTEST,
	amountMsat: 75000n,
	paymentHash: Buffer.alloc(32, 3),
	paymentSecret: Buffer.alloc(32, 4),
	description: 'External invoice signer',
	timestamp: 1700000000,
	expiry: 600
});
const sign = async (message: Buffer, privateKey = key): Promise<Buffer> => {
	const digest = createHash('sha256').update(message).digest();
	const [signature, recovery] = secp.signSync(digest, privateKey, {
		recovered: true,
		der: false
	});
	return Buffer.concat([Buffer.from(signature), Buffer.from([recovery])]);
};

describe('External BOLT 11 signer', () => {
	it('matches local encoding byte for byte with one message hash', async () => {
		const input = options();
		const external = await encodeWithSigner(input, publicKey, sign);
		assert.equal(external, encode({ ...input, privateKey: key }));
		assert.equal(
			decode(external).recoveredPubkey!.toString('hex'),
			publicKey.toString('hex')
		);
	});

	it('rejects a wrong signer or a signature over modified invoice terms', async () => {
		for (const signer of [
			(message: Buffer) => sign(message, Buffer.alloc(32, 2)),
			(message: Buffer) => sign(Buffer.concat([message, Buffer.from([0])])),
			async () => Buffer.alloc(65),
			async () => Buffer.alloc(64),
			async (message: Buffer) => {
				const result = await sign(message);
				result[64] = 4;
				return result;
			}
		]) {
			await assert.rejects(
				encodeWithSigner(options(), publicKey, signer),
				/does not match/
			);
		}
	});

	it('checks signer identity and invoice fields before calling the external service', async () => {
		let calls = 0;
		const signer = async (message: Buffer): Promise<Buffer> => {
			calls++;
			return sign(message);
		};
		await assert.rejects(
			encodeWithSigner(options(), Buffer.alloc(32), signer),
			/compressed/
		);
		await assert.rejects(
			encodeWithSigner(
				{
					...options(),
					payeeNodeKey: Buffer.from(
						secp.getPublicKey(Buffer.alloc(32, 2), true)
					)
				},
				publicKey,
				signer
			),
			/payee/
		);
		await assert.rejects(
			encodeWithSigner(
				{ ...options(), paymentHash: Buffer.alloc(31) },
				publicKey,
				signer
			),
			/32 bytes/
		);
		assert.equal(calls, 0);
	});

	it('snapshots the expected identity and invoice fields before asynchronous signing', async () => {
		const input = options();
		const expected = encode({ ...input, privateKey: key });
		const mutableKey = Buffer.from(publicKey);
		const result = await encodeWithSigner(
			input,
			mutableKey,
			async (message) => {
				await Promise.resolve();
				input.paymentHash.fill(9);
				mutableKey.fill(0);
				return sign(message);
			}
		);
		assert.equal(result, expected);
	});

	it('propagates signer rejection without emitting an invoice', async () => {
		const failure = new Error('Signer is unavailable');
		await assert.rejects(
			encodeWithSigner(options(), publicKey, async () => {
				throw failure;
			}),
			(error) => error === failure
		);
	});
});
