/**
 * BOLT 8: Post-handshake symmetric cipher state.
 *
 * After the Noise_XK handshake completes, both sides derive sending and
 * receiving keys. All subsequent messages are encrypted using ChaCha20-Poly1305
 * with a monotonically increasing nonce. Key rotation occurs every 1000 messages.
 */

import { encrypt, decrypt, nonceFromCounter } from '../crypto/chacha20poly1305';
import { hkdf2 } from '../crypto/hkdf';

const KEY_ROTATION_INTERVAL = 1000n;

/**
 * Manages a single direction of encrypted communication.
 * Tracks the encryption key, nonce counter, and chaining key for rotation.
 */
export class CipherState {
	private key: Buffer;
	private nonce: bigint;
	private chainingKey: Buffer;

	constructor(key: Buffer, chainingKey: Buffer) {
		if (key.length !== 32) {
			throw new Error(`Key must be 32 bytes, got ${key.length}`);
		}
		if (chainingKey.length !== 32) {
			throw new Error(
				`Chaining key must be 32 bytes, got ${chainingKey.length}`
			);
		}
		this.key = Buffer.from(key);
		this.nonce = 0n;
		this.chainingKey = Buffer.from(chainingKey);
	}

	/**
	 * Encrypt a plaintext message, incrementing the nonce.
	 * Rotates the key after every 1000 messages.
	 */
	encryptMessage(plaintext: Buffer): Buffer {
		const ciphertext = encrypt(
			this.key,
			nonceFromCounter(this.nonce),
			plaintext
		);
		this.nonce++;
		this.maybeRotateKey();
		return ciphertext;
	}

	/**
	 * Decrypt a ciphertext message, incrementing the nonce.
	 * Rotates the key after every 1000 messages.
	 */
	decryptMessage(ciphertext: Buffer): Buffer {
		const plaintext = decrypt(
			this.key,
			nonceFromCounter(this.nonce),
			ciphertext
		);
		this.nonce++;
		this.maybeRotateKey();
		return plaintext;
	}

	/**
	 * Encrypt with associated data (used during handshake).
	 */
	encryptWithAd(plaintext: Buffer, aad: Buffer): Buffer {
		const ciphertext = encrypt(
			this.key,
			nonceFromCounter(this.nonce),
			plaintext,
			aad
		);
		this.nonce++;
		return ciphertext;
	}

	/**
	 * Decrypt with associated data (used during handshake).
	 */
	decryptWithAd(ciphertext: Buffer, aad: Buffer): Buffer {
		const plaintext = decrypt(
			this.key,
			nonceFromCounter(this.nonce),
			ciphertext,
			aad
		);
		this.nonce++;
		return plaintext;
	}

	getNonce(): bigint {
		return this.nonce;
	}

	private maybeRotateKey(): void {
		if (this.nonce === KEY_ROTATION_INTERVAL) {
			const [newChainingKey, newKey] = hkdf2(this.chainingKey, this.key);
			this.chainingKey = newChainingKey;
			this.key = newKey;
			this.nonce = 0n;
		}
	}
}

/**
 * Wraps a pair of CipherState instances for bidirectional encrypted communication.
 */
export class TransportCipher {
	readonly sendCipher: CipherState;
	readonly recvCipher: CipherState;

	constructor(sendKey: Buffer, recvKey: Buffer, chainingKey: Buffer) {
		this.sendCipher = new CipherState(sendKey, chainingKey);
		this.recvCipher = new CipherState(recvKey, chainingKey);
	}

	/**
	 * Encrypt a Lightning message using BOLT 8 framing.
	 * Returns the encrypted length prefix (18 bytes) followed by
	 * the encrypted message body (payload.length + 16 bytes).
	 */
	encryptPacket(payload: Buffer): Buffer {
		if (payload.length > 65535) {
			throw new Error(`Payload too large: ${payload.length} > 65535`);
		}

		// Encrypt the 2-byte length
		const lengthBuf = Buffer.alloc(2);
		lengthBuf.writeUInt16BE(payload.length);
		const encryptedLength = this.sendCipher.encryptMessage(lengthBuf);

		// Encrypt the body
		const encryptedBody = this.sendCipher.encryptMessage(payload);

		return Buffer.concat([encryptedLength, encryptedBody]);
	}

	/**
	 * Decrypt an encrypted length prefix (18 bytes) to get the body length.
	 */
	decryptLength(encryptedLength: Buffer): number {
		if (encryptedLength.length !== 18) {
			throw new Error(
				`Encrypted length must be 18 bytes, got ${encryptedLength.length}`
			);
		}
		const lengthBuf = this.recvCipher.decryptMessage(encryptedLength);
		return lengthBuf.readUInt16BE(0);
	}

	/**
	 * Decrypt an encrypted message body.
	 */
	decryptBody(encryptedBody: Buffer): Buffer {
		return this.recvCipher.decryptMessage(encryptedBody);
	}
}
