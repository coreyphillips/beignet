import { expect } from 'chai';
import {
	validateHexPubkey,
	validateBuffer,
	validateBufferMinMax,
	validatePositiveBigint,
	validatePort,
	validateHost,
	MAX_MESSAGE_SIZE,
	MAX_SCRIPT_SIZE
} from '../../src/lightning/validation';

describe('Validation Utilities', function () {
	describe('validateHexPubkey', function () {
		it('should accept valid compressed pubkey', function () {
			const valid = '02' + 'a'.repeat(64);
			expect(validateHexPubkey(valid, 'key')).to.be.null;
		});

		it('should accept 03 prefix', function () {
			const valid = '03' + 'b'.repeat(64);
			expect(validateHexPubkey(valid, 'key')).to.be.null;
		});

		it('should reject wrong length', function () {
			expect(validateHexPubkey('02aabb', 'key')).to.include(
				'66 hex characters'
			);
		});

		it('should reject invalid hex chars', function () {
			const bad = '02' + 'g'.repeat(64);
			expect(validateHexPubkey(bad, 'key')).to.include('invalid hex');
		});

		it('should reject invalid prefix', function () {
			const bad = '04' + 'a'.repeat(64);
			expect(validateHexPubkey(bad, 'key')).to.include('02 or 03');
		});
	});

	describe('validateBuffer', function () {
		it('should accept buffer with correct length', function () {
			expect(validateBuffer(Buffer.alloc(32), 32, 'buf')).to.be.null;
		});

		it('should reject buffer with wrong length', function () {
			expect(validateBuffer(Buffer.alloc(16), 32, 'buf')).to.include(
				'32 bytes'
			);
		});
	});

	describe('validateBufferMinMax', function () {
		it('should accept buffer within range', function () {
			expect(validateBufferMinMax(Buffer.alloc(10), 1, 20, 'buf')).to.be.null;
		});

		it('should reject buffer below min', function () {
			expect(validateBufferMinMax(Buffer.alloc(0), 1, 20, 'buf')).to.include(
				'1-20 bytes'
			);
		});

		it('should reject buffer above max', function () {
			expect(validateBufferMinMax(Buffer.alloc(100), 1, 20, 'buf')).to.include(
				'1-20 bytes'
			);
		});
	});

	describe('validatePositiveBigint', function () {
		it('should accept positive bigint', function () {
			expect(validatePositiveBigint(100n, 'val')).to.be.null;
		});

		it('should reject zero', function () {
			expect(validatePositiveBigint(0n, 'val')).to.include('positive');
		});

		it('should reject negative', function () {
			expect(validatePositiveBigint(-5n, 'val')).to.include('positive');
		});
	});

	describe('validatePort', function () {
		it('should accept valid port', function () {
			expect(validatePort(9735)).to.be.null;
		});

		it('should reject port 0', function () {
			expect(validatePort(0)).to.include('1-65535');
		});

		it('should reject port > 65535', function () {
			expect(validatePort(70000)).to.include('1-65535');
		});
	});

	describe('validateHost', function () {
		it('should accept valid host', function () {
			expect(validateHost('localhost')).to.be.null;
		});

		it('should reject empty string', function () {
			expect(validateHost('')).to.include('non-empty');
		});
	});

	describe('Constants', function () {
		it('should define MAX_MESSAGE_SIZE as 65535', function () {
			expect(MAX_MESSAGE_SIZE).to.equal(65535);
		});

		it('should define MAX_SCRIPT_SIZE as 520', function () {
			expect(MAX_SCRIPT_SIZE).to.equal(520);
		});
	});
});
