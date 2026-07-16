import { expect } from 'chai';
import {
	encodeTxAddInputMessage,
	decodeTxAddInputMessage,
	encodeTxAddOutputMessage,
	decodeTxAddOutputMessage,
	encodeTxRemoveInputMessage,
	decodeTxRemoveInputMessage,
	encodeTxRemoveOutputMessage,
	decodeTxRemoveOutputMessage,
	encodeTxCompleteMessage,
	decodeTxCompleteMessage,
	encodeTxSignaturesMessage,
	decodeTxSignaturesMessage,
	encodeTxInitRbfMessage,
	decodeTxInitRbfMessage,
	encodeTxAckRbfMessage,
	decodeTxAckRbfMessage,
	encodeTxAbortMessage,
	decodeTxAbortMessage,
	ITxAddInputMessage,
	ITxAddOutputMessage,
	ITxSignaturesMessage,
	ITxInitRbfMessage,
	ITxAbortMessage
} from '../../src/lightning/message/interactive-tx';
import {
	InteractiveTxState,
	IInteractiveTxInput,
	IInteractiveTxOutput
} from '../../src/lightning/interactive-tx/types';
import {
	validateSerialIdParity,
	validatePeerSerialIdParity,
	checkDuplicatePrevouts,
	checkDustOutputs,
	validateInteractiveTx,
	calculateTxFee,
	checkFeeSufficiency
} from '../../src/lightning/interactive-tx/validation';
import { InteractiveTxBuilder } from '../../src/lightning/interactive-tx/builder';
import * as crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';

function randomChannelId(): Buffer {
	return crypto.randomBytes(32);
}

function randomTxid(): Buffer {
	return crypto.randomBytes(32);
}

function makeInput(
	serialId: bigint,
	prevTxid?: Buffer,
	prevOutputIndex?: number
): IInteractiveTxInput {
	const vout = prevOutputIndex ?? 0;
	// A valid prev_tx with a native-segwit output at `vout`: the receive side
	// now enforces prevtx validity + segwit-only spends (S-2.H3).
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	for (let i = 0; i <= vout; i++) {
		prevTx.addOutput(
			Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
			100_000
		);
	}
	return {
		serialId,
		prevTxid: prevTxid || randomTxid(),
		prevOutputIndex: vout,
		sequence: 0xfffffffd,
		prevTx: prevTx.toBuffer(),
		prevTxVout: vout
	};
}

function makeOutput(
	serialId: bigint,
	amountSats?: bigint
): IInteractiveTxOutput {
	return {
		serialId,
		amountSats: amountSats ?? 100000n,
		scriptPubkey: Buffer.from(
			'0014' + crypto.randomBytes(20).toString('hex'),
			'hex'
		)
	};
}

describe('Interactive TX Construction', function () {
	// ========================================================================
	// Message Encode/Decode Tests
	// ========================================================================
	describe('Message: tx_add_input (66)', function () {
		const channelId = randomChannelId();
		const prevTx = crypto.randomBytes(100);
		const sampleMsg: ITxAddInputMessage = {
			channelId,
			serialId: 42n,
			prevTx,
			prevTxVout: 1,
			sequence: 0xfffffffd
		};

		it('should encode tx_add_input', function () {
			const encoded = encodeTxAddInputMessage(sampleMsg);
			// 32 + 8 + 2 + 100 + 4 + 4 = 150
			expect(encoded.length).to.equal(150);
			// Channel ID at start
			expect(encoded.subarray(0, 32).equals(channelId)).to.be.true;
			// Serial ID at offset 32 (big endian)
			expect(encoded.readBigUInt64BE(32)).to.equal(42n);
			// prevTx length at offset 40
			expect(encoded.readUInt16BE(40)).to.equal(100);
		});

		it('should decode tx_add_input', function () {
			const encoded = encodeTxAddInputMessage(sampleMsg);
			const decoded = decodeTxAddInputMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.serialId).to.equal(42n);
			expect(decoded.prevTx.equals(prevTx)).to.be.true;
			expect(decoded.prevTxVout).to.equal(1);
			expect(decoded.sequence).to.equal(0xfffffffd);
		});

		it('should round-trip tx_add_input', function () {
			const encoded = encodeTxAddInputMessage(sampleMsg);
			const decoded = decodeTxAddInputMessage(encoded);
			const reencoded = encodeTxAddInputMessage(decoded);
			expect(reencoded.equals(encoded)).to.be.true;
		});

		it('should reject too-short payload', function () {
			expect(() => decodeTxAddInputMessage(Buffer.alloc(10))).to.throw(
				'too short'
			);
		});
	});

	describe('Message: tx_add_output (67)', function () {
		const channelId = randomChannelId();
		const scriptPubkey = Buffer.from(
			'0014' + crypto.randomBytes(20).toString('hex'),
			'hex'
		);
		const sampleMsg: ITxAddOutputMessage = {
			channelId,
			serialId: 100n,
			amountSats: 50000n,
			scriptPubkey
		};

		it('should encode tx_add_output', function () {
			const encoded = encodeTxAddOutputMessage(sampleMsg);
			// 32 + 8 + 8 + 2 + 22 = 72
			expect(encoded.length).to.equal(72);
			expect(encoded.subarray(0, 32).equals(channelId)).to.be.true;
			expect(encoded.readBigUInt64BE(32)).to.equal(100n);
			expect(encoded.readBigUInt64BE(40)).to.equal(50000n);
			expect(encoded.readUInt16BE(48)).to.equal(22);
		});

		it('should decode tx_add_output', function () {
			const encoded = encodeTxAddOutputMessage(sampleMsg);
			const decoded = decodeTxAddOutputMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.serialId).to.equal(100n);
			expect(decoded.amountSats).to.equal(50000n);
			expect(decoded.scriptPubkey.equals(scriptPubkey)).to.be.true;
		});

		it('should round-trip tx_add_output', function () {
			const encoded = encodeTxAddOutputMessage(sampleMsg);
			const decoded = decodeTxAddOutputMessage(encoded);
			const reencoded = encodeTxAddOutputMessage(decoded);
			expect(reencoded.equals(encoded)).to.be.true;
		});

		it('should reject too-short payload', function () {
			expect(() => decodeTxAddOutputMessage(Buffer.alloc(10))).to.throw(
				'too short'
			);
		});
	});

	describe('Message: tx_remove_input (68)', function () {
		const channelId = randomChannelId();
		const sampleMsg = { channelId, serialId: 7n };

		it('should encode tx_remove_input', function () {
			const encoded = encodeTxRemoveInputMessage(sampleMsg);
			expect(encoded.length).to.equal(40);
			expect(encoded.subarray(0, 32).equals(channelId)).to.be.true;
			expect(encoded.readBigUInt64BE(32)).to.equal(7n);
		});

		it('should decode tx_remove_input', function () {
			const encoded = encodeTxRemoveInputMessage(sampleMsg);
			const decoded = decodeTxRemoveInputMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.serialId).to.equal(7n);
		});

		it('should round-trip tx_remove_input', function () {
			const encoded = encodeTxRemoveInputMessage(sampleMsg);
			const decoded = decodeTxRemoveInputMessage(encoded);
			const reencoded = encodeTxRemoveInputMessage(decoded);
			expect(reencoded.equals(encoded)).to.be.true;
		});

		it('should reject too-short payload', function () {
			expect(() => decodeTxRemoveInputMessage(Buffer.alloc(5))).to.throw(
				'too short'
			);
		});
	});

	describe('Message: tx_remove_output (69)', function () {
		const channelId = randomChannelId();
		const sampleMsg = { channelId, serialId: 99n };

		it('should encode tx_remove_output', function () {
			const encoded = encodeTxRemoveOutputMessage(sampleMsg);
			expect(encoded.length).to.equal(40);
			expect(encoded.subarray(0, 32).equals(channelId)).to.be.true;
			expect(encoded.readBigUInt64BE(32)).to.equal(99n);
		});

		it('should decode tx_remove_output', function () {
			const encoded = encodeTxRemoveOutputMessage(sampleMsg);
			const decoded = decodeTxRemoveOutputMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.serialId).to.equal(99n);
		});

		it('should round-trip tx_remove_output', function () {
			const encoded = encodeTxRemoveOutputMessage(sampleMsg);
			const decoded = decodeTxRemoveOutputMessage(encoded);
			const reencoded = encodeTxRemoveOutputMessage(decoded);
			expect(reencoded.equals(encoded)).to.be.true;
		});

		it('should reject too-short payload', function () {
			expect(() => decodeTxRemoveOutputMessage(Buffer.alloc(5))).to.throw(
				'too short'
			);
		});
	});

	describe('Message: tx_complete (70)', function () {
		const channelId = randomChannelId();
		const sampleMsg = { channelId };

		it('should encode tx_complete', function () {
			const encoded = encodeTxCompleteMessage(sampleMsg);
			expect(encoded.length).to.equal(32);
			expect(encoded.equals(channelId)).to.be.true;
		});

		it('should decode tx_complete', function () {
			const encoded = encodeTxCompleteMessage(sampleMsg);
			const decoded = decodeTxCompleteMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
		});

		it('should round-trip tx_complete', function () {
			const encoded = encodeTxCompleteMessage(sampleMsg);
			const decoded = decodeTxCompleteMessage(encoded);
			const reencoded = encodeTxCompleteMessage(decoded);
			expect(reencoded.equals(encoded)).to.be.true;
		});

		it('should reject too-short payload', function () {
			expect(() => decodeTxCompleteMessage(Buffer.alloc(5))).to.throw(
				'too short'
			);
		});
	});

	describe('Message: tx_signatures (71)', function () {
		const channelId = randomChannelId();
		const txid = randomTxid();

		it('should encode tx_signatures with empty witnesses', function () {
			const msg: ITxSignaturesMessage = { channelId, txid, witnesses: [] };
			const encoded = encodeTxSignaturesMessage(msg);
			// 32 + 32 + 2 = 66
			expect(encoded.length).to.equal(66);
			expect(encoded.readUInt16BE(64)).to.equal(0);
		});

		it('should decode tx_signatures with empty witnesses', function () {
			const msg: ITxSignaturesMessage = { channelId, txid, witnesses: [] };
			const encoded = encodeTxSignaturesMessage(msg);
			const decoded = decodeTxSignaturesMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.txid.equals(txid)).to.be.true;
			expect(decoded.witnesses.length).to.equal(0);
		});

		it('should round-trip tx_signatures with witnesses', function () {
			const sig = crypto.randomBytes(72);
			const pubkey = crypto.randomBytes(33);
			const msg: ITxSignaturesMessage = {
				channelId,
				txid,
				witnesses: [[sig, pubkey]]
			};
			const encoded = encodeTxSignaturesMessage(msg);
			const decoded = decodeTxSignaturesMessage(encoded);
			expect(decoded.witnesses.length).to.equal(1);
			expect(decoded.witnesses[0].length).to.equal(2);
			expect(decoded.witnesses[0][0].equals(sig)).to.be.true;
			expect(decoded.witnesses[0][1].equals(pubkey)).to.be.true;
		});

		it('should handle multiple witnesses with multiple elements', function () {
			const w1 = [crypto.randomBytes(72), crypto.randomBytes(33)];
			const w2 = [crypto.randomBytes(64)];
			const w3 = [
				crypto.randomBytes(32),
				crypto.randomBytes(32),
				crypto.randomBytes(32)
			];
			const msg: ITxSignaturesMessage = {
				channelId,
				txid,
				witnesses: [w1, w2, w3]
			};
			const encoded = encodeTxSignaturesMessage(msg);
			const decoded = decodeTxSignaturesMessage(encoded);
			expect(decoded.witnesses.length).to.equal(3);
			expect(decoded.witnesses[0].length).to.equal(2);
			expect(decoded.witnesses[1].length).to.equal(1);
			expect(decoded.witnesses[2].length).to.equal(3);
			expect(decoded.witnesses[0][0].equals(w1[0])).to.be.true;
			expect(decoded.witnesses[0][1].equals(w1[1])).to.be.true;
			expect(decoded.witnesses[1][0].equals(w2[0])).to.be.true;
			expect(decoded.witnesses[2][0].equals(w3[0])).to.be.true;
			expect(decoded.witnesses[2][1].equals(w3[1])).to.be.true;
			expect(decoded.witnesses[2][2].equals(w3[2])).to.be.true;
		});

		it('should reject too-short payload', function () {
			expect(() => decodeTxSignaturesMessage(Buffer.alloc(10))).to.throw(
				'too short'
			);
		});

		it('encodes witnesses in standard Bitcoin stack serialization (BOLT 2 interop)', function () {
			// A P2WPKH witness: 2 elements (sig, pubkey). On the wire each witness
			// is [u16 len][CompactSize count][CompactSize len + bytes per element]
			// — NOT beignet's old [u16 numElements][u16 len][element] format,
			// which CLN/LND/Eclair cannot parse.
			const sig = Buffer.alloc(71, 0xaa);
			const pubkey = Buffer.alloc(33, 0xbb);
			const encoded = encodeTxSignaturesMessage({
				channelId,
				txid,
				witnesses: [[sig, pubkey]]
			});

			let off = 66;
			const witnessLen = encoded.readUInt16BE(off);
			off += 2;
			expect(witnessLen).to.equal(1 + 1 + 71 + 1 + 33);
			expect(encoded[off]).to.equal(2); // CompactSize element count
			expect(encoded[off + 1]).to.equal(71); // CompactSize sig length
			expect(encoded.subarray(off + 2, off + 2 + 71).equals(sig)).to.be.true;
			expect(encoded[off + 2 + 71]).to.equal(33); // CompactSize pubkey length
		});

		it('round-trips the shared_input_signature TLV (splicing)', function () {
			const sharedSig = crypto.randomBytes(64);
			const msg: ITxSignaturesMessage = {
				channelId,
				txid,
				witnesses: [],
				sharedInputSignature: sharedSig
			};
			const encoded = encodeTxSignaturesMessage(msg);
			// 66 fixed bytes + TLV (type 0, len 64, value)
			expect(encoded.length).to.equal(66 + 2 + 64);
			expect(encoded[66]).to.equal(0); // TLV type 0
			expect(encoded[67]).to.equal(64); // TLV length
			const decoded = decodeTxSignaturesMessage(encoded);
			expect(decoded.sharedInputSignature!.equals(sharedSig)).to.be.true;
			expect(decoded.witnesses.length).to.equal(0);
		});

		it('rejects a malformed shared_input_signature on encode', function () {
			expect(() =>
				encodeTxSignaturesMessage({
					channelId,
					txid,
					witnesses: [],
					sharedInputSignature: Buffer.alloc(32)
				})
			).to.throw('64 bytes');
		});
	});

	describe('Message: tx_init_rbf (72)', function () {
		const channelId = randomChannelId();
		const sampleMsg: ITxInitRbfMessage = {
			channelId,
			locktime: 800000,
			feerate: 5000
		};

		it('should encode tx_init_rbf', function () {
			const encoded = encodeTxInitRbfMessage(sampleMsg);
			expect(encoded.length).to.equal(40);
			expect(encoded.subarray(0, 32).equals(channelId)).to.be.true;
			expect(encoded.readUInt32BE(32)).to.equal(800000);
			expect(encoded.readUInt32BE(36)).to.equal(5000);
		});

		it('should decode tx_init_rbf', function () {
			const encoded = encodeTxInitRbfMessage(sampleMsg);
			const decoded = decodeTxInitRbfMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.locktime).to.equal(800000);
			expect(decoded.feerate).to.equal(5000);
		});

		it('should round-trip tx_init_rbf', function () {
			const encoded = encodeTxInitRbfMessage(sampleMsg);
			const decoded = decodeTxInitRbfMessage(encoded);
			const reencoded = encodeTxInitRbfMessage(decoded);
			expect(reencoded.equals(encoded)).to.be.true;
		});

		it('should reject too-short payload', function () {
			expect(() => decodeTxInitRbfMessage(Buffer.alloc(10))).to.throw(
				'too short'
			);
		});
	});

	describe('Message: tx_ack_rbf (73)', function () {
		const channelId = randomChannelId();
		const sampleMsg = { channelId };

		it('should encode tx_ack_rbf', function () {
			const encoded = encodeTxAckRbfMessage(sampleMsg);
			expect(encoded.length).to.equal(32);
			expect(encoded.equals(channelId)).to.be.true;
		});

		it('should decode tx_ack_rbf', function () {
			const encoded = encodeTxAckRbfMessage(sampleMsg);
			const decoded = decodeTxAckRbfMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
		});

		it('should round-trip tx_ack_rbf', function () {
			const encoded = encodeTxAckRbfMessage(sampleMsg);
			const decoded = decodeTxAckRbfMessage(encoded);
			const reencoded = encodeTxAckRbfMessage(decoded);
			expect(reencoded.equals(encoded)).to.be.true;
		});

		it('should reject too-short payload', function () {
			expect(() => decodeTxAckRbfMessage(Buffer.alloc(5))).to.throw(
				'too short'
			);
		});
	});

	describe('Message: tx_abort (74)', function () {
		const channelId = randomChannelId();
		const data = Buffer.from('Insufficient funds', 'ascii');
		const sampleMsg: ITxAbortMessage = { channelId, data };

		it('should encode tx_abort', function () {
			const encoded = encodeTxAbortMessage(sampleMsg);
			// 32 + 2 + 18 = 52
			expect(encoded.length).to.equal(52);
			expect(encoded.subarray(0, 32).equals(channelId)).to.be.true;
			expect(encoded.readUInt16BE(32)).to.equal(18);
			expect(encoded.subarray(34).toString('ascii')).to.equal(
				'Insufficient funds'
			);
		});

		it('should decode tx_abort', function () {
			const encoded = encodeTxAbortMessage(sampleMsg);
			const decoded = decodeTxAbortMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.data.toString('ascii')).to.equal('Insufficient funds');
		});

		it('should round-trip tx_abort', function () {
			const encoded = encodeTxAbortMessage(sampleMsg);
			const decoded = decodeTxAbortMessage(encoded);
			const reencoded = encodeTxAbortMessage(decoded);
			expect(reencoded.equals(encoded)).to.be.true;
		});

		it('should handle empty data', function () {
			const msg: ITxAbortMessage = { channelId, data: Buffer.alloc(0) };
			const encoded = encodeTxAbortMessage(msg);
			expect(encoded.length).to.equal(34);
			expect(encoded.readUInt16BE(32)).to.equal(0);
			const decoded = decodeTxAbortMessage(encoded);
			expect(decoded.data.length).to.equal(0);
		});

		it('should reject too-short payload', function () {
			expect(() => decodeTxAbortMessage(Buffer.alloc(10))).to.throw(
				'too short'
			);
		});
	});

	// ========================================================================
	// Validation Tests
	// ========================================================================
	describe('Validation', function () {
		describe('validateSerialIdParity', function () {
			it('should accept even serial ID for initiator', function () {
				expect(validateSerialIdParity(0n, true)).to.be.null;
				expect(validateSerialIdParity(2n, true)).to.be.null;
				expect(validateSerialIdParity(100n, true)).to.be.null;
			});

			it('should accept odd serial ID for acceptor', function () {
				expect(validateSerialIdParity(1n, false)).to.be.null;
				expect(validateSerialIdParity(3n, false)).to.be.null;
				expect(validateSerialIdParity(101n, false)).to.be.null;
			});

			it('should reject odd serial ID for initiator', function () {
				const err = validateSerialIdParity(1n, true);
				expect(err).to.contain('even');
			});

			it('should reject even serial ID for acceptor', function () {
				const err = validateSerialIdParity(2n, false);
				expect(err).to.contain('odd');
			});
		});

		describe('validatePeerSerialIdParity', function () {
			it('should accept odd serial ID from peer when we are initiator', function () {
				expect(validatePeerSerialIdParity(1n, true)).to.be.null;
				expect(validatePeerSerialIdParity(3n, true)).to.be.null;
			});

			it('should accept even serial ID from peer when we are acceptor', function () {
				expect(validatePeerSerialIdParity(0n, false)).to.be.null;
				expect(validatePeerSerialIdParity(2n, false)).to.be.null;
			});

			it('should reject even serial ID from peer when we are initiator', function () {
				const err = validatePeerSerialIdParity(2n, true);
				expect(err).to.not.be.null;
			});

			it('should reject odd serial ID from peer when we are acceptor', function () {
				const err = validatePeerSerialIdParity(1n, false);
				expect(err).to.not.be.null;
			});
		});

		describe('checkDuplicatePrevouts', function () {
			it('should return null when no duplicates', function () {
				const inputs: IInteractiveTxInput[] = [
					makeInput(0n, Buffer.alloc(32, 0x01), 0),
					makeInput(2n, Buffer.alloc(32, 0x02), 0),
					makeInput(4n, Buffer.alloc(32, 0x01), 1) // same txid, different vout
				];
				expect(checkDuplicatePrevouts(inputs)).to.be.null;
			});

			it('should detect duplicate prevouts', function () {
				const txid = Buffer.alloc(32, 0x01);
				const inputs: IInteractiveTxInput[] = [
					makeInput(0n, txid, 0),
					makeInput(2n, txid, 0) // same txid and vout
				];
				const err = checkDuplicatePrevouts(inputs);
				expect(err).to.contain('Duplicate prevout');
			});
		});

		describe('checkDustOutputs', function () {
			it('should return null when all outputs above dust', function () {
				const outputs: IInteractiveTxOutput[] = [
					makeOutput(0n, 1000n),
					makeOutput(2n, 546n)
				];
				expect(checkDustOutputs(outputs)).to.be.null;
			});

			it('should detect output below dust limit', function () {
				const outputs: IInteractiveTxOutput[] = [
					makeOutput(0n, 1000n),
					makeOutput(2n, 545n)
				];
				const err = checkDustOutputs(outputs);
				expect(err).to.contain('dust limit');
			});
		});

		describe('validateInteractiveTx', function () {
			it('should accept valid transaction', function () {
				const inputs = [makeInput(0n)];
				const outputs = [makeOutput(0n, 1000n)];
				expect(validateInteractiveTx(inputs, outputs)).to.be.null;
			});

			it('should reject transaction with no inputs', function () {
				const outputs = [makeOutput(0n, 1000n)];
				const err = validateInteractiveTx([], outputs);
				expect(err).to.contain('at least one input');
			});

			it('should reject transaction with no outputs', function () {
				const inputs = [makeInput(0n)];
				const err = validateInteractiveTx(inputs, []);
				expect(err).to.contain('at least one output');
			});

			it('should reject transaction with dust outputs', function () {
				const inputs = [makeInput(0n)];
				const outputs = [makeOutput(0n, 100n)];
				const err = validateInteractiveTx(inputs, outputs);
				expect(err).to.contain('dust limit');
			});
		});

		describe('calculateTxFee', function () {
			it('should calculate fee correctly', function () {
				const inputValues = [100000n, 50000n];
				const outputs: IInteractiveTxOutput[] = [
					makeOutput(0n, 80000n),
					makeOutput(2n, 60000n)
				];
				const fee = calculateTxFee(inputValues, outputs);
				expect(fee).to.equal(10000n);
			});

			it('should handle zero fee', function () {
				const inputValues = [100000n];
				const outputs: IInteractiveTxOutput[] = [makeOutput(0n, 100000n)];
				const fee = calculateTxFee(inputValues, outputs);
				expect(fee).to.equal(0n);
			});
		});

		describe('checkFeeSufficiency', function () {
			it('should accept sufficient fee', function () {
				// weight=400, feerate=1000 sat/kw => minFee = 400 * 1000 / 1000 = 400
				expect(checkFeeSufficiency(500n, 400, 1000)).to.be.null;
			});

			it('should reject insufficient fee', function () {
				// weight=400, feerate=1000 sat/kw => minFee = 400
				const err = checkFeeSufficiency(300n, 400, 1000);
				expect(err).to.contain('below minimum');
			});
		});
	});

	// ========================================================================
	// Builder Tests
	// ========================================================================
	describe('Builder', function () {
		it('should start in COLLECTING state', function () {
			const builder = new InteractiveTxBuilder(true);
			expect(builder.getState()).to.equal(InteractiveTxState.COLLECTING);
		});

		it('should add input with valid serial ID (initiator, even)', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.addInput(makeInput(0n));
			expect(err).to.be.null;
			expect(builder.getInputs().length).to.equal(1);
		});

		it('should reject addInput with wrong parity (initiator, odd)', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.addInput(makeInput(1n));
			expect(err).to.contain('even');
		});

		it('should add peer input with correct parity (initiator receives odd)', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.addPeerInput(makeInput(1n));
			expect(err).to.be.null;
			expect(builder.getInputs().length).to.equal(1);
		});

		it('should reject peer input with wrong parity', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.addPeerInput(makeInput(0n));
			expect(err).to.not.be.null;
		});

		it('should add output with valid serial ID', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.addOutput(makeOutput(0n));
			expect(err).to.be.null;
			expect(builder.getOutputs().length).to.equal(1);
		});

		it('should add peer output with correct parity', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.addPeerOutput(makeOutput(1n));
			expect(err).to.be.null;
			expect(builder.getOutputs().length).to.equal(1);
		});

		it('should reject peer output with wrong parity', function () {
			const builder = new InteractiveTxBuilder(false);
			// We are acceptor, so peer (initiator) should use even IDs
			const err = builder.addPeerOutput(makeOutput(1n));
			expect(err).to.not.be.null;
		});

		it('should remove input', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			expect(builder.getInputs().length).to.equal(1);
			const err = builder.removeInput(0n);
			expect(err).to.be.null;
			expect(builder.getInputs().length).to.equal(0);
		});

		it('should remove output', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addOutput(makeOutput(0n));
			expect(builder.getOutputs().length).to.equal(1);
			const err = builder.removeOutput(0n);
			expect(err).to.be.null;
			expect(builder.getOutputs().length).to.equal(0);
		});

		it('should remove peer input', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addPeerInput(makeInput(1n));
			expect(builder.getInputs().length).to.equal(1);
			const err = builder.removePeerInput(1n);
			expect(err).to.be.null;
			expect(builder.getInputs().length).to.equal(0);
		});

		it('should remove peer output', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addPeerOutput(makeOutput(1n));
			expect(builder.getOutputs().length).to.equal(1);
			const err = builder.removePeerOutput(1n);
			expect(err).to.be.null;
			expect(builder.getOutputs().length).to.equal(0);
		});

		it('should transition to SENT_COMPLETE on markComplete', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			const err = builder.markComplete();
			expect(err).to.be.null;
			expect(builder.getState()).to.equal(InteractiveTxState.SENT_COMPLETE);
		});

		it('should transition to RECEIVED_COMPLETE on handlePeerComplete', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.handlePeerComplete();
			expect(err).to.be.null;
			expect(builder.getState()).to.equal(InteractiveTxState.RECEIVED_COMPLETE);
		});

		it('should transition to COMPLETE when both sides complete (us first)', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.markComplete();
			expect(builder.getState()).to.equal(InteractiveTxState.SENT_COMPLETE);
			builder.handlePeerComplete();
			expect(builder.getState()).to.equal(InteractiveTxState.COMPLETE);
			expect(builder.isComplete()).to.be.true;
		});

		it('should transition to COMPLETE when both sides complete (peer first)', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.handlePeerComplete();
			expect(builder.getState()).to.equal(InteractiveTxState.RECEIVED_COMPLETE);
			builder.markComplete();
			expect(builder.getState()).to.equal(InteractiveTxState.COMPLETE);
			expect(builder.isComplete()).to.be.true;
		});

		it('should return sorted inputs and outputs from buildTransaction', function () {
			const builder = new InteractiveTxBuilder(true, 500);
			// Add inputs out of order (interleaved initiator/peer)
			builder.addPeerInput(makeInput(3n));
			builder.addInput(makeInput(0n));
			builder.addPeerInput(makeInput(1n));
			builder.addInput(makeInput(2n));

			// Add outputs out of order
			builder.addPeerOutput(makeOutput(5n, 10000n));
			builder.addOutput(makeOutput(0n, 50000n));
			builder.addPeerOutput(makeOutput(1n, 20000n));

			builder.markComplete();
			builder.handlePeerComplete();

			const tx = builder.buildTransaction();
			expect(tx).to.not.be.null;
			expect(tx!.inputs.length).to.equal(4);
			expect(tx!.outputs.length).to.equal(3);
			expect(tx!.locktime).to.equal(500);

			// Verify sorted by serial ID
			expect(tx!.inputs[0].serialId).to.equal(0n);
			expect(tx!.inputs[1].serialId).to.equal(1n);
			expect(tx!.inputs[2].serialId).to.equal(2n);
			expect(tx!.inputs[3].serialId).to.equal(3n);

			expect(tx!.outputs[0].serialId).to.equal(0n);
			expect(tx!.outputs[1].serialId).to.equal(1n);
			expect(tx!.outputs[2].serialId).to.equal(5n);
		});

		it('should return null from buildTransaction if not complete', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			expect(builder.buildTransaction()).to.be.null;
		});

		it('should set ABORTED state on abort', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.abort();
			expect(builder.getState()).to.equal(InteractiveTxState.ABORTED);
			expect(builder.isAborted()).to.be.true;
		});

		it('should reject addInput after abort', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.abort();
			const err = builder.addInput(makeInput(0n));
			expect(err).to.contain('aborted');
		});

		it('should reject addOutput after abort', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.abort();
			const err = builder.addOutput(makeOutput(0n));
			expect(err).to.contain('aborted');
		});

		it('should reject addPeerInput after abort', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.abort();
			const err = builder.addPeerInput(makeInput(1n));
			expect(err).to.contain('aborted');
		});

		it('should reject addPeerOutput after abort', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.abort();
			const err = builder.addPeerOutput(makeOutput(1n));
			expect(err).to.contain('aborted');
		});

		it('should reject addInput after complete', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.markComplete();
			builder.handlePeerComplete();
			const err = builder.addInput(makeInput(2n));
			expect(err).to.contain('complete');
		});

		it('should reject markComplete after abort', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.abort();
			const err = builder.markComplete();
			expect(err).to.contain('aborted');
		});

		it('should reject handlePeerComplete after abort', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.abort();
			const err = builder.handlePeerComplete();
			expect(err).to.contain('aborted');
		});

		it('should handle multiple inputs and outputs from both sides', function () {
			const builder = new InteractiveTxBuilder(true);

			// Initiator adds inputs (even)
			expect(builder.addInput(makeInput(0n))).to.be.null;
			expect(builder.addInput(makeInput(2n))).to.be.null;
			expect(builder.addInput(makeInput(4n))).to.be.null;

			// Peer adds inputs (odd)
			expect(builder.addPeerInput(makeInput(1n))).to.be.null;
			expect(builder.addPeerInput(makeInput(3n))).to.be.null;

			// Initiator adds outputs (even)
			expect(builder.addOutput(makeOutput(0n, 50000n))).to.be.null;
			expect(builder.addOutput(makeOutput(2n, 30000n))).to.be.null;

			// Peer adds outputs (odd)
			expect(builder.addPeerOutput(makeOutput(1n, 40000n))).to.be.null;

			expect(builder.getInputs().length).to.equal(5);
			expect(builder.getOutputs().length).to.equal(3);
		});

		it('should generate correct parity serial IDs with nextSerialIdForUs', function () {
			const initiator = new InteractiveTxBuilder(true);
			expect(initiator.nextSerialIdForUs()).to.equal(0n);
			expect(initiator.nextSerialIdForUs()).to.equal(2n);
			expect(initiator.nextSerialIdForUs()).to.equal(4n);

			const acceptor = new InteractiveTxBuilder(false);
			expect(acceptor.nextSerialIdForUs()).to.equal(1n);
			expect(acceptor.nextSerialIdForUs()).to.equal(3n);
			expect(acceptor.nextSerialIdForUs()).to.equal(5n);
		});

		it('should run a full flow: initiator adds, acceptor adds, both complete', function () {
			const initiator = new InteractiveTxBuilder(true, 100);
			const acceptor = new InteractiveTxBuilder(false, 100);

			// Initiator adds an input
			const iInput = makeInput(initiator.nextSerialIdForUs()); // 0n
			expect(initiator.addInput(iInput)).to.be.null;
			// Acceptor receives it
			expect(acceptor.addPeerInput(iInput)).to.be.null;

			// Acceptor adds an input
			const aInput = makeInput(acceptor.nextSerialIdForUs()); // 1n
			expect(acceptor.addInput(aInput)).to.be.null;
			// Initiator receives it
			expect(initiator.addPeerInput(aInput)).to.be.null;

			// Initiator adds an output
			const iOutput = makeOutput(initiator.nextSerialIdForUs(), 50000n); // 2n
			expect(initiator.addOutput(iOutput)).to.be.null;
			expect(acceptor.addPeerOutput(iOutput)).to.be.null;

			// Acceptor adds an output
			const aOutput = makeOutput(acceptor.nextSerialIdForUs(), 40000n); // 3n
			expect(acceptor.addOutput(aOutput)).to.be.null;
			expect(initiator.addPeerOutput(aOutput)).to.be.null;

			// Both complete
			expect(initiator.markComplete()).to.be.null;
			expect(acceptor.handlePeerComplete()).to.be.null;
			expect(acceptor.markComplete()).to.be.null;
			expect(initiator.handlePeerComplete()).to.be.null;

			expect(initiator.isComplete()).to.be.true;
			expect(acceptor.isComplete()).to.be.true;

			// Build from both sides
			const iTx = initiator.buildTransaction();
			const aTx = acceptor.buildTransaction();

			expect(iTx).to.not.be.null;
			expect(aTx).to.not.be.null;

			// Both should have same inputs in same order
			expect(iTx!.inputs.length).to.equal(aTx!.inputs.length);
			expect(iTx!.outputs.length).to.equal(aTx!.outputs.length);
			expect(iTx!.locktime).to.equal(aTx!.locktime);

			// Serial ID ordering should match
			for (let i = 0; i < iTx!.inputs.length; i++) {
				expect(iTx!.inputs[i].serialId).to.equal(aTx!.inputs[i].serialId);
			}
			for (let i = 0; i < iTx!.outputs.length; i++) {
				expect(iTx!.outputs[i].serialId).to.equal(aTx!.outputs[i].serialId);
			}
		});

		it('should support starting a new session for RBF', function () {
			const builder1 = new InteractiveTxBuilder(true, 100);
			builder1.addInput(makeInput(0n));
			builder1.addOutput(makeOutput(0n));
			builder1.markComplete();
			builder1.handlePeerComplete();
			expect(builder1.isComplete()).to.be.true;

			// Start a new builder for RBF with higher feerate locktime
			const builder2 = new InteractiveTxBuilder(true, 101);
			expect(builder2.getState()).to.equal(InteractiveTxState.COLLECTING);
			expect(builder2.getInputs().length).to.equal(0);
			expect(builder2.getOutputs().length).to.equal(0);
		});

		it('should return current items from getInputs/getOutputs', function () {
			const builder = new InteractiveTxBuilder(true);
			expect(builder.getInputs()).to.deep.equal([]);
			expect(builder.getOutputs()).to.deep.equal([]);

			const input = makeInput(0n);
			builder.addInput(input);
			expect(builder.getInputs().length).to.equal(1);
			expect(builder.getInputs()[0].serialId).to.equal(0n);

			const output = makeOutput(0n);
			builder.addOutput(output);
			expect(builder.getOutputs().length).to.equal(1);
			expect(builder.getOutputs()[0].serialId).to.equal(0n);
		});

		it('should return error when removing non-existent input', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.removeInput(999n);
			expect(err).to.contain('not found');
		});

		it('should return error when removing non-existent output', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.removeOutput(999n);
			expect(err).to.contain('not found');
		});

		it('should return error when removing non-existent peer input', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.removePeerInput(999n);
			expect(err).to.contain('not found');
		});

		it('should return error when removing non-existent peer output', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.removePeerOutput(999n);
			expect(err).to.contain('not found');
		});

		it('should return error for duplicate serial ID on input', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			const err = builder.addInput(makeInput(0n));
			expect(err).to.contain('already exists');
		});

		it('should return error for duplicate serial ID on output', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addOutput(makeOutput(0n));
			const err = builder.addOutput(makeOutput(0n));
			expect(err).to.contain('already exists');
		});

		it('should preserve locktime in build result', function () {
			const builder = new InteractiveTxBuilder(true, 750000);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.markComplete();
			builder.handlePeerComplete();
			const tx = builder.buildTransaction();
			expect(tx!.locktime).to.equal(750000);
		});

		it('should sort mixed initiator/acceptor inputs by serial ID', function () {
			const builder = new InteractiveTxBuilder(true);

			// Add in random order: peer(7), us(4), peer(1), us(2), peer(5), us(0)
			builder.addPeerInput(makeInput(7n));
			builder.addInput(makeInput(4n));
			builder.addPeerInput(makeInput(1n));
			builder.addInput(makeInput(2n));
			builder.addPeerInput(makeInput(5n));
			builder.addInput(makeInput(0n));

			builder.addOutput(makeOutput(0n, 1000n));

			builder.markComplete();
			builder.handlePeerComplete();

			const tx = builder.buildTransaction();
			expect(tx).to.not.be.null;
			expect(tx!.inputs.map((i) => i.serialId)).to.deep.equal([
				0n,
				1n,
				2n,
				4n,
				5n,
				7n
			]);
		});

		it('should reject markComplete when already SENT_COMPLETE', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.markComplete();
			const err = builder.markComplete();
			expect(err).to.contain('Already sent');
		});

		it('should reject markComplete when already COMPLETE', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.markComplete();
			builder.handlePeerComplete();
			const err = builder.markComplete();
			expect(err).to.contain('complete');
		});

		it('should reject handlePeerComplete when already COMPLETE', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.markComplete();
			builder.handlePeerComplete();
			const err = builder.handlePeerComplete();
			expect(err).to.contain('complete');
		});

		it('should reset SENT_COMPLETE to COLLECTING on addInput', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.markComplete();
			expect(builder.getState()).to.equal(InteractiveTxState.SENT_COMPLETE);

			// Adding a new input resets to COLLECTING
			builder.addInput(makeInput(2n));
			expect(builder.getState()).to.equal(InteractiveTxState.COLLECTING);
		});

		it('should reset SENT_COMPLETE to COLLECTING on addOutput', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.markComplete();
			expect(builder.getState()).to.equal(InteractiveTxState.SENT_COMPLETE);

			builder.addOutput(makeOutput(2n));
			expect(builder.getState()).to.equal(InteractiveTxState.COLLECTING);
		});

		it('should reset SENT_COMPLETE to COLLECTING on removeInput', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.markComplete();
			expect(builder.getState()).to.equal(InteractiveTxState.SENT_COMPLETE);

			builder.removeInput(0n);
			expect(builder.getState()).to.equal(InteractiveTxState.COLLECTING);
		});

		it('should reset SENT_COMPLETE to COLLECTING on removeOutput', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.addOutput(makeOutput(2n));
			builder.markComplete();
			expect(builder.getState()).to.equal(InteractiveTxState.SENT_COMPLETE);

			builder.removeOutput(0n);
			expect(builder.getState()).to.equal(InteractiveTxState.COLLECTING);
		});

		it('should expose session via getSession()', function () {
			const builder = new InteractiveTxBuilder(true, 42);
			const session = builder.getSession();
			expect(session.isInitiator).to.be.true;
			expect(session.locktime).to.equal(42);
			expect(session.state).to.equal(InteractiveTxState.COLLECTING);
		});

		it('should return null from buildTransaction when validation fails (no inputs/outputs)', function () {
			const builder = new InteractiveTxBuilder(true);
			// Force complete with no inputs/outputs
			builder.markComplete();
			builder.handlePeerComplete();
			expect(builder.isComplete()).to.be.true;
			// buildTransaction validates, so it returns null
			const tx = builder.buildTransaction();
			expect(tx).to.be.null;
		});

		it('should default locktime to 0', function () {
			const builder = new InteractiveTxBuilder(true);
			builder.addInput(makeInput(0n));
			builder.addOutput(makeOutput(0n));
			builder.markComplete();
			builder.handlePeerComplete();
			const tx = builder.buildTransaction();
			expect(tx!.locktime).to.equal(0);
		});
	});
});
