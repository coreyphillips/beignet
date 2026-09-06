import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import crypto from 'crypto';
import vector from './fixtures/swaps/p2wsh.json';
import { getPublicKey, sign, verify } from '../../src/lightning/crypto/ecdh';
import {
	buildSwapHtlc,
	buildSwapClaimTx,
	buildSwapRefundTx,
	extractSwapPreimage,
	ISwapHtlc,
	ISwapSpend,
	IReverseSwapAdmission,
	validateReverseSwapAdmission,
	validateSubmarineSwapAdmission
} from '../../src/lightning/swaps';

const claimKey = Buffer.alloc(32, 1);
const refundKey = Buffer.alloc(32, 2);
const preimage = Buffer.alloc(32, 3);
const destination = bitcoin.payments.p2wpkh({ pubkey: getPublicKey(claimKey) })
	.output!;

function contract(): ISwapHtlc {
	return {
		paymentHash: bitcoin.crypto.sha256(preimage),
		claimPublicKey: getPublicKey(claimKey),
		refundPublicKey: getPublicKey(refundKey),
		refundHeight: 800_000
	};
}

function funding(htlc = contract()): ISwapSpend {
	const fundingTransaction = new bitcoin.Transaction();
	fundingTransaction.version = 2;
	fundingTransaction.addInput(Buffer.alloc(32, 4), 1);
	fundingTransaction.addOutput(buildSwapHtlc(htlc).outputScript, 100_000);
	return {
		htlc,
		fundingTransaction,
		outputIndex: 0,
		destinationScript: destination,
		feeSatoshis: 1000n,
		privateKey: claimKey
	};
}

function reverse(): IReverseSwapAdmission {
	const paymentHash = bitcoin.crypto.sha256(preimage);
	return {
		currentHeight: 100,
		refundHeight: 150,
		paymentHash,
		expectedAmountMsat: 100_000_000n,
		committedHtlcs: [
			{
				id: 'channel-a:0',
				paymentHash,
				amountMsat: 40_000_000n,
				cltvExpiry: 250
			},
			{
				id: 'channel-b:0',
				paymentHash,
				amountMsat: 60_000_000n,
				cltvExpiry: 240
			}
		],
		fundingSafetyBlocks: 12,
		resolutionSafetyBlocks: 36,
		holdCancelSafetyBlocks: 18
	};
}

describe('P2WSH swap foundations', () => {
	it('is exported through the public Lightning namespace', async function () {
		this.timeout(20_000);
		const { swaps } = await import('../../src/lightning');
		expect(swaps.buildSwapHtlc).to.equal(buildSwapHtlc);
	});

	it('matches fixed signed transactions and independently serialized BIP143 digests', () => {
		const params = funding();
		const output = buildSwapHtlc(params.htlc, bitcoin.networks.regtest);
		expect(output.witnessScript.toString('hex')).to.equal(vector.witnessScript);
		expect(output.outputScript.toString('hex')).to.equal(vector.outputScript);
		expect(output.address).to.equal(vector.regtestAddress);
		expect(params.fundingTransaction.toHex()).to.equal(
			vector.fundingTransaction
		);
		const claim = buildSwapClaimTx({ ...params, preimage });
		const refund = buildSwapRefundTx({ ...params, privateKey: refundKey });
		expect(claim.toHex()).to.equal(vector.claimTransaction);
		expect(refund.toHex()).to.equal(vector.refundTransaction);
		const hash256 = (bytes: Buffer): Buffer =>
			crypto
				.createHash('sha256')
				.update(crypto.createHash('sha256').update(bytes).digest())
				.digest();
		const uint32 = (value: number): Buffer => {
			const bytes = Buffer.alloc(4);
			bytes.writeUInt32LE(value);
			return bytes;
		};
		const uint64 = (value: number): Buffer => {
			const bytes = Buffer.alloc(8);
			bytes.writeBigUInt64LE(BigInt(value));
			return bytes;
		};
		const outpoint = Buffer.concat([
			Buffer.from(params.fundingTransaction.getId(), 'hex').reverse(),
			uint32(0)
		]);
		const scriptCode = Buffer.from(vector.witnessScript, 'hex');
		const outputBytes = Buffer.concat([
			uint64(99_000),
			Buffer.from([destination.length]),
			destination
		]);
		for (const [tx, expectedHash] of [
			[claim, vector.claimSighash],
			[refund, vector.refundSighash]
		] as const) {
			const serialization = Buffer.concat([
				uint32(2),
				hash256(outpoint),
				hash256(uint32(0xfffffffd)),
				outpoint,
				Buffer.from([scriptCode.length]),
				scriptCode,
				uint64(100_000),
				uint32(0xfffffffd),
				hash256(outputBytes),
				uint32(tx.locktime),
				uint32(1)
			]);
			expect(hash256(serialization).toString('hex')).to.equal(expectedHash);
			expect(
				tx.hashForWitnessV0(0, scriptCode, 100_000, 1).toString('hex')
			).to.equal(expectedHash);
		}
	});

	it('constructs the independently specified script and network address', () => {
		const htlc = contract();
		// IF SIZE PUSH(32) EQUALVERIFY SHA256 PUSH(hash) EQUALVERIFY PUSH(key)
		// CHECKSIG ELSE PUSH(height, LE signed-magnitude) CLTV DROP PUSH(key) CHECKSIG ENDIF.
		const expected = Buffer.from(
			`6382012088a820${htlc.paymentHash.toString(
				'hex'
			)}8821${htlc.claimPublicKey.toString(
				'hex'
			)}ac670300350cb17521${htlc.refundPublicKey.toString('hex')}ac68`,
			'hex'
		);
		const output = buildSwapHtlc(htlc, bitcoin.networks.regtest);
		expect(output.witnessScript.equals(expected)).to.be.true;
		expect(
			output.outputScript.equals(
				Buffer.concat([
					Buffer.from('0020', 'hex'),
					bitcoin.crypto.sha256(expected)
				])
			)
		).to.be.true;
		expect(output.address).to.match(/^bcrt1/);
		expect(buildSwapHtlc(htlc).address).to.match(/^bc1/);
	});

	for (const length of [0, 20, 31, 33, 64]) {
		it(`rejects a ${length}-byte payment hash`, () => {
			expect(() =>
				buildSwapHtlc({ ...contract(), paymentHash: Buffer.alloc(length) })
			).to.throw('Payment hash');
		});
	}
	for (const height of [-1, 0, 1.5, NaN, Infinity, 500_000_000, 0xffffffff]) {
		it(`rejects invalid block CLTV ${height}`, () => {
			expect(() =>
				buildSwapHtlc({ ...contract(), refundHeight: height })
			).to.throw('block height');
		});
	}
	for (const role of ['claimPublicKey', 'refundPublicKey'] as const) {
		for (const invalidKey of [
			Buffer.alloc(32),
			Buffer.alloc(33),
			Buffer.alloc(65),
			Buffer.from(`02${'ff'.repeat(32)}`, 'hex')
		]) {
			it(`rejects invalid ${role} ${invalidKey.toString('hex').slice(0, 8)}/${
				invalidKey.length
			}`, () => {
				expect(() =>
					buildSwapHtlc({ ...contract(), [role]: invalidKey })
				).to.throw('compressed public key');
			});
		}
	}

	it('signs both branches with amount-bound SIGHASH_ALL and non-final sequence', () => {
		const params = funding();
		const claim = buildSwapClaimTx({ ...params, preimage });
		const refund = buildSwapRefundTx({ ...params, privateKey: refundKey });
		for (const [tx, pubkey] of [
			[claim, params.htlc.claimPublicKey],
			[refund, params.htlc.refundPublicKey]
		] as const) {
			expect(tx.version).to.equal(2);
			expect(tx.ins[0].sequence).to.equal(0xfffffffd);
			expect(tx.outs[0].value).to.equal(99_000);
			const { signature, hashType } = bitcoin.script.signature.decode(
				tx.ins[0].witness[0]
			);
			expect(hashType).to.equal(bitcoin.Transaction.SIGHASH_ALL);
			const script = buildSwapHtlc(params.htlc).witnessScript;
			expect(
				verify(
					tx.hashForWitnessV0(0, script, 100_000, hashType),
					pubkey,
					signature,
					true
				)
			).to.be.true;
			expect(
				verify(
					tx.hashForWitnessV0(0, script, 100_001, hashType),
					pubkey,
					signature,
					true
				)
			).to.be.false;
		}
		expect(claim.locktime).to.equal(0);
		expect(refund.locktime).to.equal(params.htlc.refundHeight);
		expect(refund.ins[0].witness).to.have.length(3);
		expect(refund.ins[0].witness[1].length).to.equal(0);
		expect(extractSwapPreimage(claim, params)?.equals(preimage)).to.be.true;
		expect(extractSwapPreimage(refund, params)).to.equal(undefined);
	});

	for (const length of [0, 31, 33, 64]) {
		it(`rejects ${length}-byte preimages even when their hash matches`, () => {
			const invalid = Buffer.alloc(length, 3);
			const params = funding({
				...contract(),
				paymentHash: bitcoin.crypto.sha256(invalid)
			});
			expect(() => buildSwapClaimTx({ ...params, preimage: invalid })).to.throw(
				'32 bytes'
			);
		});
	}
	it('rejects a wrong preimage and wrong-branch private keys', () => {
		const params = funding();
		expect(() =>
			buildSwapClaimTx({ ...params, preimage: Buffer.alloc(32) })
		).to.throw('payment hash');
		expect(() =>
			buildSwapClaimTx({ ...params, preimage, privateKey: refundKey })
		).to.throw('selected swap branch');
		expect(() => buildSwapRefundTx(params)).to.throw('selected swap branch');
		for (const privateKey of [
			Buffer.alloc(31),
			Buffer.alloc(32),
			Buffer.alloc(32, 255)
		]) {
			expect(() =>
				buildSwapClaimTx({ ...params, preimage, privateKey })
			).to.throw('valid 32-byte scalar');
		}
	});

	it('validates funding script, index, amounts, fees and destinations before signing', () => {
		for (const outputIndex of [-1, 0.5, 1, NaN]) {
			expect(() =>
				buildSwapClaimTx({ ...funding(), outputIndex, preimage })
			).to.throw('output index');
		}
		const wrongScript = funding();
		wrongScript.fundingTransaction.outs[0].script = destination;
		expect(() => buildSwapClaimTx({ ...wrongScript, preimage })).to.throw(
			'does not match'
		);
		for (const value of [
			0,
			-1,
			0.5,
			NaN,
			Number.MAX_SAFE_INTEGER,
			2_100_000_000_000_001
		]) {
			const params = funding();
			params.fundingTransaction.outs[0].value = value;
			expect(() => buildSwapClaimTx({ ...params, preimage })).to.throw();
		}
		for (const feeSatoshis of [
			-1n,
			0n,
			100_000n,
			100_001n,
			99_707n,
			2_100_000_000_000_001n
		]) {
			expect(() =>
				buildSwapClaimTx({ ...funding(), feeSatoshis, preimage })
			).to.throw();
		}
		for (const destinationScript of [
			Buffer.alloc(0),
			Buffer.from([bitcoin.opcodes.OP_RETURN]),
			bitcoin.payments.p2pkh({ pubkey: getPublicKey(claimKey) }).output!
		]) {
			expect(() =>
				buildSwapClaimTx({ ...funding(), destinationScript, preimage })
			).to.throw('Destination');
		}
		expect(
			buildSwapClaimTx({ ...funding(), feeSatoshis: 99_706n, preimage }).outs[0]
				.value
		).to.equal(294);
		for (const prefix of [0, bitcoin.opcodes.OP_1]) {
			const destinationScript = Buffer.concat([
				Buffer.from([prefix, 32]),
				Buffer.alloc(32, 6)
			]);
			expect(
				buildSwapClaimTx({
					...funding(),
					destinationScript,
					feeSatoshis: 99_670n,
					preimage
				}).outs[0].value
			).to.equal(330);
			expect(() =>
				buildSwapClaimTx({
					...funding(),
					destinationScript,
					feeSatoshis: 99_671n,
					preimage
				})
			).to.throw('dust');
		}
	});

	const mutations: Array<[string, (tx: bitcoin.Transaction) => void]> = [
		[
			'wrong prevout',
			(tx): void => {
				tx.ins[0].hash[0] ^= 1;
			}
		],
		[
			'wrong output index',
			(tx): void => {
				tx.ins[0].index = 1;
			}
		],
		[
			'nonempty scriptSig',
			(tx): void => {
				tx.ins[0].script = Buffer.from([0]);
			}
		],
		[
			'wrong preimage',
			(tx): void => {
				tx.ins[0].witness[1] = Buffer.alloc(32);
			}
		],
		[
			'short preimage',
			(tx): void => {
				tx.ins[0].witness[1] = Buffer.alloc(31);
			}
		],
		[
			'non-minimal true',
			(tx): void => {
				tx.ins[0].witness[2] = Buffer.from([2]);
			}
		],
		[
			'false branch',
			(tx): void => {
				tx.ins[0].witness[2] = Buffer.alloc(0);
			}
		],
		[
			'wrong witness script',
			(tx): void => {
				tx.ins[0].witness[3][1] ^= 1;
			}
		],
		[
			'extra stack item',
			(tx): void => {
				tx.ins[0].witness.unshift(Buffer.alloc(0));
			}
		],
		[
			'missing signature',
			(tx): void => {
				tx.ins[0].witness[0] = Buffer.alloc(0);
			}
		],
		[
			'malformed signature',
			(tx): void => {
				tx.ins[0].witness[0] = Buffer.alloc(72, 255);
			}
		],
		[
			'wrong sighash',
			(tx): void => {
				const sig = tx.ins[0].witness[0];
				sig[sig.length - 1] = 2;
			}
		],
		[
			'changed destination',
			(tx): void => {
				tx.outs[0].script[3] ^= 1;
			}
		],
		[
			'changed fee',
			(tx): void => {
				tx.outs[0].value--;
			}
		],
		[
			'changed locktime',
			(tx): void => {
				tx.locktime = 1;
			}
		],
		[
			'changed sequence',
			(tx): void => {
				tx.ins[0].sequence--;
			}
		],
		[
			'duplicate expected input',
			(tx): void => {
				tx.ins.push(tx.ins[0]);
			}
		]
	];
	for (const [label, mutate] of mutations) {
		it(`does not extract a preimage from a claim with ${label}`, () => {
			const params = funding();
			const tx = buildSwapClaimTx({ ...params, preimage });
			mutate(tx);
			expect(extractSwapPreimage(tx, params)).to.equal(undefined);
		});
	}

	it('extracts the expected input at a nonzero index and returns a copy', () => {
		const params = funding();
		const tx = buildSwapClaimTx({ ...params, preimage });
		tx.ins.unshift({
			hash: Buffer.alloc(32, 9),
			index: 0,
			script: Buffer.alloc(0),
			sequence: 0xffffffff,
			witness: []
		});
		const script = buildSwapHtlc(params.htlc).witnessScript;
		tx.ins[1].witness[0] = bitcoin.script.signature.encode(
			sign(tx.hashForWitnessV0(1, script, 100_000, 1), claimKey),
			1
		);
		const extracted = extractSwapPreimage(tx, params)!;
		expect(extracted.equals(preimage)).to.be.true;
		extracted[0] ^= 1;
		expect(tx.ins[1].witness[1].equals(preimage)).to.be.true;
	});

	for (const hashType of [
		bitcoin.Transaction.SIGHASH_ALL,
		bitcoin.Transaction.SIGHASH_NONE,
		bitcoin.Transaction.SIGHASH_SINGLE,
		bitcoin.Transaction.SIGHASH_ALL | bitcoin.Transaction.SIGHASH_ANYONECANPAY,
		bitcoin.Transaction.SIGHASH_NONE | bitcoin.Transaction.SIGHASH_ANYONECANPAY,
		bitcoin.Transaction.SIGHASH_SINGLE |
			bitcoin.Transaction.SIGHASH_ANYONECANPAY
	]) {
		it(`extracts a claim signed with defined sighash type ${hashType}`, () => {
			const params = funding();
			const tx = buildSwapClaimTx({ ...params, preimage });
			const script = buildSwapHtlc(params.htlc).witnessScript;
			tx.ins[0].witness[0] = bitcoin.script.signature.encode(
				sign(tx.hashForWitnessV0(0, script, 100_000, hashType), claimKey),
				hashType
			);
			expect(extractSwapPreimage(tx, params)?.equals(preimage)).to.be.true;
		});
	}
});

describe('Direction-specific swap admission', () => {
	const submarine = {
		currentHeight: 100,
		refundHeight: 250,
		latestOutgoingHtlcExpiry: 200,
		claimSafetyBlocks: 36,
		fundingConfirmations: 3,
		minimumFundingConfirmations: 2
	};
	it('requires the submarine refund to outlive every outgoing expiry and margin', () => {
		expect(() => validateSubmarineSwapAdmission(submarine)).not.to.throw();
		for (const refundHeight of [199, 200, 220, 236]) {
			expect(() =>
				validateSubmarineSwapAdmission({ ...submarine, refundHeight })
			).to.throw('must outlive');
		}
		expect(() =>
			validateSubmarineSwapAdmission({ ...submarine, refundHeight: 237 })
		).not.to.throw();
		expect(() =>
			validateSubmarineSwapAdmission({ ...submarine, fundingConfirmations: 1 })
		).to.throw('insufficient confirmations');
		expect(() =>
			validateSubmarineSwapAdmission({
				...submarine,
				latestOutgoingHtlcExpiry: 100
			})
		).to.throw('future');
	});

	it('uses the earliest committed reverse HTLC and actual early cancellation margin', () => {
		expect(validateReverseSwapAdmission(reverse())).to.equal(222);
		const params = reverse();
		params.refundHeight = 220; // The unsafe common inequality from the original proposal.
		params.committedHtlcs = [
			{
				...params.committedHtlcs[0],
				amountMsat: params.expectedAmountMsat,
				cltvExpiry: 200
			}
		];
		expect(() => validateReverseSwapAdmission(params)).to.throw('must outlive');
		params.refundHeight = 145; // 200 - 18 = 182, and 145 + 36 = 181.
		expect(validateReverseSwapAdmission(params)).to.equal(182);
		params.refundHeight = 146; // Equality is refused, leaving a full-block boundary.
		expect(() => validateReverseSwapAdmission(params)).to.throw('must outlive');
	});

	it('refuses incomplete, duplicate, overfunded and unrelated committed MPP parts', () => {
		const params = reverse();
		for (const committedHtlcs of [
			[],
			[params.committedHtlcs[0]],
			[params.committedHtlcs[0], params.committedHtlcs[0]],
			[
				...params.committedHtlcs,
				{ ...params.committedHtlcs[0], id: 'channel-c:0' }
			]
		]) {
			expect(() =>
				validateReverseSwapAdmission({ ...params, committedHtlcs })
			).to.throw();
		}
		for (const replacement of [
			{ paymentHash: Buffer.alloc(32) },
			{ amountMsat: 0n },
			{ amountMsat: -1n },
			{ amountMsat: params.expectedAmountMsat + 1n },
			{ id: '' },
			{ cltvExpiry: 100 },
			{ cltvExpiry: 500_000_000 }
		]) {
			expect(() =>
				validateReverseSwapAdmission({
					...params,
					committedHtlcs: [
						{ ...params.committedHtlcs[0], ...replacement },
						params.committedHtlcs[1]
					]
				})
			).to.throw();
		}
	});

	it('refuses expired quotes and invalid amounts, heights, margins and confirmations', () => {
		for (const property of [
			'currentHeight',
			'refundHeight',
			'latestOutgoingHtlcExpiry',
			'claimSafetyBlocks',
			'minimumFundingConfirmations'
		] as const) {
			for (const invalid of [-1, 0, 1.2, NaN, Infinity, 500_000_000]) {
				expect(() =>
					validateSubmarineSwapAdmission({ ...submarine, [property]: invalid })
				).to.throw();
			}
		}
		for (const property of [
			'currentHeight',
			'refundHeight',
			'fundingSafetyBlocks',
			'resolutionSafetyBlocks'
		] as const) {
			for (const invalid of [-1, 0, 1.2, NaN, Infinity, 500_000_000]) {
				expect(() =>
					validateReverseSwapAdmission({ ...reverse(), [property]: invalid })
				).to.throw();
			}
		}
		for (const expectedAmountMsat of [0n, -1n, 2_100_000_000_000_000_001n]) {
			expect(() =>
				validateReverseSwapAdmission({ ...reverse(), expectedAmountMsat })
			).to.throw('Expected amount');
		}
		expect(() =>
			validateReverseSwapAdmission({ ...reverse(), refundHeight: 112 })
		).to.throw('insufficient funding');
		expect(() =>
			validateReverseSwapAdmission({ ...reverse(), holdCancelSafetyBlocks: -1 })
		).to.throw('Hold cancellation');
		expect(() =>
			validateReverseSwapAdmission({
				...reverse(),
				paymentHash: Buffer.alloc(31)
			})
		).to.throw('Payment hash');
	});
});
