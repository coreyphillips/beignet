import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import {
	createPsbtCoinSigner,
	IPsbtCoinSignerOptions,
	IPsbtSigningContext
} from '../../src/direct-funding/psbt';
import { ownershipProbeTransaction } from '../../src/lightning/direct-funding/messages';
import { taprootTweakPrivateKey } from '../../src/lightning/wallet/wallet-funding-provider';
import { ITestCoin, makeCoin } from '../lightning/helpers/df-sender';

bitcoin.initEccLib(ecc);

async function refuses(
	promise: Promise<unknown>,
	message: string
): Promise<void> {
	try {
		await promise;
		expect.fail('expected signing to be refused');
	} catch (error) {
		expect((error as Error).message).to.include(message);
	}
}

function signWithCoin(
	psbt: bitcoin.Psbt,
	coin: ITestCoin,
	inputIndex: number,
	finalize = false,
	hashType = coin.kind === 'p2wpkh' ? 1 : 0
): string {
	const privkey =
		coin.kind === 'p2wpkh'
			? coin.privkey
			: taprootTweakPrivateKey(coin.privkey, coin.pubkey);
	if (coin.kind === 'p2tr' && !psbt.data.inputs[inputIndex].tapInternalKey) {
		psbt.updateInput(inputIndex, { tapInternalKey: coin.pubkey.subarray(1) });
	}
	psbt.data.inputs[inputIndex].sighashType = hashType;
	psbt.signInput(
		inputIndex,
		{
			publicKey: Buffer.from(ecc.pointFromScalar(privkey)!),
			sign: (digest) => Buffer.from(ecc.sign(digest, privkey)),
			signSchnorr: (digest) => Buffer.from(ecc.signSchnorr(digest, privkey))
		},
		[hashType]
	);
	if (finalize) psbt.finalizeInput(inputIndex);
	return psbt.toBase64();
}

function funding(coin: ITestCoin): {
	tx: bitcoin.Transaction;
	prevouts: { scripts: Buffer[]; values: bigint[] };
} {
	const other = makeCoin(50_000);
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 100;
	tx.addInput(Buffer.from(other.txidHex, 'hex').reverse(), 0, 0xfffffffd);
	tx.addInput(
		Buffer.from(coin.txidHex, 'hex').reverse(),
		coin.vout,
		0xfffffffd
	);
	tx.addOutput(Buffer.from('0014' + '22'.repeat(20), 'hex'), 120_000);
	tx.addOutput(Buffer.from('0014' + '33'.repeat(20), 'hex'), 129_000);
	return {
		tx,
		prevouts: {
			scripts: [other.script, coin.script],
			values: [other.valueSat, coin.valueSat]
		}
	};
}

function probe(coin: ITestCoin): ReturnType<typeof ownershipProbeTransaction> {
	return ownershipProbeTransaction(
		Buffer.alloc(16, 4),
		Buffer.from(coin.txidHex, 'hex'),
		coin.vout,
		0xfffffffd,
		coin.script,
		coin.valueSat,
		Buffer.alloc(32, 5),
		coin.pubkey
	);
}

function optionsFor(coin: ITestCoin, finalize = false): IPsbtCoinSignerOptions {
	return {
		getTransaction: async () => coin.prevTx.toBuffer(),
		signPsbt: async (encoded, { inputIndex }) =>
			signWithCoin(bitcoin.Psbt.fromBase64(encoded), coin, inputIndex, finalize)
	};
}

describe('Direct-funding PSBT signer', () => {
	for (const kind of ['p2wpkh', 'p2tr'] as const) {
		describe(kind, () => {
			for (const finalized of [false, true]) {
				it(`returns a verified ${
					finalized ? 'finalized' : 'partial'
				} ownership proof`, async () => {
					const coin = makeCoin(200_000, kind);
					const options = optionsFor(coin, finalized);
					const calls: IPsbtSigningContext[] = [];
					const signer = createPsbtCoinSigner(coin, {
						...options,
						signPsbt: async (encoded, context) => {
							calls.push(context);
							const psbt = bitcoin.Psbt.fromBase64(encoded);
							expect(psbt.data.inputs[0].nonWitnessUtxo).to.be.instanceOf(
								Buffer
							);
							expect(psbt.data.inputs[1].nonWitnessUtxo).to.equal(undefined);
							return options.signPsbt(encoded, context);
						}
					});
					const { tx, prevouts } = probe(coin);
					const proof = await signer.signOwnershipProbe!(tx, prevouts);
					expect(calls).to.deep.equal([
						{ inputIndex: 0, purpose: 'ownership' }
					]);
					expect(proof.signature).to.have.length(64);
					if (kind === 'p2wpkh') {
						expect(proof.pubkey.equals(coin.pubkey)).to.equal(true);
						const scriptCode = bitcoin.payments.p2pkh({ pubkey: coin.pubkey })
							.output!;
						const digest = tx.hashForWitnessV0(0, scriptCode, 200_000, 1);
						expect(
							ecc.verify(digest, proof.pubkey, proof.signature, true)
						).to.equal(true);
					} else {
						expect(proof.pubkey.equals(coin.script.subarray(2))).to.equal(true);
						const digest = tx.hashForWitnessV1(
							0,
							prevouts.scripts,
							[200_000, 0],
							0
						);
						expect(
							ecc.verifySchnorr(digest, proof.pubkey, proof.signature)
						).to.equal(true);
					}
				});

				it(`returns a verified ${
					finalized ? 'finalized' : 'partial'
				} funding witness for only the selected input`, async () => {
					const coin = makeCoin(200_000, kind);
					const options = optionsFor(coin, finalized);
					const signer = createPsbtCoinSigner(coin, {
						...options,
						signPsbt: async (encoded, context) => {
							expect(context).to.deep.equal({
								inputIndex: 1,
								purpose: 'funding'
							});
							return options.signPsbt(encoded, context);
						}
					});
					const { tx, prevouts } = funding(coin);
					const witness = await signer.signInput(tx, 1, prevouts);
					expect(witness).to.have.length(kind === 'p2wpkh' ? 2 : 1);
					expect(tx.ins[0].witness).to.deep.equal([]);
					expect(tx.ins[1].witness).to.deep.equal([]);
				});
			}

			it('rejects a valid signature over an altered funding transaction', async () => {
				const coin = makeCoin(200_000, kind);
				const signer = createPsbtCoinSigner(coin, {
					...optionsFor(coin),
					signPsbt: async (encoded, context) => {
						const psbt = bitcoin.Psbt.fromBase64(encoded);
						psbt.setLocktime(psbt.locktime + 1);
						return signWithCoin(psbt, coin, context.inputIndex);
					}
				});
				const { tx, prevouts } = funding(coin);
				await refuses(
					Promise.resolve(signer.signInput(tx, 1, prevouts)),
					'changed the unsigned transaction'
				);
			});

			it('rejects altered previous-output metadata even with a valid signature', async () => {
				const coin = makeCoin(200_000, kind);
				const signer = createPsbtCoinSigner(coin, {
					...optionsFor(coin),
					signPsbt: async (encoded, context) => {
						const psbt = bitcoin.Psbt.fromBase64(encoded);
						psbt.data.inputs[0].witnessUtxo!.value++;
						return signWithCoin(psbt, coin, context.inputIndex);
					}
				});
				const { tx, prevouts } = funding(coin);
				await refuses(
					Promise.resolve(signer.signInput(tx, 1, prevouts)),
					'changed a previous output'
				);
			});

			it('rejects signatures over a different transaction while preserving the original PSBT', async () => {
				const coin = makeCoin(200_000, kind);
				const signer = createPsbtCoinSigner(coin, {
					...optionsFor(coin),
					signPsbt: async (encoded, context) => {
						const psbt = bitcoin.Psbt.fromBase64(encoded);
						const changed = psbt.clone().setLocktime(0);
						const signed = bitcoin.Psbt.fromBase64(
							signWithCoin(changed, coin, context.inputIndex)
						);
						const signature = signed.data.inputs[context.inputIndex];
						psbt.updateInput(
							context.inputIndex,
							kind === 'p2wpkh'
								? { partialSig: signature.partialSig }
								: { tapKeySig: signature.tapKeySig }
						);
						return psbt.toBase64();
					}
				});
				const { tx, prevouts } = funding(coin);
				await refuses(
					Promise.resolve(signer.signInput(tx, 1, prevouts)),
					'invalid'
				);
			});

			it('rejects ANYONECANPAY even after finalization removes the sighash field', async () => {
				const coin = makeCoin(200_000, kind);
				const signer = createPsbtCoinSigner(coin, {
					...optionsFor(coin),
					signPsbt: async (encoded, context) =>
						signWithCoin(
							bitcoin.Psbt.fromBase64(encoded),
							coin,
							context.inputIndex,
							true,
							bitcoin.Transaction.SIGHASH_ALL |
								bitcoin.Transaction.SIGHASH_ANYONECANPAY
						)
				});
				const { tx, prevouts } = funding(coin);
				await refuses(
					Promise.resolve(signer.signInput(tx, 1, prevouts)),
					kind === 'p2wpkh' ? 'SIGHASH_ALL' : 'SIGHASH_DEFAULT'
				);
			});

			it('refuses a spendable transaction passed as an ownership probe before asking the wallet', async () => {
				const coin = makeCoin(200_000, kind);
				let called = false;
				const signer = createPsbtCoinSigner(coin, {
					...optionsFor(coin),
					signPsbt: async () => {
						called = true;
						throw new Error('must not sign');
					}
				});
				const { tx, prevouts } = probe(coin);
				tx.ins[1].hash = Buffer.alloc(32, 1);
				await refuses(
					Promise.resolve(signer.signOwnershipProbe!(tx, prevouts)),
					'ownership probe'
				);
				expect(called).to.equal(false);
			});
		});
	}

	it('allows derivation metadata but rejects decorator changes before the wallet signs', async () => {
		const coin = makeCoin();
		const { tx, prevouts } = funding(coin);
		let calls = 0;
		const base = optionsFor(coin);
		const options: IPsbtCoinSignerOptions = {
			...base,
			signPsbt: async (encoded, context) => {
				calls++;
				return base.signPsbt(encoded, context);
			},
			decoratePsbt: (psbt, { inputIndex }) => {
				psbt.updateInput(inputIndex, {
					bip32Derivation: [
						{
							pubkey: coin.pubkey,
							path: "m/84'/1'/0'/0/0",
							masterFingerprint: Buffer.alloc(4, 1)
						}
					]
				});
			}
		};
		await createPsbtCoinSigner(coin, options).signInput(tx, 1, prevouts);
		expect(calls).to.equal(1);
		const changed = createPsbtCoinSigner(coin, {
			...options,
			decoratePsbt: (psbt) => {
				psbt.setInputSequence(1, 0xffffffff);
			}
		});
		await refuses(
			Promise.resolve(changed.signInput(tx, 1, prevouts)),
			'changed the unsigned transaction'
		);
		expect(calls).to.equal(1);
	});

	it('checks the previous transaction against both the txid and the coin metadata', async () => {
		const coin = makeCoin();
		const { tx, prevouts } = funding(coin);
		let signed = false;
		const options: IPsbtCoinSignerOptions = {
			getTransaction: async () => makeCoin().prevTx.toBuffer(),
			signPsbt: async () => {
				signed = true;
				return '';
			}
		};
		await refuses(
			Promise.resolve(
				createPsbtCoinSigner(coin, options).signInput(tx, 1, prevouts)
			),
			'previous transaction'
		);
		expect(signed).to.equal(false);
		const wrongCoin = { ...coin, valueSat: coin.valueSat + 1n };
		prevouts.values[1] = wrongCoin.valueSat;
		await refuses(
			Promise.resolve(
				createPsbtCoinSigner(wrongCoin, optionsFor(coin)).signInput(
					tx,
					1,
					prevouts
				)
			),
			'previous transaction'
		);
	});

	it('rejects missing signatures and malformed finalized witnesses', async () => {
		const coin = makeCoin();
		const { tx, prevouts } = funding(coin);
		for (const trailing of [false, true]) {
			const signer = createPsbtCoinSigner(coin, {
				...optionsFor(coin),
				signPsbt: async (encoded, context) => {
					if (!trailing) return encoded;
					const signed = bitcoin.Psbt.fromBase64(
						signWithCoin(
							bitcoin.Psbt.fromBase64(encoded),
							coin,
							context.inputIndex,
							true
						)
					);
					const input = signed.data.inputs[context.inputIndex];
					input.finalScriptWitness = Buffer.concat([
						input.finalScriptWitness!,
						Buffer.from([0])
					]);
					return signed.toBase64();
				}
			});
			await refuses(
				Promise.resolve(signer.signInput(tx, 1, prevouts)),
				trailing ? 'trailing bytes' : 'did not return'
			);
		}
	});

	it('rejects unsupported scripts and duplicate or wrong target inputs', async () => {
		const coin = makeCoin();
		expect(() =>
			createPsbtCoinSigner(
				{ ...coin, script: Buffer.from([0x51]) },
				optionsFor(coin)
			)
		).to.throw('P2WPKH or P2TR');
		const signer = createPsbtCoinSigner(coin, optionsFor(coin));
		const { tx, prevouts } = funding(coin);
		await refuses(
			Promise.resolve(signer.signInput(tx, 0, prevouts)),
			'selected coin'
		);
		tx.addInput(Buffer.from(coin.txidHex, 'hex').reverse(), 0);
		prevouts.scripts.push(coin.script);
		prevouts.values.push(coin.valueSat);
		await refuses(
			Promise.resolve(signer.signInput(tx, 1, prevouts)),
			'selected coin'
		);
	});

	it('snapshots caller inputs before awaiting external wallet operations', async () => {
		const coin = makeCoin();
		const { tx, prevouts } = funding(coin);
		const original = bitcoin.Transaction.fromBuffer(tx.toBuffer());
		const originalPubkey = Buffer.from(coin.pubkey);
		const signer = createPsbtCoinSigner(coin, {
			...optionsFor(coin),
			getTransaction: async () => {
				tx.locktime++;
				tx.outs[0].script.fill(0);
				prevouts.values[1]++;
				return coin.prevTx.toBuffer();
			}
		});
		const witness = await signer.signInput(tx, 1, prevouts);
		const sig = bitcoin.script.signature.decode(witness[0]);
		const scriptCode = bitcoin.payments.p2pkh({ pubkey: originalPubkey })
			.output!;
		const digest = original.hashForWitnessV0(1, scriptCode, 200_000, 1);
		expect(ecc.verify(digest, originalPubkey, sig.signature, true)).to.equal(
			true
		);
	});
});
