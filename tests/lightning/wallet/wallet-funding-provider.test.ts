import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	WalletFundingProvider,
	IWalletLike
} from '../../../src/lightning/wallet/wallet-funding-provider';

bitcoin.initEccLib(ecc);

// ─────────────── Helpers ───────────────

/**
 * Build a fake funding transaction that pays to a given P2WSH address.
 * Returns the raw hex and the expected txid + output index.
 */
function buildFakeFundingTx(
	address: string,
	amountSats: number,
	network: bitcoin.Network
): { txHex: string; txid: Buffer; outputIndex: number } {
	const tx = new bitcoin.Transaction();
	// Dummy input
	tx.addInput(Buffer.alloc(32, 0xaa), 0);

	// Output 0: change output (P2WPKH-style with random hash)
	const changeScript = bitcoin.script.compile([
		bitcoin.opcodes.OP_0,
		crypto.randomBytes(20)
	]);
	tx.addOutput(changeScript, 50_000);

	// Output 1: the funding output
	const fundingScript = bitcoin.address.toOutputScript(address, network);
	tx.addOutput(fundingScript, amountSats);

	const txHex = tx.toHex();
	const txid = Buffer.from(tx.getHash());

	return { txHex, txid, outputIndex: 1 };
}

function mockOk(value: string): {
	isErr(): boolean;
	isOk(): boolean;
	value: string;
} {
	return { isErr: () => false, isOk: () => true, value };
}

function mockErr(message: string): {
	isErr(): boolean;
	isOk(): boolean;
	error: { message: string };
} {
	return { isErr: () => true, isOk: () => false, error: { message } };
}

function createMockWallet(
	sendResult: { txHex: string } | { error: string }
): IWalletLike {
	return {
		send: async () => {
			if ('error' in sendResult) {
				return mockErr(sendResult.error);
			}
			return mockOk(sendResult.txHex);
		},
		electrum: {
			broadcastTransaction: async () => {
				return mockOk('mock-txid-hex');
			}
		}
	};
}

// ─────────────── Tests ───────────────

describe('WalletFundingProvider', () => {
	const network = bitcoin.networks.regtest;

	// Create a real P2WSH address for testing
	const pk1 = Buffer.alloc(33, 0x02);
	pk1[32] = 0x01;
	const pk2 = Buffer.alloc(33, 0x03);
	pk2[32] = 0x01;
	const witnessScript = bitcoin.script.compile([
		bitcoin.opcodes.OP_2,
		pk1,
		pk2,
		bitcoin.opcodes.OP_2,
		bitcoin.opcodes.OP_CHECKMULTISIG
	]);
	const p2wsh = bitcoin.payments.p2wsh({
		redeem: { output: witnessScript },
		network
	});
	const fundingAddress = p2wsh.address!;

	describe('buildFundingTransaction', () => {
		it('should parse tx hex and find the funding output', async () => {
			const {
				txHex,
				txid: expectedTxid,
				outputIndex: expectedIdx
			} = buildFakeFundingTx(fundingAddress, 100_000, network);

			const wallet = createMockWallet({ txHex });
			const provider = new WalletFundingProvider(wallet);

			const result = await provider.buildFundingTransaction(
				fundingAddress,
				100_000n
			);

			expect(result.txHex).to.equal(txHex);
			expect(result.txid.equals(expectedTxid)).to.be.true;
			expect(result.outputIndex).to.equal(expectedIdx);
		});

		it('should pass satsPerByte to wallet.send when provided', async () => {
			const { txHex } = buildFakeFundingTx(fundingAddress, 50_000, network);

			let capturedSatsPerByte: number | undefined;
			const wallet: IWalletLike = {
				send: async (params) => {
					capturedSatsPerByte = params.satsPerByte;
					return mockOk(txHex);
				},
				electrum: {
					broadcastTransaction: async () => mockOk('')
				}
			};

			const provider = new WalletFundingProvider(wallet);
			await provider.buildFundingTransaction(fundingAddress, 50_000n, 5);

			expect(capturedSatsPerByte).to.equal(5);
		});

		it('should send with broadcast=false and shuffleOutputs=true', async () => {
			const { txHex } = buildFakeFundingTx(fundingAddress, 50_000, network);

			let capturedBroadcast: boolean | undefined;
			let capturedShuffle: boolean | undefined;
			const wallet: IWalletLike = {
				send: async (params) => {
					capturedBroadcast = params.broadcast;
					capturedShuffle = params.shuffleOutputs;
					return mockOk(txHex);
				},
				electrum: {
					broadcastTransaction: async () => mockOk('')
				}
			};

			const provider = new WalletFundingProvider(wallet);
			await provider.buildFundingTransaction(fundingAddress, 50_000n);

			expect(capturedBroadcast).to.equal(false);
			expect(capturedShuffle).to.equal(true);
		});

		it('should throw when wallet send fails', async () => {
			const wallet = createMockWallet({ error: 'Insufficient funds' });
			const provider = new WalletFundingProvider(wallet);

			try {
				await provider.buildFundingTransaction(fundingAddress, 100_000n);
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.include('Insufficient funds');
			}
		});

		it('should throw when funding output not found in tx', async () => {
			// Build a tx that doesn't contain the funding address
			const tx = new bitcoin.Transaction();
			tx.addInput(Buffer.alloc(32, 0xaa), 0);
			tx.addOutput(Buffer.alloc(22, 0x00), 50_000); // dummy output
			const txHex = tx.toHex();

			const wallet = createMockWallet({ txHex });
			const provider = new WalletFundingProvider(wallet);

			try {
				await provider.buildFundingTransaction(fundingAddress, 100_000n);
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.include('Funding output not found');
			}
		});

		it('should return txid in internal byte order', async () => {
			const { txHex } = buildFakeFundingTx(fundingAddress, 100_000, network);
			const wallet = createMockWallet({ txHex });
			const provider = new WalletFundingProvider(wallet);

			const result = await provider.buildFundingTransaction(
				fundingAddress,
				100_000n
			);

			// Verify txid matches bitcoin.Transaction.getHash() (internal byte order)
			const tx = bitcoin.Transaction.fromHex(txHex);
			expect(result.txid.equals(Buffer.from(tx.getHash()))).to.be.true;
		});

		it('sweeps via sendMax (not send) when max is set', async () => {
			const { txHex } = buildFakeFundingTx(fundingAddress, 100_000, network);
			let sendCalled = false;
			let sendMaxCalled = false;
			let capturedRate: number | undefined;
			let capturedBroadcast: boolean | undefined;
			const wallet: IWalletLike = {
				send: async () => {
					sendCalled = true;
					return mockOk(txHex);
				},
				sendMax: async (p) => {
					sendMaxCalled = true;
					capturedRate = p.satsPerByte;
					capturedBroadcast = p.broadcast;
					return mockOk(txHex);
				},
				electrum: { broadcastTransaction: async () => mockOk('') }
			};
			const provider = new WalletFundingProvider(wallet);

			const res = await provider.buildFundingTransaction(
				fundingAddress,
				100_000n,
				7,
				true
			);
			expect(sendMaxCalled, 'used sendMax').to.be.true;
			expect(sendCalled, 'did not use fixed send').to.be.false;
			expect(capturedRate).to.equal(7);
			expect(capturedBroadcast).to.equal(false);
			expect(res.outputIndex).to.equal(1);
		});

		it('still uses fixed send when max is not set', async () => {
			const { txHex } = buildFakeFundingTx(fundingAddress, 100_000, network);
			let sendCalled = false;
			let sendMaxCalled = false;
			const wallet: IWalletLike = {
				send: async () => {
					sendCalled = true;
					return mockOk(txHex);
				},
				sendMax: async () => {
					sendMaxCalled = true;
					return mockOk(txHex);
				},
				electrum: { broadcastTransaction: async () => mockOk('') }
			};
			const provider = new WalletFundingProvider(wallet);

			await provider.buildFundingTransaction(fundingAddress, 100_000n);
			expect(sendCalled).to.be.true;
			expect(sendMaxCalled).to.be.false;
		});

		it('throws when the swept output does not match the committed amount', async () => {
			// The sweep produced 90k but the caller committed 100k as funding_satoshis
			// (balance changed between quote and funding): signing the commitment
			// against a mismatched output would break the channel, so it must fail.
			const { txHex } = buildFakeFundingTx(fundingAddress, 90_000, network);
			const wallet: IWalletLike = {
				send: async () => mockOk(txHex),
				sendMax: async () => mockOk(txHex),
				electrum: { broadcastTransaction: async () => mockOk('') }
			};
			const provider = new WalletFundingProvider(wallet);

			try {
				await provider.buildFundingTransaction(
					fundingAddress,
					100_000n,
					undefined,
					true
				);
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.include(
					'does not match committed funding amount'
				);
			}
		});

		it('throws when max funding is requested but the wallet cannot sweep', async () => {
			const wallet = createMockWallet({ txHex: '' }); // legacy mock, no sendMax
			const provider = new WalletFundingProvider(wallet);

			try {
				await provider.buildFundingTransaction(
					fundingAddress,
					100_000n,
					undefined,
					true
				);
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.include(
					'does not support max funding'
				);
			}
		});
	});

	describe('broadcastTransaction', () => {
		it('should broadcast via electrum and return txid', async () => {
			const wallet = createMockWallet({ txHex: '' });
			const provider = new WalletFundingProvider(wallet);

			const txid = await provider.broadcastTransaction('deadbeef');
			expect(txid).to.equal('mock-txid-hex');
		});

		it('should pass rawTx to electrum.broadcastTransaction', async () => {
			let capturedRawTx = '';
			const wallet: IWalletLike = {
				send: async () => mockOk(''),
				electrum: {
					broadcastTransaction: async (params) => {
						capturedRawTx = params.rawTx;
						return mockOk('txid123');
					}
				}
			};

			const provider = new WalletFundingProvider(wallet);
			await provider.broadcastTransaction('aabbccdd');

			expect(capturedRawTx).to.equal('aabbccdd');
		});

		it('should throw when broadcast fails', async () => {
			const wallet: IWalletLike = {
				send: async () => mockOk(''),
				electrum: {
					broadcastTransaction: async () => mockErr('Network error')
				}
			};

			const provider = new WalletFundingProvider(wallet);

			try {
				await provider.broadcastTransaction('deadbeef');
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.include('Network error');
			}
		});
	});

	describe('selectSpliceInputs', () => {
		const { ECPairFactory } = require('ecpair');
		const ECPair = ECPairFactory(ecc);

		interface IMockUtxoSetup {
			utxos: Array<{ valueSats: number; height?: number; nonP2wpkh?: boolean }>;
		}

		function createSpliceMockWallet(setup: IMockUtxoSetup): {
			wallet: IWalletLike;
			changeAddress: string;
		} {
			const wifByPath = new Map<string, string>();
			const txByHash = new Map<string, { txid: string; hex: string }>();
			const utxos: any[] = [];

			setup.utxos.forEach((u, i) => {
				const priv = crypto
					.createHash('sha256')
					.update(`splice-utxo-${i}`)
					.digest();
				const keyPair = ECPair.fromPrivateKey(priv, { network });
				const pubkey = Buffer.from(keyPair.publicKey);
				const path = `m/84'/0'/0'/0/${i}`;
				wifByPath.set(path, keyPair.toWIF());

				const script = u.nonP2wpkh
					? bitcoin.payments.p2wsh({
							redeem: {
								output: bitcoin.script.compile([bitcoin.opcodes.OP_1])
							},
							network
					  }).output!
					: bitcoin.payments.p2wpkh({ pubkey, network }).output!;
				const address = bitcoin.address.fromOutputScript(script, network);

				const prevTx = new bitcoin.Transaction();
				prevTx.version = 2;
				prevTx.addInput(crypto.randomBytes(32), 0);
				prevTx.addOutput(script, u.valueSats);
				const txidDisplay = Buffer.from(prevTx.getHash())
					.reverse()
					.toString('hex');
				txByHash.set(txidDisplay, { txid: txidDisplay, hex: prevTx.toHex() });

				utxos.push({
					address,
					path,
					tx_hash: txidDisplay,
					tx_pos: 0,
					value: u.valueSats,
					height: u.height ?? 100,
					publicKey: pubkey.toString('hex')
				});
			});

			const changePriv = crypto
				.createHash('sha256')
				.update('splice-change')
				.digest();
			const changeKey = ECPair.fromPrivateKey(changePriv, { network });
			const changeAddress = bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(changeKey.publicKey),
				network
			}).address!;

			const wallet: IWalletLike = {
				send: async () => mockOk(''),
				electrum: {
					broadcastTransaction: async () => mockOk(''),
					getTransactions: async ({ txHashes }) =>
						({
							isErr: () => false,
							isOk: () => true,
							value: {
								data: txHashes.map((h) => ({
									data: { tx_hash: h.tx_hash },
									result: txByHash.get(h.tx_hash) ?? {}
								}))
							}
						}) as any
				},
				listUtxos: () => utxos,
				getPrivateKey: (path: string) => wifByPath.get(path)!,
				getChangeAddress: async () =>
					({
						isErr: () => false,
						isOk: () => true,
						value: { address: changeAddress }
					}) as any,
				network: 'regtest'
			};

			return { wallet, changeAddress };
		}

		it('selects a single UTXO covering amount + fee and builds verifiable witnesses', async () => {
			const { wallet, changeAddress } = createSpliceMockWallet({
				utxos: [{ valueSats: 500_000 }]
			});
			const provider = new WalletFundingProvider(wallet);

			const { inputs, changeScript } = await provider.selectSpliceInputs(
				300_000n,
				253
			);
			expect(inputs.length).to.equal(1);
			expect(inputs[0].value).to.equal(500_000n);
			expect(inputs[0].sequence).to.equal(0xfffffffd);
			expect(
				changeScript.equals(
					bitcoin.address.toOutputScript(changeAddress, network)
				)
			).to.be.true;

			// The signWitness closure produces a valid P2WPKH witness.
			const prevTx = bitcoin.Transaction.fromBuffer(inputs[0].prevTx);
			const spend = new bitcoin.Transaction();
			spend.version = 2;
			spend.addInput(
				prevTx.getHash(),
				inputs[0].prevOutputIndex,
				inputs[0].sequence
			);
			spend.addOutput(Buffer.alloc(22, 0x01), 499_000);
			const witness = inputs[0].signWitness(spend, 0, inputs[0].value);
			expect(witness.length).to.equal(2); // [der-sig, pubkey]

			const pubkey = witness[1];
			const scriptCode = bitcoin.payments.p2pkh({ pubkey, network }).output!;
			const sighash = spend.hashForWitnessV0(
				0,
				scriptCode,
				Number(inputs[0].value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			const decoded = bitcoin.script.signature.decode(witness[0]);
			expect(ecc.verify(sighash, pubkey, decoded.signature)).to.be.true;
		});

		it('adds a second UTXO when the first cannot also cover the fee', async () => {
			const { wallet } = createSpliceMockWallet({
				utxos: [{ valueSats: 100_000 }, { valueSats: 50_000 }]
			});
			const provider = new WalletFundingProvider(wallet);

			// 99_900 + fee(1 input) > 100_000 → iterative selection must add the 2nd.
			const { inputs } = await provider.selectSpliceInputs(99_900n, 253);
			expect(inputs.length).to.equal(2);
		});

		it('prefers confirmed UTXOs over unconfirmed', async () => {
			const { wallet } = createSpliceMockWallet({
				utxos: [
					{ valueSats: 900_000, height: 0 },
					{ valueSats: 200_000, height: 50 }
				]
			});
			const provider = new WalletFundingProvider(wallet);

			const { inputs } = await provider.selectSpliceInputs(100_000n, 253);
			expect(inputs.length).to.equal(1);
			expect(
				inputs[0].value,
				'picked the confirmed UTXO despite smaller value'
			).to.equal(200_000n);
		});

		it('skips non-P2WPKH UTXOs', async () => {
			const { wallet } = createSpliceMockWallet({
				utxos: [{ valueSats: 800_000, nonP2wpkh: true }, { valueSats: 300_000 }]
			});
			const provider = new WalletFundingProvider(wallet);

			const { inputs } = await provider.selectSpliceInputs(100_000n, 253);
			expect(inputs.length).to.equal(1);
			expect(inputs[0].value).to.equal(300_000n);
		});

		it('throws a clear error when wallet funds are insufficient', async () => {
			const { wallet } = createSpliceMockWallet({
				utxos: [{ valueSats: 10_000 }]
			});
			const provider = new WalletFundingProvider(wallet);

			try {
				await provider.selectSpliceInputs(50_000n, 253);
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.include(
					'insufficient wallet funds for splice-in'
				);
			}
		});

		it('throws a capability error for wallets without UTXO/key access', async () => {
			const wallet = createMockWallet({ txHex: '' }); // legacy minimal mock
			const provider = new WalletFundingProvider(wallet);

			try {
				await provider.selectSpliceInputs(50_000n, 253);
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.include('does not support splice-in');
			}
		});

		describe('quoteSpliceIn', () => {
			it('quotes a max the selection will actually fund', async () => {
				// The regression this guards: a UI computed its own "max" from the
				// total balance and an approximate fee, and the daemon then rejected
				// it as unfundable. The quoted max must round-trip through the real
				// selection.
				const { wallet } = createSpliceMockWallet({
					utxos: [{ valueSats: 60_000 }, { valueSats: 19_772 }]
				});
				const provider = new WalletFundingProvider(wallet);

				const q = provider.quoteSpliceIn(2500);
				expect(q.inputCount).to.equal(2);
				expect(q.spendableSats).to.equal(79_772n);
				expect(q.maxAmountSats).to.equal(q.spendableSats - q.feeSats);

				const { inputs } = await provider.selectSpliceInputs(
					q.maxAmountSats,
					2500
				);
				expect(inputs.length).to.equal(2);
			});

			it('excludes non-P2WPKH UTXOs from the spendable total', () => {
				const { wallet } = createSpliceMockWallet({
					utxos: [
						{ valueSats: 40_000 },
						{ valueSats: 100_000, nonP2wpkh: true }
					]
				});
				const provider = new WalletFundingProvider(wallet);

				const q = provider.quoteSpliceIn(253);
				expect(q.inputCount).to.equal(1);
				expect(q.spendableSats).to.equal(40_000n);
			});

			it('quotes zero max when the fee exceeds the balance', () => {
				const { wallet } = createSpliceMockWallet({
					utxos: [{ valueSats: 200 }]
				});
				const provider = new WalletFundingProvider(wallet);

				const q = provider.quoteSpliceIn(50_000);
				expect(q.maxAmountSats).to.equal(0n);
			});
		});
	});

	describe('network detection', () => {
		it('should detect regtest from bcrt1 address', async () => {
			// The fundingAddress we created is regtest (bcrt1...)
			expect(fundingAddress).to.match(/^bcrt1/);

			const { txHex } = buildFakeFundingTx(fundingAddress, 50_000, network);
			const wallet = createMockWallet({ txHex });
			const provider = new WalletFundingProvider(wallet);

			// Should not throw (correct network detection)
			const result = await provider.buildFundingTransaction(
				fundingAddress,
				50_000n
			);
			expect(result.outputIndex).to.be.a('number');
		});
	});
});
