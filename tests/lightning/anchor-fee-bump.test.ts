import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import {
	attachFeeInputsToZeroFeeHtlcTx,
	buildAnchorCpfpTx
} from '../../src/lightning/chain/sweep';
import { buildAnchorScript } from '../../src/lightning/script/anchor';
import {
	WalletFundingProvider,
	IWalletLike
} from '../../src/lightning/wallet/wallet-funding-provider';
import type { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { ChainActionType } from '../../src/lightning/chain/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;

// ─────────────── Helpers ───────────────

/**
 * Build a real P2WPKH wallet input (with a working signWitness closure that
 * mirrors WalletFundingProvider) backed by a freshly-minted prev tx.
 */
function makeWalletInput(valueSats: number, seed: string): ISpliceWalletInput {
	const priv = crypto.createHash('sha256').update(seed).digest();
	const keyPair = ECPair.fromPrivateKey(priv, { network });
	const pubkey = Buffer.from(keyPair.publicKey);
	const script = bitcoin.payments.p2wpkh({ pubkey, network }).output!;

	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(script, valueSats);

	const scriptCode = bitcoin.payments.p2pkh({ pubkey, network }).output!;
	return {
		prevTx: Buffer.from(prevTx.toBuffer()),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value) => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				SIGHASH_ALL
			);
			const sig64 = Buffer.from(ecc.sign(sighash, priv));
			const der = bitcoin.script.signature.encode(sig64, SIGHASH_ALL);
			return [der, pubkey];
		}
	};
}

/** Verify the P2WPKH witness at `inputIndex` of `tx` signs `value` correctly. */
function verifyWalletInput(
	tx: bitcoin.Transaction,
	inputIndex: number,
	value: bigint
): boolean {
	const witness = tx.ins[inputIndex].witness;
	const pubkey = witness[1];
	const scriptCode = bitcoin.payments.p2pkh({ pubkey, network }).output!;
	const sighash = tx.hashForWitnessV0(
		inputIndex,
		scriptCode,
		Number(value),
		SIGHASH_ALL
	);
	const decoded = bitcoin.script.signature.decode(witness[0]);
	return ecc.verify(sighash, pubkey, decoded.signature);
}

/** Build a zero-fee anchor second-level HTLC tx (1 input, 1 output). */
function buildZeroFeeHtlcTx(
	htlcAmount: number,
	locktime = 0
): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = locktime;
	tx.addInput(crypto.randomBytes(32), 0, 1); // seq=1 anchor CSV
	const p2wsh = bitcoin.payments.p2wsh({
		redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_1]) },
		network
	}).output!;
	tx.addOutput(p2wsh, htlcAmount);
	return tx;
}

/** A WalletFundingProvider backed by mock P2WPKH UTXOs of the given values. */
function createFeeBumpProvider(values: number[]): WalletFundingProvider {
	const wifByPath = new Map<string, string>();
	const txByHash = new Map<string, { txid: string; hex: string }>();
	const utxos: any[] = [];
	values.forEach((value, i) => {
		const priv = crypto.createHash('sha256').update(`wire-utxo-${i}`).digest();
		const keyPair = ECPair.fromPrivateKey(priv, { network });
		const pubkey = Buffer.from(keyPair.publicKey);
		const path = `m/84'/0'/0'/0/${i}`;
		wifByPath.set(path, keyPair.toWIF());
		const script = bitcoin.payments.p2wpkh({ pubkey, network }).output!;
		const prevTx = new bitcoin.Transaction();
		prevTx.version = 2;
		prevTx.addInput(crypto.randomBytes(32), 0);
		prevTx.addOutput(script, value);
		const txidDisplay = Buffer.from(prevTx.getHash()).reverse().toString('hex');
		txByHash.set(txidDisplay, { txid: txidDisplay, hex: prevTx.toHex() });
		utxos.push({
			address: bitcoin.address.fromOutputScript(script, network),
			path,
			tx_hash: txidDisplay,
			tx_pos: 0,
			value,
			height: 100,
			publicKey: pubkey.toString('hex')
		});
	});
	const changeKey = ECPair.fromPrivateKey(
		crypto.createHash('sha256').update('wire-change').digest(),
		{ network }
	);
	const changeAddress = bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(changeKey.publicKey),
		network
	}).address!;
	const wallet: IWalletLike = {
		send: async () =>
			({ isErr: () => false, isOk: () => true, value: '' }) as any,
		electrum: {
			broadcastTransaction: async () =>
				({ isErr: () => false, isOk: () => true, value: '' }) as any,
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
	return new WalletFundingProvider(wallet);
}

function makeBasepoints(seed: string): IChannelBasepoints {
	const p = (i: number) =>
		getPublicKey(crypto.createHash('sha256').update(`${seed}-${i}`).digest());
	return {
		fundingPubkey: p(0),
		revocationBasepoint: p(1),
		paymentBasepoint: p(2),
		delayedPaymentBasepoint: p(3),
		htlcBasepoint: p(4),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

// An opaque pre-signed counterparty witness (SIGHASH_SINGLE|ANYONECANPAY form).
const HTLC_WITNESS: Buffer[] = [
	Buffer.alloc(0),
	Buffer.concat([Buffer.alloc(71, 0xab), Buffer.from([0x83])]), // remote sig
	Buffer.concat([Buffer.alloc(71, 0xcd), Buffer.from([0x83])]), // local sig
	Buffer.alloc(0),
	Buffer.from('5187', 'hex') // dummy witnessScript
];

// ─────────────── Tests ───────────────

describe('anchor fee bumping', () => {
	describe('attachFeeInputsToZeroFeeHtlcTx', () => {
		it('appends a wallet input + change and pays the target fee', () => {
			const htlcTx = buildZeroFeeHtlcTx(50_000);
			const walletInput = makeWalletInput(100_000, 'attach-1');
			const changeScript = bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
				network
			}).output!;

			const { tx, txid } = attachFeeInputsToZeroFeeHtlcTx({
				htlcTx,
				htlcWitness: HTLC_WITNESS,
				walletInputs: [walletInput],
				changeScript,
				feeratePerVbyte: 10
			});

			expect(tx.ins.length).to.equal(2);
			expect(tx.outs.length).to.equal(2);
			// Output 0 (the SIGHASH_SINGLE-committed output) is untouched.
			expect(tx.outs[0].script.equals(htlcTx.outs[0].script)).to.be.true;
			expect(tx.outs[0].value).to.equal(50_000);
			// The pre-signed HTLC witness is byte-identical.
			expect(tx.ins[0].witness.length).to.equal(HTLC_WITNESS.length);
			tx.ins[0].witness.forEach(
				(w, i) => expect(w.equals(HTLC_WITNESS[i])).to.be.true
			);
			// Wallet input signature verifies over the finalised tx.
			expect(verifyWalletInput(tx, 1, walletInput.value)).to.be.true;
			expect(txid).to.equal(tx.getId());

			// Fee = wallet input − change; effective rate clears the target.
			const change = BigInt(tx.outs[1].value);
			const fee = walletInput.value - change;
			expect(Number(fee) / tx.virtualSize()).to.be.gte(10);
		});

		it('folds change into the fee when it would be dust', () => {
			const htlcTx = buildZeroFeeHtlcTx(50_000);
			// At 1 sat/vB the fee is ~170 sats; a 400-sat input leaves <dust change.
			const walletInput = makeWalletInput(400, 'attach-dust');
			const changeScript = bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
				network
			}).output!;

			const { tx } = attachFeeInputsToZeroFeeHtlcTx({
				htlcTx,
				htlcWitness: HTLC_WITNESS,
				walletInputs: [walletInput],
				changeScript,
				feeratePerVbyte: 1
			});

			expect(tx.outs.length).to.equal(1); // change dropped
			expect(tx.outs[0].value).to.equal(50_000);
		});

		it('throws when the wallet input cannot cover the fee', () => {
			const htlcTx = buildZeroFeeHtlcTx(50_000);
			const walletInput = makeWalletInput(200, 'attach-broke');
			expect(() =>
				attachFeeInputsToZeroFeeHtlcTx({
					htlcTx,
					htlcWitness: HTLC_WITNESS,
					walletInputs: [walletInput],
					changeScript: Buffer.alloc(22),
					feeratePerVbyte: 50
				})
			).to.throw(/insufficient wallet input value/);
		});
	});

	describe('buildAnchorCpfpTx', () => {
		const fundingPriv = crypto
			.createHash('sha256')
			.update('anchor-funding')
			.digest();
		const fundingPub = Buffer.from(
			ECPair.fromPrivateKey(fundingPriv, { network }).publicKey
		);
		const anchorWitnessScript = buildAnchorScript(fundingPub);

		it('spends the anchor + wallet inputs and clears the package fee rate', () => {
			const walletInput = makeWalletInput(100_000, 'cpfp-1');
			const changeScript = bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(ECPair.makeRandom({ network }).publicKey),
				network
			}).output!;

			const parentVbytes = 200;
			const parentFeeSats = 200n; // deliberately under-funded parent
			const feerate = 10;

			const { tx } = buildAnchorCpfpTx({
				commitmentTxid: crypto.randomBytes(32).toString('hex'),
				anchorOutputIndex: 2,
				anchorAmount: 330n,
				anchorWitnessScript,
				localFundingPrivkey: fundingPriv,
				parentVbytes,
				parentFeeSats,
				walletInputs: [walletInput],
				changeScript,
				feeratePerVbyte: feerate
			});

			expect(tx.ins.length).to.equal(2);
			expect(tx.outs.length).to.equal(1);

			// Anchor witness = [sig, witnessScript], and the sig verifies.
			const anchorWitness = tx.ins[0].witness;
			expect(anchorWitness.length).to.equal(2);
			expect(anchorWitness[1].equals(anchorWitnessScript)).to.be.true;
			const sighash = tx.hashForWitnessV0(
				0,
				anchorWitnessScript,
				330,
				SIGHASH_ALL
			);
			const decoded = bitcoin.script.signature.decode(anchorWitness[0]);
			expect(ecc.verify(sighash, fundingPub, decoded.signature)).to.be.true;

			// Wallet input verifies.
			expect(verifyWalletInput(tx, 1, walletInput.value)).to.be.true;

			// Package fee rate clears the target.
			const totalIn = 330n + walletInput.value;
			const childFee = totalIn - BigInt(tx.outs[0].value);
			const packageRate =
				Number(parentFeeSats + childFee) / (parentVbytes + tx.virtualSize());
			expect(packageRate).to.be.gte(feerate);
		});

		it('throws when wallet funds leave change below dust', () => {
			const walletInput = makeWalletInput(400, 'cpfp-broke');
			expect(() =>
				buildAnchorCpfpTx({
					commitmentTxid: crypto.randomBytes(32).toString('hex'),
					anchorOutputIndex: 2,
					anchorAmount: 330n,
					anchorWitnessScript,
					localFundingPrivkey: fundingPriv,
					parentVbytes: 200,
					parentFeeSats: 0n,
					walletInputs: [walletInput],
					changeScript: Buffer.alloc(22),
					feeratePerVbyte: 20
				})
			).to.throw(/insufficient funds for anchor CPFP/);
		});
	});

	describe('WalletFundingProvider.selectFeeBumpInputs', () => {
		function createMockWallet(values: number[]): IWalletLike {
			const wifByPath = new Map<string, string>();
			const txByHash = new Map<string, { txid: string; hex: string }>();
			const utxos: any[] = [];
			values.forEach((value, i) => {
				const priv = crypto
					.createHash('sha256')
					.update(`feebump-utxo-${i}`)
					.digest();
				const keyPair = ECPair.fromPrivateKey(priv, { network });
				const pubkey = Buffer.from(keyPair.publicKey);
				const path = `m/84'/0'/0'/0/${i}`;
				wifByPath.set(path, keyPair.toWIF());
				const script = bitcoin.payments.p2wpkh({ pubkey, network }).output!;
				const prevTx = new bitcoin.Transaction();
				prevTx.version = 2;
				prevTx.addInput(crypto.randomBytes(32), 0);
				prevTx.addOutput(script, value);
				const txidDisplay = Buffer.from(prevTx.getHash())
					.reverse()
					.toString('hex');
				txByHash.set(txidDisplay, { txid: txidDisplay, hex: prevTx.toHex() });
				utxos.push({
					address: bitcoin.address.fromOutputScript(script, network),
					path,
					tx_hash: txidDisplay,
					tx_pos: 0,
					value,
					height: 100,
					publicKey: pubkey.toString('hex')
				});
			});
			const changeKey = ECPair.fromPrivateKey(
				crypto.createHash('sha256').update('feebump-change').digest(),
				{ network }
			);
			const changeAddress = bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(changeKey.publicKey),
				network
			}).address!;
			return {
				send: async () =>
					({ isErr: () => false, isOk: () => true, value: '' }) as any,
				electrum: {
					broadcastTransaction: async () =>
						({ isErr: () => false, isOk: () => true, value: '' }) as any,
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
		}

		it('selects inputs covering the target fee plus its own weight + dust', async () => {
			const provider = new WalletFundingProvider(createMockWallet([500_000]));
			const { inputs, changeScript } = await provider.selectFeeBumpInputs(
				5_000n,
				253
			);
			expect(inputs.length).to.equal(1);
			expect(inputs[0].value).to.equal(500_000n);
			expect(changeScript.length).to.equal(22);
		});

		it('adds inputs until the target is covered', async () => {
			const provider = new WalletFundingProvider(
				createMockWallet([3_000, 3_000, 3_000])
			);
			const { inputs } = await provider.selectFeeBumpInputs(5_000n, 253);
			expect(inputs.length).to.be.gte(2);
		});

		it('throws a clear error when funds are insufficient', async () => {
			const provider = new WalletFundingProvider(createMockWallet([1_000]));
			let threw = false;
			try {
				await provider.selectFeeBumpInputs(50_000n, 253);
			} catch (err) {
				threw = true;
				expect((err as Error).message).to.include(
					'insufficient wallet funds for fee-bump'
				);
			}
			expect(threw).to.be.true;
		});
	});

	describe('ChannelManager FEE_BUMP_AND_BROADCAST wiring', () => {
		function makeManager(
			provider: WalletFundingProvider | null
		): ChannelManager {
			const cm = new ChannelManager({
				localBasepoints: makeBasepoints('wire-cm'),
				localPerCommitmentSeed: crypto
					.createHash('sha256')
					.update('wire-seed')
					.digest(),
				localFundingPrivkey: crypto
					.createHash('sha256')
					.update('wire-funding')
					.digest()
			} as any);
			cm.on('error', () => {}); // swallow fallback warnings
			cm.setFundingProvider(provider);
			return cm;
		}

		function htlcFeeAttachAction() {
			const htlcTx = buildZeroFeeHtlcTx(50_000);
			htlcTx.setWitness(0, HTLC_WITNESS);
			return {
				type: ChainActionType.FEE_BUMP_AND_BROADCAST as const,
				kind: 'htlc-fee-attach' as const,
				tx: htlcTx.toBuffer(),
				description: 'HTLC-timeout',
				feeratePerVbyte: 10
			};
		}

		it('attaches a wallet input and broadcasts the bumped HTLC tx', async () => {
			const cm = makeManager(createFeeBumpProvider([200_000]));
			const broadcasts: Buffer[] = [];
			cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

			await (cm as any)._handleFeeBumpAndBroadcast(
				Buffer.alloc(32, 1),
				htlcFeeAttachAction()
			);

			expect(broadcasts.length).to.equal(1);
			const tx = bitcoin.Transaction.fromBuffer(broadcasts[0]);
			expect(tx.ins.length).to.equal(2); // HTLC input + attached wallet input
			expect(verifyWalletInput(tx, 1, 200_000n)).to.be.true;
			// The pre-signed HTLC witness survives unchanged.
			tx.ins[0].witness.forEach(
				(w, i) => expect(w.equals(HTLC_WITNESS[i])).to.be.true
			);
		});

		it('falls back to broadcasting the unbumped tx when no funding provider', async () => {
			const cm = makeManager(null);
			const broadcasts: Buffer[] = [];
			cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

			const action = htlcFeeAttachAction();
			await (cm as any)._handleFeeBumpAndBroadcast(Buffer.alloc(32, 1), action);

			expect(broadcasts.length).to.equal(1);
			expect(broadcasts[0].equals(action.tx)).to.be.true; // unmodified
		});

		it('falls back to broadcasting the unbumped tx when wallet funds are insufficient', async () => {
			const cm = makeManager(createFeeBumpProvider([100])); // far too little
			const broadcasts: Buffer[] = [];
			cm.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

			const action = htlcFeeAttachAction();
			await (cm as any)._handleFeeBumpAndBroadcast(Buffer.alloc(32, 1), action);

			expect(broadcasts.length).to.equal(1);
			expect(broadcasts[0].equals(action.tx)).to.be.true;
		});

		// M1: the initial commitment CPFP is one-shot; a stuck package must be
		// re-CPFP'd at a higher live feerate each block until it confirms.
		describe('reCpfpStuckCommitments (commitment package re-bump)', () => {
			function managerWithPendingCpfp(
				opts: { fullyResolved?: boolean; commitmentConfirmed?: boolean } = {}
			): {
				cm: ChannelManager;
				channelIdHex: string;
				calls: any[];
			} {
				const cm = makeManager(createFeeBumpProvider([200_000]));
				const channelIdHex = 'ab'.repeat(32);
				(cm as any)._pendingCommitmentCpfp.set(channelIdHex, {
					action: {
						type: ChainActionType.FEE_BUMP_AND_BROADCAST,
						kind: 'anchor-cpfp',
						tx: Buffer.alloc(10),
						description: 'anchor commitment CPFP',
						feeratePerVbyte: 10,
						anchorOutputIndex: 0,
						anchorWitnessScript: Buffer.alloc(34),
						parentVbytes: 200,
						parentFeeSats: 0n,
						commitmentTxid: 'cd'.repeat(32)
					},
					broadcastHeight: 100,
					lastFeeRate: 10
				});
				// Stub monitor exposing the confirmation-driven guards the re-CPFP loop
				// now uses (isFullyResolved / isCommitmentConfirmed) instead of getState().
				(cm as any).monitors.set(channelIdHex, {
					isFullyResolved: () => opts.fullyResolved === true,
					isCommitmentConfirmed: () => opts.commitmentConfirmed === true
				});
				// Spy on the CPFP re-issue instead of building a real wallet tx.
				const calls: any[] = [];
				(cm as any)._handleFeeBumpAndBroadcast = (
					_cid: Buffer,
					action: any
				) => {
					calls.push(action);
					return Promise.resolve();
				};
				return { cm, channelIdHex, calls };
			}

			it('re-issues the CPFP for a mempool-detected but UNCONFIRMED commitment (H1)', () => {
				// The real stuck-commitment state: our force-close is in the mempool
				// (monitor left WATCHING on the unconfirmed sighting) but not yet
				// confirmed. Gating on WATCHING previously made this inert; now it bumps.
				const { cm, channelIdHex, calls } = managerWithPendingCpfp({
					fullyResolved: false,
					commitmentConfirmed: false
				});
				// 6 blocks after broadcast (100), live feerate 30 > last 10.
				cm.reCpfpStuckCommitments(106, 30);

				expect(calls.length).to.equal(1);
				expect(calls[0].feeratePerVbyte).to.equal(30);
				expect(calls[0].kind).to.equal('anchor-cpfp');
				expect(calls[0].description).to.match(/re-bump/);
				const entry = (cm as any)._pendingCommitmentCpfp.get(channelIdHex);
				expect(entry.lastFeeRate).to.equal(30);
				expect(entry.broadcastHeight).to.equal(106);
			});

			it('does not re-issue before the interval, or when the feerate is not higher', () => {
				const early = managerWithPendingCpfp();
				early.cm.reCpfpStuckCommitments(103, 30); // only 3 blocks elapsed
				expect(early.calls.length).to.equal(0);

				const sameFee = managerWithPendingCpfp();
				sameFee.cm.reCpfpStuckCommitments(110, 10); // interval ok, feerate == last
				expect(sameFee.calls.length).to.equal(0);
			});

			it('drops the entry once the commitment CONFIRMS (not merely detected)', () => {
				const { cm, channelIdHex, calls } = managerWithPendingCpfp({
					commitmentConfirmed: true
				});
				cm.reCpfpStuckCommitments(200, 100);
				expect(calls.length).to.equal(0);
				expect((cm as any)._pendingCommitmentCpfp.has(channelIdHex)).to.be
					.false;
			});

			it('drops the entry once the monitor is fully resolved', () => {
				const { cm, channelIdHex, calls } = managerWithPendingCpfp({
					fullyResolved: true
				});
				cm.reCpfpStuckCommitments(200, 100);
				expect(calls.length).to.equal(0);
				expect((cm as any)._pendingCommitmentCpfp.has(channelIdHex)).to.be
					.false;
			});
		});
	});
});
