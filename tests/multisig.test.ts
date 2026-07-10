/**
 * Sorted-multisig (BIP 48 / BIP 67) P2WSH wallet tests. Fully OFFLINE: the
 * wallets point at an unreachable Electrum port, addresses are pure key
 * derivation and the PSBT round trip uses fabricated UTXOs. Expected
 * addresses and scripts are computed INDEPENDENTLY inside the test with
 * bitcoinjs-lib (p2ms + p2wsh + lexicographic key sort), never through the
 * code under test.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import BIP32Factory, { BIP32Interface } from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';

import {
	appendDescriptorChecksum,
	descriptorChecksum,
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	getScriptHash,
	IUtxo,
	MultisigSpendError,
	Wallet,
	WatchOnlySigningError
} from '../src';

bitcoin.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);
const ECPair = ECPairFactory(ecc);

const MNEMONIC_A =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const MNEMONIC_B =
	'legal winner thank year wave sausage worth useful legal winner thank yellow';
const MNEMONIC_C =
	'letter advice cage absurd amount doctor acoustic avoid letter advice cage above';

const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const regtest = bitcoin.networks.regtest;
const network = EAvailableNetworks.regtest;
const testTimeout = 120000;

// Pinned regression vector for the exact 2-of-3 descriptor exported by
// wallet A below, checksum computed once with the BIP 380 implementation
// that matches the Bitcoin Core doc vectors (see descriptors.test.ts).
const PINNED_EXTERNAL_DESCRIPTOR =
	'wsh(sortedmulti(2,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*,[8d70f947]tpubDEwqCvJxKwKWX9xvRe48uofWJn1Y89Jn8UeH1Efrjb1UEVjUDy3URYTiqWaVCW7WdvHrL8XrSihHEhTwv5H3VDJoakjuCHiAnr6xcF2Xm4s/0/*,[67d8576d]tpubDEfobrrtptRTbKf4gysDhoabneABDTAcdj3Vbn4XwPsLE2pmqpizSPRG6zHsbAMuiSgWmWPsYCLHTKTPpyrGJ5rAoTpKoQNZcxodiPf2tSJ/0/*))#u4dz746u';

// Unreachable on purpose: these tests must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65529,
		tcp: 65529,
		protocol: EProtocol.tcp
	}
};

const THRESHOLD = 2;
const ACCOUNT_PATH = "m/48'/1'/0'/2'";

let rootA: BIP32Interface;
let rootB: BIP32Interface;
let rootC: BIP32Interface;
let xpubA: string;
let xpubB: string;
let xpubC: string;
const createdWallets: Wallet[] = [];

const track = (wallet: Wallet): Wallet => {
	createdWallets.push(wallet);
	return wallet;
};

/** Independently computed sortedmulti P2WSH payment for one index. */
const expectedPayment = (
	change: number,
	index: number
): { address: string; witnessScript: Buffer; pubkeys: Buffer[] } => {
	const pubkeys = [rootA, rootB, rootC]
		.map((root) => root.derivePath(`${ACCOUNT_PATH}/${change}/${index}`))
		.map((node) => node.publicKey)
		.sort((a, b) => a.compare(b));
	const p2ms = bitcoin.payments.p2ms({
		m: THRESHOLD,
		pubkeys,
		network: regtest
	});
	const p2wsh = bitcoin.payments.p2wsh({ redeem: p2ms, network: regtest });
	return { address: p2wsh.address!, witnessScript: p2ms.output!, pubkeys };
};

/** Fabricates a wallet-owned multisig UTXO; no network needed. */
const makeMultisigUtxo = async (
	wallet: Wallet,
	{ index, value, txPos = 0 }: { index: number; value: number; txPos?: number }
): Promise<IUtxo> => {
	const address = await wallet.getAddress({ index: String(index) });
	const path = `${ACCOUNT_PATH.replace(/'/g, "'")}/0/${index}`;
	return {
		address,
		index,
		path,
		scriptHash: getScriptHash({ address, network }),
		height: 100,
		tx_hash: Buffer.from(
			bitcoin.crypto.sha256(Buffer.from(`multisig-utxo-${index}`))
		).toString('hex'),
		tx_pos: txPos,
		value,
		publicKey: rootA
			.derivePath(`${ACCOUNT_PATH}/0/${index}`)
			.publicKey.toString('hex')
	};
};

describe('Multisig P2WSH Wallets', async function () {
	this.timeout(testTimeout);

	before(function () {
		rootA = bip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC_A), regtest);
		rootB = bip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC_B), regtest);
		rootC = bip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC_C), regtest);
		xpubA = rootA.derivePath(ACCOUNT_PATH).neutered().toBase58();
		xpubB = rootB.derivePath(ACCOUNT_PATH).neutered().toBase58();
		xpubC = rootC.derivePath(ACCOUNT_PATH).neutered().toBase58();
	});

	after(async function () {
		await Promise.all(createdWallets.map((w) => w?.stop()));
	});

	describe('Address vectors (BIP 48 derivation, BIP 67 ordering)', () => {
		let walletA: Wallet;

		before(async () => {
			const res = await Wallet.createMultisig({
				threshold: THRESHOLD,
				mnemonic: MNEMONIC_A,
				cosigners: [xpubB, xpubC],
				network,
				electrumOptions
			});
			if (res.isErr()) throw res.error;
			walletA = track(res.value);
		});

		it('is a p2wsh multisig wallet monitoring only p2wsh', () => {
			expect(walletA.isMultisig).to.equal(true);
			expect(walletA.isWatchOnly).to.equal(false);
			expect(walletA.addressType).to.equal(EAddressType.p2wsh);
			expect(walletA.addressTypesToMonitor).to.deep.equal([EAddressType.p2wsh]);
			expect(walletA.multisigInfo).to.deep.equal({
				threshold: 2,
				totalCosigners: 3
			});
		});

		it('derives receive and change addresses matching an independent sortedmulti computation', async () => {
			for (const index of [0, 1, 5, 21]) {
				const receive = await walletA.getAddress({
					index: String(index),
					changeAddress: false
				});
				const change = await walletA.getAddress({
					index: String(index),
					changeAddress: true
				});
				expect(receive).to.equal(expectedPayment(0, index).address);
				expect(change).to.equal(expectedPayment(1, index).address);
			}
		});

		it('yields identical addresses for a shuffled cosigner input order (BIP 67)', async () => {
			const res = await Wallet.createMultisig({
				threshold: THRESHOLD,
				mnemonic: MNEMONIC_A,
				cosigners: [xpubC, xpubB],
				network,
				electrumOptions
			});
			if (res.isErr()) throw res.error;
			const shuffled = track(res.value);
			expect(shuffled.id).to.equal(walletA.id);
			for (const index of [0, 3]) {
				expect(await shuffled.getAddress({ index: String(index) })).to.equal(
					await walletA.getAddress({ index: String(index) })
				);
			}
		});

		it('derives the same addresses from a different cosigner mnemonic (B)', async () => {
			const res = await Wallet.createMultisig({
				threshold: THRESHOLD,
				mnemonic: MNEMONIC_B,
				cosigners: [xpubA, xpubC],
				network,
				electrumOptions
			});
			if (res.isErr()) throw res.error;
			const walletB = track(res.value);
			expect(walletB.id).to.equal(walletA.id);
			expect(await walletB.getAddress({ index: '0' })).to.equal(
				expectedPayment(0, 0).address
			);
		});

		it('watch-only multisig (no mnemonic) derives the same addresses', async () => {
			const res = await Wallet.createMultisig({
				threshold: THRESHOLD,
				cosigners: [xpubA, xpubB, xpubC],
				network,
				electrumOptions
			});
			if (res.isErr()) throw res.error;
			const watchOnly = track(res.value);
			expect(watchOnly.isWatchOnly).to.equal(true);
			expect(watchOnly.id).to.equal(walletA.id);
			for (const index of [0, 7]) {
				expect(await watchOnly.getAddress({ index: String(index) })).to.equal(
					expectedPayment(0, index).address
				);
				expect(
					await watchOnly.getAddress({
						index: String(index),
						changeAddress: true
					})
				).to.equal(expectedPayment(1, index).address);
			}
		});

		it('normalizes a SLIP-132 Vpub cosigner encoding to the same addresses', async () => {
			const slipNetwork = {
				...regtest,
				bip32: { public: 0x02575483, private: 0x02575048 }
			};
			const slipRootB = bip32.fromSeed(
				bip39.mnemonicToSeedSync(MNEMONIC_B),
				slipNetwork
			);
			const vpubB = slipRootB.derivePath(ACCOUNT_PATH).neutered().toBase58();
			expect(vpubB.startsWith('Vpub')).to.equal(true);
			const res = await Wallet.createMultisig({
				threshold: THRESHOLD,
				mnemonic: MNEMONIC_A,
				cosigners: [vpubB, xpubC],
				network,
				electrumOptions
			});
			if (res.isErr()) throw res.error;
			const wallet = track(res.value);
			expect(wallet.id).to.equal(walletA.id);
			expect(await wallet.getAddress({ index: '0' })).to.equal(
				expectedPayment(0, 0).address
			);
		});

		it('exposes BIP 48 paths in address metadata after a refresh', async () => {
			await walletA.refreshWallet({});
			const addressIndex = walletA.data.addressIndex[EAddressType.p2wsh];
			expect(addressIndex.path).to.equal("m/48'/1'/0'/2'/0/0");
			expect(addressIndex.address).to.equal(expectedPayment(0, 0).address);
		});
	});

	describe('Validation', () => {
		it('rejects a non-integer or non-positive threshold', async () => {
			for (const threshold of [0, -1, 1.5]) {
				const res = await Wallet.createMultisig({
					threshold,
					mnemonic: MNEMONIC_A,
					cosigners: [xpubB, xpubC],
					network,
					electrumOptions
				});
				expect(res.isErr(), `threshold ${threshold}`).to.equal(true);
			}
		});

		it('rejects a threshold above the cosigner count', async () => {
			const res = await Wallet.createMultisig({
				threshold: 4,
				mnemonic: MNEMONIC_A,
				cosigners: [xpubB, xpubC],
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('exceeds');
			}
		});

		it('rejects more than 15 cosigners', async () => {
			const cosigners: string[] = [];
			for (let i = 0; i < 16; i++) {
				cosigners.push(
					rootB.derivePath(`m/48'/1'/${i}'/2'`).neutered().toBase58()
				);
			}
			const res = await Wallet.createMultisig({
				threshold: 2,
				cosigners,
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('15');
			}
		});

		it('rejects duplicate cosigner xpubs', async () => {
			const res = await Wallet.createMultisig({
				threshold: 2,
				mnemonic: MNEMONIC_A,
				cosigners: [xpubB, xpubB],
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('Duplicate');
			}
		});

		it('rejects an explicit ourXpub that does not match the mnemonic', async () => {
			const res = await Wallet.createMultisig({
				threshold: 2,
				mnemonic: MNEMONIC_A,
				cosigners: [xpubB, xpubC],
				ourXpub: xpubB,
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('does not match');
			}
		});

		it('accepts a matching explicit ourXpub and an already-listed our xpub', async () => {
			const explicit = await Wallet.createMultisig({
				threshold: 2,
				mnemonic: MNEMONIC_A,
				cosigners: [xpubB, xpubC],
				ourXpub: xpubA,
				network,
				electrumOptions
			});
			if (explicit.isErr()) throw explicit.error;
			track(explicit.value);
			const listed = await Wallet.createMultisig({
				threshold: 2,
				mnemonic: MNEMONIC_A,
				cosigners: [xpubA, xpubB, xpubC],
				network,
				electrumOptions
			});
			if (listed.isErr()) throw listed.error;
			track(listed.value);
			expect(explicit.value.multisigInfo?.totalCosigners).to.equal(3);
			expect(listed.value.multisigInfo?.totalCosigners).to.equal(3);
			expect(explicit.value.id).to.equal(listed.value.id);
		});

		it('rejects a malformed cosigner xpub', async () => {
			const res = await Wallet.createMultisig({
				threshold: 2,
				mnemonic: MNEMONIC_A,
				cosigners: ['tpubnotarealkey'],
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
		});

		it('rejects an extended PRIVATE key as a cosigner', async () => {
			const tprv = rootB.derivePath(ACCOUNT_PATH).toBase58();
			const res = await Wallet.createMultisig({
				threshold: 2,
				mnemonic: MNEMONIC_A,
				cosigners: [tprv],
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('PRIVATE');
			}
		});

		it('rejects p2wsh on single-sig wallets', async () => {
			const full = await Wallet.create({
				mnemonic: MNEMONIC_A,
				addressType: EAddressType.p2wsh,
				network,
				electrumOptions
			});
			expect(full.isErr()).to.equal(true);
			const watch = await Wallet.createWatchOnly({
				xpub: xpubA,
				addressType: EAddressType.p2wsh,
				network,
				electrumOptions
			});
			expect(watch.isErr()).to.equal(true);
		});
	});

	describe('PSBT round trip (2-of-3, offline)', () => {
		let walletA: Wallet;
		let walletB: Wallet;
		let watchOnly: Wallet;
		let builtBase64: string;
		let inputValues: number[];

		before(async () => {
			const resA = await Wallet.createMultisig({
				threshold: THRESHOLD,
				mnemonic: MNEMONIC_A,
				cosigners: [xpubB, xpubC],
				network,
				electrumOptions
			});
			if (resA.isErr()) throw resA.error;
			walletA = track(resA.value);
			const resB = await Wallet.createMultisig({
				threshold: THRESHOLD,
				mnemonic: MNEMONIC_B,
				cosigners: [xpubA, xpubC],
				network,
				electrumOptions
			});
			if (resB.isErr()) throw resB.error;
			walletB = track(resB.value);
			const resW = await Wallet.createMultisig({
				threshold: THRESHOLD,
				cosigners: [xpubA, xpubB, xpubC],
				network,
				electrumOptions
			});
			if (resW.isErr()) throw resW.error;
			watchOnly = track(resW.value);
			// Populates index-0 addresses (including the change address that
			// setupTransaction needs); the Electrum sync fails harmlessly offline.
			await walletA.refreshWallet({});
			walletA.data.utxos.push(
				await makeMultisigUtxo(walletA, { index: 0, value: 60000 }),
				await makeMultisigUtxo(walletA, { index: 1, value: 40000 })
			);
		});

		it('buildPsbt populates witnessScript and ALL cosigner bip32Derivations', async () => {
			const res = await walletA.buildPsbt({
				address: RECIPIENT,
				amount: 80000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (res.isErr()) throw res.error;
			expect(res.value.fee).to.be.greaterThan(0);
			builtBase64 = res.value.psbtBase64;
			const psbt = bitcoin.Psbt.fromBase64(builtBase64, { network: regtest });
			expect(psbt.inputCount).to.equal(2);
			inputValues = psbt.data.inputs.map((i) => i.witnessUtxo!.value);
			psbt.data.inputs.forEach((input, i) => {
				// Which fabricated UTXO this input spends (order may vary).
				const index = input.witnessUtxo!.value === 60000 ? 0 : 1;
				const expected = expectedPayment(0, index);
				expect(input.witnessScript, `input ${i} witnessScript`).to.not.be
					.undefined;
				expect(input.witnessScript!.equals(expected.witnessScript)).to.equal(
					true
				);
				// witnessUtxo must commit to the witnessScript (P2WSH).
				const p2wsh = bitcoin.payments.p2wsh({
					redeem: { output: input.witnessScript! },
					network: regtest
				});
				expect(input.witnessUtxo!.script.equals(p2wsh.output!)).to.equal(true);
				// One derivation per cosigner, in BIP 67 (script) key order.
				expect(input.bip32Derivation).to.have.length(3);
				expect(
					input.bip32Derivation!.map((d) => d.pubkey.toString('hex'))
				).to.deep.equal(expected.pubkeys.map((pk) => pk.toString('hex')));
				for (const derivation of input.bip32Derivation!) {
					expect(derivation.path).to.equal(`m/48'/1'/0'/2'/0/${index}`);
				}
				// Unsigned: no partial signatures yet.
				expect(input.partialSig ?? []).to.have.length(0);
			});
			// Our key carries our real master fingerprint on every input.
			const fpA = Buffer.from(rootA.fingerprint).toString('hex');
			const flattened = psbt.data.inputs.flatMap(
				(input) => input.bip32Derivation ?? []
			);
			expect(
				flattened.some((d) => d.masterFingerprint.toString('hex') === fpA)
			).to.equal(true);
		});

		it('signPsbtWithOurKey adds exactly our partial signature without finalizing', () => {
			const res = walletA.signPsbtWithOurKey(builtBase64);
			if (res.isErr()) throw res.error;
			const psbt = bitcoin.Psbt.fromBase64(res.value, { network: regtest });
			psbt.data.inputs.forEach((input, i) => {
				expect(input.partialSig, `input ${i}`).to.have.length(1);
				expect(input.finalScriptWitness).to.be.undefined;
				const index = input.witnessUtxo!.value === 60000 ? 0 : 1;
				const ourPubkey = rootA.derivePath(
					`${ACCOUNT_PATH}/0/${index}`
				).publicKey;
				expect(input.partialSig![0].pubkey.equals(ourPubkey)).to.equal(true);
			});
		});

		it('watch-only multisig cannot sign (typed error)', () => {
			const res = watchOnly.signPsbtWithOurKey(builtBase64);
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error).to.be.instanceOf(WatchOnlySigningError);
			}
		});

		it('rejects finalization below the threshold naming have/need', () => {
			const signedA = walletA.signPsbtWithOurKey(builtBase64);
			if (signedA.isErr()) throw signedA.error;
			const res = watchOnly.importSignedPsbt(signedA.value);
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.match(/have 1 signature\(s\), need 2/);
			}
		});

		it('cosigner B signs a copy, combine + import finalizes at threshold and the witnesses verify', () => {
			const signedA = walletA.signPsbtWithOurKey(builtBase64);
			if (signedA.isErr()) throw signedA.error;
			// Cosigner B signs an independent COPY of the unsigned PSBT.
			const signedB = walletB.signPsbtWithOurKey(builtBase64);
			if (signedB.isErr()) throw signedB.error;
			const combined = watchOnly.combinePsbts([signedA.value, signedB.value]);
			if (combined.isErr()) throw combined.error;
			const merged = bitcoin.Psbt.fromBase64(combined.value, {
				network: regtest
			});
			merged.data.inputs.forEach((input) => {
				expect(input.partialSig).to.have.length(2);
			});
			const imported = watchOnly.importSignedPsbt(combined.value);
			if (imported.isErr()) throw imported.error;
			const tx = bitcoin.Transaction.fromHex(imported.value.txHex);
			expect(tx.getId()).to.equal(imported.value.txid);
			expect(tx.ins.length).to.equal(2);
			tx.ins.forEach((txInput, i) => {
				const witness = txInput.witness;
				// [OP_0 placeholder, sig, sig, witnessScript]
				expect(witness.length).to.equal(4);
				expect(witness[0].length).to.equal(0);
				const witnessScript = witness[witness.length - 1];
				const index = inputValues[i] === 60000 ? 0 : 1;
				const expected = expectedPayment(0, index);
				expect(witnessScript.equals(expected.witnessScript)).to.equal(true);
				// Cryptographically verify every signature against script keys.
				const sighash = tx.hashForWitnessV0(
					i,
					witnessScript,
					inputValues[i],
					bitcoin.Transaction.SIGHASH_ALL
				);
				const sigs = witness.slice(1, -1);
				expect(sigs.length).to.equal(THRESHOLD);
				for (const rawSig of sigs) {
					const decoded = bitcoin.script.signature.decode(rawSig);
					expect(decoded.hashType).to.equal(bitcoin.Transaction.SIGHASH_ALL);
					const verifies = expected.pubkeys.some((pk) =>
						ECPair.fromPublicKey(pk).verify(sighash, decoded.signature)
					);
					expect(verifies).to.equal(true);
				}
			});
		});

		it('rejects a signature from a key outside the multisig script', () => {
			const psbt = bitcoin.Psbt.fromBase64(builtBase64, { network: regtest });
			// A valid signature from an unrelated single-sig key must not count.
			const rogue = rootA.derivePath("m/84'/1'/0'/0/0");
			psbt.data.inputs.forEach((_input, i) => {
				psbt.data.updateInput(i, {
					partialSig: [
						{
							pubkey: rogue.publicKey,
							signature: bitcoin.script.signature.encode(
								Buffer.alloc(64, 1),
								bitcoin.Transaction.SIGHASH_ALL
							)
						}
					]
				});
			});
			const res = watchOnly.importSignedPsbt(psbt.toBase64());
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('not in the multisig script');
			}
		});

		it('direct spends are rejected with the typed PSBT-only error', async () => {
			const send = await walletA.send({
				address: RECIPIENT,
				amount: 1000
			});
			expect(send.isErr()).to.equal(true);
			if (send.isErr()) {
				expect(send.error).to.be.instanceOf(MultisigSpendError);
				expect(send.error.message).to.include('buildPsbt');
			}
			const sendMany = await walletA.sendMany({
				txs: [{ address: RECIPIENT, amount: 1000 }]
			});
			expect(sendMany.isErr()).to.equal(true);
			if (sendMany.isErr()) {
				expect(sendMany.error).to.be.instanceOf(MultisigSpendError);
			}
			const sendMax = await walletA.sendMax({ address: RECIPIENT });
			expect(sendMax.isErr()).to.equal(true);
			if (sendMax.isErr()) {
				expect(sendMax.error).to.be.instanceOf(MultisigSpendError);
			}
		});
	});

	describe('Descriptor export', () => {
		let walletA: Wallet;

		before(async () => {
			const res = await Wallet.createMultisig({
				threshold: THRESHOLD,
				mnemonic: MNEMONIC_A,
				cosigners: [xpubB, xpubC],
				network,
				electrumOptions
			});
			if (res.isErr()) throw res.error;
			walletA = track(res.value);
		});

		it('exports the expected wsh(sortedmulti(...)) descriptors with checksums', () => {
			const res = walletA.exportDescriptors();
			if (res.isErr()) throw res.error;
			const info = res.value;
			expect(info.watchOnly).to.equal(false);
			expect(info.descriptors).to.have.length(1);
			expect(info.descriptors[0].addressType).to.equal(EAddressType.p2wsh);
			// Build the expected descriptor independently: account keys sorted
			// by account-level pubkey; our key carries the full origin, xpub-only
			// cosigners a fingerprint-only origin (their parent fingerprint).
			const fpA = Buffer.from(rootA.fingerprint).toString('hex');
			const entries = [
				{ root: rootA, ours: true },
				{ root: rootB, ours: false },
				{ root: rootC, ours: false }
			]
				.map(({ root, ours }) => ({
					ours,
					account: root.derivePath(ACCOUNT_PATH).neutered(),
					parentFp: Buffer.from(
						root.derivePath("m/48'/1'/0'").fingerprint
					).toString('hex')
				}))
				.sort((a, b) => a.account.publicKey.compare(b.account.publicKey));
			const keyExpr = (chain: number): string =>
				entries
					.map((e) => {
						const origin = e.ours ? `[${fpA}/48h/1h/0h/2h]` : `[${e.parentFp}]`;
						return `${origin}${e.account.toBase58()}/${chain}/*`;
					})
					.join(',');
			const externalBody = `wsh(sortedmulti(${THRESHOLD},${keyExpr(0)}))`;
			const internalBody = `wsh(sortedmulti(${THRESHOLD},${keyExpr(1)}))`;
			expect(info.descriptors[0].external).to.equal(
				appendDescriptorChecksum(externalBody)
			);
			expect(info.descriptors[0].internal).to.equal(
				appendDescriptorChecksum(internalBody)
			);
			// Checksum round trip through the existing implementation.
			const [body, checksum] = info.descriptors[0].external.split('#');
			expect(descriptorChecksum(body)).to.equal(checksum);
			// Pinned regression vector (hand-checked once against the BIP 380
			// implementation that matches the Bitcoin Core doc vectors).
			expect(info.descriptors[0].external).to.equal(PINNED_EXTERNAL_DESCRIPTOR);
		});

		it('NEVER includes private key material', () => {
			const res = walletA.exportDescriptors();
			if (res.isErr()) throw res.error;
			expect(JSON.stringify(res.value)).to.not.contain('prv');
		});
	});
});
