/**
 * Key-origin metadata regression tests (S-B.H1 / S-B.M1 / S-B.M2, 2026-07-15
 * review). Root cause: the wallet had no way to learn a key's true master
 * fingerprint or origin path, so watch-only PSBTs paired the xpub's PARENT
 * fingerprint with a from-master path (hardware signers refuse to match),
 * multisig descriptors exported zero-path origins (Sparrow/Coldcard refuse
 * registration), and segwit v0 external-signer PSBTs lacked non_witness_utxo
 * (Ledger 2.x / Trezor >= 2.3.5 reject them).
 *
 * Fully OFFLINE (unreachable Electrum, fabricated UTXOs), the pattern of
 * psbt-flow.test.ts / multisig.test.ts.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import BIP32Factory, { BIP32Interface } from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	getScriptHash,
	normalizeKeyOrigin,
	ok,
	Wallet
} from '../src';

bitcoin.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);

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

const fingerprintHex = (root: BIP32Interface): string =>
	Buffer.from(root.fingerprint).toString('hex');

let rootA: BIP32Interface;
let rootB: BIP32Interface;
let rootC: BIP32Interface;
const createdWallets: Wallet[] = [];

const track = (wallet: Wallet): Wallet => {
	createdWallets.push(wallet);
	return wallet;
};

describe('Wallet key-origin metadata (S-B.H1/M1/M2)', function () {
	this.timeout(testTimeout);

	before(() => {
		rootA = bip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC_A), regtest);
		rootB = bip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC_B), regtest);
		rootC = bip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC_C), regtest);
	});

	after(async () => {
		await Promise.all(createdWallets.map((w) => w?.stop()));
	});

	describe('normalizeKeyOrigin', () => {
		it('accepts and normalizes fingerprint + h-hardened path', () => {
			const res = normalizeKeyOrigin('73C5DA0A', 'm/84h/1h/0h');
			if (res.isErr()) throw res.error;
			expect(res.value.fingerprint.toString('hex')).to.equal('73c5da0a');
			expect(res.value.path).to.equal("84'/1'/0'");
		});

		it('rejects a malformed fingerprint and a malformed path', () => {
			expect(normalizeKeyOrigin('xyz', "m/84'/1'/0'").isErr()).to.equal(true);
			expect(normalizeKeyOrigin('73c5da0a', 'm/84q/other').isErr()).to.equal(
				true
			);
		});
	});

	describe('watch-only single-sig (S-B.H1 + S-B.M1)', () => {
		let watchOnly: Wallet;

		before(async () => {
			const res = await Wallet.createWatchOnly({
				xpub: rootA.derivePath("m/84'/1'/0'").neutered().toBase58(),
				masterFingerprint: fingerprintHex(rootA),
				originPath: "m/84'/1'/0'",
				addressType: EAddressType.p2wpkh,
				network,
				electrumOptions
			});
			if (res.isErr()) throw res.error;
			watchOnly = track(res.value);
			await watchOnly.refreshWallet({});
			const address = await watchOnly.getAddress({
				index: '0',
				addressType: EAddressType.p2wpkh
			});
			watchOnly.data.utxos.push({
				address,
				index: 0,
				path: "m/84'/1'/0'/0/0",
				scriptHash: getScriptHash({ address, network }),
				height: 100,
				tx_hash: Buffer.from(
					bitcoin.crypto.sha256(Buffer.from('key-origin-utxo-0'))
				).toString('hex'),
				tx_pos: 0,
				value: 60000,
				publicKey: rootA.derivePath("m/84'/1'/0'/0/0").publicKey.toString('hex')
			});
		});

		it('getMasterFingerprint returns the supplied master fingerprint', () => {
			expect(watchOnly.getMasterFingerprint().toString('hex')).to.equal(
				fingerprintHex(rootA)
			);
		});

		it('PSBTs pair the master fingerprint with the origin-mapped path and the device key signs', async () => {
			const res = await watchOnly.buildPsbt({
				address: RECIPIENT,
				amount: 40000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (res.isErr()) throw res.error;
			const psbt = bitcoin.Psbt.fromBase64(res.value.psbtBase64, {
				network: regtest
			});
			const derivation = psbt.data.inputs[0].bip32Derivation;
			expect(derivation).to.have.length(1);
			expect(derivation![0].masterFingerprint.toString('hex')).to.equal(
				fingerprintHex(rootA)
			);
			expect(derivation![0].path).to.equal("m/84'/1'/0'/0/0");
			// The hardware-signer contract: deriving the derivation path from the
			// master matching the fingerprint yields the input's pubkey.
			const derived = rootA.derivePath(derivation![0].path);
			expect(derived.publicKey.toString('hex')).to.equal(
				derivation![0].pubkey.toString('hex')
			);
			psbt.signInput(0, derived);
			expect(
				psbt.validateSignaturesOfInput(0, (pubkey, msghash, signature) =>
					ecc.verify(msghash, pubkey, signature)
				)
			).to.equal(true);
		});

		it('exportDescriptors carries the full BIP 380 key origin', () => {
			const res = watchOnly.exportDescriptors();
			if (res.isErr()) throw res.error;
			const external = res.value.descriptors[0].external;
			expect(external).to.include(`[${fingerprintHex(rootA)}/84h/1h/0h]`);
		});

		it('fingerprint-only metadata keeps the wallet-derived path', async () => {
			const res = await Wallet.createWatchOnly({
				xpub: rootA.derivePath("m/84'/1'/0'").neutered().toBase58(),
				masterFingerprint: fingerprintHex(rootA),
				addressType: EAddressType.p2wpkh,
				network,
				electrumOptions,
				name: 'fponly'
			});
			if (res.isErr()) throw res.error;
			const wallet = track(res.value);
			expect(wallet.getMasterFingerprint().toString('hex')).to.equal(
				fingerprintHex(rootA)
			);
			expect(wallet.mapPathToKeyOrigin("m/84'/1'/0'/0/5")).to.equal(
				"m/84'/1'/0'/0/5"
			);
		});

		it('rejects invalid metadata at creation', async () => {
			const badFp = await Wallet.createWatchOnly({
				xpub: rootA.derivePath("m/84'/1'/0'").neutered().toBase58(),
				masterFingerprint: 'nothex!!',
				network,
				electrumOptions,
				name: 'badfp'
			});
			expect(badFp.isErr()).to.equal(true);
			const pathOnly = await Wallet.createWatchOnly({
				xpub: rootA.derivePath("m/84'/1'/0'").neutered().toBase58(),
				originPath: "m/84'/1'/0'",
				network,
				electrumOptions,
				name: 'pathonly'
			});
			expect(pathOnly.isErr()).to.equal(true);
		});
	});

	describe('multisig cosigner objects (S-B.H1 + S-B.M1)', () => {
		let walletA: Wallet;

		before(async () => {
			const res = await Wallet.createMultisig({
				threshold: 2,
				mnemonic: MNEMONIC_A,
				cosigners: [
					{
						xpub: rootB.derivePath("m/48'/1'/0'/2'").neutered().toBase58(),
						masterFingerprint: fingerprintHex(rootB),
						originPath: "m/48'/1'/0'/2'"
					},
					{
						xpub: rootC.derivePath("m/48'/1'/0'/2'").neutered().toBase58(),
						masterFingerprint: fingerprintHex(rootC),
						originPath: "m/48'/1'/0'/2'"
					}
				],
				network,
				electrumOptions
			});
			if (res.isErr()) throw res.error;
			walletA = track(res.value);
		});

		it('PSBT derivations carry each cosigner true master fingerprint and path', () => {
			const payment = walletA.getMultisigPayment("m/48'/1'/0'/2'/0/0");
			if (payment.isErr()) throw payment.error;
			for (const root of [rootA, rootB, rootC]) {
				const child = root.derivePath("m/48'/1'/0'/2'/0/0");
				const entry = payment.value.derivations.find((d) =>
					d.pubkey.equals(child.publicKey)
				);
				expect(entry, `derivation for ${fingerprintHex(root)}`).to.not.be
					.undefined;
				expect(entry!.masterFingerprint.toString('hex')).to.equal(
					fingerprintHex(root)
				);
				expect(entry!.path).to.equal("m/48'/1'/0'/2'/0/0");
			}
		});

		it('exported descriptor carries full origins for every cosigner', () => {
			const res = walletA.exportDescriptors();
			if (res.isErr()) throw res.error;
			const external = res.value.descriptors[0].external;
			for (const root of [rootA, rootB, rootC]) {
				expect(external).to.include(`[${fingerprintHex(root)}/48h/1h/0h/2h]`);
			}
			// No zero-path origins remain.
			expect(external).to.not.match(/\[[0-9a-f]{8}\]/);
		});

		it('bare-string cosigners keep the legacy parent-fingerprint fallback', async () => {
			const res = await Wallet.createMultisig({
				threshold: 2,
				mnemonic: MNEMONIC_A,
				cosigners: [
					rootB.derivePath("m/48'/1'/0'/2'").neutered().toBase58(),
					rootC.derivePath("m/48'/1'/0'/2'").neutered().toBase58()
				],
				network,
				electrumOptions,
				name: 'legacyms'
			});
			if (res.isErr()) throw res.error;
			const legacy = track(res.value);
			const desc = legacy.exportDescriptors();
			if (desc.isErr()) throw desc.error;
			// Zero-path fingerprint-only origins, exactly as before the change.
			expect(desc.value.descriptors[0].external).to.match(/\[[0-9a-f]{8}\]/);
		});
	});

	describe('non_witness_utxo on segwit v0 inputs (S-B.M2)', () => {
		it('p2wpkh inputs carry the full previous transaction when available', async () => {
			const res = await Wallet.create({
				mnemonic: MNEMONIC_A,
				network,
				addressType: EAddressType.p2wpkh,
				electrumOptions,
				name: 'nwutxo'
			});
			if (res.isErr()) throw res.error;
			const wallet = track(res.value);
			await wallet.refreshWallet({});
			const address = await wallet.getAddress({
				index: '0',
				addressType: EAddressType.p2wpkh
			});
			const prevTx = new bitcoin.Transaction();
			prevTx.addInput(Buffer.alloc(32, 7), 0);
			prevTx.addOutput(bitcoin.address.toOutputScript(address, regtest), 60000);
			wallet.data.utxos.push({
				address,
				index: 0,
				path: "m/84'/1'/0'/0/0",
				scriptHash: getScriptHash({ address, network }),
				height: 100,
				tx_hash: prevTx.getId(),
				tx_pos: 0,
				value: 60000,
				publicKey: rootA.derivePath("m/84'/1'/0'/0/0").publicKey.toString('hex')
			});
			const electrum = wallet.electrum as unknown as {
				getTransactions: () => Promise<unknown>;
			};
			const original = electrum.getTransactions;
			electrum.getTransactions = async (): Promise<unknown> =>
				ok({ data: [{ result: { hex: prevTx.toHex() } }] });
			try {
				const built = await wallet.buildPsbt({
					address: RECIPIENT,
					amount: 40000,
					satsPerByte: 2,
					shuffleOutputs: false
				});
				if (built.isErr()) throw built.error;
				const psbt = bitcoin.Psbt.fromBase64(built.value.psbtBase64, {
					network: regtest
				});
				expect(psbt.data.inputs[0].nonWitnessUtxo).to.not.be.undefined;
				expect(psbt.data.inputs[0].witnessUtxo).to.not.be.undefined;
				expect(
					bitcoin.Transaction.fromBuffer(
						psbt.data.inputs[0].nonWitnessUtxo!
					).getId()
				).to.equal(prevTx.getId());
			} finally {
				electrum.getTransactions = original;
			}
		});

		it('build still succeeds without the previous transaction (offline)', async () => {
			const res = await Wallet.create({
				mnemonic: MNEMONIC_A,
				network,
				addressType: EAddressType.p2wpkh,
				electrumOptions,
				name: 'nwutxooffline'
			});
			if (res.isErr()) throw res.error;
			const wallet = track(res.value);
			await wallet.refreshWallet({});
			const address = await wallet.getAddress({
				index: '0',
				addressType: EAddressType.p2wpkh
			});
			wallet.data.utxos.push({
				address,
				index: 0,
				path: "m/84'/1'/0'/0/0",
				scriptHash: getScriptHash({ address, network }),
				height: 100,
				tx_hash: Buffer.from(
					bitcoin.crypto.sha256(Buffer.from('offline-utxo'))
				).toString('hex'),
				tx_pos: 0,
				value: 60000,
				publicKey: rootA.derivePath("m/84'/1'/0'/0/0").publicKey.toString('hex')
			});
			const built = await wallet.buildPsbt({
				address: RECIPIENT,
				amount: 40000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (built.isErr()) throw built.error;
			const psbt = bitcoin.Psbt.fromBase64(built.value.psbtBase64, {
				network: regtest
			});
			expect(psbt.data.inputs[0].nonWitnessUtxo).to.be.undefined;
			expect(psbt.data.inputs[0].witnessUtxo).to.not.be.undefined;
		});
	});
});
