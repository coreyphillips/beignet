/**
 * Descriptor export tests. Fully OFFLINE: descriptor construction is pure
 * key derivation; the wallets point at an unreachable Electrum port.
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
	Wallet,
	descriptorChecksum,
	appendDescriptorChecksum
} from '../src';

const bip32 = BIP32Factory(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
// Master fingerprint of the BIP84 test vector seed above.
const FINGERPRINT = '73c5da0a';

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

// Regtest keeps everything offline: mainnet wallets rotate to live fallback
// Electrum peers when the configured server is unreachable.
const network = EAvailableNetworks.regtest;
const testTimeout = 60000;

// p2wsh is multisig-only and has no single-key descriptor.
const SINGLE_SIG_TYPES = Object.values(EAddressType).filter(
	(t) => t !== EAddressType.p2wsh
);

const PURPOSE: { [key in EAddressType]: string } = {
	[EAddressType.p2pkh]: '44',
	[EAddressType.p2sh]: '49',
	[EAddressType.p2wpkh]: '84',
	[EAddressType.p2tr]: '86',
	[EAddressType.p2wsh]: '48'
};

const wrapExpected = (addressType: EAddressType, keyExpr: string): string => {
	switch (addressType) {
		case EAddressType.p2pkh:
			return `pkh(${keyExpr})`;
		case EAddressType.p2sh:
			return `sh(wpkh(${keyExpr}))`;
		case EAddressType.p2wpkh:
			return `wpkh(${keyExpr})`;
		case EAddressType.p2tr:
			return `tr(${keyExpr})`;
		case EAddressType.p2wsh:
			return `wsh(${keyExpr})`;
	}
};

describe('Descriptor checksum (BIP 380)', () => {
	// External vectors from Bitcoin Core (doc/descriptors.md).
	it('matches the Bitcoin Core wpkh example vector', () => {
		expect(
			descriptorChecksum(
				'wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)'
			)
		).to.equal('cjjspncu');
	});

	it('matches the Bitcoin Core raw example vector', () => {
		expect(descriptorChecksum('raw(deadbeef)')).to.equal('89f8spxm');
	});

	it('returns null for characters outside the descriptor charset', () => {
		expect(descriptorChecksum('wpkh(é)')).to.equal(null);
	});

	it('appendDescriptorChecksum produces body#checksum', () => {
		expect(appendDescriptorChecksum('raw(deadbeef)')).to.equal(
			'raw(deadbeef)#89f8spxm'
		);
	});
});

describe('Wallet.exportDescriptors', function () {
	this.timeout(testTimeout);

	let root: BIP32Interface;
	let wallet: Wallet;

	before(async function () {
		root = bip32.fromSeed(
			bip39.mnemonicToSeedSync(MNEMONIC),
			bitcoin.networks.regtest
		);
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'desctest',
			network,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
	});

	after(async function () {
		await wallet?.stop();
	});

	it('exports checksummed descriptors for all four address types', () => {
		const res = wallet.exportDescriptors();
		if (res.isErr()) throw res.error;
		const info = res.value;
		expect(info.fingerprint).to.equal(FINGERPRINT);
		expect(info.network).to.equal(network);
		expect(info.account).to.equal(0);
		expect(info.watchOnly).to.equal(false);
		expect(info.descriptors).to.have.length(4);
		for (const addressType of SINGLE_SIG_TYPES) {
			const entry = info.descriptors.find((d) => d.addressType === addressType);
			expect(entry, `missing ${addressType}`).to.not.equal(undefined);
			const purpose = PURPOSE[addressType];
			// Exact expected strings from an independent derivation.
			const xpub = root.derivePath(`m/${purpose}'/1'/0'`).neutered().toBase58();
			const origin = `[${FINGERPRINT}/${purpose}h/1h/0h]`;
			expect(entry!.external).to.equal(
				appendDescriptorChecksum(
					wrapExpected(addressType, `${origin}${xpub}/0/*`)
				)
			);
			expect(entry!.internal).to.equal(
				appendDescriptorChecksum(
					wrapExpected(addressType, `${origin}${xpub}/1/*`)
				)
			);
			// Every descriptor must carry an 8-character checksum.
			expect(entry!.external).to.match(
				/#[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8}$/
			);
			expect(entry!.internal).to.match(
				/#[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8}$/
			);
		}
	});

	it('NEVER includes private key material', () => {
		const res = wallet.exportDescriptors();
		if (res.isErr()) throw res.error;
		const serialized = JSON.stringify(res.value);
		expect(serialized).to.not.contain('xprv');
		expect(serialized).to.not.contain('tprv');
		expect(serialized).to.not.contain('prv');
	});

	it('exports a single origin-less descriptor for watch-only wallets', async () => {
		// SLIP-132 vpub input must still export a STANDARD tpub encoding.
		const accountNode = root.derivePath("m/84'/1'/0'");
		const slipNetwork = {
			...bitcoin.networks.regtest,
			bip32: { public: 0x045f1cf6, private: 0x045f18bc }
		};
		const slipRoot = bip32.fromSeed(
			bip39.mnemonicToSeedSync(MNEMONIC),
			slipNetwork
		);
		const vpub = slipRoot.derivePath("m/84'/1'/0'").neutered().toBase58();
		expect(vpub.startsWith('vpub')).to.equal(true);
		const res = await Wallet.createWatchOnly({
			xpub: vpub,
			name: 'descwatch',
			network,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		const watchOnly = res.value;
		const exportRes = watchOnly.exportDescriptors();
		if (exportRes.isErr()) throw exportRes.error;
		const info = exportRes.value;
		expect(info.watchOnly).to.equal(true);
		expect(info.descriptors).to.have.length(1);
		const xpub = accountNode.neutered().toBase58();
		expect(xpub.startsWith('tpub')).to.equal(true);
		// No key origin (master fingerprint unknown), standard tpub encoding.
		expect(info.descriptors[0].external).to.equal(
			appendDescriptorChecksum(`wpkh(${xpub}/0/*)`)
		);
		expect(info.descriptors[0].internal).to.equal(
			appendDescriptorChecksum(`wpkh(${xpub}/1/*)`)
		);
		expect(JSON.stringify(info)).to.not.contain('prv');
		await watchOnly.stop();
	});

	it('uses the account index in the origin path for non-zero accounts', async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'descacct',
			network,
			electrumOptions,
			account: 2
		});
		if (res.isErr()) throw res.error;
		const acctWallet = res.value;
		const exportRes = acctWallet.exportDescriptors();
		if (exportRes.isErr()) throw exportRes.error;
		const p2wpkh = exportRes.value.descriptors.find(
			(d) => d.addressType === EAddressType.p2wpkh
		);
		const xpub = root.derivePath("m/84'/1'/2'").neutered().toBase58();
		expect(p2wpkh!.external).to.equal(
			appendDescriptorChecksum(`wpkh([${FINGERPRINT}/84h/1h/2h]${xpub}/0/*)`)
		);
		await acctWallet.stop();
	});
});
