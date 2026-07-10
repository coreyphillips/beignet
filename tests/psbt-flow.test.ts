/**
 * External-signer PSBT flow tests. Fully OFFLINE: wallets point at an
 * unreachable Electrum server and UTXOs are fabricated locally, so these
 * tests exercise PSBT construction, signer metadata, external signing,
 * validation, finalization and combining without any network. The daemon
 * route section boots a node against the same unreachable Electrum (the
 * tests/cli/onchain-power.test.ts pattern) to exercise validation paths.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import net from 'net';
import tls from 'tls';
import { AddressInfo } from 'net';
import BIP32Factory, { BIP32Interface } from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	getScriptHash,
	IUtxo,
	ok,
	validatePsbtSignature,
	Wallet
} from '../src';
import { startDaemon } from '../src/cli/daemon';
import { BeignetNode } from '../src/cli/beignet-node';
import { BeignetError } from '../src/cli/errors';

bitcoin.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
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

let root: BIP32Interface;
const createdWallets: Wallet[] = [];

/** Fabricates a wallet-owned UTXO for a derived address; no network needed. */
const makeUtxo = async (
	wallet: Wallet,
	{
		index,
		value,
		addressType = EAddressType.p2wpkh,
		changeAddress = false,
		txHash,
		txPos = 0
	}: {
		index: number;
		value: number;
		addressType?: EAddressType;
		changeAddress?: boolean;
		txHash?: string;
		txPos?: number;
	}
): Promise<IUtxo> => {
	const address = await wallet.getAddress({
		index: String(index),
		addressType,
		changeAddress
	});
	const purpose = { p2pkh: 44, p2sh: 49, p2wpkh: 84, p2tr: 86 }[addressType];
	const derivationPath = `m/${purpose}'/1'/0'/${
		changeAddress ? 1 : 0
	}/${index}`;
	const node = wallet.derivePublicNode(derivationPath);
	if (node.isErr()) throw node.error;
	return {
		address,
		index,
		path: derivationPath,
		scriptHash: getScriptHash({ address, network }),
		height: 100,
		tx_hash:
			txHash ??
			Buffer.from(
				bitcoin.crypto.sha256(Buffer.from(`utxo-${addressType}-${index}`))
			).toString('hex'),
		tx_pos: txPos,
		value,
		publicKey: node.value.publicKey.toString('hex')
	};
};

/** Signs every input of a PSBT from its bip32 derivation metadata, acting as
 *  the hardware wallet. */
const signExternally = (psbtBase64: string): string => {
	const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network: regtest });
	for (let i = 0; i < psbt.inputCount; i++) {
		const input = psbt.data.inputs[i];
		if (input.tapBip32Derivation?.length) {
			const keyPair = root.derivePath(input.tapBip32Derivation[0].path);
			const tweaked = keyPair.tweak(
				bitcoin.crypto.taggedHash('TapTweak', input.tapInternalKey!)
			);
			psbt.signInput(i, tweaked);
		} else {
			const derivation = input.bip32Derivation;
			expect(derivation, `input ${i} carries bip32Derivation`).to.not.be
				.undefined;
			psbt.signInput(i, root.derivePath(derivation![0].path));
		}
	}
	return psbt.toBase64();
};

const createWallet = async (
	addressType: EAddressType = EAddressType.p2wpkh
): Promise<Wallet> => {
	const res = await Wallet.create({
		mnemonic: MNEMONIC,
		network,
		addressType,
		electrumOptions
	});
	if (res.isErr()) throw res.error;
	createdWallets.push(res.value);
	// Populates index-0 addresses (including the change address setupTransaction
	// needs); the Electrum sync itself fails harmlessly offline.
	await res.value.refreshWallet({});
	return res.value;
};

const createWatchOnlyWallet = async (): Promise<Wallet> => {
	const xpub = root.derivePath("m/84'/1'/0'").neutered().toBase58();
	const res = await Wallet.createWatchOnly({
		xpub,
		addressType: EAddressType.p2wpkh,
		network,
		electrumOptions
	});
	if (res.isErr()) throw res.error;
	createdWallets.push(res.value);
	await res.value.refreshWallet({});
	return res.value;
};

describe('External-Signer PSBT Flow', async function () {
	this.timeout(testTimeout);

	before(function () {
		root = bip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC), regtest);
	});

	after(async function () {
		await Promise.all(createdWallets.map((w) => w?.stop()));
	});

	describe('buildPsbt', () => {
		let wallet: Wallet;

		before(async () => {
			wallet = await createWallet();
			wallet.data.utxos.push(
				await makeUtxo(wallet, { index: 0, value: 60000 }),
				await makeUtxo(wallet, { index: 1, value: 40000 })
			);
		});

		it('returns a decodable, unsigned PSBT with fee and summaries', async () => {
			const res = await wallet.buildPsbt({
				address: RECIPIENT,
				amount: 80000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (res.isErr()) throw res.error;
			const built = res.value;
			expect(built.fee).to.be.greaterThan(0);
			expect(built.vsizeEstimate).to.be.greaterThan(0);
			expect(built.fee).to.equal(built.vsizeEstimate * built.satsPerByte);
			expect(built.inputs.length).to.equal(2);
			expect(built.outputs.length).to.equal(2); // recipient + change
			expect(built.outputs.map((o) => o.address)).to.include(RECIPIENT);

			const psbt = bitcoin.Psbt.fromBase64(built.psbtBase64, {
				network: regtest
			});
			expect(psbt.inputCount).to.equal(2);
			for (const input of psbt.data.inputs) {
				expect(input.partialSig ?? []).to.have.length(0);
				expect(input.finalScriptWitness).to.be.undefined;
				expect(input.witnessUtxo).to.not.be.undefined;
			}
			// Input value amounts must match the fabricated UTXOs.
			const witnessValues = psbt.data.inputs
				.map((i) => i.witnessUtxo!.value)
				.sort((a, b) => a - b);
			expect(witnessValues).to.deep.equal([40000, 60000]);
		});

		it('carries correct bip32Derivation for every input', async () => {
			const res = await wallet.buildPsbt({
				address: RECIPIENT,
				amount: 50000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (res.isErr()) throw res.error;
			const psbt = bitcoin.Psbt.fromBase64(res.value.psbtBase64, {
				network: regtest
			});
			const masterFingerprint = Buffer.from(root.fingerprint).toString('hex');
			psbt.data.inputs.forEach((input, i) => {
				const derivation = input.bip32Derivation;
				expect(derivation, `input ${i}`).to.not.be.undefined;
				expect(derivation).to.have.length(1);
				expect(derivation![0].masterFingerprint.toString('hex')).to.equal(
					masterFingerprint
				);
				const expectedPubkey = root
					.derivePath(derivation![0].path)
					.publicKey.toString('hex');
				expect(derivation![0].pubkey.toString('hex')).to.equal(expectedPubkey);
			});
		});

		it('includes redeemScript for p2sh-p2wpkh inputs', async () => {
			const p2shWallet = await createWallet(EAddressType.p2sh);
			p2shWallet.data.utxos.push(
				await makeUtxo(p2shWallet, {
					index: 0,
					value: 50000,
					addressType: EAddressType.p2sh
				})
			);
			const res = await p2shWallet.buildPsbt({
				address: RECIPIENT,
				amount: 40000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (res.isErr()) throw res.error;
			const psbt = bitcoin.Psbt.fromBase64(res.value.psbtBase64, {
				network: regtest
			});
			expect(psbt.data.inputs[0].redeemScript).to.not.be.undefined;
			expect(psbt.data.inputs[0].bip32Derivation).to.have.length(1);
		});

		it('includes nonWitnessUtxo for legacy p2pkh inputs', async () => {
			const p2pkhWallet = await createWallet(EAddressType.p2pkh);
			const address = await p2pkhWallet.getAddress({
				index: '0',
				addressType: EAddressType.p2pkh
			});
			// Fabricate the previous transaction paying the p2pkh address so
			// the electrum prev-tx fetch can be stubbed with a consistent hex.
			const prevTx = new bitcoin.Transaction();
			prevTx.addInput(Buffer.alloc(32, 7), 0);
			prevTx.addOutput(bitcoin.address.toOutputScript(address, regtest), 50000);
			p2pkhWallet.data.utxos.push(
				await makeUtxo(p2pkhWallet, {
					index: 0,
					value: 50000,
					addressType: EAddressType.p2pkh,
					txHash: prevTx.getId(),
					txPos: 0
				})
			);
			const electrum = p2pkhWallet.electrum as unknown as {
				getTransactions: () => Promise<unknown>;
			};
			const originalGetTransactions = electrum.getTransactions;
			electrum.getTransactions = async (): Promise<unknown> =>
				ok({ data: [{ result: { hex: prevTx.toHex() } }] });
			try {
				const res = await p2pkhWallet.buildPsbt({
					address: RECIPIENT,
					amount: 40000,
					satsPerByte: 2,
					shuffleOutputs: false
				});
				if (res.isErr()) throw res.error;
				const psbt = bitcoin.Psbt.fromBase64(res.value.psbtBase64, {
					network: regtest
				});
				expect(psbt.data.inputs[0].nonWitnessUtxo).to.not.be.undefined;
				expect(psbt.data.inputs[0].bip32Derivation).to.have.length(1);
			} finally {
				electrum.getTransactions = originalGetTransactions;
			}
		});

		it('includes tapInternalKey and tapBip32Derivation for p2tr inputs', async () => {
			const trWallet = await createWallet(EAddressType.p2tr);
			trWallet.data.utxos.push(
				await makeUtxo(trWallet, {
					index: 0,
					value: 50000,
					addressType: EAddressType.p2tr
				})
			);
			const res = await trWallet.buildPsbt({
				address: RECIPIENT,
				amount: 40000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (res.isErr()) throw res.error;
			const psbt = bitcoin.Psbt.fromBase64(res.value.psbtBase64, {
				network: regtest
			});
			const input = psbt.data.inputs[0];
			expect(input.tapInternalKey).to.not.be.undefined;
			expect(input.tapBip32Derivation).to.have.length(1);
			expect(input.tapBip32Derivation![0].pubkey.length).to.equal(32);
			expect(input.tapBip32Derivation![0].path).to.equal("m/86'/1'/0'/0/0");
			// x-only pubkey must match the wallet key at that path.
			const expected = root
				.derivePath("m/86'/1'/0'/0/0")
				.publicKey.subarray(1)
				.toString('hex');
			expect(input.tapBip32Derivation![0].pubkey.toString('hex')).to.equal(
				expected
			);
		});

		it('fails when there are no UTXOs', async () => {
			const empty = await createWallet();
			const res = await empty.buildPsbt({
				address: RECIPIENT,
				amount: 1000
			});
			expect(res.isErr()).to.equal(true);
		});

		it('fails when no outputs are specified', async () => {
			const res = await wallet.buildPsbt({});
			expect(res.isErr()).to.equal(true);
		});
	});

	describe('Round trip on a WATCH-ONLY wallet (build -> external sign -> import)', () => {
		let watchOnly: Wallet;
		let builtBase64: string;

		before(async () => {
			watchOnly = await createWatchOnlyWallet();
			watchOnly.data.utxos.push(
				await makeUtxo(watchOnly, { index: 0, value: 60000 }),
				await makeUtxo(watchOnly, { index: 1, value: 40000 })
			);
		});

		it('buildPsbt works on the watch-only wallet and uses the xpub parent fingerprint', async () => {
			const res = await watchOnly.buildPsbt({
				address: RECIPIENT,
				amount: 80000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (res.isErr()) throw res.error;
			builtBase64 = res.value.psbtBase64;
			const psbt = bitcoin.Psbt.fromBase64(builtBase64, { network: regtest });
			const accountNode = root.derivePath("m/84'/1'/0'");
			const expectedFingerprint = Buffer.alloc(4);
			expectedFingerprint.writeUInt32BE(accountNode.parentFingerprint, 0);
			psbt.data.inputs.forEach((input) => {
				expect(
					input.bip32Derivation![0].masterFingerprint.toString('hex')
				).to.equal(expectedFingerprint.toString('hex'));
			});
		});

		it('externally signed PSBT imports, validates and finalizes without broadcasting', () => {
			const signed = signExternally(builtBase64);
			const importRes = watchOnly.importSignedPsbt(signed);
			if (importRes.isErr()) throw importRes.error;
			const { txHex, txid } = importRes.value;
			const tx = bitcoin.Transaction.fromHex(txHex);
			expect(tx.getId()).to.equal(txid);
			expect(tx.ins.length).to.equal(2);
			expect(tx.outs.length).to.equal(2);
			// Independently verify each input signature against the PSBT.
			const check = bitcoin.Psbt.fromBase64(signed, { network: regtest });
			expect(
				check.validateSignaturesOfAllInputs(validatePsbtSignature)
			).to.equal(true);
		});

		it('rejects a PSBT with no signatures', () => {
			const res = watchOnly.importSignedPsbt(builtBase64);
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('missing a signature');
			}
		});

		it('rejects a PSBT whose signature was tampered with', () => {
			const psbt = bitcoin.Psbt.fromBase64(signExternally(builtBase64), {
				network: regtest
			});
			// Corrupt a byte inside the DER-encoded s value: the signature stays
			// decodable but no longer verifies.
			const signature = psbt.data.inputs[0].partialSig![0].signature;
			signature[signature.length - 10] ^= 0xff;
			const res = watchOnly.importSignedPsbt(psbt.toBase64());
			expect(res.isErr()).to.equal(true);
		});

		it('rejects a PSBT with a partially signed input set', () => {
			const psbt = bitcoin.Psbt.fromBase64(builtBase64, { network: regtest });
			const derivation = psbt.data.inputs[0].bip32Derivation![0];
			psbt.signInput(0, root.derivePath(derivation.path));
			const res = watchOnly.importSignedPsbt(psbt.toBase64());
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('Input 1');
			}
		});

		it('rejects garbage input', () => {
			expect(watchOnly.importSignedPsbt('not-a-psbt').isErr()).to.equal(true);
			expect(watchOnly.importSignedPsbt('').isErr()).to.equal(true);
		});

		it('broadcastTransaction is exposed and fails gracefully offline', async () => {
			const signed = signExternally(builtBase64);
			const importRes = watchOnly.importSignedPsbt(signed);
			if (importRes.isErr()) throw importRes.error;
			const res = await watchOnly.broadcastTransaction(importRes.value.txHex);
			expect(res.isErr()).to.equal(true);
		});
	});

	describe('Taproot round trip on a full wallet', () => {
		it('builds, signs externally (tweaked schnorr) and imports', async () => {
			const trWallet = await createWallet(EAddressType.p2tr);
			trWallet.data.utxos.push(
				await makeUtxo(trWallet, {
					index: 2,
					value: 70000,
					addressType: EAddressType.p2tr
				})
			);
			const built = await trWallet.buildPsbt({
				address: RECIPIENT,
				amount: 60000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (built.isErr()) throw built.error;
			const signed = signExternally(built.value.psbtBase64);
			const importRes = trWallet.importSignedPsbt(signed);
			if (importRes.isErr()) throw importRes.error;
			const tx = bitcoin.Transaction.fromHex(importRes.value.txHex);
			expect(tx.ins[0].witness.length).to.equal(1); // key-path spend
		});
	});

	describe('combinePsbts', () => {
		it('merges two partially signed copies of the same PSBT', async () => {
			const wallet = await createWallet();
			wallet.data.utxos.push(
				await makeUtxo(wallet, { index: 3, value: 30000 }),
				await makeUtxo(wallet, { index: 4, value: 30000 })
			);
			const built = await wallet.buildPsbt({
				address: RECIPIENT,
				amount: 50000,
				satsPerByte: 2,
				shuffleOutputs: false
			});
			if (built.isErr()) throw built.error;

			const copyA = bitcoin.Psbt.fromBase64(built.value.psbtBase64, {
				network: regtest
			});
			const copyB = bitcoin.Psbt.fromBase64(built.value.psbtBase64, {
				network: regtest
			});
			copyA.signInput(
				0,
				root.derivePath(copyA.data.inputs[0].bip32Derivation![0].path)
			);
			copyB.signInput(
				1,
				root.derivePath(copyB.data.inputs[1].bip32Derivation![0].path)
			);

			const combined = wallet.combinePsbts([
				copyA.toBase64(),
				copyB.toBase64()
			]);
			if (combined.isErr()) throw combined.error;
			const merged = bitcoin.Psbt.fromBase64(combined.value, {
				network: regtest
			});
			expect(merged.data.inputs[0].partialSig).to.have.length(1);
			expect(merged.data.inputs[1].partialSig).to.have.length(1);

			const importRes = wallet.importSignedPsbt(combined.value);
			expect(importRes.isOk()).to.equal(true);
		});

		it('rejects fewer than two PSBTs', async () => {
			const wallet = await createWallet();
			expect(wallet.combinePsbts([]).isErr()).to.equal(true);
			expect(wallet.combinePsbts(['cHNidP8=']).isErr()).to.equal(true);
		});
	});
});

describe('Daemon PSBT routes (offline validation paths)', function () {
	this.timeout(testTimeout);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	const httpJson = (
		method: string,
		urlPath: string,
		body?: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> => {
		return new Promise((resolve, reject) => {
			const payload = body ? JSON.stringify(body) : undefined;
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					path: urlPath,
					method,
					headers: payload
						? {
								'Content-Type': 'application/json',
								'Content-Length': Buffer.byteLength(payload)
						  }
						: {}
				},
				(res) => {
					const chunks: Buffer[] = [];
					res.on('data', (chunk: Buffer) => chunks.push(chunk));
					res.on('end', () => {
						try {
							resolve({
								status: res.statusCode!,
								body: JSON.parse(Buffer.concat(chunks).toString())
							});
						} catch {
							resolve({ status: res.statusCode!, body: {} });
						}
					});
				}
			);
			req.on('error', reject);
			if (payload) req.write(payload);
			req.end();
		});
	};

	before(async function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-psbt-routes-'));
		// Electrum intentionally unreachable: only validation paths run here.
		({ server, node } = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			daemonPort: 0
		}));
		port = (server.address() as AddressInfo).port;
	});

	after(async function () {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('exposes the three PSBT methods on BeignetNode', () => {
		expect(node.buildPsbt).to.be.a('function');
		expect(node.importSignedPsbt).to.be.a('function');
		expect(node.combinePsbts).to.be.a('function');
	});

	it('POST /psbt/build rejects missing outputs', async () => {
		const res = await httpJson('POST', '/psbt/build', {});
		expect(res.body.ok).to.equal(false);
		expect((res.body.error as { code: string }).code).to.equal(
			'INVALID_PARAMS'
		);
	});

	it('POST /psbt/build rejects malformed outputs', async () => {
		const res = await httpJson('POST', '/psbt/build', {
			outputs: [{ address: RECIPIENT }]
		});
		expect(res.body.ok).to.equal(false);
		expect((res.body.error as { code: string }).code).to.equal(
			'INVALID_PARAMS'
		);
	});

	it('POST /psbt/build fails cleanly with no UTXOs', async () => {
		const res = await httpJson('POST', '/psbt/build', {
			outputs: [{ address: RECIPIENT, amountSats: 1000 }]
		});
		expect(res.body.ok).to.equal(false);
		expect((res.body.error as { code: string }).code).to.equal(
			'PSBT_BUILD_FAILED'
		);
	});

	it('POST /psbt/import-signed rejects missing psbtBase64', async () => {
		const res = await httpJson('POST', '/psbt/import-signed', {});
		expect(res.body.ok).to.equal(false);
		expect((res.body.error as { code: string }).code).to.equal(
			'INVALID_PARAMS'
		);
	});

	it('POST /psbt/import-signed rejects a malformed PSBT', async () => {
		const res = await httpJson('POST', '/psbt/import-signed', {
			psbtBase64: 'not-a-psbt'
		});
		expect(res.body.ok).to.equal(false);
		expect((res.body.error as { code: string }).code).to.equal(
			'PSBT_IMPORT_FAILED'
		);
	});

	it('POST /psbt/combine rejects fewer than two PSBTs', async () => {
		const res = await httpJson('POST', '/psbt/combine', {
			psbts: ['cHNidP8=']
		});
		expect(res.body.ok).to.equal(false);
		expect((res.body.error as { code: string }).code).to.equal(
			'INVALID_PARAMS'
		);
	});

	it('POST /psbt/combine surfaces malformed PSBTs as PSBT_COMBINE_FAILED', async () => {
		const res = await httpJson('POST', '/psbt/combine', {
			psbts: ['garbage-a', 'garbage-b']
		});
		expect(res.body.ok).to.equal(false);
		expect((res.body.error as { code: string }).code).to.equal(
			'PSBT_COMBINE_FAILED'
		);
	});

	it('node.buildPsbt validates the fee rate', async () => {
		try {
			await node.buildPsbt([{ address: RECIPIENT, amountSats: 1000 }], -1);
			throw new Error('expected INVALID_PARAMS');
		} catch (e) {
			expect(e).to.be.instanceOf(BeignetError);
			expect((e as BeignetError).code).to.equal('INVALID_PARAMS');
		}
	});
});
