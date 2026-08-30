/**
 * Direct funding, wallet side (issue #613, LFBW port #532 workstream 4D).
 *
 * The payer engine lives in `src/lightning/direct-funding/sender` and knows
 * nothing about wallets. This is the adapter that gives it coins: it turns the
 * on-chain wallet into `IDfSenderWallet`, and it is where every piece of key
 * material stops. The engine gets a signer that can produce exactly two things,
 * an ownership proof over a digest and a witness for one input of one
 * transaction, and no way to ask for anything else.
 *
 * The signing itself is the ordinary wallet path, the same one
 * `wallet-funding-provider.ts` uses for a splice-in contribution: taproot key
 * spend over `hashForWitnessV1` with the BIP 86 tweak, P2WPKH over
 * `hashForWitnessV0`, and in both cases a check that the key the wallet derived
 * for the coin's path is the key the coin's script commits to.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import type { Wallet } from '../wallet';
import type { IUtxo } from '../types';
import {
	scriptKind,
	taprootTweakPrivateKey
} from '../lightning/wallet/wallet-funding-provider';
import { schnorrSign } from '../lightning/offer/schnorr';
import { getPublicKey } from '../lightning/crypto/ecdh';
import {
	IDfCoinSigner,
	IDfSenderCoin,
	IDfSenderWallet
} from '../lightning/direct-funding';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

/**
 * The narrow slice of the on-chain wallet this needs. Declared structurally so
 * the adapter can be driven by a stub in tests, and so nothing here can reach
 * for a wallet method the direct-funding path has no business calling.
 */
export type IDfWallet = Pick<
	Wallet,
	| 'listUtxos'
	| 'isUtxoFrozen'
	| 'listFrozenUtxos'
	| 'freezeUtxo'
	| 'unfreezeUtxo'
	| 'getPrivateKey'
	| 'getChangeAddress'
	| 'transactions'
	| 'electrum'
>;

/**
 * Marks a freeze as this payer's reservation. The wallet answers Ok for a coin
 * that is already frozen, so the result alone cannot say whose reservation one
 * is; an operator's freeze carries no tag and the funding provider's pledges
 * carry theirs. Taking one of those as our own would sign a coin somebody
 * withheld, and releasing it at the end would delete their entry.
 */
const DF_FREEZE_TAG = 'direct-funding';

/**
 * Whether a wallet transaction is mined. Electrum reports an unconfirmed
 * transaction at height 0 and one with an unconfirmed parent at -1, so a
 * truthiness test would read the second as confirmed and release the payer's
 * coin against a funding still sitting in the mempool.
 */
function isConfirmed(height?: number): boolean {
	return (height ?? 0) > 0;
}

/**
 * Adapt the on-chain wallet for the payer engine.
 *
 * @param wallet The on-chain wallet.
 * @param network bitcoinjs network, for address decoding and key derivation.
 */
export function directFundingWallet(
	wallet: IDfWallet,
	network: bitcoin.Network
): IDfSenderWallet {
	/** The coin's scriptPubKey, or null when its address does not decode. */
	const scriptFor = (address: string): Buffer | null => {
		try {
			return bitcoin.address.toOutputScript(address, network);
		} catch {
			return null;
		}
	};

	/** The frozen-list entry for an outpoint, which carries whose freeze it is. */
	const frozenEntry = (txidHex: string, vout: number): IUtxo | undefined =>
		wallet
			.listFrozenUtxos()
			.find((f) => f.tx_hash === txidHex && f.tx_pos === vout);

	return {
		listSpendable(): IDfSenderCoin[] {
			const coins: IDfSenderCoin[] = [];
			for (const utxo of wallet.listUtxos() ?? []) {
				// A frozen coin is one another funding already committed, or one the
				// operator withheld. Either way it is not ours to offer.
				if (wallet.isUtxoFrozen(utxo.tx_hash, utxo.tx_pos)) continue;
				const script = scriptFor(utxo.address);
				// Only the two kinds whose witness a receiver can verify and whose
				// ownership proof the protocol defines.
				if (!script || !scriptKind(script)) continue;
				coins.push({
					txidHex: utxo.tx_hash,
					vout: utxo.tx_pos,
					valueSat: BigInt(utxo.value),
					script,
					height: utxo.height
				});
			}
			return coins;
		},

		findCoin(txidHex: string, vout: number): IDfSenderCoin | null {
			// Frozen coins included: this is how a resumed attempt finds the coin it
			// froze before the run that took it died. A freeze is this payer's own
			// reservation, not a coin that went somewhere else.
			const utxo = (wallet.listUtxos() ?? []).find(
				(u) => u.tx_hash === txidHex && u.tx_pos === vout
			);
			if (!utxo) return null;
			const script = scriptFor(utxo.address);
			if (!script || !scriptKind(script)) return null;
			return {
				txidHex: utxo.tx_hash,
				vout: utxo.tx_pos,
				valueSat: BigInt(utxo.value),
				script,
				height: utxo.height
			};
		},

		ownsOutpoint(txidHex: string, vout: number): boolean {
			// Frozen coins included on purpose: the question is whether spending
			// this outpoint moves OUR money, and a freeze does not change that.
			return (wallet.listUtxos() ?? []).some(
				(u) => u.tx_hash === txidHex && u.tx_pos === vout
			);
		},

		async getTransaction(txidHex: string): Promise<Buffer> {
			const result = await wallet.electrum.getTransactions({
				txHashes: [{ tx_hash: txidHex }]
			});
			if (result.isErr()) {
				throw new Error(`could not fetch transaction ${txidHex}`);
			}
			const hex = result.value.data?.[0]?.result?.hex;
			if (!hex) throw new Error(`transaction ${txidHex} is unavailable`);
			return Buffer.from(hex, 'hex');
		},

		async changeScript(): Promise<Buffer> {
			const result = await wallet.getChangeAddress();
			if (result.isErr()) {
				throw new Error(
					`could not derive a change address: ${result.error.message}`
				);
			}
			const script = scriptFor(result.value.address);
			if (!script) {
				throw new Error(
					'the wallet change address does not decode on this network'
				);
			}
			return script;
		},

		signerFor(coin: IDfSenderCoin): IDfCoinSigner | null {
			const utxo = (wallet.listUtxos() ?? []).find(
				(u) => u.tx_hash === coin.txidHex && u.tx_pos === coin.vout
			);
			if (!utxo) return null;
			const kind = scriptKind(coin.script);
			if (!kind) return null;
			let keyPair: ReturnType<typeof ECPair.fromWIF>;
			try {
				keyPair = ECPair.fromWIF(wallet.getPrivateKey(utxo.path), network);
			} catch {
				// Watch-only, or a path this wallet cannot derive.
				return null;
			}
			const pubkey = Buffer.from(keyPair.publicKey);
			// The same check the splice-input path makes: a derived key that does
			// not match the one recorded for the coin would produce a witness that
			// cannot spend it, and the failure would only surface after broadcast.
			if (utxo.publicKey && pubkey.toString('hex') !== utxo.publicKey)
				return null;
			const privKey = Buffer.from(keyPair.privateKey!);

			if (kind === 'p2tr') {
				const tweaked = taprootTweakPrivateKey(privKey, pubkey);
				return {
					kind,
					// The x-only OUTPUT key, not the internal one: the ownership proof
					// is a Schnorr signature by the tweaked key, and the receiver lifts
					// the key it verifies under straight out of the scriptPubKey. The
					// internal key would name a key the signature does not belong to,
					// and 32 bytes is also what tells the receiver to verify under
					// Schnorr rather than ECDSA.
					ownershipPubkey: getPublicKey(tweaked).subarray(1, 33),
					signOwnership: (digest): Buffer => schnorrSign(digest, tweaked),
					signInput: (tx, inputIndex, prevouts): Buffer[] => [
						// SIGHASH_DEFAULT, the 64-byte form: this is an ordinary wallet
						// input in a transaction the receiver's channel assembles, not a
						// BOLT 2 tx_signatures signature, so the explicit ALL byte the
						// splice path emits is not required here.
						schnorrSign(
							tx.hashForWitnessV1(
								inputIndex,
								prevouts.scripts,
								prevouts.values.map((v) => Number(v)),
								bitcoin.Transaction.SIGHASH_DEFAULT
							),
							tweaked
						)
					]
				};
			}

			const scriptCode = bitcoin.payments.p2pkh({ pubkey, network }).output!;
			return {
				kind,
				ownershipPubkey: pubkey,
				signOwnership: (digest): Buffer =>
					Buffer.from(ecc.sign(digest, privKey)),
				signInput: (tx, inputIndex): Buffer[] => {
					const sighash = tx.hashForWitnessV0(
						inputIndex,
						scriptCode,
						Number(coin.valueSat),
						bitcoin.Transaction.SIGHASH_ALL
					);
					return [
						bitcoin.script.signature.encode(
							Buffer.from(ecc.sign(sighash, privKey)),
							bitcoin.Transaction.SIGHASH_ALL
						),
						pubkey
					];
				}
			};
		},

		async freezeUtxo(txidHex: string, vout: number): Promise<boolean> {
			const held = frozenEntry(txidHex, vout);
			// A freeze already on the coin is only a reservation this payer may sign
			// against when this payer took it. Anyone else's is a coin withheld from
			// us, and the wallet's Ok would otherwise read as our own.
			if (held) return held.freezeTag === DF_FREEZE_TAG;
			const result = await wallet.freezeUtxo({
				txid: txidHex,
				index: vout,
				tag: DF_FREEZE_TAG
			});
			return result.isOk();
		},

		async unfreezeUtxo(txidHex: string, vout: number): Promise<boolean> {
			// Ours only. A payment settling must not lift the freeze an operator put
			// on the same coin, which outlives this payment by design.
			if (frozenEntry(txidHex, vout)?.freezeTag !== DF_FREEZE_TAG) return false;
			const result = await wallet.unfreezeUtxo({ txid: txidHex, index: vout });
			return result.isOk();
		},

		blockHeight(): number {
			// The stored header, which is what every other height question in this
			// wallet reads. A node that has not synced one yet answers 0, and the
			// payer refuses a future-locked transaction rather than guess.
			try {
				return wallet.electrum.getBlockHeader()?.height ?? 0;
			} catch {
				return 0;
			}
		},

		txStatus(txidHex: string): { known: boolean; confirmed: boolean } | null {
			const tx = wallet.transactions[txidHex];
			if (!tx) return null;
			return { known: true, confirmed: isConfirmed(tx.height) };
		},

		confirmedSpendOf(txidHex: string, vout: number): string | null {
			// The coin is ours, so the only thing that can double-spend it is this
			// wallet, and this wallet indexes its own transactions. Only a CONFIRMED
			// one counts: rev 2 makes a payment FAILED on a conflict that confirmed,
			// never on one merely seen.
			for (const tx of Object.values(wallet.transactions)) {
				if (!isConfirmed(tx.height)) continue;
				for (const vin of tx.vin) {
					if (!('txid' in vin)) continue;
					if (vin.txid === txidHex && vin.vout === vout) return tx.txid;
				}
			}
			return null;
		}
	};
}
