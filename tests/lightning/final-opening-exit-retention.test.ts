import { expect } from 'chai';
import { mnemonicToSeedSync } from 'bip39';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	bip32RootFromSeed,
	deriveChannelKeys
} from '../../src/lightning/keys/wallet-keys';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { generateFinalDaemonWallet } from '../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { alice, bob, signingFixture } from './helpers/final-opening-signing';

describe('Enrolled daemon retains an enforceable exit', () => {
	for (const contributes of [true, false]) {
		it(
			'recovers device-ahead authorization and detects a lost exit for ' +
				(contributes ? 'a wallet funder' : 'the zero-input signer'),
			() => {
				const dir = fs.mkdtempSync(
					path.join(os.tmpdir(), 'opening-obligation-')
				);
				const file = path.join(dir, 'wallet.db');
				const snapshot = path.join(dir, 'before-exit.db');
				const enrolled = generateFinalDaemonWallet();
				const root = bip32RootFromSeed(mnemonicToSeedSync(enrolled.mnemonic));
				const keys = deriveChannelKeys(root, 1, 7);
				const bp = keys.channelBasepoints;
				const local = {
					binding: enrolled.binding,
					root,
					keys,
					index: 7,
					points: {
						fundingPubkey: bp.fundingPubkey.toString('hex'),
						revocationBasepoint: bp.revocationBasepoint.toString('hex'),
						paymentBasepoint: bp.paymentBasepoint.toString('hex'),
						delayedPaymentBasepoint: bp.delayedPaymentBasepoint.toString('hex'),
						htlcBasepoint: bp.htlcBasepoint.toString('hex'),
						firstPerCommitmentPoint: getPublicKey(
							generateFromSeed(keys.perCommitmentSeed, MAX_INDEX)
						).toString('hex')
					}
				};
				const peer = contributes ? bob : alice;
				const opening = contributes
					? signingFixture(true, local, peer)
					: signingFixture(true, peer, local);
				const own = contributes ? opening : opening.counterpart;
				const theirs = contributes ? opening.counterpart : opening;
				const id = opening.id;
				let store = SqliteStorage.createFinalWallet(file, enrolled.binding);
				const other = SqliteStorage.createFinalWallet(
					path.join(dir, 'peer.db'),
					peer.binding
				);
				try {
					store.rememberFinalOpening(own.candidate);
					other.rememberFinalOpening(theirs.candidate);
					const nonce = store.finalOpeningTxComplete(id, keys.fundingPrivkey);
					store.rememberFinalPeerTxComplete(
						id,
						other.finalOpeningTxComplete(id, peer.keys.fundingPrivkey)
					);
					other.rememberFinalPeerTxComplete(id, nonce);
					if (contributes) {
						const share = store.signFinalPeerCommitment(
							id,
							own.terms,
							root,
							local.index
						);
						other.acceptFinalPeerCommitment(
							id,
							theirs.terms,
							peer.root,
							peer.index,
							share
						);
					}
					store.close();
					fs.copyFileSync(file, snapshot);
					store = SqliteStorage.openFinalWallet(file, enrolled.binding);
					store.assertFinalDaemonIdentity(enrolled.binding.nodeId);
					const peerShare = other.signFinalPeerCommitment(
						id,
						theirs.terms,
						peer.root,
						peer.index
					);
					store.acceptFinalPeerCommitment(
						id,
						own.terms,
						root,
						local.index,
						peerShare
					);
					if (contributes) {
						expect(() =>
							store.finalOpeningTxSignatures(id, () => {
								throw new Error('test wallet unavailable');
							})
						).to.throw('test wallet unavailable');
						expect(store.loadFinalLocalTxSignatures(id)).to.equal(null);
					} else {
						store.signFinalPeerCommitment(id, own.terms, root, local.index);
					}
					store.close();
					store = SqliteStorage.openFinalWallet(file, enrolled.binding);
					store.assertFinalDaemonIdentity(enrolled.binding.nodeId);
					expect(store.loadFinalOpeningExit(id)).to.be.instanceOf(Buffer);
					store.close();
					fs.copyFileSync(snapshot, file);
					store = SqliteStorage.openFinalWallet(file, enrolled.binding);
					expect(() =>
						store.assertFinalDaemonIdentity(enrolled.binding.nodeId)
					).to.throw(/exit/i);
				} finally {
					store.close();
					other.close();
					fs.rmSync(dir, { recursive: true, force: true });
				}
			}
		);
	}
});
