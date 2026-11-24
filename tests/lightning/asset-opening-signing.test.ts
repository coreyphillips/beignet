import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { mnemonicToSeedSync } from 'bip39';
import { payments, Transaction } from 'bitcoinjs-lib';
import { tweakTaprootKeyPathPrivkey } from '../../src/lightning/script/commitment-taproot';
import { FinalOpeningTransport } from '../../src/lightning/channel/final-opening-transport';
import { MessageType } from '../../src/lightning/message/types';
import type { IAuxiliaryDualFunding } from '../../src/lightning/channel/asset-opening-provider';
import { assetOpeningOutputClaims } from '../../src/lightning/chain/asset-opening-claims';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';
import { ASSET_OPENING_TYPE_HEX } from '../../src/lightning/features/asset-opening';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { bip32RootFromSeed } from '../../src/lightning/keys/wallet-keys';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { generateFinalDaemonWallet } from '../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { ecc } from '../../src/utils/ecc';
import {
	boundParticipant,
	signingFixture
} from './helpers/final-opening-signing';
import { otherOpeningView } from './helpers/final-opening-commitment';

function contributor() {
	const { binding, mnemonic } = generateFinalDaemonWallet(false, true);
	return boundParticipant(
		bip32RootFromSeed(mnemonicToSeedSync(mnemonic)),
		1,
		binding
	);
}

describe('Original device dual-funded opening signatures', function () {
	this.timeout(90000);
	it('retains both asset exits before wallet witness authorization and replays after restart', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-open-signer-'));
		const alice = contributor(),
			bob = contributor();
		const file = path.join(dir, 'a.db');
		let a = SqliteStorage.createFinalWallet(file, alice.binding);
		const b = SqliteStorage.createFinalWallet(
			path.join(dir, 'b.db'),
			bob.binding
		);
		try {
			const { candidate, terms, id, funding } = signingFixture(
				false,
				alice,
				bob
			);
			const root = Buffer.alloc(32, 17);
			candidate.channelType = ASSET_OPENING_TYPE_HEX;
			const out = funding.outs[candidate.fundingOutputIndex];
			out.script = createTaprootFundingScript(
				alice.keys.channelBasepoints.fundingPubkey,
				bob.keys.channelBasepoints.fundingPubkey,
				undefined,
				root
			).p2trOutput;
			const prevs = candidate.inputs.map((input, i) => {
				const secret = Buffer.alloc(32, 31 + i);
				const anchor = payments.p2tr({
					internalPubkey: getPublicKey(secret).subarray(1),
					scriptTree: { output: Buffer.from('6a0142', 'hex') }
				});
				const tx = Transaction.fromHex(input.prevTxHex);
				tx.outs[0].script = anchor.output!;
				funding.ins[i].hash = tx.getHash();
				input.prevTxHex = tx.toHex();
				return { tx, secret: tweakTaprootKeyPathPrivkey(secret, anchor.hash!) };
			});
			candidate.fundingTxHex = funding.toHex();
			const counterpart = otherOpeningView(candidate, terms);
			const side = (n: number) => ({
				toLocal: { script: '6a01' + n.toString(16).padStart(2, '0') },
				toRemote: { script: '6a00' },
				proofs: Buffer.from([n]).toString('hex')
			});
			const evidence = {
				fundingRoot: root.toString('hex'),
				layoutDigest: '23'.repeat(32),
				finalDigest: '24'.repeat(32),
				fundingProofs: '91',
				local: side(1),
				remote: side(2)
			};
			a.allocateFinalChannelKeyIndex(1);
			b.allocateFinalChannelKeyIndex(1);
			const preview = a.previewAssetOpeningTxComplete(
				candidate,
				root,
				alice.keys.fundingPrivkey,
				1
			);
			expect(() =>
				a.previewAssetOpeningTxComplete(
					candidate,
					Buffer.alloc(32, 19),
					alice.keys.fundingPrivkey,
					1
				)
			).to.throw();
			const second = (p: typeof alice) =>
				getPublicKey(
					generateFromSeed(p.keys.perCommitmentSeed, MAX_INDEX - 1n)
				).toString('hex');
			const remember = (proofs: typeof evidence) =>
				a.rememberAssetOpeningSession(
					candidate,
					bob.binding.nodeId,
					terms,
					1,
					second(bob),
					proofs
				);
			expect(() =>
				remember({ ...evidence, local: { ...evidence.local, proofs: '' } })
			).to.throw();
			remember(evidence);
			b.rememberAssetOpeningSession(
				counterpart.candidate,
				alice.binding.nodeId,
				counterpart.terms,
				1,
				second(alice),
				{ ...evidence, local: evidence.remote, remote: evidence.local }
			);
			expect(() =>
				remember({ ...evidence, finalDigest: '25'.repeat(32) })
			).to.throw();
			expect(() => a.prepareAssetOpeningWitnesses(id)).to.throw();
			const nb = b.finalOpeningTxComplete(id, bob.keys.fundingPrivkey);
			a.saveAssetOpenStage(id, 'peerNonce', nb);
			a.close();
			a = SqliteStorage.openFinalWallet(file, alice.binding);
			const reconnect = new FinalOpeningTransport(
				{ storage: a, root: alice.root },
				async () => 'unspent',
				() => null,
				() => undefined,
				() => undefined,
				() => undefined
			);
			reconnect.reconnected(bob.binding.nodeId);
			expect(
				a.loadFinalLocalTxComplete(id),
				'restore the promised nonce before reestablish'
			).to.deep.equal(preview);
			expect(
				a.loadFinalPeerTxComplete(id),
				'recover the peer nonce from the construction journal'
			).to.deep.equal(nb);
			const na = a.finalOpeningTxComplete(id, alice.keys.fundingPrivkey);
			b.rememberFinalPeerTxComplete(id, na);
			const sa = a.signFinalPeerCommitment(id, terms, alice.root, 1);
			const sb = b.signFinalPeerCommitment(id, counterpart.terms, bob.root, 1);
			expect(() => a.prepareAssetOpeningWitnesses(id)).to.throw();
			const beforeExit = path.join(dir, 'before-exit');
			a.close();
			fs.copyFileSync(file, beforeExit);
			a = SqliteStorage.openFinalWallet(file, alice.binding);
			const ea = a.acceptFinalPeerCommitment(id, terms, alice.root, 1, sb);
			const eb = b.acceptFinalPeerCommitment(
				id,
				counterpart.terms,
				bob.root,
				1,
				sa
			);
			expect(ea.equals(eb)).to.equal(false);
			for (const raw of [ea, eb]) {
				const tx = Transaction.fromBuffer(raw);
				expect(
					ecc.verifySchnorr(
						tx.hashForWitnessV1(0, [out.script], [out.value], 0),
						out.script.subarray(2),
						tx.ins[0].witness[0]
					)
				).to.equal(true);
			}
			a.close();
			a = SqliteStorage.openFinalWallet(file, alice.binding);
			expect(a.loadAssetOpeningEvidence(id)).to.deep.equal(evidence);
			expect(a.prepareAssetOpeningWitnesses(id).tx.toHex()).to.equal(
				funding.toHex()
			);
			expect(a.signFinalPeerCommitment(id, terms, alice.root, 1)).to.deep.equal(
				sa
			);
			expect(a.loadFinalOpeningExit(id)).to.deep.equal(ea);
			const signed = (tx: Transaction, indices: readonly number[]) =>
				indices.map((i) => [
					Buffer.from(
						ecc.signSchnorr(
							tx.hashForWitnessV1(
								i,
								prevs.map((p) => p.tx.outs[0].script),
								prevs.map((p) => p.tx.outs[0].value),
								0
							),
							prevs[i].secret
						)
					)
				]);
			let fallback = 0;
			expect(() =>
				a.finalOpeningTxSignatures(id, () => {
					fallback++;
					return [];
				})
			).to.throw();
			expect(fallback).to.equal(0);
			expect(() =>
				a.storeAssetOpeningWitnesses(id, [[Buffer.alloc(64)]])
			).to.throw();
			const beforeFunding = path.join(dir, 'before-funding');
			a.close();
			fs.copyFileSync(file, beforeFunding);
			a = SqliteStorage.openFinalWallet(file, alice.binding);
			const imports: string[] = [],
				sent: MessageType[] = [],
				errors: string[] = [];
			let spendable = false,
				releaseImport: (() => void) | undefined,
				signCalls = 0;
			const provider = {
				signFunding: async (_candidate, proofs, tx, indices) => {
					expect(a.loadFinalOpeningExit(id)).to.deep.equal(ea);
					expect(proofs.toString('hex')).to.equal(evidence.fundingProofs);
					expect(tx.toHex()).to.equal(funding.toHex());
					signCalls++;
					return signed(tx, indices);
				},
				confirmFunding: async () => {
					imports.push('confirm');
					await new Promise<void>((done) => (releaseImport = done));
				},
				retractFunding: async () => {
					imports.push('retract');
				}
			} as Partial<IAuxiliaryDualFunding> as IAuxiliaryDualFunding;
			const wire = new FinalOpeningTransport(
				{ storage: a, root: alice.root, dualFunding: provider },
				async () => (spendable ? 'unspent' : 'spent-or-missing'),
				() => {
					throw new Error('Unexpected generic wallet');
				},
				(_peer, type) => {
					sent.push(type);
					if (type === MessageType.TX_SIGNATURES)
						expect(a.loadFinalLocalTxSignatures(id)).to.be.instanceOf(Buffer);
				},
				() => undefined,
				(_id, error) => errors.push(error)
			);
			const tick = () => new Promise<void>((done) => setImmediate(done));
			wire.opened(bob.binding.nodeId, id);
			wire.queue(bob.binding.nodeId, id);
			await tick();
			expect(signCalls).to.equal(0);
			spendable = true;
			wire.queue(bob.binding.nodeId, id);
			await tick();
			expect(
				signCalls,
				'larger input holder must wait for the peer witnesses'
			).to.equal(0);
			const bWire = b.storeAssetOpeningWitnesses(id, signed(funding, [1]));
			spendable = false;
			wire.queue(bob.binding.nodeId, id, {
				type: MessageType.TX_SIGNATURES,
				payload: bWire
			});
			await tick();
			expect(signCalls).to.equal(0);
			spendable = true;
			wire.queue(bob.binding.nodeId, id, {
				type: MessageType.TX_SIGNATURES,
				payload: bWire
			});
			await tick();
			expect(signCalls, errors.join(' ')).to.equal(1);
			const aWire = a.loadFinalLocalTxSignatures(id)!;
			const full = a.loadFinalFundingTransaction(id)!;
			const confirmed = Transaction.fromBuffer(full);
			const impostor = confirmed.clone();
			impostor.outs[0].value--;
			expect(() => b.rememberObservedAssetFunding(id, impostor)).to.throw();
			const forged = confirmed.clone();
			forged.setWitness(0, [Buffer.alloc(64, 7)]);
			expect(() => b.rememberObservedAssetFunding(id, forged)).to.throw();
			expect(b.loadFinalPeerTxSignatures(id)).to.equal(null);
			b.rememberObservedAssetFunding(id, confirmed);
			expect(full).to.deep.equal(b.loadFinalFundingTransaction(id));
			wire.fundingDepth(id, true);
			const readyB = b.finalOpeningChannelReady(id, bob.root);
			wire.queue(bob.binding.nodeId, id, {
				type: MessageType.CHANNEL_READY,
				payload: readyB
			});
			await tick();
			expect(imports).to.deep.equal(['confirm']);
			expect(sent).not.to.include(MessageType.CHANNEL_READY);
			expect(!!a.loadFinalDaemonOpening(id)!.readyExchanged).to.equal(false);
			releaseImport!();
			await tick();
			expect(sent).to.include(MessageType.CHANNEL_READY);
			expect(a.loadFinalDaemonOpening(id)!.readyExchanged).to.equal(true);
			wire.invalidateAssetFundingAnchor(id);
			wire.assetFundingAnchor(id, true, 200);
			wire.assetFundingSpendable(id, true);
			await tick();
			expect(wire.hasDepth(id)).to.equal(false);
			expect(imports).to.deep.equal(['confirm', 'confirm']);
			releaseImport!();
			await tick();
			expect(wire.hasDepth(id)).to.equal(true);
			wire.assetFundingAnchor(id, true, 199);
			await tick();
			expect(wire.hasDepth(id)).to.equal(false);
			wire.fundingDepth(id, false);
			releaseImport!();
			await tick();
			expect(imports).to.deep.equal([
				'confirm',
				'confirm',
				'confirm',
				'retract'
			]);
			expect(wire.hasDepth(id)).to.equal(false);
			for (const [holder, exit] of [
				['local', ea],
				['remote', eb]
			] as const) {
				const parent = Transaction.fromBuffer(exit);
				const recovery = {
					...provider,
					recoverOutput: async (
						ctx: Parameters<IAuxiliaryDualFunding['recoverOutput']>[0]
					) => {
						expect(ctx.holder).to.equal(holder);
						expect(ctx.exitProofs.toString('hex')).to.equal(
							evidence[holder].proofs
						);
						const sweep = new Transaction();
						sweep.version = 2;
						sweep.addInput(parent.getHash(), ctx.outputIndex, ctx.delay);
						sweep.addOutput(
							Buffer.from('0014' + '84'.repeat(20), 'hex'),
							parent.outs[ctx.outputIndex].value - 300
						);
						const differentOutpoint = sweep.clone();
						differentOutpoint.ins[0].index++;
						expect(() => ctx.signSweep(differentOutpoint, [parent])).to.throw();
						const stack = ctx.signSweep(sweep, [parent]);
						const digest = sweep.hashForWitnessV1(
							0,
							[parent.outs[ctx.outputIndex].script],
							[parent.outs[ctx.outputIndex].value],
							0,
							tapleafHash(stack[1], 0xc0)
						);
						const key = stack[1].subarray(1, 33);
						expect(ecc.verifySchnorr(digest, key, stack[0])).to.equal(true);
						sweep.setWitness(0, stack);
						return sweep;
					}
				};
				const claims = assetOpeningOutputClaims(
					{ storage: a, root: alice.root },
					Buffer.from(id, 'hex'),
					parent,
					Buffer.alloc(22),
					1,
					recovery
				);
				expect(claims).to.have.length(1);
				expect(claims[0].tx).to.equal(null);
				expect(await claims[0].recover!()).to.be.instanceOf(Transaction);
				const fake = parent.clone();
				fake.outs[0].value++;
				expect(
					assetOpeningOutputClaims(
						{ storage: a, root: alice.root },
						Buffer.from(id, 'hex'),
						fake,
						Buffer.alloc(22),
						1,
						recovery
					)
				).to.deep.equal([]);
			}
			a.close();
			fs.copyFileSync(beforeFunding, file);
			a = SqliteStorage.openFinalWallet(file, alice.binding);
			expect(a.loadFinalLocalTxSignatures(id)).to.deep.equal(aWire);
			expect(a.loadFinalPeerTxSignatures(id)).to.deep.equal(bWire);
			expect(a.loadFinalFundingTransaction(id)).to.deep.equal(full);
			a.close();
			fs.copyFileSync(beforeExit, file);
			expect(() =>
				SqliteStorage.openFinalWallet(file, alice.binding)
			).to.throw();
			fs.copyFileSync(beforeFunding, file);
			a = SqliteStorage.openFinalWallet(file, alice.binding);
		} finally {
			a.close();
			b.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
