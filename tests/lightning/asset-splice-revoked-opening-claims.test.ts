import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Transaction } from 'bitcoinjs-lib';
import type {
	IAssetSpliceSigningHost,
	IAssetSpliceExitEvidence
} from '../../src/lightning/channel/asset-splice-signature-round';
import type { AssetUpdateChange } from '../../src/lightning/channel/asset-splice-update-provider';
import type {
	IAssetOpeningPayout,
	IAuxiliaryDualFunding
} from '../../src/lightning/channel';
import { assetOpeningOutputClaims } from '../../src/lightning/chain/asset-opening-claims';
import { matchedAssetPayoutViews } from '../../src/lightning/chain/asset-splice-output-view';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { AssetSpliceConstruction } from '../../src/lightning/channel/asset-splice-construction';
import {
	assetSpliceLayoutDigest,
	verifyAssetSpliceCandidate
} from '../../src/lightning/channel/asset-splice-manifest';
import { sha256 } from '../../src/lightning/crypto/provider';
import { walletSigner } from './helpers/final-update-pair';
import { signatureRoundFixture } from './helpers/asset-splice-signature-round';
import { assetUpdateTestHost } from './helpers/asset-splice-update';

describe('a revoked opening commitment after a splice from a later state', function () {
	this.timeout(90000);
	it('still gives the defender its own balance and the penalty on the original outpoint', async () => {
		const dir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'splice-revoked-opening-')
		);
		const f = signatureRoundFixture(dir, false, 5),
			{ s } = f,
			id = f.f.id,
			proof = sha256(Buffer.alloc(32, 10)),
			assetId = '4c'.repeat(32),
			destination = Buffer.from('0014' + 'cd'.repeat(20), 'hex');
		try {
			const defender = {
				storage: f.f.devices[0].store,
				root: f.f.devices[0].party.root
			};
			const observe = (tx: Transaction, provider?: IAuxiliaryDualFunding) =>
				assetOpeningOutputClaims(
					{ storage: f.f.devices[0].store, root: defender.root },
					Buffer.from(id, 'hex'),
					tx,
					destination,
					1,
					provider
				);
			// The peer's own signed opening exit, read before any update supersedes it.
			const opening = f.f.devices[1].store.loadFinalOpeningExit(id);
			assert(opening);
			const retired = Transaction.fromBuffer(opening);
			assert.equal(retired.ins[0].witness[0]?.length, 64);
			assert.equal(
				Buffer.from(retired.ins[0].hash).reverse().toString('hex'),
				s.layout.parent.getId()
			);
			assert.equal(retired.ins[0].index, s.layout.parentIndex);
			assert.equal(observe(retired).length, 1);

			const ops = (i: number): AssetUpdateChange[] =>
				[0, 1].map((n) => ({
					kind: 'add',
					htlc: {
						offeredBy: i === n ? 'local' : 'peer',
						id: 0n,
						paymentHash: proof,
						amountMsat: n ? 2000000n : 5000000n,
						cltvExpiry: 601000 + n,
						allocations: n ? [] : [{ assetId, units: 3n }]
					}
				}));
			const batch = f.f.devices.map((d, i) =>
					d.store.assetSpliceUpdateBatch(
						id,
						d.party.root,
						1n,
						ops(i),
						() => 600900
					)
				),
				updateHosts = [
					assetUpdateTestHost(0, [], 1),
					assetUpdateTestHost(1, [], 1)
				];
			const offers = batch.map((b) => b.offer());
			batch.forEach((b, i) => b.acceptOffer(offers[1 - i]));
			const shares = (await Promise.all(
				batch.map((b, i) => b.signAssetShares(updateHosts[i]))
			)) as [Buffer, Buffer];
			const children = (await Promise.all(
				batch.map((b, i) => b.signAssetHtlcs(updateHosts[i], shares))
			)) as [Buffer, Buffer];
			await Promise.all(
				batch.map((b, i) =>
					b.verifyAssetShares(updateHosts[i], shares, children)
				)
			);
			const commits = batch.map((b) => b.commitments());
			await Promise.all(
				batch.map((b, i) => b.acceptCommitments(updateHosts[i], commits[1 - i]))
			);
			const revokes = batch.map((b) => b.revocation());
			batch.forEach((b, i) => b.receiveRevocation(revokes[1 - i]));
			// With state 1 committed and no splice yet, the opening is revoked and claimable.
			assert.equal(observe(retired).length, 2);

			const heads = f.f.devices.map(
				(d) => d.store.assetSpliceUpdateHead(id).committed!
			);
			assert.equal(heads[0].digest, heads[1].digest);
			const stateNumber = 1n,
				priorDigest = Buffer.from(heads[0].digest, 'hex');
			const layout = {
				...s.layout,
				stateNumber,
				priorDigest,
				parentBalances: {
					issuances: [{ assetId, funding: 20n, initiator: 8n, acceptor: 9n }],
					htlcs: heads[0].htlcs.map((h) => ({
						...h,
						id: BigInt(h.id),
						offeredBy:
							h.offeredBy === 'local'
								? ('initiator' as const)
								: ('acceptor' as const),
						amountMsat: BigInt(h.amountMsat),
						allocations: h.allocations.map((a) => ({
							...a,
							units: BigInt(a.units)
						}))
					}))
				}
			};
			const make = (i: number) => {
				const digest = assetSpliceLayoutDigest(layout);
				const approved = verifyAssetSpliceCandidate(
					layout,
					digest,
					i === 0,
					s.tx,
					{
						layoutDigest: digest,
						transaction: s.tx.toBuffer(),
						fundingRoot: f.f.terms[0].assetFundingRoots!.candidate,
						proofDigest: Buffer.alloc(32, 85),
						fundingProofs: Buffer.from('b0c1', 'hex')
					},
					[Buffer.alloc(32, 86), Buffer.alloc(32, 87)]
				);
				return {
					approved,
					round: f.f.devices[i].store.assetSpliceSignatureRound(
						f.f.devices[i].party.root,
						layout,
						approved,
						2
					)
				};
			};
			const rounds = [make(0), make(1)];
			const sides = rounds.map(
				({ approved, round }, i) =>
					new AssetSpliceConstruction(
						layout,
						approved,
						round.txComplete(),
						f.f.devices[i].store
					)
			);
			for (let n = 0; n < 16; n++) {
				const i = n % 2,
					v = sides[i].next();
				if (!v) break;
				sides[1 - i].receive(v.type, v.payload);
			}
			assert(sides.every((x) => !!x.agreement()));
			const ctx = (i: number) => ({
				...f.ctx(i),
				stateNumber,
				priorDigest,
				currentParent: () => ({
					...f.ctx(i).currentParent(),
					stateNumber,
					priorDigest
				})
			});
			const hosts = f.f.devices.map((device, i): IAssetSpliceSigningHost => {
				const old = heads[i].members[0];
				const fromOld = (h: 'local' | 'remote'): IAssetSpliceExitEvidence => {
					const v = h === 'local' ? old.localRecovery : old.remoteRecovery;
					return {
						toLocal: v.toLocal!,
						toRemote: v.toRemote!,
						proofs: h === 'local' ? old.localProofs : old.remoteProofs,
						htlcs: v.htlcs.flatMap((a) =>
							a.outputLeaf && a.secondLevelLeaf
								? [
										{
											id: a.id,
											offeredBy: a.offeredBy,
											output: a.outputLeaf,
											secondLevel: a.secondLevelLeaf
										}
								  ]
								: []
						),
						htlcSignatures: decodeCommitmentSignedMessage(
							Buffer.from(
								(h === 'local'
									? heads[i].peerCommitments
									: heads[i].localCommitments)[0],
								'hex'
							),
							{ customRecords: true }
						)
							.customRecords!.get(65537n)!
							.toString('hex')
					};
				};
				const result = {
					parent: { local: fromOld('local'), remote: fromOld('remote') },
					candidate: { local: fromOld('local'), remote: fromOld('remote') }
				};
				return {
					async signSpliceExits() {
						return Buffer.of(1 + i);
					},
					async signSpliceExitHtlcs() {
						return Buffer.of(3 + i);
					},
					async verifySpliceExits() {
						return result;
					},
					async retainSpliceExits(_c, v, exact) {
						const e = f.f.evidence(i),
							candidate = e.candidate;
						e.parent = old;
						e.finalDigest = rounds[i].approved.digest.toString('hex');
						e.stateNumber = String(stateNumber);
						candidate.localCommitment = exact.candidate.local.toHex();
						candidate.remoteCommitment = exact.candidate.remote.toHex();
						candidate.localProofs = result.candidate.local.proofs;
						candidate.remoteProofs = result.candidate.remote.proofs;
						for (const side of ['local', 'remote'] as const) {
							const r =
									side === 'local' ? old.localRecovery : old.remoteRecovery,
								holder = v.candidate[side];
							candidate[side === 'local' ? 'localRecovery' : 'remoteRecovery'] =
								{
									...r,
									point: holder.point.toString('hex'),
									localBalanceMsat: String(holder.localBalanceMsat),
									remoteBalanceMsat: String(holder.remoteBalanceMsat),
									ownedOutputIndex:
										(side === 'local'
											? holder.outputMap.toLocal
											: holder.outputMap.toRemote) ?? null,
									htlcs: r.htlcs.map((h) => ({
										...h,
										outputIndex:
											holder.htlcOutputs.find(
												(out) =>
													String(out.htlc.id) === h.id &&
													out.htlc.offeredBy === h.offeredBy
											)?.outputIndex ?? null
									}))
								};
						}
						return { ...e, priorDigest: priorDigest.toString('hex') };
					},
					async signSpliceFunding(_c, _digest, tx, indices, prevouts) {
						if (i === 1) return [];
						return walletSigner(device.party.keys.fundingPrivkey, 1, f.f.calls)(
							tx,
							indices,
							prevouts
						);
					}
				};
			});
			const joints = (await Promise.all(
				rounds.map(({ round }, i) => round.signExitShares(hosts[i], ctx(i)))
			)) as [Buffer, Buffer];
			const kids = (await Promise.all(
				rounds.map(({ round }, i) =>
					round.signExitHtlcs(hosts[i], ctx(i), joints)
				)
			)) as [Buffer, Buffer];
			const handles = await Promise.all(
				rounds.map(({ round }, i) =>
					round.verifyExitShares(hosts[i], ctx(i), joints, kids)
				)
			);
			const wires = rounds.map(({ round }, i) =>
				round.commitmentSigned(handles[i])
			);
			for (const [i, { round }] of rounds.entries()) {
				round.acceptCommitmentSigned(handles[i], wires[1 - i]);
				await round.retainExits(hosts[i], ctx(i), handles[i]);
			}
			const first = await rounds[1].round.nextFunding(
				hosts[1],
				ctx(1),
				async () => 'unspent'
			);
			assert(first);
			rounds[0].round.receiveFunding(first);
			const second = await rounds[0].round.nextFunding(
				hosts[0],
				ctx(0),
				async () => 'unspent'
			);
			assert(second);
			rounds[1].round.receiveFunding(second);
			const kinds = f.f.devices[0].store
				.readAssetSpliceJournal<{ kind: string }>(id)
				.records.map((r) => r.kind);
			assert(kinds.includes('funding-reserved'));
			assert(kinds.includes('funding-released'));

			// The splice receipt names state 1. The retired opening still spends the
			// original outpoint, so it must stay claimable while the splice is unconfirmed.
			const calls: IAssetOpeningPayout[] = [];
			const provider = {
				assetSpliceRecoveryVersion: 1,
				outputRecoveryReceipt(
					_channelId: string,
					_parentTxid: string,
					_outputIndex: number,
					payout: Transaction
				) {
					return Buffer.from(payout.getId(), 'hex');
				},
				async restoreOutputReceipt() {},
				async recoverOutput(c: IAssetOpeningPayout) {
					calls.push(c);
					const sweep = new Transaction();
					sweep.version = 2;
					sweep.addInput(retired.getHash(), c.outputIndex, c.delay);
					sweep.addOutput(destination, retired.outs[c.outputIndex].value - 400);
					sweep.setWitness(0, c.signSweep(sweep, [retired]));
					return sweep;
				}
			} as unknown as IAuxiliaryDualFunding;
			const claims = observe(retired, provider);
			assert.equal(claims.length, 2);
			const txs = await Promise.all(claims.map((c) => c.recover!()));
			assert.equal(new Set(txs.map((tx) => tx!.getId())).size, 2);
			assert.equal(calls.length, 2);
			for (const c of calls) {
				assert.equal(c.holder, 'remote');
				assert.equal(c.update, undefined);
				assert.equal(c.splice, undefined);
				assert.equal(c.virtualPayout?.stateNumber, '0');
				assert.equal(c.virtualPayout?.fundingTxid, s.layout.parent.getId());
			}
			const penalty = calls.filter((c) => c.revocation);
			assert.equal(penalty.length, 1);
			assert.equal(penalty[0].delay, 0);
			// The current state on the original outpoint is matched, but not as revoked.
			const current = Transaction.fromHex(heads[1].members[0].localCommitment);
			const [live] = matchedAssetPayoutViews(f.f.devices[0].store, id, current);
			assert(live);
			assert.equal(live.state, 1n);
			assert.equal(live.revoked, undefined);
			assert(live.update);
		} finally {
			for (const d of f.f.devices) d.store.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
