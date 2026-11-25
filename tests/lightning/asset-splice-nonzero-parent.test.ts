import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { Transaction } from 'bitcoinjs-lib';
import type {
	IAssetSpliceSigningHost,
	IAssetSpliceExitEvidence
} from '../../src/lightning/channel/asset-splice-signature-round';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import { walletSigner } from './helpers/final-update-pair';
import { sha256 } from '../../src/lightning/crypto/provider';
import { AssetSpliceConstruction } from '../../src/lightning/channel/asset-splice-construction';
import {
	assetSpliceLayoutDigest,
	verifyAssetSpliceCandidate
} from '../../src/lightning/channel/asset-splice-manifest';
import type { AssetUpdateChange } from '../../src/lightning/channel/asset-splice-update-provider';
import { signatureRoundFixture } from './helpers/asset-splice-signature-round';
import { assetUpdateTestHost } from './helpers/asset-splice-update';

describe('a splice carrying an irrevocable mixed HTLC set', function () {
	this.timeout(90000);
	it('pins the current parent digest, named obligations and four enforceable exits before a funding signature', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-signed-parent-'));
		const f = signatureRoundFixture(dir),
			{ s } = f,
			id = f.f.id,
			proof = sha256(Buffer.alloc(32, 10)),
			assetId = '4c'.repeat(32);
		try {
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
				host = [assetUpdateTestHost(0, [], 1), assetUpdateTestHost(1, [], 1)];
			const offers = batch.map((b) => b.offer());
			batch.forEach((b, i) => b.acceptOffer(offers[1 - i]));
			const shares = (await Promise.all(
				batch.map((b, i) => b.signAssetShares(host[i]))
			)) as [Buffer, Buffer];
			const children = (await Promise.all(
				batch.map((b, i) => b.signAssetHtlcs(host[i], shares))
			)) as [Buffer, Buffer];
			await Promise.all(
				batch.map((b, i) => b.verifyAssetShares(host[i], shares, children))
			);
			const commits = batch.map((b) => b.commitments());
			await Promise.all(
				batch.map((b, i) => b.acceptCommitments(host[i], commits[1 - i]))
			);
			const revokes = batch.map((b) => b.revocation());
			batch.forEach((b, i) => b.receiveRevocation(revokes[1 - i]));
			const heads = f.f.devices.map(
				(d) => d.store.assetSpliceUpdateHead(id).committed!
			);
			assert.equal(heads[0].digest, heads[1].digest);
			const priorDigest = Buffer.from(heads[0].digest, 'hex');
			const layout = {
				...s.layout,
				stateNumber: 1n,
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
			const make = (i: number, l = layout) => {
				const digest = assetSpliceLayoutDigest(l);
				const approved = verifyAssetSpliceCandidate(
					l,
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
						l,
						approved,
						2
					)
				};
			};
			assert.throws(() =>
				make(0, { ...layout, priorDigest: Buffer.alloc(32, 22) })
			);
			assert.throws(() =>
				make(0, {
					...layout,
					parentBalances: {
						...layout.parentBalances,
						htlcs: layout.parentBalances.htlcs.slice(0, 1)
					}
				})
			);
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
			const ctx = (i: number) => ({
				...f.ctx(i),
				stateNumber: 1n,
				priorDigest,
				currentParent: () => ({
					...f.ctx(i).currentParent(),
					stateNumber: 1n,
					priorDigest
				})
			});
			assert.equal(
				sides.every((x) => !!x.agreement()),
				true
			);
			const parent = heads[0].members[0];
			assert.equal(
				Transaction.fromHex(parent.localCommitment).ins[0].witness[0].length,
				64
			);
			await assert.rejects(() =>
				rounds[0].round.verifyExitShares(f.hosts[0], ctx(0), [
					Buffer.of(1),
					Buffer.of(2)
				])
			);
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
					async signSpliceExits(c, v) {
						assert.deepEqual(c.priorDigest, priorDigest);
						assert.equal(v.candidate.local.htlcs.length, 2);
						assert.equal(v.candidate.remote.htlcOutputs.length, 2);
						return Buffer.of(1 + i);
					},
					async signSpliceExitHtlcs(c, v, joints, signer) {
						assert.deepEqual(joints, [Buffer.of(1), Buffer.of(2)]);
						const key = v.terms.localBasepoints.htlcBasepoint,
							holder = v.candidate.local,
							auth = holder.htlcs.find((h) => h.allocations.length)!;
						assert.throws(() =>
							signer.signHtlc(
								proof,
								holder.point,
								Buffer.from(key, 'hex'),
								old.fundingTxid + ':' + old.outputIndex,
								auth.offeredBy,
								auth.id,
								assetId
							)
						);
						const sig = signer.signHtlc(
							proof,
							holder.point,
							Buffer.from(key, 'hex'),
							s.tx.getId() + ':' + s.f.candidates[i].fundingIndex,
							auth.offeredBy,
							auth.id,
							assetId
						);
						assert.equal(sig.length, 64);
						return Buffer.of(3 + i);
					},
					async verifySpliceExits(c, v, joints, kids) {
						assert.deepEqual(kids, [Buffer.of(3), Buffer.of(4)]);
						return result;
					},
					async retainSpliceExits(c, v, exact) {
						const e = f.f.evidence(i),
							candidate = e.candidate;
						e.parent = old;
						e.finalDigest = rounds[i].approved.digest.toString('hex');
						e.stateNumber = '1';
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
					async signSpliceFunding(c, digest, tx, indices, prevouts) {
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
			await assert.rejects(() =>
				rounds[0].round.signExitHtlcs(hosts[0], ctx(0), [
					joints[0],
					Buffer.of(8)
				])
			);
			for (const [i, d] of f.f.devices.entries()) {
				d.store.close();
				d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
				rounds[i] = make(i);
				const shouldReplay = {
					...hosts[i],
					async signSpliceExits() {
						throw Error('Re-signed prior joint share');
					},
					async signSpliceExitHtlcs() {
						throw Error('Re-signed prior child share');
					}
				};
				assert.deepEqual(
					await rounds[i].round.signExitHtlcs(shouldReplay, ctx(i), joints),
					kids[i]
				);
			}

			const handles = await Promise.all(
				rounds.map(({ round }, i) =>
					round.verifyExitShares(hosts[i], ctx(i), joints, kids)
				)
			);
			const wires = rounds.map(({ round }, i) =>
				round.commitmentSigned(handles[i])
			);
			const invalid = decodeCommitmentSignedMessage(wires[1], {
				customRecords: true
			});
			invalid.customRecords = new Map([[65537n, Buffer.of(0xff)]]);
			assert.throws(() =>
				rounds[0].round.acceptCommitmentSigned(
					handles[0],
					encodeCommitmentSignedMessage(invalid)
				)
			);
			for (const [i, { round }] of rounds.entries()) {
				const decoded = decodeCommitmentSignedMessage(wires[i], {
					customRecords: true
				});
				assert.equal(decoded.htlcSignatures.length, 2);
				assert(decoded.customRecords?.get(65537n));
				round.acceptCommitmentSigned(handles[i], wires[1 - i]);
				await assert.rejects(() =>
					round.retainExits(
						{
							...hosts[i],
							async retainSpliceExits(c, views, exact) {
								const e = await hosts[i].retainSpliceExits(c, views, exact);
								e.candidate.localRecovery.htlcs.find(
									(x) => x.secondLevelLeaf
								)!.secondLevelLeaf = { script: '51' };
								return e;
							}
						},
						ctx(i),
						handles[i]
					)
				);
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
			assert.equal(rounds[0].round.transaction()?.getId(), s.tx.getId());
			for (const d of f.f.devices)
				assert.equal(d.store.loadFinalFundingExits(id).length, 2);
			// The signed next nonce on the new candidate came from tx_complete at the previous height.
			const finish = f.f.devices.map((d, i) =>
				d.store.assetSpliceUpdateBatch(
					id,
					d.party.root,
					2n,
					[
						{
							kind: 'fulfill',
							offeredBy: i ? 'peer' : 'local',
							id: 0n,
							preimage: Buffer.alloc(32, 10)
						},
						{
							kind: 'fail',
							offeredBy: i ? 'local' : 'peer',
							id: 0n,
							reason: Buffer.of(12)
						}
					],
					() => 600910
				)
			);
			const nextOffers = finish.map((b) => b.offer());
			finish.forEach((b, i) => b.acceptOffer(nextOffers[1 - i]));
			const updateHosts = [assetUpdateTestHost(0), assetUpdateTestHost(1)];
			const joins = (await Promise.all(
				finish.map((b, i) => b.signAssetShares(updateHosts[i]))
			)) as [Buffer, Buffer];
			const resolutions = (await Promise.all(
				finish.map((b, i) => b.signAssetHtlcs(updateHosts[i], joins))
			)) as [Buffer, Buffer];
			await Promise.all(
				finish.map((b, i) =>
					b.verifyAssetShares(updateHosts[i], joins, resolutions)
				)
			);
			const blocks = finish.map((b) => b.commitments());
			await Promise.all(
				finish.map((b, i) => b.acceptCommitments(updateHosts[i], blocks[1 - i]))
			);
			const acks = finish.map((b) => b.revocation());
			finish.forEach((b, i) => b.receiveRevocation(acks[1 - i]));
			assert.equal(
				f.f.devices[1].store.assetSpliceUpdateHead(id).committed?.htlcs.length,
				0
			);
		} finally {
			for (const d of f.f.devices) d.store.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
