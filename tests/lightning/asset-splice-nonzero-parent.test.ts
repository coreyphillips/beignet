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

import { COMMIT_ALL } from './helpers/channel-persistence';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { AssetSpliceUpdateTransport } from '../../src/lightning/channel/asset-splice-update-transport';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import { MessageType as M } from '../../src/lightning/message/types';

async function connectedUpdates(
	f: ReturnType<typeof signatureRoundFixture>,
	changes: (i: number) => AssetUpdateChange[]
) {
	const { devices, id } = f.f;
	const managers = devices.map(
		({ party }) =>
			new ChannelManager({
				localBasepoints: party.keys.channelBasepoints,
				localPerCommitmentSeed: party.keys.perCommitmentSeed,
				localFundingPrivkey: party.keys.fundingPrivkey,
				persistence: COMMIT_ALL
			})
	);
	const queue: { from: number; type: number; wire: Buffer }[] = [],
		errors: string[] = [];
	const settled = [0, 0];
	const updates = devices.map(
		(d, i) =>
			new AssetSpliceUpdateTransport(
				{ storage: d.store, root: d.party.root },
				assetUpdateTestHost(i, [], 1),
				(channel) =>
					channel === id
						? {
								peer: devices[1 - i].party.binding.nodeId,
								originalInitiator: i === 0
						  }
						: undefined,
				() => 600900,
				(_peer, type, wire) => queue.push({ from: i, type, wire }),
				async () => {
					settled[i]++;
				},
				(_id, e) => errors.push(e)
			)
	);
	for (const [i, m] of managers.entries())
		Object.assign(m, { assetUpdates: updates[i] });
	for (let origin = 0; origin < 2; origin++) {
		await updates[origin].start(id, [changes(origin)[origin]]);
		for (
			let turns = 0;
			turns < 1000 && settled.some((n) => n !== origin + 1);
			turns++
		) {
			const msg = queue.shift();
			if (msg) {
				const peer = devices[msg.from].party.binding.nodeId,
					to = 1 - msg.from;
				if (msg.type === BEIGNET_CUSTOM_MESSAGE_TYPE)
					updates[to].custom(peer, decodeCustomMessage(msg.wire).payload);
				else managers[to].handleMessage(peer, msg.type, msg.wire);
			}
			await new Promise<void>((resolve) => setImmediate(resolve));
			assert.deepEqual(errors, []);
		}
		assert.deepEqual(settled, [origin + 1, origin + 1]);
	}
	return managers;
}
describe('a splice carrying an irrevocable mixed HTLC set', function () {
	this.timeout(90000);
	it('pins the current parent digest, named obligations and four enforceable exits before a funding signature', () =>
		exercise(false));
	it('dispatches signed candidate commitments after a settled update on the same peer connection', () =>
		exercise(true));
	async function exercise(connected: boolean) {
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
			const managers = connected ? await connectedUpdates(f, ops) : undefined;
			const stateNumber = connected ? 2n : 1n;
			if (!connected) {
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
			}
			const heads = f.f.devices.map(
				(d) => d.store.assetSpliceUpdateHead(id).committed!
			);
			assert.equal(heads[0].digest, heads[1].digest);
			const priorDigest = Buffer.from(heads[0].digest, 'hex');
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
				stateNumber,
				priorDigest,
				currentParent: () => ({
					...f.ctx(i).currentParent(),
					stateNumber,
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
			const approvals: string[] = [];
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
					candidate: {
						local: fromOld('local'),
						remote: fromOld('remote')
					}
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
					async signSpliceFunding(c, digest, tx, indices, prevouts) {
						assert.equal(c.stateNumber, stateNumber);
						assert.deepEqual(digest, rounds[i].approved.digest);
						assert.equal(tx.toHex(), s.tx.toHex());
						assert.deepEqual(indices, f.f.candidates[i].localInputs);
						assert.deepEqual(prevouts.scripts, f.f.candidates[i].scripts);
						assert.deepEqual(
							prevouts.values,
							f.f.candidates[i].values.map(BigInt)
						);
						approvals.push(tx.getId());
						if (i === 1) {
							assert.deepEqual(indices, []);
							return [];
						}
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
				if (!connected) {
					d.store.close();
					d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
				}
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
				if (managers) {
					const received: Buffer[] = [];
					const peer = f.f.devices[1 - i].party.binding.nodeId;
					Object.assign(managers[i], {
						assetSplice: {
							handle: (p: string, type: number, wire: Buffer) => {
								assert.equal(p, peer);
								assert.equal(type, M.COMMITMENT_SIGNED);
								round.acceptCommitmentSigned(handles[i], wire);
								received.push(wire);
								return true;
							}
						}
					});
					managers[i].handleMessage(
						peer,
						M.COMMITMENT_SIGNED,
						Buffer.from(heads[i].peerCommitments[0], 'hex')
					);
					assert.equal(received.length, 0);
					managers[i].handleMessage(peer, M.COMMITMENT_SIGNED, wires[1 - i]);
					assert.equal(
						received.length,
						1,
						'The completed update swallowed the new candidate commitment'
					);
					assert.deepEqual(received[0], wires[1 - i]);
				} else round.acceptCommitmentSigned(handles[i], wires[1 - i]);
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
			const refusingHost = {
				...hosts[1],
				async signSpliceFunding(): Promise<Buffer[][]> {
					throw Error('Wallet refused the shared funding input');
				}
			};
			const acceptor = f.f.devices[1];
			await assert.rejects(
				rounds[1].round.nextFunding(
					refusingHost,
					ctx(1),
					async () => 'unspent'
				),
				/Wallet refused the shared funding input/
			);
			const fundingEvents = () =>
				acceptor.store
					.readAssetSpliceJournal<{ kind: string }>(id)
					.records.map((row) => row.kind);
			assert(fundingEvents().includes('funding-reserved'));
			assert(!fundingEvents().includes('funding-released'));
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
			assert.deepEqual(approvals, [s.tx.getId(), s.tx.getId()]);
			assert(fundingEvents().includes('funding-released'));
			assert.deepEqual(
				await make(1).round.nextFunding(
					refusingHost,
					ctx(1),
					async () => 'spent'
				),
				first
			);
			assert.equal(rounds[0].round.transaction()?.getId(), s.tx.getId());
			for (const d of f.f.devices)
				assert.equal(d.store.loadFinalFundingExits(id).length, 2);
			// The signed next nonce on the new candidate came from tx_complete at the previous height.
			const finish = f.f.devices.map((d, i) =>
				d.store.assetSpliceUpdateBatch(
					id,
					d.party.root,
					stateNumber + 1n,
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
	}
});
