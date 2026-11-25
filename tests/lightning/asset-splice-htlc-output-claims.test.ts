import { strict as assert } from 'assert';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { payments, Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import {
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput
} from '../../src/lightning/script/commitment-taproot';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';
import { sha256 } from '../../src/lightning/crypto/provider';
import { assetOpeningOutputClaims } from '../../src/lightning/chain/asset-opening-claims';
import { retainedAssetFundingLineage } from '../../src/lightning/chain/asset-splice-output-view';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';
import { assetUpdateHistory } from '../../src/lightning/storage/asset-update-history';
import type {
	IAssetOpeningHtlcPayout,
	IAuxiliaryDualFunding
} from '../../src/lightning/channel/asset-opening-provider';
import type { AssetUpdateChange } from '../../src/lightning/channel/asset-splice-update-provider';
import {
	setupFundedAssetUpdatePair,
	assetUpdateTestHost
} from './helpers/asset-splice-update';

// Check the virtual signature with bitcoinjs's complete BIP341 transaction serializer.
function verifyAssetSignature(ctx: IAssetOpeningHtlcPayout) {
	const delayed = ctx.kind === 'second_level_delayed';
	const local = ctx.holder === 'local';
	const offered = (ctx.htlc.offeredBy === 'local') === local;
	const keys = ctx.keys;
	const args = [
		keys.revocationPubkey,
		keys.localHtlcPubkey,
		keys.remoteHtlcPubkey,
		ctx.htlc.paymentHash
	] as const;
	const branches = offered
		? buildTaprootOfferedHtlcOutput(...args, undefined, 'final')
		: buildTaprootReceivedHtlcOutput(
				...args,
				ctx.htlc.cltvExpiry,
				undefined,
				'final'
		  );
	const child = buildTaprootSecondLevelOutput(
		keys.revocationPubkey,
		keys.localDelayedPubkey,
		ctx.toSelfDelay,
		undefined,
		'final'
	);
	const leaf = delayed
		? child.delay
		: ctx.kind.endsWith('success')
		? branches.success
		: branches.timeout;
	const tweak = Buffer.alloc(32);
	tweak.writeBigUInt64BE(ctx.htlc.id + 1n, 24);
	const internal = ecc.pointAddScalar(keys.revocationPubkey, tweak);
	assert(internal);
	const source = payments.p2tr({
		internalPubkey: Buffer.from(internal).subarray(1),
		scriptTree: delayed
			? { output: child.delay.script }
			: [
					{ output: branches.timeout.script },
					{ output: branches.success.script }
			  ]
	}).output!;
	const { assetId, units } = ctx.htlc.allocations[0];
	const inputRoot = Buffer.alloc(32, 31),
		outputRoot = Buffer.alloc(32, 87);
	const sum = Buffer.alloc(8);
	sum.writeBigUInt64BE(units);
	const tx = new Transaction();
	tx.version = 2;
	tx.locktime = ctx.transaction.locktime;
	const sequence =
		ctx.transaction.ins[0].sequence < 0x80000000
			? ctx.transaction.ins[0].sequence
			: 0;
	tx.addInput(sha256(Buffer.concat([inputRoot, sum])), 0, sequence);
	tx.addOutput(Buffer.concat([Buffer.of(0x51, 32), outputRoot]), Number(units));
	const request = {
		stage: delayed ? ('second-level' as const) : ('commitment' as const),
		assetId,
		inputRoot,
		outputRoot,
		lockTime: tx.locktime,
		sequence
	};
	const signature = ctx.signVirtual(request);
	const digest = tx.hashForWitnessV1(
		0,
		[source],
		[Number(units)],
		ctx.kind.startsWith('htlc_second_level_') ? 0x83 : 0,
		tapleafHash(leaf.script, leaf.leafVersion)
	);
	const publicKey = delayed
		? keys.localDelayedPubkey
		: local
		? keys.localHtlcPubkey
		: keys.remoteHtlcPubkey;
	assert(ecc.verifySchnorr(digest, publicKey.subarray(1), signature), ctx.kind);
	assert.throws(() =>
		ctx.signVirtual({ ...request, outputRoot: Buffer.alloc(32, 88) })
	);
	assert.throws(() =>
		ctx.signVirtual({ ...request, assetId: 'ff'.repeat(32) })
	);
	assert.throws(() => ctx.signVirtual({ ...request, sequence: sequence + 1 }));
}

describe('confirmed HTLC claims for both live asset funding outputs', function () {
	this.timeout(90000);
	it('includes only released successors on the authenticated funding path', () => {
		const dir = mkdtempSync(join(tmpdir(), 'released-funding-lineage-'));
		const f = setupAssetSpliceProofs(dir, undefined, 5);
		try {
			const store = f.devices[0].store,
				opening = store.loadFinalOpening(f.id)!;
			const branch = f.evidence(0).candidate;
			const lineage = (txid = branch.fundingTxid, vout = branch.outputIndex) =>
				retainedAssetFundingLineage(store, f.id, opening, txid, vout);
			assert.deepEqual(
				lineage(
					Transaction.fromHex(opening.fundingTxHex).getId(),
					opening.fundingOutputIndex
				),
				[]
			);
			f.retain(0);
			assert.throws(() => lineage());
			assert.throws(() =>
				f.sign(0, f.context(0), f.views[0], () => {
					throw Error('interrupted witness');
				})
			);
			assert.throws(() => lineage());
			f.sign(0, f.context(0));
			const path = lineage();
			assert.equal(path.length, 1);
			assert.equal(
				path[0].parentTxid,
				Transaction.fromHex(opening.fundingTxHex).getId()
			);
			assert.equal(path[0].fundingTxid, branch.fundingTxid);
			assert.throws(() => lineage('df'.repeat(32)));
			assert.throws(() => lineage(branch.fundingTxid, branch.outputIndex + 1));
		} finally {
			for (const device of f.devices) device.store.close();
			rmSync(dir, { force: true, recursive: true });
		}
	});

	it('uses the authenticated child on the local commitment and the direct branch on the peer commitment', async () => {
		const dir = mkdtempSync(join(tmpdir(), 'asset-splice-htlc-claims-'));
		const { f } = await setupFundedAssetUpdatePair(dir, 5);
		const preimage = Buffer.alloc(32, 13),
			hash = sha256(preimage);
		const assetId = '4c'.repeat(32),
			expiry = 601000;
		try {
			const b = f.devices.map(({ store, party }, i) => {
				const change: AssetUpdateChange = {
					kind: 'add',
					htlc: {
						id: 0n,
						offeredBy: i ? 'peer' : 'local',
						amountMsat: 5000000n,
						paymentHash: hash,
						cltvExpiry: expiry,
						allocations: [{ assetId, units: 3n }]
					}
				};
				return store.assetSpliceUpdateBatch(
					f.id,
					party.root,
					1n,
					[change],
					() => 600900
				);
			});
			const hosts = [assetUpdateTestHost(0), assetUpdateTestHost(1)];
			const offers = b.map((x) => x.offer());
			b.forEach((x, i) => x.acceptOffer(offers[1 - i]));
			const shares = (await Promise.all(
				b.map((x, i) => x.signAssetShares(hosts[i]))
			)) as [Buffer, Buffer];
			const children = (await Promise.all(
				b.map((x, i) => x.signAssetHtlcs(hosts[i], shares))
			)) as [Buffer, Buffer];
			await Promise.all(
				b.map((x, i) => x.verifyAssetShares(hosts[i], shares, children))
			);
			const commitments = b.map((x) => x.commitments());
			await Promise.all(
				b.map((x, i) => x.acceptCommitments(hosts[i], commitments[1 - i]))
			);
			const revokes = b.map((x) => x.revocation());
			b.forEach((x, i) => x.receiveRevocation(revokes[1 - i]));
			for (const [i, device] of f.devices.entries()) {
				const storage = device.store,
					id = Buffer.from(f.id, 'hex');
				const runtime = { storage, root: device.party.root };
				const state = assetUpdateHistory(storage, f.id).states.get(1n)!;
				assert.equal(state.members.length, 2);
				if (i) storage.savePreimage(hash.toString('hex'), preimage);
				for (const member of state.members) {
					for (const holder of ['local', 'remote'] as const) {
						const local = holder === 'local';
						const parent = Transaction.fromHex(
							local ? member.localCommitment : member.remoteCommitment
						);
						const index = (local ? member.localRecovery : member.remoteRecovery)
							.htlcs[0].outputIndex;
						assert(index !== null);
						const destination = Buffer.from('0014' + 'ae'.repeat(20), 'hex');
						const capability = (provider?: IAuxiliaryDualFunding) =>
							assetOpeningOutputClaims(
								runtime,
								id,
								parent,
								destination,
								1,
								provider
							).find((c) => c.outputIndex === index);
						const inactive = capability();
						assert(
							!inactive?.tx && !inactive?.recover,
							'asset output cannot fall through to a Bitcoin-only sweep'
						);
						const calls: IAssetOpeningHtlcPayout[] = [];
						const provider = {
							assetSpliceRecoveryVersion: 1,
							async recoverHtlc(ctx: IAssetOpeningHtlcPayout) {
								calls.push(ctx);
								verifyAssetSignature(ctx);
								assert.equal(ctx.walletGeneration, 5);
								const original = Transaction.fromHex(
									ctx.candidate.fundingTxHex
								).getId();
								const path = ctx.fundingLineage;
								assert(path);
								if (member.fundingTxid === original) assert.deepEqual(path, []);
								else {
									assert.equal(path.length, 1);
									assert.equal(path[0].parentTxid, original);
									assert.equal(
										path[0].parentOutputIndex,
										ctx.candidate.fundingOutputIndex
									);
									assert.equal(path[0].fundingTxid, member.fundingTxid);
									assert.equal(path[0].fundingOutputIndex, member.outputIndex);
									assert.equal(
										Transaction.fromHex(path[0].fundingTxHex).getId(),
										member.fundingTxid
									);
								}
								assert.equal(ctx.commitment.getId(), parent.getId());
								assert.equal(ctx.virtualPayout.fundingTxid, member.fundingTxid);
								assert.equal(
									ctx.virtualPayout.fundingOutputIndex,
									member.outputIndex
								);
								assert.deepEqual(ctx.htlc.allocations, [
									{ assetId, units: 3n }
								]);
								assert.equal(ctx.commitmentOutputIndex, index);
								return null;
							}
						} as unknown as IAuxiliaryDualFunding;
						const claim = capability(provider);
						assert(claim?.recover);
						assert.equal(claim.relativeDelay, 1);
						assert.equal(claim.absoluteHeight, i ? 0 : expiry);
						if (local) {
							assert(claim.tx && claim.sponsor && claim.child);
							const template = claim.tx;
							assert(template.ins[0].hash.equals(parent.getHash()));
							assert.equal(template.ins[0].index, index);
							assert.equal(template.outs[0].value, parent.outs[index].value);
							assert.equal(template.ins[0].witness[0].at(-1), 0x83);
							assert.equal(template.ins[0].witness[1].at(-1), 0x83);
							const sponsored = template.clone();
							sponsored.addInput(Buffer.alloc(32, 77), 4);
							sponsored.addOutput(destination, 500);
							await claim.recover(sponsored);
							assert.equal(
								calls[0].kind,
								i ? 'htlc_second_level_success' : 'htlc_second_level_timeout'
							);
							assert.equal(calls[0].transaction.getId(), sponsored.getId());
							const changed = sponsored.clone();
							changed.outs[0].value--;
							assert.equal(claim.child(changed, 0), null);
							const delayed = claim.child(sponsored, 0);
							assert(delayed?.recover && delayed.relativeDelay > 1);
							await delayed.recover();
							assert.equal(calls[1].kind, 'second_level_delayed');
							assert.equal(calls[1].parent.getId(), sponsored.getId());
						} else {
							assert(!claim.sponsor);
							await claim.recover();
							assert.equal(calls[0].kind, i ? 'htlc_success' : 'htlc_timeout');
						}
						if (i) assert.deepEqual(calls[0].preimage, preimage);
					}
				}
			}
		} finally {
			for (const d of f.devices) d.store.close();
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
