import { strict as assert } from 'assert';
import { Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { AssetSpliceConfirmationCoordinator } from '../../src/lightning/channel/asset-splice-confirmation';
import { ChannelState } from '../../src/lightning/channel/types';
import { encodeSpliceLockedMessage } from '../../src/lightning/message/splice';
import { MessageType as M } from '../../src/lightning/message/types';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';

describe('asset splice balances and commitment admission on the original devices', function () {
	this.timeout(30000);
	let dir: string, f: ReturnType<typeof setupAssetSpliceProofs>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-balance-'));
		f = setupAssetSpliceProofs(dir);
		f.fundOpening();
	});
	afterEach(() => {
		for (const d of f?.devices ?? []) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	it('reports the selected old or candidate amount when an offline holder closes before splice lock', () => {
		for (const [i, d] of f.devices.entries()) {
			const manager = new ChannelManager({
				finalOpening: { storage: d.store, root: d.party.root },
				persistence: { persist: () => 'committed' }
			} as unknown as IChannelManagerConfig);
			const e = f.evidence(i);
			f.retain(i);
			f.sign(i, f.context(i));
			const branch = i ? e.parent : e.candidate;
			const exact = d.store.requestFinalOpeningExit(
				f.id,
				Buffer.from(branch.fundingTxid, 'hex').reverse(),
				branch.outputIndex
			);
			assert.equal(
				Transaction.fromBuffer(exact).getId(),
				Transaction.fromHex(branch.localCommitment).getId()
			);
			const row = manager.finalOpeningInfo(Buffer.from(f.id, 'hex'))[0];
			assert.equal(row.state, ChannelState.FORCE_CLOSED);
			assert.equal(row.fundingTxid, branch.fundingTxid);
			assert.equal(
				row.localBalanceMsat,
				BigInt(branch.localRecovery.localBalanceMsat)
			);
			assert.equal(row.pendingSpliceTxid, undefined);
		}
	});
	it('reports the original balance until both locks and import, the exact candidate after import, and zero available after reconciliation', async () => {
		for (const [i, d] of f.devices.entries()) {
			const manager = new ChannelManager({
				finalOpening: { storage: d.store, root: d.party.root },
				verifyRemoteFundingInput: async () => 'unspent',
				persistence: { persist: () => 'committed' }
			} as unknown as IChannelManagerConfig);
			const id = Buffer.from(f.id, 'hex'),
				row = () => manager.finalOpeningInfo(id)[0],
				e = f.evidence(i);
			const opening = row();
			assert.equal(opening.fundingTxid, e.parent.fundingTxid);
			assert.equal(
				opening.localBalanceMsat,
				BigInt(e.parent.localRecovery.localBalanceMsat)
			);
			f.retain(i);
			f.sign(i, f.context(i));
			const pending = row();
			assert.equal(pending.state, ChannelState.SPLICING);
			assert.equal(pending.pendingSpliceTxid, e.candidate.fundingTxid);
			assert.equal(
				pending.pendingSpliceLocalBalanceMsat,
				BigInt(e.candidate.localRecovery.localBalanceMsat)
			);
			assert.equal(pending.fundingTxid, e.parent.fundingTxid);
			assert.equal(pending.localBalanceMsat, opening.localBalanceMsat);
			assert.equal(pending.htlcUsable, false);
			assert.equal(pending.spendableOutboundMsat, 0n);
			assert.throws(
				() =>
					d.store.stageFinalHtlcUpdate(
						f.id,
						'local',
						M.UPDATE_ADD_HTLC,
						Buffer.alloc(1450)
					),
				/original update wallet/
			);
			assert.throws(
				() => d.store.acceptFinalUpdateCommitmentBatch(f.id, d.party.root, []),
				/original update wallet/
			);
			let importAllowed = false;
			const c = new AssetSpliceConfirmationCoordinator(
				d.store,
				{
					async verifySpliceFunding() {},
					async confirmSpliceFunding() {
						if (!importAllowed) throw Error('waiting');
					},
					async retractSpliceFunding() {}
				},
				() => {},
				() => {}
			);
			c.restore(f.id);
			const txid = e.candidate.fundingTxid,
				peer = f.devices[1 - i].party.binding.nodeId;
			await c.receive(
				peer,
				encodeSpliceLockedMessage({
					channelId: id,
					fundingTxid: Buffer.from(txid, 'hex').reverse()
				})
			);
			const proof = async () => ({
				txid,
				blockHash: 'ab'.repeat(32),
				confirmations: e.minimumDepth
			});
			await c.observe(f.id, txid, 12, proof, () => true).catch(() => {});
			assert.equal(row().fundingTxid, e.parent.fundingTxid);
			assert.equal(row().pendingSpliceTxid, txid);
			importAllowed = true;
			await c.observe(f.id, txid, 12, proof, () => true);
			const adopted = row();
			assert.equal(adopted.fundingTxid, txid);
			assert.equal(adopted.fundingOutputIndex, e.candidate.outputIndex);
			assert.equal(
				adopted.localBalanceMsat,
				BigInt(e.candidate.localRecovery.localBalanceMsat)
			);
			assert.equal(
				adopted.remoteBalanceMsat,
				BigInt(e.candidate.localRecovery.remoteBalanceMsat)
			);
			assert.equal(adopted.fundingSatoshis, 150000n);
			assert.equal(adopted.pendingSpliceTxid, undefined);
			assert.deepEqual(adopted.previousFundingTxids, [e.parent.fundingTxid]);
			assert.equal(adopted.htlcCount, 0);
			assert.equal(adopted.htlcUsable, false);
			await c.observe(f.id, txid, undefined, proof, () => true);
			assert.equal(row().state, ChannelState.ERRORED);
			assert.equal(row().localBalanceMsat, 0n);
			assert.equal(row().remoteBalanceMsat, 0n);
		}
	});
});
