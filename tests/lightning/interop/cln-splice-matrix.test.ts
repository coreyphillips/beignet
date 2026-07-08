/**
 * Interop: Beignet ↔ CLN splicing edge-case matrix (regtest).
 *
 * Splice-in/out were validated live against CLN on mainnet; this matrix
 * covers the interop surfaces that had never been exercised against a real
 * CLN peer, each tier ending in splice_locked + both sides NORMAL on the new
 * funding outpoint:
 *
 *   A1 beignet-initiated splice-out (full flow, first time in the harness)
 *   A2 repeat splice on the already-spliced channel (outpoint chaining)
 *   A3 payment over the spliced channel (CLN pays a beignet invoice)
 *   A4 splice-out again after routed payments changed both balances
 *   B1 CLN-INITIATED splice (beignet as pure acceptor) via CLN's splice RPCs
 *   C1 multi-UTXO splice-in (real on-chain wallet inputs, spec witness
 *      serialization with >1 input)
 *   D1 mid-splice disconnect after the commitment round (beignet's
 *      tx_signatures dropped) -> reconnect -> next_funding_txid resume
 *
 * Requires the compose `cln` container (v26.06.1, --experimental-splicing).
 * Auto-skips when CLN is unreachable.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	setupClnChannel,
	CLN_P2P_HOST,
	CLN_P2P_PORT,
	sleep
} from './cln-helpers';
import { bitcoinRpc, mineBlocks, ensureBitcoindFunds } from './shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import type { ISpliceWalletInput } from '../../../src/lightning/channel/channel';
import { MessageType } from '../../../src/lightning/message/types';

bitcoin.initEccLib(ecc);

describe('Interop: Beignet ↔ CLN splice matrix (regtest)', function () {
	this.timeout(600_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let skipAll = false;
	const nodes: LightningNode[] = [];

	before(async function () {
		this.timeout(60_000);
		if (!(await isClnAvailable())) {
			skipAll = true;
			console.log('    [skip] CLN container not reachable');
			this.skip();
			return;
		}
		const client = await createClnClient();
		if (!client) {
			skipAll = true;
			this.skip();
			return;
		}
		cln = client;
		await waitForClnSync(cln);
		clnPubkey = (await cln.getInfo()).id;
		await ensureBitcoindFunds(2.0);
	});

	after(function () {
		for (const n of nodes) {
			try {
				n.destroy();
			} catch {
				/* ignore */
			}
		}
	});

	/** Wait for the channel to be NORMAL on a NEW funding outpoint. */
	async function waitForSpliceComplete(
		node: LightningNode,
		channelId: Buffer,
		oldFundingTxidHex: string,
		timeoutMs = 60_000
	): Promise<void> {
		const cm = node.getChannelManager();
		const deadline = Date.now() + timeoutMs;
		for (;;) {
			const ch = cm.getChannel(channelId);
			const st = ch?.getFullState();
			if (
				st &&
				st.state === 'NORMAL' &&
				st.fundingTxid &&
				Buffer.from(st.fundingTxid).toString('hex') !== oldFundingTxidHex
			) {
				return;
			}
			if (Date.now() > deadline) {
				throw new Error(
					`splice did not complete: state=${st?.state} splice=${ch
						?.getSpliceSession()
						?.getState()}`
				);
			}
			await sleep(1000);
		}
	}

	/** Current splice txid recorded on the channel state (display order). */
	function spliceTxidHex(
		node: LightningNode,
		channelId: Buffer
	): string | null {
		const st = node
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState() as unknown as { spliceFundingTxid?: Buffer | null };
		return st.spliceFundingTxid
			? Buffer.from(st.spliceFundingTxid).reverse().toString('hex')
			: null;
	}

	/**
	 * Drive the on-chain leg: wait for THIS splice's tx (a NEW txid, distinct
	 * from any earlier splice on the channel) to be signed and broadcast (an
	 * external miner may confirm it before we look, so mempool OR confirmed
	 * both count), mine it to splice-lock depth, then let beignet send
	 * splice_locked (no chain backend is wired in the harness).
	 */
	async function confirmSplice(
		node: LightningNode,
		channelId: Buffer,
		prevSpliceTxid: string | null
	): Promise<string> {
		const cm = node.getChannelManager();

		let spliceTxid: string | null = null;
		const deadline = Date.now() + 60_000;
		while (Date.now() < deadline) {
			const current = spliceTxidHex(node, channelId);
			if (current && current !== prevSpliceTxid) {
				spliceTxid = current;
				break;
			}
			await sleep(500);
		}
		expect(spliceTxid, 'negotiated splice txid (new)').to.not.equal(null);

		// Wait for the tx to be known to bitcoind (mempool or already mined).
		const seenDeadline = Date.now() + 30_000;
		let seen = false;
		while (Date.now() < seenDeadline) {
			try {
				await bitcoinRpc('getrawtransaction', [spliceTxid!]);
				seen = true;
				break;
			} catch {
				await sleep(1000);
			}
		}
		expect(seen, `splice tx ${spliceTxid} was broadcast`).to.equal(true);

		await mineBlocks(6);
		await sleep(2000);
		cm.sendSpliceLocked(channelId);
		return spliceTxid!;
	}

	/**
	 * Poll CLN until its channel with `peerId` reports CHANNELD_NORMAL on the
	 * expected (post-splice) funding txid. Stale zombie channels from earlier
	 * runs are ignored by matching on peer AND funding outpoint.
	 */
	async function waitForClnSplicedNormal(
		peerId: string,
		expectedFundingTxid: string,
		timeoutMs = 90_000
	): Promise<void> {
		const deadline = Date.now() + timeoutMs;
		let last = '';
		while (Date.now() < deadline) {
			const { channels } = await cln.listChannels();
			const entry = (channels || []).find(
				(c) => c.peer_id === peerId && c.funding_txid === expectedFundingTxid
			);
			if (entry && entry.state === 'CHANNELD_NORMAL') return;
			last = entry ? entry.state : 'no-entry';
			await sleep(1000);
		}
		throw new Error(
			`CLN never reached CHANNELD_NORMAL on ${expectedFundingTxid} (last: ${last})`
		);
	}

	// ── Tier A: beignet-initiated lifecycle on ONE channel ──
	describe('Tier A: beignet-initiated splices + payment', function () {
		let node: LightningNode;
		let channelId: Buffer;

		before(async function () {
			if (skipAll) this.skip();
			// CLN funds 1M sats, pushes 400k to beignet so it can splice out.
			const setup = await setupClnChannel(
				cln,
				clnPubkey,
				220,
				1_000_000,
				400_000_000
			);
			node = setup.node;
			nodes.push(node);
			channelId = setup.channelId;
		});

		it('A1: beignet splice-out completes to NORMAL on the new outpoint', async function () {
			const cm = node.getChannelManager();
			const before = cm.getChannel(channelId)!.getFullState();
			const oldTxid = Buffer.from(before.fundingTxid!).toString('hex');
			const oldCap = before.fundingSatoshis;
			const prevSplice = spliceTxidHex(node, channelId);

			const res = node.spliceOut(channelId, 50_000n, 1000);
			expect(res.ok, res.error).to.equal(true);

			const spliceTxid = await confirmSplice(node, channelId, prevSplice);
			await waitForSpliceComplete(node, channelId, oldTxid);

			const after = cm.getChannel(channelId)!.getFullState();
			expect(after.fundingSatoshis < oldCap - 50_000n).to.equal(true);
			expect(
				Buffer.from(after.fundingTxid!).reverse().toString('hex')
			).to.equal(spliceTxid);
			await waitForClnSplicedNormal(node.getNodeId(), spliceTxid);
			console.log(
				`    A1 spliced: cap ${oldCap} -> ${after.fundingSatoshis}, txid ${spliceTxid}`
			);
		});

		it('A2: repeat splice-out on the already-spliced channel', async function () {
			const cm = node.getChannelManager();
			const before = cm.getChannel(channelId)!.getFullState();
			const oldTxid = Buffer.from(before.fundingTxid!).toString('hex');
			const oldCap = before.fundingSatoshis;
			const prevSplice = spliceTxidHex(node, channelId);

			const res = node.spliceOut(channelId, 40_000n, 1000);
			expect(res.ok, res.error).to.equal(true);

			const spliceTxid = await confirmSplice(node, channelId, prevSplice);
			await waitForSpliceComplete(node, channelId, oldTxid);

			const after = cm.getChannel(channelId)!.getFullState();
			expect(after.fundingSatoshis < oldCap - 40_000n).to.equal(true);
			await waitForClnSplicedNormal(node.getNodeId(), spliceTxid);
		});

		it('A3: CLN pays a beignet invoice over the spliced channel', async function () {
			const invoice = node.createInvoice({
				amountMsat: 25_000_000n,
				description: 'splice-matrix-a3'
			});

			// CLN's REST pay blocks until the payment resolves; cap it so a
			// stalled payment fails the test instead of eating the suite budget.
			const payResult = await Promise.race([
				cln.pay(invoice.bolt11),
				sleep(60_000).then(() => {
					throw new Error('CLN pay timed out after 60s');
				})
			]);
			expect(payResult.status).to.equal('complete');

			// Give the fulfill round a moment to settle both sides.
			await sleep(2000);
			const cm = node.getChannelManager();
			expect(cm.getChannel(channelId)!.getState()).to.equal('NORMAL');
		});

		it('A4: splice-out again after routed payments changed both balances', async function () {
			const cm = node.getChannelManager();
			const before = cm.getChannel(channelId)!.getFullState();
			const oldTxid = Buffer.from(before.fundingTxid!).toString('hex');
			const prevSplice = spliceTxidHex(node, channelId);

			const res = node.spliceOut(channelId, 30_000n, 1000);
			expect(res.ok, res.error).to.equal(true);

			const spliceTxid = await confirmSplice(node, channelId, prevSplice);
			await waitForSpliceComplete(node, channelId, oldTxid);
			await waitForClnSplicedNormal(node.getNodeId(), spliceTxid);
		});
	});

	// ── Tier B: CLN-initiated splice, beignet is a pure acceptor ──
	describe('Tier B: CLN-initiated splice (beignet acceptor)', function () {
		it('B1: CLN splices out of its own balance via its splice RPCs', async function () {
			if (skipAll) this.skip();
			const setup = await setupClnChannel(cln, clnPubkey, 221, 800_000, 0);
			const node = setup.node;
			nodes.push(node);
			const channelId = setup.channelId;
			const cm = node.getChannelManager();
			// getFullState() returns the LIVE state object — snapshot scalars.
			const before = cm.getChannel(channelId)!.getFullState();
			const capBefore = before.fundingSatoshis;
			const localBefore = before.localBalanceMsat;
			const oldTxid = Buffer.from(before.fundingTxid!).toString('hex');

			const clnChannelId = before.channelId!.toString('hex');

			// CLN drives: splice_init -> splice_update (until commitments are
			// secured) -> splice_signed (signs + broadcasts).
			const init = await cln.spliceInit(clnChannelId, -60_000);
			let psbt = init.psbt;
			let secured = false;
			for (let i = 0; i < 10 && !secured; i++) {
				const upd = await cln.spliceUpdate(clnChannelId, psbt);
				psbt = upd.psbt;
				secured = upd.commitments_secured;
				if (!secured) await sleep(500);
			}
			expect(secured, 'CLN reports commitments secured').to.equal(true);
			const signed = await cln.spliceSigned(psbt, clnChannelId);
			console.log(`    B1 CLN broadcast splice txid ${signed.txid}`);

			await mineBlocks(6);
			await sleep(2000);
			cm.sendSpliceLocked(channelId);
			await waitForSpliceComplete(node, channelId, oldTxid);

			const after = cm.getChannel(channelId)!.getFullState();
			console.log(
				`    B1 beignet view: cap ${capBefore} -> ${
					after.fundingSatoshis
				}, txid ${Buffer.from(after.fundingTxid!).reverse().toString('hex')}`
			);
			// CLN withdrew 60k from its own side: capacity down by the declared
			// relative amount, beignet's balance untouched.
			expect(after.fundingSatoshis).to.equal(capBefore - 60_000n);
			expect(after.localBalanceMsat).to.equal(localBefore);
			expect(
				Buffer.from(after.fundingTxid!).reverse().toString('hex')
			).to.equal(signed.txid);
			await waitForClnSplicedNormal(node.getNodeId(), signed.txid);
		});
	});

	// ── Tier C: multi-UTXO splice-in with real on-chain inputs ──
	describe('Tier C: multi-UTXO splice-in', function () {
		it('C1: beignet splices in from TWO real wallet UTXOs with change', async function () {
			if (skipAll) this.skip();
			const setup = await setupClnChannel(cln, clnPubkey, 222, 500_000, 0);
			const node = setup.node;
			nodes.push(node);
			const channelId = setup.channelId;
			const cm = node.getChannelManager();
			const ch = cm.getChannel(channelId)!;
			const before = ch.getFullState();
			const oldTxid = Buffer.from(before.fundingTxid!).toString('hex');
			const oldCap = before.fundingSatoshis;

			// Create two REAL confirmed P2WPKH UTXOs we control.
			const makeRealInput = async (
				tag: string,
				valueSat: number
			): Promise<ISpliceWalletInput> => {
				const priv = crypto
					.createHash('sha256')
					.update(`splice-matrix-c1-${tag}`)
					.digest();
				const pub = Buffer.from(ecc.pointFromScalar(priv, true)!);
				const payment = bitcoin.payments.p2wpkh({
					pubkey: pub,
					network: bitcoin.networks.regtest
				});
				const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
				const txid = (await bitcoinRpc('sendtoaddress', [
					payment.address!,
					valueSat / 1e8
				])) as string;
				await mineBlocks(1);
				const raw = (await bitcoinRpc('getrawtransaction', [txid])) as string;
				const prevTx = bitcoin.Transaction.fromHex(raw);
				const vout = prevTx.outs.findIndex((o) =>
					Buffer.from(o.script).equals(payment.output!)
				);
				expect(vout, 'funded output present').to.be.gte(0);
				return {
					prevTx: prevTx.toBuffer(),
					prevOutputIndex: vout,
					value: BigInt(valueSat),
					sequence: 0xfffffffd,
					confirmed: true,
					signWitness: (
						tx: bitcoin.Transaction,
						inputIndex: number,
						v: bigint
					): Buffer[] => {
						const sighash = tx.hashForWitnessV0(
							inputIndex,
							scriptCode,
							Number(v),
							bitcoin.Transaction.SIGHASH_ALL
						);
						const sig64 = Buffer.from(ecc.sign(sighash, priv));
						const der = bitcoin.script.signature.encode(
							sig64,
							bitcoin.Transaction.SIGHASH_ALL
						);
						return [der, pub];
					}
				};
			};

			const in1 = await makeRealInput('a', 60_000);
			const in2 = await makeRealInput('b', 50_000);
			const changePriv = crypto
				.createHash('sha256')
				.update('splice-matrix-c1-change')
				.digest();
			const changeScript = bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(ecc.pointFromScalar(changePriv, true)!)
			}).output!;

			ch.setSpliceInInputs([in1, in2], changeScript);
			const prevSplice = spliceTxidHex(node, channelId);
			const res = cm.initiateSplice(channelId, 80_000n, 1000);
			expect(res.ok, 'splice-in initiated').to.equal(true);

			const spliceTxid = await confirmSplice(node, channelId, prevSplice);
			await waitForSpliceComplete(node, channelId, oldTxid);

			const after = cm.getChannel(channelId)!.getFullState();
			expect(after.fundingSatoshis).to.equal(oldCap + 80_000n);
			await waitForClnSplicedNormal(node.getNodeId(), spliceTxid);
			console.log(
				`    C1 spliced in 80k from 2 UTXOs: cap ${oldCap} -> ${after.fundingSatoshis}`
			);
		});
	});

	// ── Tier D: mid-splice disconnect + next_funding_txid resume ──
	describe('Tier D: mid-splice disconnect + resume', function () {
		it('D1: dropped tx_signatures, reconnect, splice resumes and completes', async function () {
			if (skipAll) this.skip();
			const setup = await setupClnChannel(
				cln,
				clnPubkey,
				223,
				900_000,
				300_000_000
			);
			const node = setup.node;
			nodes.push(node);
			const channelId = setup.channelId;
			const cm = node.getChannelManager();
			const before = cm.getChannel(channelId)!.getFullState();
			const oldTxid = Buffer.from(before.fundingTxid!).toString('hex');

			// Intercept beignet's outbound TX_SIGNATURES (sent LAST by the splice
			// initiator) and cut the connection instead of delivering it: the
			// splice is then in flight on both sides with CLN still waiting.
			// The wire path is channelManager.sendMessage -> peerManager.sendToPeer.
			const pm = (
				node as unknown as {
					peerManager: {
						sendToPeer(pk: string, type: number, payload: Buffer): void;
					};
				}
			).peerManager;
			const realSend = pm.sendToPeer.bind(pm);
			let dropped = false;
			pm.sendToPeer = (pk: string, type: number, payload: Buffer): void => {
				if (type === MessageType.TX_SIGNATURES && !dropped) {
					dropped = true;
					console.log('    D1 dropping beignet tx_signatures + disconnecting');
					setImmediate(() => node.disconnectPeer(clnPubkey));
					return;
				}
				realSend(pk, type, payload);
			};

			const res = node.spliceOut(channelId, 45_000n, 1000);
			expect(res.ok, res.error).to.equal(true);

			// Wait until the drop + disconnect actually happened.
			const dropDeadline = Date.now() + 30_000;
			while (!dropped && Date.now() < dropDeadline) await sleep(500);
			expect(dropped, 'tx_signatures was dropped').to.equal(true);
			await sleep(2000);

			// Restore the wire and reconnect: channel_reestablish announces
			// next_funding_txid on both sides, beignet retransmits its
			// tx_signatures, and the splice resumes (CLN also runs an update_fee
			// round as start_batch commitment batches in this window).
			pm.sendToPeer = realSend;
			await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);

			const spliceTxid = await confirmSplice(node, channelId, null);
			await waitForSpliceComplete(node, channelId, oldTxid, 90_000);
			await waitForClnSplicedNormal(node.getNodeId(), spliceTxid);
		});
	});
});
