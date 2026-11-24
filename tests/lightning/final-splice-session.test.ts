import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { FinalOpeningTransport } from '../../src/lightning/channel/final-opening-transport';
import { FinalSpliceTransport } from '../../src/lightning/channel/final-splice-transport';
import { encodeStfuMessage } from '../../src/lightning/message/stfu';
import { encodeTxAbortMessage } from '../../src/lightning/message/interactive-tx';
import { expect } from 'chai';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Transaction, payments } from 'bitcoinjs-lib';
import {
	generateSide,
	fundReadyPair,
	walletSigner,
	type Side
} from './helpers/final-update-pair';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { MessageType as M } from '../../src/lightning/message/types';
import type { IFinalOpeningMessage } from '../../src/lightning/channel/final-opening-runtime';
import {
	decodeTxCompleteMessage,
	decodeTxSignaturesMessage,
	encodeTxSignaturesMessage,
	encodeTxAddInputMessage,
	decodeTxAddInputMessage
} from '../../src/lightning/message/interactive-tx';
import { encodeSpliceLockedMessage } from '../../src/lightning/message/splice';
import { validateFundingWitness } from '../../src/lightning/interactive-tx/funding-witness';
import { taprootKeySpendSighash } from '../../src/lightning/script/funding-taproot';
import { ecc } from '../../src/utils/ecc';
import {
	encodeUpdateFeeMessage,
	encodeUpdateAddHtlcMessage,
	encodeUpdateFulfillHtlcMessage
} from '../../src/lightning/message/channel-update';
import { sha256 } from '../../src/lightning/crypto/provider';

describe('final splice negotiation and recovery', function () {
	this.timeout(120000);
	let dir: string,
		id: string,
		a: SqliteStorage,
		b: SqliteStorage,
		alice: Side,
		bob: Side;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-lifecycle-'));
		alice = generateSide();
		bob = generateSide();
		a = SqliteStorage.createFinalWallet(path.join(dir, 'a'), alice.binding);
		b = SqliteStorage.createFinalWallet(path.join(dir, 'b'), bob.binding);
		id = fundReadyPair(a, b, alice, bob);
	});
	afterEach(() => {
		a.close();
		b.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	function restart() {
		a.close();
		b.close();
		a = SqliteStorage.openFinalWallet(path.join(dir, 'a'), alice.binding);
		b = SqliteStorage.openFinalWallet(path.join(dir, 'b'), bob.binding);
	}
	function transport(store: SqliteStorage, side: Side) {
		const sent: IFinalOpeningMessage[] = [],
			released: Array<{ txid: string; vout: number }> = [],
			failures: string[] = [];
		const wire = new FinalSpliceTransport(
			{ storage: store, root: side.root },
			() => ({
				releaseInputPledges: async (inputs) => {
					released.push(...inputs);
				}
			}),
			async () => 'unspent',
			undefined,
			(_peer, type, payload) => sent.push({ type, payload }),
			() => {},
			() => {},
			() => {},
			() => false,
			(_id, reason) => failures.push(reason)
		);
		wire.fundingDepth(id, true);
		return { wire, sent, released, failures };
	}
	for (const interruption of [
		'before commitment',
		'during verification',
		'recovered during verification',
		'after witness release on one peer'
	] as const) {
		it(
			'gates splice signatures on live funding when depth changes ' +
				interruption,
			async () => {
				const stores = [a, b],
					peers = [alice, bob];
				const sockets: FinalOpeningTransport[] = [],
					splices: FinalSpliceTransport[] = [];
				const messages: Array<IFinalOpeningMessage & { from: number }> = [];
				const signatures: Array<{ side: number; type: M; depth: boolean }> = [];
				const errors: string[] = [],
					verified: string[] = [];
				const tick = () =>
					new Promise<void>((resolve) => setImmediate(resolve));
				let lost = false;
				const asymmetric = interruption === 'after witness release on one peer';
				const parent = Transaction.fromHex(
					a.loadFinalOpening(id)!.fundingTxHex
				).getId();
				const depths = [new Set([parent]), new Set([parent])];
				for (const i of [0, 1]) {
					const runtime = { storage: stores[i], root: peers[i].root };
					const send = (_peer: string, type: M, payload: Buffer) => {
						messages.push({ from: i, type, payload });
						if ([M.COMMITMENT_SIGNED, M.TX_SIGNATURES].includes(type))
							signatures.push({
								side: i,
								type,
								depth: sockets[i].hasDepth(id)
							});
					};
					const verify = async (input: { txid: Buffer }) => {
						if (i === 1) {
							verified.push(input.txid.toString('hex'));
							if (asymmetric && verified.length === 1) {
								expect(
									stores[i]
										.loadFinalFundingExits(id)
										.map((x) =>
											Buffer.from(x.fundingTxid).reverse().toString('hex')
										)
								).to.deep.equal([parent]);
								expect(
									stores[i]
										.loadFinalResolutionStates(id)!
										.locals.map((x) => x.funding)
								).to.deep.equal([undefined]);
							}
							if (
								!lost &&
								!asymmetric &&
								interruption !== 'before commitment'
							) {
								lost = true;
								sockets[i].fundingDepth(id, false);
								await tick();
								if (interruption === 'recovered during verification')
									sockets[i].fundingDepth(id, true);
							}
						}
						return 'unspent' as const;
					};
					const splicer = new FinalSpliceTransport(
						runtime,
						() => ({ resolveFinalSpliceInputs: async () => () => [] }),
						verify,
						undefined,
						send,
						() => {},
						() => {},
						() => {},
						(_id, txid) => depths[i].has(txid),
						(_id, e) => errors.push(e)
					);
					const socket = new FinalOpeningTransport(
						runtime,
						verify,
						() => null,
						send,
						() => {},
						(_id, e) => errors.push(e),
						() => ({ alias: true, splice: true }),
						undefined,
						() => {},
						() => true,
						undefined,
						undefined,
						splicer
					);
					sockets.push(socket);
					splices.push(splicer);
					socket.opened(peers[1 - i].binding.nodeId, id);
					socket.fundingDepth(id, true);
				}
				messages.length = 0;
				const script = payments.p2wpkh({
					pubkey: alice.keys.channelBasepoints.fundingPubkey
				}).output!;
				splices[0].start(id, {
					localDelta: '-10500',
					feeBudget: '500',
					feerate: 253,
					locktime: 0,
					inputs: [],
					outputs: [{ value: '10000', script: script.toString('hex') }]
				});
				const drain = async () => {
					for (let n = 0; n < 100; n++) {
						await tick();
						const packet = messages.shift();
						if (!packet) {
							await tick();
							if (!messages.length) return;
							continue;
						}
						if (
							asymmetric &&
							!lost &&
							packet.from === 0 &&
							packet.type === M.TX_SIGNATURES
						) {
							lost = true;
							continue;
						}
						const dest = sockets[1 - packet.from];
						dest.queue(peers[packet.from].binding.nodeId, id, packet);
						await tick();
						if (
							!lost &&
							interruption === 'before commitment' &&
							packet.from === 1 &&
							packet.type === M.STFU
						) {
							lost = true;
							sockets[1].fundingDepth(id, false);
						}
					}
					throw new Error('Splice wire did not settle');
				};
				await drain();
				expect(lost).to.equal(true);
				if (asymmetric) {
					const funding = Transaction.fromHex(
						a.loadFinalSpliceAttempts(id)[0].funded!
					);
					const child = funding.getId(),
						channelId = Buffer.from(id, 'hex');
					expect(b.loadFinalSpliceAttempts(id)[0].funded).to.equal(undefined);
					expect(
						b
							.loadFinalFundingExits(id)
							.some((e) => e.fundingTxid.equals(funding.getHash()))
					).to.equal(true);
					for (const i of [0, 1]) {
						const socket = sockets[i],
							peer = peers[1 - i].binding.nodeId;
						socket.disconnected(peer);
						const manager: ChannelManager = Object.assign(
							Object.create(ChannelManager.prototype),
							{
								config: {
									finalOpening: { storage: stores[i], root: peers[i].root }
								},
								finalObservedFunding: new Map(),
								finalDepthByChannel: new Map([[id, depths[i]]]),
								finalObservedClose: new Map(),
								finalTransport: socket,
								finalSplice: splices[i]
							}
						);
						manager.forgetFinalFundingConfirmation(channelId, parent);
						manager.observeFinalFunding(id, child, 550, false);
						expect(socket.hasDepth(id)).to.equal(false);
						manager.handleFundingConfirmed(channelId, child);
						expect(socket.hasDepth(id)).to.equal(true);
						if (i === 1)
							expect(
								stores[i].loadFinalSpliceAttempts(id)[0].localLock
							).to.equal(undefined);
					}
					for (const i of [0, 1])
						sockets[i].reconnected(peers[1 - i].binding.nodeId);
					await drain();
					expect(errors).to.deep.equal([]);
					for (const store of stores) {
						const result = store.loadFinalSpliceAttempts(id)[0];
						expect(result.funded).to.equal(funding.toHex());
						expect(result.adopted).to.equal(child);
					}
					return;
				}
				if (interruption !== 'recovered during verification') {
					expect(sockets[1].hasDepth(id)).to.equal(false);
					expect(
						signatures.some((x) => x.side === 1 && x.type === M.TX_SIGNATURES)
					).to.equal(false);
					sockets[1].fundingDepth(id, true);
					await drain();
				}
				expect(errors).to.deep.equal([]);
				expect(signatures.filter((x) => !x.depth)).to.deep.equal([]);
				expect(
					signatures.filter((x) => x.side === 1 && x.type === M.TX_SIGNATURES)
				).to.have.length(1);
				const own = a.loadFinalSpliceAttempts(id)[0].funded;
				expect(own).to.be.a('string');
				expect(b.loadFinalSpliceAttempts(id)[0].funded).to.equal(own);
				if (interruption !== 'before commitment') {
					expect(verified.length).to.be.greaterThan(1);
					expect(new Set(verified).size).to.equal(1);
				}
			}
		);
	}

	const empty = {
		localDelta: '0',
		feeBudget: '0',
		feerate: 1000,
		locktime: 0,
		inputs: [],
		outputs: []
	};
	it('releases retired inputs once on unsigned reconnect and burns the retired key', async () => {
		const coin = new Transaction();
		coin.addInput(Buffer.alloc(32, 19), 0);
		coin.addOutput(Buffer.alloc(34), 10000);
		const t = transport(a, alice);
		t.wire.start(id, {
			...empty,
			inputs: [{ prevTxHex: coin.toHex(), vout: 0, sequence: 0xfffffffd }]
		});
		expect([...a.loadFinalSpliceWalletOutpoints()]).to.deep.equal([
			coin.getId() + ':0'
		]);
		const first = a.loadFinalSpliceAttempts(id)[0].intent.localFundingPubkey;
		const msg = b.finalUpdateReestablish(id, bob.root);
		await t.wire.reestablished(id, msg, () => true);
		await t.wire.reestablished(id, msg, () => true);
		expect(t.sent.map((m) => m.type)).to.deep.equal([M.STFU]);
		expect(t.released).to.deep.equal([{ txid: coin.getId(), vout: 0 }]);
		expect([...a.loadFinalSpliceWalletOutpoints()]).to.deep.equal([]);
		restart();
		transport(a, alice).wire.start(id, empty);
		expect(
			a.loadFinalSpliceAttempts(id)[1].intent.localFundingPubkey
		).not.to.equal(first);
	});
	it('echoes a peer abort and awaits acknowledgment of a locally refused turn', async () => {
		const msg = {
			type: M.TX_ABORT,
			payload: encodeTxAbortMessage({
				channelId: Buffer.from(id, 'hex'),
				data: Buffer.from('funding unavailable')
			})
		};
		const t = transport(a, alice);
		t.wire.start(id, empty);
		await t.wire.receive(id, msg, true, () => true);
		expect(t.sent.map((m) => m.type)).to.deep.equal([M.STFU, M.TX_ABORT]);
		t.wire.start(id, empty);
		await t.wire.receive(
			id,
			{ type: M.SPLICE_ACK, payload: Buffer.from(id, 'hex') },
			true,
			() => true
		);
		expect(t.sent[t.sent.length - 1].type).to.equal(M.TX_ABORT);
		expect(() => t.wire.start(id, empty)).to.throw(/abort is incomplete/);
		await t.wire.receive(id, msg, true, () => true);
		expect(t.failures).to.have.length(2);
		t.wire.start(id, empty);
	});
	it('gives the original opener priority on crossed quiescence requests', async () => {
		const ta = transport(a, alice),
			tb = transport(b, bob);
		ta.wire.start(id, empty);
		tb.wire.start(id, empty);
		const crossed = {
			type: M.STFU,
			payload: encodeStfuMessage({
				channelId: Buffer.from(id, 'hex'),
				initiator: true
			})
		};
		await ta.wire.receive(id, crossed, false, () => true);
		await tb.wire.receive(id, crossed, false, () => true);
		expect(ta.sent.map((m) => m.type)).to.deep.equal([M.STFU, M.SPLICE]);
		expect(tb.sent.map((m) => m.type)).to.deep.equal([M.STFU]);
		expect(tb.failures).to.have.length(1);
		await tb.wire.receive(id, ta.sent[1], false, () => true);
		expect(tb.sent[1].type).to.equal(M.SPLICE_ACK);
		expect(b.loadFinalSpliceAttempts(id)[1].intent.initiator).to.equal(false);
	});
	function exchangeUpdate(type: M, payload: Buffer, outgoing: boolean) {
		const [sender, receiver] = outgoing ? [a, b] : [b, a],
			[first, second] = outgoing ? [alice, bob] : [bob, alice];
		sender.stageFinalHtlcUpdate(id, 'local', type, payload);
		receiver.stageFinalHtlcUpdate(id, 'peer', type, payload);
		const us = sender.signFinalUpdateCommitmentBatch(id, first.root);
		const r = receiver.acceptFinalUpdateCommitmentBatch(id, second.root, us);
		sender.acceptFinalUpdateRevocation(id, r);
		const them = receiver.signFinalUpdateCommitmentBatch(id, second.root);
		const s = sender.acceptFinalUpdateCommitmentBatch(id, first.root, them);
		receiver.acceptFinalUpdateRevocation(id, s);
		return us.length;
	}
	for (const spliceIn of [false, true])
		it(
			'restores both originals at every signed boundary during a splice-' +
				(spliceIn ? 'in' : 'out'),
			() => {
				const chan = Buffer.from(id, 'hex');
				const preimage = Buffer.alloc(32, 71);
				const add = encodeUpdateAddHtlcMessage({
					channelId: chan,
					id: 0n,
					amountMsat: 2000000n,
					paymentHash: sha256(preimage),
					cltvExpiry: 800,
					onionRoutingPacket: Buffer.alloc(1366)
				});
				expect(exchangeUpdate(M.UPDATE_ADD_HTLC, add, true)).to.equal(1);
				const ref = a.loadFinalActiveFunding(id)!;
				const parent = Transaction.fromHex(ref.fundingTxHex);
				const walletKey = alice.keys.fundingPrivkey;
				const script = payments.p2wpkh({
					pubkey: alice.keys.channelBasepoints.fundingPubkey
				}).output!;
				const coin = new Transaction();
				coin.addInput(Buffer.alloc(32, 55), 1);
				coin.addOutput(script, 17000);
				a.finalSpliceSession(id, alice.root).begin(true, {
					localDelta: spliceIn ? '10000' : '-10500',
					feeBudget: '500',
					feerate: 253,
					locktime: 0,
					inputs: spliceIn
						? [{ prevTxHex: coin.toHex(), vout: 0, sequence: 0xfffffffd }]
						: [],
					outputs: [
						{
							value: spliceIn ? '6500' : '10000',
							script: script.toString('hex')
						}
					]
				});
				expect(() => a.signFinalUpdateCommitment(id, alice.root)).to.throw(
					/quiescent/
				);
				expect(() =>
					a.acceptFinalUpdateCommitment(id, alice.root, Buffer.alloc(0))
				).to.throw(/quiescent/);
				expect(() =>
					a.acceptFinalUpdateRevocation(id, Buffer.alloc(0))
				).to.throw(/quiescent/);
				b.finalSpliceSession(id, bob.root).begin(false, {
					localDelta: '0',
					feeBudget: '0',
					feerate: 1,
					locktime: 0,
					inputs: [],
					outputs: []
				});
				const sent: { from: boolean; message: IFinalOpeningMessage }[] = [];
				const broadcasts: Transaction[] = [];
				for (let round = 0; round < 40 && broadcasts.length < 2; round++) {
					for (const from of [true, false]) {
						const [self, peer, key, other] = from
							? ([a, b, alice, bob] as const)
							: ([b, a, bob, alice] as const);
						const session = self.finalSpliceSession(id, key.root);
						let ret = session.next();
						if (ret?.verify) {
							expect(ret.verify.candidate.outputOwners).to.deep.equal([
								from,
								!from
							]);
							const local = ret.verify.candidate.localInputs;
							ret = session.next(
								local.length ? walletSigner(walletKey, local[0], []) : () => []
							);
						}
						if (ret?.wire) {
							const msg = ret.wire;
							if (msg.type === M.TX_SIGNATURES) {
								const candidate =
									self.loadFinalSpliceAttempts(id)[0].candidate!;
								expect(candidate).not.to.have.property('localExit');
								expect(
									self
										.loadFinalFundingExits(id)
										.some((e) =>
											e.fundingTxid.equals(
												Transaction.fromHex(
													candidate.funding.fundingTxHex
												).getHash()
											)
										)
								).to.equal(true);
								expect(
									sent.some(
										(p) =>
											p.from === from && p.message.type === M.COMMITMENT_SIGNED
									)
								).to.equal(true);
								const decoded = decodeTxSignaturesMessage(msg.payload, {
									taproot: true
								});
								const changed = Buffer.from(
									decoded.sharedInputPartialSignatureWithNonce!
								);
								changed[0] ^= 1;
								const changedMsg = {
									type: msg.type,
									payload: encodeTxSignaturesMessage({
										...decoded,
										sharedInputPartialSignatureWithNonce: changed
									})
								};
								expect(() =>
									peer.finalSpliceSession(id, other.root).receive(changedMsg)
								).to.throw();
							}
							sent.push({ from, message: msg });
							peer.finalSpliceSession(id, other.root).receive(msg);
						}
						if (ret?.broadcast)
							broadcasts.push(Transaction.fromBuffer(ret.broadcast));
						restart();
					}
				}
				expect(broadcasts).to.have.length(2);
				const tx = broadcasts[0];
				expect(tx.toHex()).to.equal(broadcasts[1].toHex());
				const sig = tx.ins[0].witness[0],
					scripts = [parent.outs[ref.fundingOutputIndex].script],
					values = [parent.outs[ref.fundingOutputIndex].value];
				if (spliceIn) {
					scripts.push(script);
					values.push(17000);
				}
				expect(sig).to.have.length(64);
				expect(
					ecc.verifySchnorr(
						taprootKeySpendSighash(tx, 0, scripts, values),
						scripts[0].subarray(2),
						sig
					)
				).to.equal(true);
				if (spliceIn)
					expect(
						validateFundingWitness(tx, 1, tx.ins[1].witness, {
							scripts,
							values: values.map(BigInt)
						})
					).to.equal(null);
				for (const who of [true, false]) {
					const completed = sent
						.filter((x) => x.from === who && x.message.type === M.TX_COMPLETE)
						.slice(-1)[0];
					const nonce = decodeTxCompleteMessage(completed.message.payload, {
						taproot: true
					});
					expect(
						new Set(
							[
								nonce.fundingInputNonce!,
								nonce.commitNonces!.current,
								nonce.commitNonces!.next
							].map((v) => v.toString('hex'))
						).size
					).to.equal(3);
				}
				if (spliceIn) {
					const peer = b.finalUpdateReestablish(id, bob.root);
					const missing = {
						...peer,
						nextFundingTxid: tx.getHash(),
						nextFundingRetransmitFlags: 0,
						nextLocalNonces: peer.nextLocalNonces.filter(
							(n) => !n.fundingTxid.equals(tx.getHash())
						)
					};
					expect(
						a.acceptFinalUpdateReestablish(id, alice.root, missing)
					).to.deep.equal([]);
					expect(a.loadFinalUpdateStatus(id)!.awaitingFundingNonce).to.equal(
						true
					);
					expect(() =>
						a.signFinalUpdateCommitmentBatch(id, alice.root)
					).to.throw(/verification nonce/);
					const own = a.finalUpdateReestablish(id, alice.root),
						full = b.finalUpdateReestablish(id, bob.root);
					a.acceptFinalUpdateReestablish(id, alice.root, full);
					b.acceptFinalUpdateReestablish(id, bob.root, own);
					expect(a.loadFinalUpdateStatus(id)!.awaitingFundingNonce).to.equal(
						false
					);
				}
				const settle = encodeUpdateFulfillHtlcMessage({
					channelId: chan,
					id: 0n,
					paymentPreimage: preimage
				});
				expect(exchangeUpdate(M.UPDATE_FULFILL_HTLC, settle, false)).to.equal(
					2
				);
				const feeChange = encodeUpdateFeeMessage({
					channelId: chan,
					feeratePerKw: 610
				});
				expect(
					exchangeUpdate(
						M.UPDATE_FEE,
						feeChange,
						a.loadFinalOpening(id)!.isInitiator
					)
				).to.equal(2);
				for (const original of [a, b]) {
					const states = original.loadFinalResolutionStates(id)!;
					expect(states.locals.map((v) => v.feeratePerKw)).to.deep.equal([
						610, 610
					]);
					expect(states.revoked.some((v) => v.feeratePerKw === 253)).to.equal(
						true
					);
				}
				const sa = a.finalSpliceSession(id, alice.root),
					sb = b.finalSpliceSession(id, bob.root);
				for (const txid of [undefined, Buffer.alloc(32, 70)])
					expect(() =>
						sa.receive({
							type: M.SPLICE_LOCKED,
							payload: encodeSpliceLockedMessage({
								channelId: chan,
								fundingTxid: txid
							})
						})
					).to.throw();
				const left = sa.lock(tx.getId())!;
				sb.receive(left);
				expect(b.loadFinalActiveFunding(id)).to.equal(null);
				restart();
				const right = b.finalSpliceSession(id, bob.root).lock(tx.getId())!;
				expect(b.finalSpliceSession(id, bob.root).next()?.adopted).to.equal(
					undefined
				);
				expect(b.loadFinalUpdateStatus(id)!.multipleFunding).to.equal(true);
				expect(() =>
					b.stageFinalHtlcUpdate(id, 'local', M.UPDATE_ADD_HTLC, add)
				).to.throw(/quiescent/);
				expect(() => b.signFinalUpdateCommitmentBatch(id, bob.root)).to.throw(
					/quiescent/
				);
				const reconnectA = a.finalUpdateReestablish(id, alice.root);
				const reconnectB = b.finalUpdateReestablish(id, bob.root);
				expect(reconnectB.nextLocalNonces).to.have.length(2);
				a.acceptFinalUpdateReestablish(id, alice.root, reconnectB);
				b.acceptFinalUpdateReestablish(id, bob.root, reconnectA);
				expect(
					b.finalSpliceSession(id, bob.root).next(undefined, tx.getId())
						?.adopted
				).to.equal(tx.getId());
				if (spliceIn) {
					const msg = {
						...b.finalUpdateReestablish(id, bob.root),
						myCurrentFundingLocked: { txid: tx.getHash(), retransmitFlags: 0 }
					};
					expect(msg.nextLocalNonces).to.have.length(1);
					const bad = {
						...msg,
						yourLastPerCommitmentSecret: Buffer.alloc(32, 11)
					};
					expect(() =>
						a.acceptFinalUpdateReestablish(id, alice.root, bad)
					).to.throw(/wrong revocation secret/i);
					expect(a.loadFinalSpliceAttempts(id)[0].peerLock).to.equal(undefined);
					a.acceptFinalUpdateReestablish(id, alice.root, msg);
					expect(a.loadFinalSpliceAttempts(id)[0].peerLock).to.equal(
						tx.getId()
					);
				} else a.finalSpliceSession(id, alice.root).receive(right);
				expect(a.finalSpliceSession(id, alice.root).next()?.adopted).to.equal(
					undefined
				);
				expect(
					a.finalSpliceSession(id, alice.root).next(undefined, tx.getId())
						?.adopted
				).to.equal(tx.getId());
				restart();
				expect(
					Transaction.fromHex(
						a.loadFinalActiveFunding(id)!.fundingTxHex
					).getId()
				).to.equal(tx.getId());
				expect(a.loadFinalCommitmentSnapshot(id)!.htlcs).to.have.length(0);
				expect(
					a.loadFinalCommitmentSnapshot(id)!.terms.commitmentFeeratePerKw
				).to.equal(610);
				expect(a.loadFinalCommitmentSnapshot(id)!.localBalanceMsat).to.equal(
					BigInt(a.loadFinalOpening(id)!.localContributionSats) * 1000n -
						2000000n +
						(spliceIn ? 10000n : -10500n) * 1000n
				);
				// Advancing the adopted funding releases the parent's latest local secret on every outpoint.
				const newFee = encodeUpdateFeeMessage({
					channelId: chan,
					feeratePerKw: 620
				});
				expect(
					exchangeUpdate(
						M.UPDATE_FEE,
						newFee,
						a.loadFinalOpening(id)!.isInitiator
					)
				).to.equal(1);
				for (const original of [a, b]) {
					const resolution = original.loadFinalResolutionStates(id)!;
					expect(resolution.locals.map((v) => v.height)).to.deep.equal([
						resolution.local.height
					]);
					expect(resolution.local.tx).to.deep.equal(resolution.locals[0].tx);
					expect(
						[...resolution.remote, ...resolution.revoked].every(
							(v) => !Transaction.fromBuffer(v.tx).hasWitnesses()
						)
					).to.equal(true);
					expect(
						original.loadFinalFundingExits(id).map((x) => x.fundingTxid)
					).to.deep.equal([tx.getHash()]);
					expect(() =>
						original.requestFinalOpeningExit(id, parent.getHash())
					).to.throw(/current funding commitment/);
					expect(original.loadFinalDaemonOpening(id)!.exitToBroadcast).to.equal(
						undefined
					);
					expect(
						Transaction.fromBuffer(
							original.requestFinalOpeningExit(id, tx.getHash())
						).ins[0].hash
					).to.deep.equal(tx.getHash());
				}
			}
		);
	it('preserves Eclair compact input fields and refuses contradictory previous output forms', () => {
		const msg = {
			channelId: Buffer.alloc(32, 9),
			serialId: 2n,
			prevTx: Buffer.alloc(0),
			prevTxVout: 1,
			sequence: 0xfffffffd,
			prevTxOut: {
				txid: Buffer.alloc(32, 4),
				amount: 2000n,
				script: Buffer.from([81])
			}
		};
		const raw = encodeTxAddInputMessage(msg);
		expect(
			decodeTxAddInputMessage(raw, { taproot: true }).prevTxOut
		).to.deep.equal(msg.prevTxOut);
		expect(() =>
			encodeTxAddInputMessage({ ...msg, sharedInputTxid: Buffer.alloc(32) })
		).to.throw();
	});
});
