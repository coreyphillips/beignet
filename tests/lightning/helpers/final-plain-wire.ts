import { expect } from 'chai';
import { payments, Transaction } from 'bitcoinjs-lib';
import { FinalOpeningTransport } from '../../../src/lightning/channel/final-opening-transport';
import type { IFinalOpeningMessage } from '../../../src/lightning/channel/final-opening-runtime';
import { FinalSpliceTransport } from '../../../src/lightning/channel/final-splice-transport';
import { sha256 } from '../../../src/lightning/crypto/provider';
import {
	encodeUpdateAddHtlcMessage,
	encodeUpdateFulfillHtlcMessage
} from '../../../src/lightning/message/channel-update';
import { MessageType as M } from '../../../src/lightning/message/types';
import type { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import type { Side } from './final-update-pair';

/** Two original devices of one plain final channel, driven through the storage update API. */
export function plainUpdates(
	stores: readonly SqliteStorage[],
	sides: readonly Side[],
	id: string
) {
	const preimage = Buffer.alloc(32, 234);
	function stage(from: number, type: M, wire: Buffer): void {
		stores[from].stageFinalHtlcUpdate(id, 'local', type, wire);
		stores[1 - from].stageFinalHtlcUpdate(id, 'peer', type, wire);
	}
	function exchange(from: number): void {
		const sig = stores[from].signFinalUpdateCommitment(id, sides[from].root);
		const ack = stores[1 - from].acceptFinalUpdateCommitment(
			id,
			sides[1 - from].root,
			sig
		);
		stores[from].acceptFinalUpdateRevocation(id, ack);
	}
	function deliver(): void {
		for (const store of stores)
			for (const event of store.loadFinalUpdateDeliveries(id))
				store.ackFinalUpdateDelivery(id, event.id);
	}
	/** Side 0 offers an HTLC that both commitments lock in. */
	function add(cltvExpiry = 1100, amountMsat = 8000000n): void {
		stage(
			0,
			M.UPDATE_ADD_HTLC,
			encodeUpdateAddHtlcMessage({
				channelId: Buffer.from(id, 'hex'),
				id: 0n,
				amountMsat,
				paymentHash: sha256(preimage),
				cltvExpiry,
				onionRoutingPacket: Buffer.alloc(1366)
			})
		);
		exchange(0);
		exchange(1);
		deliver();
	}
	/** Side 1 settles the HTLC side 0 offered, so value moves both ways. */
	function fulfill(): void {
		stage(
			1,
			M.UPDATE_FULFILL_HTLC,
			encodeUpdateFulfillHtlcMessage({
				channelId: Buffer.from(id, 'hex'),
				id: 0n,
				paymentPreimage: preimage
			})
		);
		exchange(1);
		exchange(0);
		deliver();
	}
	return { stage, exchange, deliver, add, fulfill, preimage };
}

/** Drive a cooperative close through the storage close step, which reads no init features. */
export function closeCooperatively(
	stores: readonly SqliteStorage[],
	sides: readonly Side[],
	id: string
): Buffer[] {
	const scripts = sides.map(
		(s) =>
			payments.p2wpkh({ pubkey: s.keys.channelBasepoints.paymentBasepoint })
				.output!
	);
	const request = (
		i: number,
		message?: IFinalOpeningMessage,
		start = false
	) => ({
		script: scripts[i],
		blockHeight: 200,
		feeratePerKw: 1000,
		...(message && { message }),
		...(start && { start: true })
	});
	const txs: (Buffer | undefined)[] = [undefined, undefined];
	const queue: { to: number; message: IFinalOpeningMessage }[] = [];
	const step = (i: number, message?: IFinalOpeningMessage, start = false) => {
		const result = stores[i].finalSimpleCloseStep(
			id,
			sides[i].root,
			request(i, message, start)
		);
		if (result.transaction) txs[i] = result.transaction;
		for (const m of result.messages) queue.push({ to: 1 - i, message: m });
	};
	step(0, undefined, true);
	for (let n = 0; n < 24 && queue.length; n++) {
		const { to, message } = queue.shift()!;
		step(to, message);
	}
	expect(txs[0], 'closer transaction').to.not.equal(undefined);
	expect(txs[1], 'closee transaction').to.not.equal(undefined);
	return txs as Buffer[];
}

/** The final opening and splice transports of both devices, joined by an in-memory wire. */
export function plainWire(
	stores: readonly SqliteStorage[],
	sides: readonly Side[],
	id: string,
	reportErrors = true
) {
	const sockets: FinalOpeningTransport[] = [],
		splices: FinalSpliceTransport[] = [];
	const messages: Array<IFinalOpeningMessage & { from: number }> = [];
	const errors: string[] = [];
	const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
	const parent = Transaction.fromHex(
		stores[0].loadFinalOpening(id)!.fundingTxHex
	).getId();
	const depths = [new Set([parent]), new Set([parent])];
	for (const i of [0, 1]) {
		const runtime = { storage: stores[i], root: sides[i].root };
		const send = (_peer: string, type: M, payload: Buffer) =>
			messages.push({ from: i, type, payload });
		const verify = async () => 'unspent' as const;
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
			(_id, e) => reportErrors && errors.push(e)
		);
		const socket = new FinalOpeningTransport(
			runtime,
			verify,
			() => null,
			send,
			() => {},
			(_id, e) => reportErrors && errors.push(String(e)),
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
		socket.opened(sides[1 - i].binding.nodeId, id);
		socket.fundingDepth(id, true);
	}
	async function drain(): Promise<void> {
		for (let n = 0; n < 200; n++) {
			await tick();
			const packet = messages.shift();
			if (!packet) {
				await tick();
				if (!messages.length) return;
				continue;
			}
			sockets[1 - packet.from].queue(
				sides[packet.from].binding.nodeId,
				id,
				packet
			);
			await tick();
		}
		throw new Error('Plain final wire did not settle');
	}
	/** Splice 10500 sat out of side 0 and stop with the child funded and unadopted. */
	async function spliceOut(): Promise<Transaction> {
		await drain();
		const script = payments.p2wpkh({
			pubkey: sides[0].keys.channelBasepoints.fundingPubkey
		}).output!;
		splices[0].start(id, {
			localDelta: '-10500',
			feeBudget: '500',
			feerate: 253,
			locktime: 0,
			inputs: [],
			outputs: [{ value: '10000', script: script.toString('hex') }]
		});
		await drain();
		expect(errors).to.deep.equal([]);
		const funded = stores[0].loadFinalSpliceAttempts(id)[0]?.funded;
		expect(funded, 'funded plain splice').to.be.a('string');
		expect(stores[1].loadFinalSpliceAttempts(id)[0].funded).to.equal(funded);
		return Transaction.fromHex(funded!);
	}
	/** Exchange splice_locked at the storage sessions and adopt the child on both devices. */
	function adopt(child: Transaction): void {
		const txid = child.getId();
		const left = stores[0].finalSpliceSession(id, sides[0].root).lock(txid)!;
		stores[1].finalSpliceSession(id, sides[1].root).receive(left);
		const right = stores[1].finalSpliceSession(id, sides[1].root).lock(txid)!;
		stores[0].finalSpliceSession(id, sides[0].root).receive(right);
		for (const i of [0, 1]) {
			stores[i].finalSpliceSession(id, sides[i].root).next(undefined, txid);
			expect(
				Transaction.fromHex(
					stores[i].loadFinalActiveFunding(id)!.fundingTxHex
				).getId(),
				'adopted funding on side ' + i
			).to.equal(txid);
		}
	}
	function destroy(): void {
		for (const i of [0, 1])
			sockets[i].disconnected(sides[1 - i].binding.nodeId);
	}
	return {
		sockets,
		splices,
		messages,
		errors,
		depths,
		parent,
		drain,
		spliceOut,
		adopt,
		destroy
	};
}
