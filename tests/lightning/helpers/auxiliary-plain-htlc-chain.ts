/**
 * A plain HTLC on an asset channel, for the tests of one on the chain and
 * over the database of another build: an HTLC with no units and no custom
 * records, which a peer offers when its forwarding picks the asset channel
 * for an ordinary payment. The host of these tests values one that arrived
 * on an asset channel and pays an invoice of the node at the bitcoin it
 * carries, as the payment of that invoice.
 *
 * This node never offers such an HTLC itself, and no engine payer keeps a
 * record of one: the peer is made to offer it by an add of its channel
 * manager, its channel asked for no asset side, and the evidence of the
 * payer is that channel.
 */

import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import type { IAuxiliaryIncomingHtlc } from '../../../src/lightning/channel/auxiliary-funding';
import {
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../../src/lightning/chain/types';
import {
	constructOnionPacket,
	encodeOnionPacket
} from '../../../src/lightning/onion/construct';
import type { TestChain } from './auxiliary-chain';
import type { IAssetHost } from './auxiliary-nodes';
import { trackedOutputs } from './auxiliary-on-chain';
import { hash } from './auxiliary-pair';

/**
 * The host's answer for an incoming HTLC: one with units at 1,000 msat a
 * unit, as the other tests of asset channels value them; one without units
 * that arrived on an asset channel and pays an invoice of this node at the
 * bitcoin it carries; any other without units is not the host's.
 */
export function valuePlainHtlc(
	context: IAuxiliaryIncomingHtlc
): bigint | undefined {
	if (context.auxiliaryAmount !== undefined) {
		return context.auxiliaryAmount * 1000n;
	}
	return context.state.auxiliaryState !== undefined &&
		context.invoice !== undefined
		? context.wireAmountMsat
		: undefined;
}

/** A payment one plain HTLC of the peer pays, or a part of it. */
export interface IPlainHtlcPayment {
	amountMsat: bigint;
	paymentHash: Buffer;
	paymentSecret: Buffer;
	/** The height the HTLC expires at. */
	cltvExpiry: number;
	/** The total the payment's parts declare; the amount when left out. */
	totalMsat?: bigint;
}

/**
 * `from` offers `to` a plain HTLC on a channel between them, through its
 * channel manager, with an onion that names `to` as the last hop. On an
 * asset channel the channel of `from` is made to ask for no asset side,
 * as a peer that offers a plain HTLC there does. Throws when the add is
 * refused.
 */
export function offerPlainHtlc(
	from: IAssetHost,
	to: IAssetHost,
	channelId: Buffer,
	payment: IPlainHtlcPayment
): void {
	const manager = from.node.getChannelManager();
	const channel = manager.getChannel(channelId);
	if (!channel) throw new Error('the peer has no such channel');
	(
		channel as unknown as { _prepareAuxiliaryHtlc: () => void }
	)._prepareAuxiliaryHtlc = (): void => undefined;
	const packet = constructOnionPacket(
		hash(
			`plain HTLC session key ${payment.paymentHash.toString('hex')} ${
				payment.amountMsat
			} ${channelId.toString('hex')}`
		),
		[
			{
				pubkey: Buffer.from(to.node.getNodeId(), 'hex'),
				payload: {
					amountToForwardMsat: payment.amountMsat,
					outgoingCltvValue: payment.cltvExpiry,
					paymentSecret: payment.paymentSecret,
					totalMsat: payment.totalMsat ?? payment.amountMsat
				}
			}
		],
		payment.paymentHash
	);
	const added = manager.addHtlc(
		channelId,
		payment.amountMsat,
		payment.paymentHash,
		payment.cltvExpiry,
		encodeOnionPacket(packet)
	);
	if (!added.ok) {
		throw new Error(`the plain HTLC was not added: ${added.error}`);
	}
}

/** A preimage of a test's own and its payment hash. */
export function preimageOf(tag: string): {
	preimage: Buffer;
	paymentHash: Buffer;
} {
	const preimage = hash(`plain HTLC preimage ${tag}`);
	return {
		preimage,
		paymentHash: crypto.createHash('sha256').update(preimage).digest()
	};
}

/** The parts of a hold invoice a node keeps parked. */
export const parkedOf = (host: IAssetHost, paymentHash: Buffer): number =>
	(host.node as unknown as { heldHtlcs: Map<string, unknown[]> }).heldHtlcs.get(
		paymentHash.toString('hex')
	)?.length ?? 0;

/** The output of the HTLC a host received, on the commitment that went to the chain. */
export const receivedHtlcOutput = (
	host: IAssetHost,
	channelId: Buffer
): ITrackedOutput | undefined =>
	trackedOutputs(host, channelId).find(
		(output) =>
			output.outputType === OutputType.RECEIVED_HTLC &&
			output.isSecondLevelHtlc !== true
	);

/** The output a host's own second-level transaction made, which waits out the delay. */
export const secondLevelOutput = (
	host: IAssetHost,
	channelId: Buffer
): ITrackedOutput | undefined =>
	trackedOutputs(host, channelId).find(
		(output) => output.isSecondLevelHtlc === true
	);

export const isSpent = (output: ITrackedOutput | undefined): boolean =>
	!!output &&
	[OutputStatus.SPEND_CONFIRMED, OutputStatus.IRREVOCABLY_RESOLVED].includes(
		output.status
	);

/**
 * Keep from the chain every transaction handed to it that spends one
 * outpoint, each once, in the order it came; whoever handed it over is
 * told it was taken. Every other transaction is judged as the chain judges
 * it. Kept at the chain, it holds across a restart of the node that sends
 * them. `publish` hands a kept one to the chain.
 */
export function withholdSpends(
	chain: TestChain,
	outpoint: { txid: string; outputIndex: number }
): {
	kept: string[];
	publish: (hex: string) => void;
} {
	const admit = chain.admit.bind(chain);
	const kept: string[] = [];
	chain.admit = (tx, judge): { fee: number; vsize: number } => {
		const spends = tx.ins.some(
			(input) =>
				Buffer.from(input.hash).reverse().toString('hex') === outpoint.txid &&
				input.index === outpoint.outputIndex
		);
		if (!spends) return admit(tx, judge);
		const hex = tx.toHex();
		if (!kept.includes(hex)) kept.push(hex);
		return { fee: 0, vsize: tx.virtualSize() };
	};
	return {
		kept,
		publish: (hex: string): void => {
			admit(bitcoin.Transaction.fromHex(hex));
		}
	};
}

/** What a transaction pays in fees, from the outputs the chain has for its inputs. */
export const feeOf = (chain: TestChain, tx: bitcoin.Transaction): number =>
	tx.ins.reduce(
		(sum, input) =>
			sum +
			chain.transaction(Buffer.from(input.hash).reverse().toString('hex'))!
				.outs[input.index].value,
		0
	) - tx.outs.reduce((sum, out) => sum + out.value, 0);
