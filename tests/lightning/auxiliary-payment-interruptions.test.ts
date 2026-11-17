/**
 * Issue #2093: an asset payment that is interrupted.
 *
 * A direct asset payment is cut after each message in turn, one side is
 * stopped and started again from its database, and the two reconnect. Every
 * case has to end paid or failed on both sides, with the units accounted
 * for.
 */

import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { PaymentStatus } from '../../src/lightning/node/types';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { amountRecord } from './helpers/auxiliary-pair';
import {
	assetHost,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

const settle = async (rounds = 60): Promise<void> => {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

interface IWire {
	/** Messages delivered so far, both ways. */
	delivered: number;
	/** Deliver this many, then drop everything. */
	limit: number;
	types: number[];
}

function wire(a: IAssetHost, b: IAssetHost, ctl: IWire): void {
	const route = (from: IAssetHost, to: IAssetHost): void => {
		from.node.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer !== to.node.getNodeId()) return;
				if (ctl.delivered >= ctl.limit) return;
				ctl.delivered++;
				ctl.types.push(type);
				to.node.handlePeerMessage(from.node.getNodeId(), type, payload);
			}
		);
	};
	route(a, b);
	route(b, a);
}

async function comeBack(a: IAssetHost, b: IAssetHost): Promise<void> {
	const held: Array<() => void> = [];
	const originals = [a, b].map((host) => host.node.handlePeerMessage);
	for (const host of [a, b]) {
		const deliver = host.node.handlePeerMessage.bind(host.node);
		host.node.handlePeerMessage = ((
			peer: string,
			type: number,
			payload: Buffer
		) => {
			held.push(() => deliver(peer, type, payload));
		}) as typeof host.node.handlePeerMessage;
	}
	a.node.getChannelManager().handlePeerReconnected(b.node.getNodeId());
	b.node.getChannelManager().handlePeerReconnected(a.node.getNodeId());
	while (held.length > 0) held.shift()!();
	a.node.handlePeerMessage = originals[0];
	b.node.handlePeerMessage = originals[1];
	await settle(200);
}

describe('an asset payment that is interrupted (issue #2093)', function () {
	this.timeout(240_000);
	withAssetOpens();

	it('cut after any message, with either side restarted, ends paid or failed on both sides with the units accounted for', async () => {
		const failures: string[] = [];
		const lines: string[] = [];
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-cut-'));
		const bobHooks: Partial<IAuxiliaryChannelConfig> = {
			valueIncomingHtlc: (context) =>
				context.auxiliaryAmount !== undefined
					? context.auxiliaryAmount * 1000n
					: undefined
		};
		// How many messages a whole payment takes.
		const total = 12;
		for (const crash of ['alice', 'bob'] as const) {
			for (let cut = 0; cut <= total; cut++) {
				const tag = `rev-a-cut-${crash}-${cut}`;
				const alicePath = path.join(directory, `${tag}-alice.sqlite`);
				const bobPath = path.join(directory, `${tag}-bob.sqlite`);
				const open: IAssetHost[] = [];
				try {
					let alice = assetHost(tag, 1, {}, { sqlitePath: alicePath });
					let bob = assetHost(tag, 2, bobHooks, { sqlitePath: bobPath });
					open.push(alice, bob);
					const ctl: IWire = { delivered: 0, limit: Infinity, types: [] };
					wire(alice, bob, ctl);
					const channelId = await openAssetChannel(alice, bob, {
						tag,
						openerUnits: 9000n,
						acceptorUnits: 1000n
					});
					const invoice = bob.node.createInvoice({
						amountMsat: 5_000_000n,
						description: tag
					});
					ctl.delivered = 0;
					ctl.types = [];
					ctl.limit = cut;
					alice.node.sendPaymentToRoute(
						{
							hops: [
								{
									pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
									shortChannelId: Buffer.alloc(8, 9),
									amountToForwardMsat: 5_000_000n,
									outgoingCltvValue: 40
								}
							]
						},
						invoice.paymentHash,
						40,
						invoice.paymentSecret,
						undefined,
						undefined,
						undefined,
						undefined,
						{
							assetPayment: {
								channelId,
								wireAmountMsat: 354_000n,
								customRecords: amountRecord(5000n)
							}
						}
					);
					await settle(100);
					if (crash === 'alice' && cut === 0 && ctl.limit === 0) {
						// Learn the length of an uncut payment once.
					}
					const seen = ctl.types.join(',');
					// One side stops and starts again from its database.
					const victim = crash === 'alice' ? alice : bob;
					const other = crash === 'alice' ? bob : alice;
					const victimId = victim.node.getNodeId();
					victim.node.destroy();
					other.node.getChannelManager().handlePeerDisconnected(victimId);
					other.node.removeAllListeners('message:outbound');
					const restarted = assetHost(
						tag,
						crash === 'alice' ? 1 : 2,
						crash === 'alice' ? {} : bobHooks,
						{ sqlitePath: crash === 'alice' ? alicePath : bobPath }
					);
					open.push(restarted);
					if (crash === 'alice') alice = restarted;
					else bob = restarted;
					const after: IWire = { delivered: 0, limit: Infinity, types: [] };
					wire(alice, bob, after);
					await comeBack(alice, bob);
					await settle(200);

					const a = alice.node.getAuxiliaryChannelInfo(channelId);
					const b = bob.node.getAuxiliaryChannelInfo(channelId);
					const aPay = alice.node.getPayment(invoice.paymentHash)?.status;
					const bPay = bob.node.getPayment(invoice.paymentHash)?.status;
					const line =
						`${crash} restarted after ${cut} messages [${seen}]: ` +
						`alice ${a?.state} ${a?.localAssetBalance}/${a?.remoteAssetBalance} htlcs ${a?.htlcs.length} pay ${aPay} | ` +
						`bob ${b?.state} ${b?.localAssetBalance}/${b?.remoteAssetBalance} htlcs ${b?.htlcs.length} pay ${bPay}`;
					lines.push(line);
					const paid =
						a?.localAssetBalance === 4000n &&
						a?.remoteAssetBalance === 6000n &&
						b?.localAssetBalance === 6000n &&
						b?.remoteAssetBalance === 4000n &&
						aPay === PaymentStatus.COMPLETED &&
						bPay === PaymentStatus.COMPLETED;
					const failed =
						a?.localAssetBalance === 9000n &&
						a?.remoteAssetBalance === 1000n &&
						b?.localAssetBalance === 1000n &&
						b?.remoteAssetBalance === 9000n &&
						aPay !== PaymentStatus.COMPLETED &&
						bPay !== PaymentStatus.COMPLETED;
					const quiet =
						a?.state === 'NORMAL' &&
						b?.state === 'NORMAL' &&
						a.htlcs.length === 0 &&
						b.htlcs.length === 0;
					if (!quiet || !(paid || failed)) {
						failures.push(
							`${line} || errors: ${JSON.stringify(
								[...alice.errors, ...bob.errors].filter(
									(e) => !e.startsWith('NO_ROUTING')
								)
							).slice(0, 600)}`
						);
					}
					if (cut === 0 && crash === 'alice') {
						// nothing
					}
				} catch (err) {
					failures.push(`${tag}: threw ${(err as Error).message}`);
				} finally {
					for (const host of open) {
						try {
							host.node.destroy();
						} catch {
							// already destroyed
						}
						host.storage?.close();
					}
				}
			}
		}
		fs.rmSync(directory, { recursive: true, force: true });
		expect(failures).to.deep.equal([]);
	});
});
