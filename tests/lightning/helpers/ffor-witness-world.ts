/**
 * The four-node receipt-witness world P -> W -> S -> R (spec section 9.6):
 * W is a witness on P's route to S, holds its ledger in a SQLite store, and
 * has a direct link to R for provisioning and fetching. Shared by the M9
 * tests (barrier, paging).
 */

import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../../src/lightning/node/types';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { encodeShortChannelId } from '../../../src/lightning/gossip/types';
import { MessageType } from '../../../src/lightning/message/types';
import {
	IWorld,
	NodeLink,
	TIP,
	makeNodeConfig,
	openReadyChannel,
	publishChannel
} from './ffor-world';

export interface IWitnessWorld extends IWorld {
	w: LightningNode;
	wStorage: SqliteStorage;
	pw: NodeLink;
	ws: NodeLink;
	rw: NodeLink;
	pwChannelId: Buffer;
	wsChannelId: Buffer;
}

let seed = 4000;

export function createWitnessWorld(
	witness: Partial<INodeConfig['fforWitness']> = {}
): IWitnessWorld {
	seed += 10;
	const pConfig = makeNodeConfig(seed + 1);
	const wStorage = new SqliteStorage(':memory:');
	wStorage.open();
	const wConfig = makeNodeConfig(seed + 4, wStorage, {
		fforWitness: { enabled: true, ...witness }
	});
	const sConfig = makeNodeConfig(seed + 2);
	const rConfig = makeNodeConfig(seed + 3);
	const p = new LightningNode(pConfig);
	const w = new LightningNode(wConfig);
	const s = new LightningNode(sConfig);
	const r = new LightningNode(rConfig);
	const errors = { p: [] as string[], s: [] as string[], r: [] as string[] };
	for (const n of [p, w, s, r]) n.on('node:error', () => {});
	s.on('node:error', (e: { message: string }) => errors.s.push(e.message));
	r.on('node:error', (e: { message: string }) => errors.r.push(e.message));
	const pw = new NodeLink(p, w);
	const ws = new NodeLink(w, s);
	const sr = new NodeLink(s, r);
	const rw = new NodeLink(r, w);
	const pwChannelId = openReadyChannel(p, w, 1_000_000n);
	const wsChannelId = openReadyChannel(w, s, 1_000_000n);
	const srChannelId = openReadyChannel(s, r, 1_000_000n);
	const scid = (i: number): Buffer =>
		encodeShortChannelId({ block: 500, txIndex: i, outputIndex: 0 });
	publishChannel(p, p, w, pwChannelId, scid(1));
	publishChannel(p, w, s, wsChannelId, scid(2));
	publishChannel(s, s, r, srChannelId, scid(3));
	for (const n of [p, w, s, r]) n.handleNewBlock(TIP);
	for (const l of [pw, ws, sr, rw]) l.log.length = 0;
	return {
		p,
		s,
		r,
		w,
		wStorage,
		pConfig,
		sConfig,
		rConfig,
		ps: pw,
		sr,
		pw,
		ws,
		rw,
		psChannelId: pwChannelId,
		pwChannelId,
		wsChannelId,
		srChannelId,
		srHex: srChannelId.toString('hex'),
		errors
	};
}

export const sleep = (ms: number): Promise<void> =>
	new Promise((r) => setTimeout(r, ms));

export async function waitFor(
	cond: () => boolean,
	label: string,
	ms = 5_000
): Promise<void> {
	const deadline = Date.now() + ms;
	while (!cond()) {
		if (Date.now() > deadline) throw new Error(`timed out: ${label}`);
		await sleep(10);
	}
}

/** Fulfils and fails W sent upstream to P. */
export function fulfilsToP(w: IWitnessWorld): number {
	return w.pw
		.sentBy(w.w)
		.filter(
			(e) =>
				e.type === MessageType.UPDATE_FAIL_HTLC ||
				e.type === MessageType.UPDATE_FULFILL_HTLC
		).length;
}
