/**
 * The FFOR test world (helpers/ffor-world.ts: a payer P, a settlement peer
 * S and a receiver R as LightningNodes) set up for concurrent receive:
 * S and R opt in to option_ff_concurrent, S's settle policy answers the
 * profile, and each node's channel manager reads the other's advertised
 * features through the feature seam (no transport runs here, so nothing
 * records an init exchange).
 */

import { expect } from 'chai';
import { encodeShortChannelId } from '../../../src/lightning/gossip/types';
import { FforState } from '../../../src/lightning/ffor/types';
import {
	AMOUNTS,
	createWorld,
	D_DEADLINE,
	FEE_BASE,
	FEE_PPM,
	IWorld,
	IWorldOptions,
	publishChannel,
	record,
	T_EXP
} from './ffor-world';

export interface IConcurrentWorldOptions extends IWorldOptions {
	/** Opt S and R in to the extension (default true). */
	concurrent?: boolean;
	/** Whether S's settle policy answers the profile (default true). */
	allowConcurrent?: boolean;
}

/** Point S and R at each other's advertised features. */
export function wireWorldFeatures(w: IWorld): void {
	w.s
		.getChannelManager()
		.setFforPeerFeatureSource((peer) =>
			peer === w.r.getNodeId() ? w.r.getLocalFeatures() : null
		);
	w.r
		.getChannelManager()
		.setFforPeerFeatureSource((peer) =>
			peer === w.s.getNodeId() ? w.s.getLocalFeatures() : null
		);
}

/**
 * A world whose S-R channel can run a concurrent epoch, with R holding a
 * balance of its own and every node able to route to every other.
 */
export function createConcurrentWorld(
	opts: IConcurrentWorldOptions = {}
): IWorld {
	const concurrent = opts.concurrent ?? true;
	const w = createWorld({
		srPushMsat: 200_000_000n,
		...opts,
		sExtra: {
			...(concurrent ? { fforConcurrent: { enabled: true } } : {}),
			fforSettle: {
				enabled: true,
				allowConcurrent: opts.allowConcurrent ?? true
			},
			...opts.sExtra
		},
		rExtra: {
			...(concurrent ? { fforConcurrent: { enabled: true } } : {}),
			...opts.rExtra
		}
	});
	wireWorldFeatures(w);
	// createWorld shows P the P-S channel and S the S-R channel. Ordinary
	// payments between P and R, either way, need both ends to see both.
	const scidPS = encodeShortChannelId({
		block: 500,
		txIndex: 1,
		outputIndex: 0
	});
	const scidSR = encodeShortChannelId({
		block: 500,
		txIndex: 2,
		outputIndex: 0
	});
	publishChannel(w.p, w.s, w.r, w.srChannelId, scidSR);
	publishChannel(w.r, w.s, w.r, w.srChannelId, scidSR);
	publishChannel(w.r, w.p, w.s, w.psChannelId, scidPS);
	publishChannel(w.s, w.p, w.s, w.psChannelId, scidPS);
	w.ps.log.length = 0;
	w.sr.log.length = 0;
	return w;
}

/** R sets up an epoch on the S-R channel, asking for the profile or not. */
export function activateWorld(
	w: IWorld,
	concurrent: boolean,
	amounts: bigint[] = AMOUNTS
): void {
	const res = w.r.startFforEpoch(w.srHex, {
		voucherAmountsMsat: amounts,
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: FEE_BASE,
		feeProportionalMillionths: FEE_PPM,
		...(concurrent ? { concurrent: true } : {})
	});
	expect(res.ok, res.error).to.equal(true);
	expect(record(w.s, w.srHex).state, JSON.stringify(w.errors)).to.equal(
		FforState.ACTIVE
	);
	expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
	expect(record(w.s, w.srHex).concurrentVersion ?? 0).to.equal(
		concurrent ? 1 : 0
	);
	expect(record(w.r, w.srHex).concurrentVersion ?? 0).to.equal(
		concurrent ? 1 : 0
	);
}
