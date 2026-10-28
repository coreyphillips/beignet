/**
 * Issue #1901: nothing clears preReestablishState when a channel wrapped by
 * a disconnect closes. getChannelDiagnostics read it on any state, so a
 * channel force closed while its peer was away was diagnosed as if it were
 * still NORMAL: no NOT_NORMAL issue, and preReestablishState: 'NORMAL'.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { writableState } from '../lightning/helpers/writable-state';

const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

describe('Channel diagnostics after a wrapped channel closes (issue #1901)', function () {
	this.timeout(20_000);

	let node: BeignetNode;

	before(async () => {
		node = await BeignetNode.create({
			network: 'regtest',
			dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-diag-wrap-')),
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});
	});

	after(async () => {
		await node.destroy();
	});

	/** A restored channel in `state`, wrapping NORMAL; returns its id. */
	function restoreWrapped(state: ChannelState): string {
		const point = getPublicKey(crypto.randomBytes(32));
		const bp = {
			fundingPubkey: point,
			revocationBasepoint: point,
			paymentBasepoint: point,
			delayedPaymentBasepoint: point,
			htlcBasepoint: point,
			firstPerCommitmentPoint: point
		};
		const channel = new Channel(
			createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: bp,
				localPerCommitmentSeed: crypto.randomBytes(32)
			})
		);
		const st = writableState(channel);
		st.channelId = crypto.randomBytes(32);
		st.fundingTxid = crypto.randomBytes(32);
		st.remoteBasepoints = bp;
		st.state = state;
		st.preReestablishState = ChannelState.NORMAL;
		node
			.getNode()
			.getChannelManager()
			.restoreChannel(channel, crypto.randomBytes(33).toString('hex'));
		return st.channelId.toString('hex');
	}

	function diagnose(channelId: string): {
		preReestablishState: string | null;
		issues: string[];
	} {
		return node.getChannelDiagnostics(channelId) as unknown as {
			preReestablishState: string | null;
			issues: string[];
		};
	}

	it('diagnoses a channel force closed while wrapped by its own state', () => {
		const d = diagnose(restoreWrapped(ChannelState.FORCE_CLOSED));
		expect(d.preReestablishState).to.equal(null);
		expect(d.issues).to.include(
			'NOT_NORMAL: Channel state is FORCE_CLOSED (pre-reestablish: none). Routing hints require a usable channel.'
		);
	});

	it('still names the earlier state while the channel awaits reestablish', () => {
		const d = diagnose(restoreWrapped(ChannelState.AWAITING_REESTABLISH));
		expect(d.preReestablishState).to.equal(ChannelState.NORMAL);
		expect(d.issues.some((i) => i.startsWith('NOT_NORMAL'))).to.equal(false);
	});
});
