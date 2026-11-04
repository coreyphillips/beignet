/**
 * A peer's BOLT 1 warning reaches LightningNode as peer:warning, logged with
 * its sender, and never as a node:error (issue #1956).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeErrorMessage } from '../../src/lightning/message/error';
import { MessageType } from '../../src/lightning/message/types';
import type {
	ILightningError,
	IStructuredLog
} from '../../src/lightning/node/types';
import type { ILogger } from '../../src/logger';
import { createNode } from './helpers/loopback-nodes';

interface ILoggerCall {
	level: string;
	message: string;
	meta?: unknown;
}

function recordingLogger(): { calls: ILoggerCall[]; logger: ILogger } {
	const calls: ILoggerCall[] = [];
	const record =
		(level: string) =>
		(message: string, meta?: unknown): void => {
			calls.push({ level, message, meta });
		};
	return {
		calls,
		logger: {
			debug: record('debug'),
			info: record('info'),
			warn: record('warn'),
			error: record('error')
		}
	};
}

describe('Peer warnings (issue #1956)', function () {
	const peer = getPublicKey(
		crypto.createHash('sha256').update('peer-warning-sender').digest()
	).toString('hex');

	let node: LightningNode;
	let calls: ILoggerCall[];
	let warnings: Array<{
		pubkey: string;
		channelId: Buffer | null;
		text: string;
	}>;
	let nodeErrors: ILightningError[];
	let structured: IStructuredLog[];

	beforeEach(function () {
		const recorded = recordingLogger();
		calls = recorded.calls;
		node = createNode('peer-warning', 1, undefined, {
			logger: recorded.logger
		});
		warnings = [];
		nodeErrors = [];
		structured = [];
		node.on('peer:warning', (w) => warnings.push(w));
		node.on('node:error', (e) => nodeErrors.push(e));
		node.on('log', (entry) => structured.push(entry));
	});

	afterEach(function () {
		node.destroy();
	});

	function warn(channelId: Buffer, text: string): void {
		node.handlePeerMessage(
			peer,
			MessageType.WARNING,
			encodeErrorMessage({ channelId, data: Buffer.from(text, 'ascii') })
		);
	}

	it('names the sender of a connection-level warning and leaves out the all-zero id', function () {
		warn(Buffer.alloc(32), 'Unknown UTXO 503816x1343x1');

		expect(warnings).to.deep.equal([
			{ pubkey: peer, channelId: null, text: 'Unknown UTXO 503816x1343x1' }
		]);
		expect(nodeErrors).to.deep.equal([]);
		const logged = calls.filter((c) => c.message === 'Peer warning');
		expect(logged).to.deep.equal([
			{
				level: 'warn',
				message: 'Peer warning',
				meta: { pubkey: peer, text: 'Unknown UTXO 503816x1343x1' }
			}
		]);
		expect(calls.some((c) => c.level === 'error')).to.equal(false);
		const entry = structured.find(
			(l) => l.category === 'peer' && l.action === 'warning'
		);
		expect(entry?.data).to.deep.equal({
			pubkey: peer,
			text: 'Unknown UTXO 503816x1343x1'
		});
	});

	it('carries the channel id of a channel-level warning', function () {
		const channelId = crypto.randomBytes(32);
		warn(channelId, 'Splice feerate_perkw is too low');

		expect(warnings).to.have.length(1);
		expect(warnings[0].pubkey).to.equal(peer);
		expect(warnings[0].channelId!.equals(channelId)).to.equal(true);
		expect(warnings[0].text).to.equal('Splice feerate_perkw is too low');
		expect(nodeErrors).to.deep.equal([]);
		expect(calls.find((c) => c.message === 'Peer warning')?.meta).to.deep.equal(
			{
				pubkey: peer,
				channelId: channelId.toString('hex'),
				text: 'Splice feerate_perkw is too low'
			}
		);
	});
});
