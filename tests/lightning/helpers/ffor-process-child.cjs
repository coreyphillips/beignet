/** Isolated receiver for positive concurrent receive process-restart checks. */
'use strict';
/* eslint-disable @typescript-eslint/no-var-requires */
const path = require('path');
const root = path.resolve(__dirname, '../../..');
const { LightningNode } = require(path.join(
	root,
	'src/lightning/node/lightning-node'
));
const { SqliteStorage } = require(path.join(
	root,
	'src/lightning/storage/sqlite-storage'
));
const { FeatureFlags } = require(path.join(
	root,
	'src/lightning/features/flags'
));
let node;
let storage;
let completions = 0;

// Observe constructor reconciliation as well as later wire-driven credit.
class ObservedReceiver extends LightningNode {
	emit(event, ...args) {
		if (event === 'payment:received') completions++;
		return super.emit(event, ...args);
	}
}

function send(message) {
	if (process.connected) process.send(message);
}

process.on('message', (request) => {
	try {
		let value;
		switch (request.op) {
			case 'init':
				storage = new SqliteStorage(request.dbPath);
				storage.open();
				node = new ObservedReceiver({ ...request.config, storage });
				node
					.getChannelManager()
					.setFforPeerFeatureSource((peer) =>
						peer === request.peer
							? FeatureFlags.fromBuffer(request.peerFeatures)
							: null
					);
				node.on('node:error', (error) =>
					send({ event: 'error', message: error.message })
				);
				node.on('message:outbound', (peer, type, payload) =>
					send({ event: 'wire', peer, type, payload })
				);
				value = node.getNodeId();
				break;
			case 'message':
				node.handlePeerMessage(request.peer, request.type, request.payload);
				break;
			case 'reconnect':
				node.getChannelManager().handlePeerReconnected(request.peer);
				break;
			case 'disconnect':
				node.getChannelManager().handlePeerDisconnected(request.peer);
				break;
			case 'sync':
				value = node.fforSync(request.channelId);
				value = { ok: value.ok, error: value.error };
				break;
			case 'block':
				node.handleNewBlock(request.height);
				break;
			case 'inspect': {
				const channel = node
					.getChannelManager()
					.getChannel(Buffer.from(request.channelId, 'hex'));
				const state = channel.getFullState();
				const epoch = channel.getFforEpoch();
				value = {
					state: channel.getState(),
					epochState: epoch.state,
					syncPending: epoch.syncRequestWire !== undefined,
					outcomes: epoch.voucherOutcomes?.map(
						(outcome) => outcome?.outcome ?? null
					),
					localBalanceMsat: state.localBalanceMsat,
					vouchers: [...state.htlcs.values()]
						.filter((entry) => entry.fforVoucher)
						.map((entry) => entry.paymentHash.toString('hex')),
					payments: epoch.paymentHashes.map((hash) => {
						const payment = node.getPayment(hash);
						return {
							status: payment?.status,
							completedAt: payment?.completedAt,
							amountMsat: payment?.amountMsat
						};
					}),
					completions
				};
				break;
			}
			default:
				throw new Error('unknown process qualification command');
		}
		send({ id: request.id, value });
	} catch (error) {
		send({ id: request.id, error: error.message });
	}
});

process.on('disconnect', () => {
	if (node) node.destroy();
	if (storage) storage.close();
	process.exit(0);
});
