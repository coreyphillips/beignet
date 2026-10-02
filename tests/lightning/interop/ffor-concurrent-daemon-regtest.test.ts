import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import { AddressInfo, Server } from 'net';
import * as bitcoin from 'bitcoinjs-lib';
import { startDaemon, IStartedDaemon } from '../../../src/cli/daemon';
import { BeignetNode } from '../../../src/cli/beignet-node';
import { FforReceiveService } from '../../../src/cli/ffor-receive';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../../src/lightning/node/types';
import { ChannelState } from '../../../src/lightning/channel/types';
import { Feature } from '../../../src/lightning/features/flags';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { createFundingScript } from '../../../src/lightning/script/funding';
import { encodeShortChannelId } from '../../../src/lightning/gossip/types';
import { makeNodeConfig, publishChannel, REGTEST } from '../helpers/ffor-world';
import { bitcoinRpc, ensureBitcoindFunds, mineBlocks } from './shared-helpers';

async function until<T>(read: () => T | undefined, label: string): Promise<T> {
	const end = Date.now() + 30000;
	for (;;) {
		const result = read();
		if (result !== undefined) return result;
		if (Date.now() > end) throw new Error(`Timed out waiting for ${label}`);
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
}

async function api(
	daemon: IStartedDaemon,
	method: string,
	route: string,
	body?: unknown
): Promise<any> {
	const port = (daemon.server.address() as AddressInfo).port;
	return new Promise((resolve, reject) => {
		const payload = body === undefined ? undefined : JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				method,
				path: route,
				headers: payload
					? {
							'Content-Type': 'application/json',
							'Content-Length': Buffer.byteLength(payload)
					  }
					: {}
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk) => chunks.push(chunk));
				res.on('end', () => {
					const answer = JSON.parse(Buffer.concat(chunks).toString());
					if (res.statusCode !== 200 || !answer.ok)
						reject(new Error(`${method} ${route}: ${JSON.stringify(answer)}`));
					else resolve(answer.result);
				});
			}
		);
		req.on('error', reject);
		if (payload) req.write(payload);
		req.end();
	});
}

async function fund(
	opener: LightningNode,
	receiver: LightningNode,
	push = 0n
): Promise<{ id: Buffer; txid: string }> {
	const pending = opener.openChannel(receiver.getNodeId(), 1000000n, push);
	const channel = await until(() => {
		const found = opener
			.getChannelManager()
			.getTempChannel(pending.getTemporaryChannelId());
		return found?.getFullState().remoteBasepoints ? found : undefined;
	}, 'accept_channel');
	const state = channel.getFullState();
	const script = createFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey,
		REGTEST
	);
	const txid = (await bitcoinRpc('sendtoaddress', [
		script.address,
		0.01
	])) as string;
	await mineBlocks(1);
	const tx = bitcoin.Transaction.fromHex(
		(await bitcoinRpc('getrawtransaction', [txid])) as string
	);
	const index = tx.outs.findIndex((output) =>
		Buffer.from(output.script).equals(script.p2wshOutput)
	);
	expect(index).to.be.greaterThan(-1);
	const id = opener.createFunding(
		pending,
		tx.getHash(),
		index,
		crypto.randomBytes(64)
	)!;
	await until(
		() =>
			[
				ChannelState.SENT_FUNDING_SIGNED,
				ChannelState.AWAITING_FUNDING_CONFIRMED
			].includes(
				receiver.getChannelManager().getChannel(id)?.getState() as ChannelState
			) &&
			opener.getChannelManager().getChannel(id)?.getState() ===
				ChannelState.AWAITING_FUNDING_CONFIRMED
				? true
				: undefined,
		'funding_signed'
	).catch((error) => {
		throw new Error(
			`${error.message}: ${JSON.stringify({
				opener: opener
					.getChannelManager()
					.listChannels()
					.map((entry) => entry.getState()),
				receiver: receiver
					.getChannelManager()
					.listChannels()
					.map((entry) => entry.getState())
			})}`
		);
	});
	opener.handleFundingConfirmed(id);
	receiver.handleFundingConfirmed(id);
	await until(
		() =>
			[opener, receiver].every(
				(node) =>
					node.getChannelManager().getChannel(id)?.getState() ===
					ChannelState.NORMAL
			)
				? true
				: undefined,
		'channel_ready'
	);
	return { id, txid };
}

describe('Concurrent receive daemon HTTP acceptance on regtest', function () {
	this.timeout(180000);
	it('reuses a funded home channel, pays both ways, receives while stopped and credits once on two restarts', async () => {
		await ensureBitcoindFunds(2);
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ffor-daemon-regtest-'));
		const storage = new SqliteStorage(':memory:');
		storage.open();
		// The fixture funds a v1 2-of-2 outpoint itself, including push_msat.
		// Negotiate that opening protocol explicitly over the real transport.
		const features = LightningNode.defaultFeatures();
		features.clearBit(Feature.DUAL_FUND);
		features.clearBit(Feature.DUAL_FUND + 1);
		const s = new LightningNode(
			makeNodeConfig(92002, storage, {
				localFeatures: features,
				enableNetworking: true,
				autoReconnect: false,
				fforConcurrent: { enabled: true },
				fforSettle: { enabled: true, allowConcurrent: true }
			})
		);
		const p = new LightningNode(
			makeNodeConfig(92001, undefined, {
				enableNetworking: true,
				autoReconnect: false
			})
		);
		const errors: string[] = [];
		for (const node of [p, s])
			node.on('node:error', (error) => errors.push(error.message));
		const service = new FforReceiveService(
			{
				getNode: () => s,
				getStorage: () => storage,
				fforConcurrentNegotiated: (peer: string) =>
					s.getChannelManager().peerNegotiatedFforConcurrent(peer)
			} as unknown as BeignetNode,
			{ enabled: true },
			undefined,
			true
		);
		const options = {
			dataDir: dir,
			network: 'regtest' as const,
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			autoBootstrap: false,
			logLevel: 'silent' as const,
			fforConcurrent: true,
			fforSettleConcurrent: true
		};
		let daemon: IStartedDaemon | undefined;
		try {
			await s.listen(0, '127.0.0.1');
			const peerPort = (
				(
					s.getPeerManager() as unknown as { server: Server }
				).server.address() as AddressInfo
			).port;
			await p.connectPeer(s.getNodeId(), '127.0.0.1', peerPort);
			daemon = await startDaemon(options);
			let r = daemon.node.getNode();
			await r.connectPeer(s.getNodeId(), '127.0.0.1', peerPort);
			await until(
				() =>
					s.listPeers().length === 2 &&
					s.listPeers().every((peer) => peer.state === 'ready')
						? true
						: undefined,
				'both init exchanges'
			);
			const ps = await fund(p, s);
			const sr = await fund(s, r, 200000000n);
			const tip = (await bitcoinRpc('getblockcount')) as number;
			for (const node of [p, s, r]) node.handleNewBlock(tip);
			const scidPS = encodeShortChannelId({
				block: tip,
				txIndex: 1,
				outputIndex: 0
			});
			const scidSR = encodeShortChannelId({
				block: tip,
				txIndex: 2,
				outputIndex: 0
			});
			for (const viewer of [p, s, r]) {
				publishChannel(viewer, p, s, ps.id, scidPS);
				publishChannel(viewer, s, r, sr.id, scidSR);
			}
			const channelId = sr.id.toString('hex');
			const quote = await api(
				daemon,
				'GET',
				`/receive/quote?peer=${s.getNodeId()}&amountSats=100000`
			);
			expect(quote.mode).to.equal('bolt11');
			expect(quote.concurrentVersion).to.equal(2);
			const invoice = await api(daemon, 'POST', '/receive/invoice', {
				peer: s.getNodeId(),
				amountSats: 100000,
				requestId: 'regtest-concurrent-daemon-request',
				quote,
				description: 'offline daemon acceptance'
			});
			expect(invoice.concurrentVersion).to.equal(2);
			const ordinary = await api(daemon, 'POST', '/invoice/create', {
				amountSats: 2000,
				description: 'online receive beside reservation'
			});
			const incoming = s.sendPayment(ordinary.bolt11);
			await until(
				() => (incoming.status === PaymentStatus.COMPLETED ? true : undefined),
				'ordinary incoming payment'
			);
			const outgoing = s.createInvoice({
				amountMsat: 1000000n,
				description: 'online send beside reservation'
			});
			await api(daemon, 'POST', '/invoice/pay', {
				bolt11: outgoing.bolt11,
				timeoutMs: 30000
			});
			const before = (await api(daemon, 'GET', '/channels')).find(
				(entry: any) => entry.channelId === channelId
			);
			expect(before.localBalanceSats).to.equal(201000);
			expect(before.ffor.reservedInboundSats).to.equal(100000);
			expect(before.htlcUsable).to.equal(true);
			await api(daemon, 'POST', '/ffor/sync', { channelId });
			await until(
				() => (!r.getFforEpoch(channelId)!.syncRequestWire ? true : undefined),
				'explicit live sync'
			);
			await daemon.stop();
			daemon = undefined;
			await until(
				() =>
					!s.listPeers().some((peer) => peer.pubkey === r.getNodeId())
						? true
						: undefined,
				'receiver disconnect'
			);
			const paid = p.sendPayment(invoice.bolt11);
			await until(
				() => (paid.status !== PaymentStatus.PENDING ? paid : undefined),
				'offline payment'
			);
			expect(paid.status, JSON.stringify(errors)).to.equal(
				PaymentStatus.COMPLETED
			);
			let completedAt: number | undefined;
			for (let restart = 0; restart < 2; restart++) {
				daemon = await startDaemon(options);
				r = daemon.node.getNode();
				const restoredStatus = await api(daemon, 'GET', '/receive/status');
				expect(
					restoredStatus.requests.find(
						(entry: any) => entry.id === 'regtest-concurrent-daemon-request'
					)
				).to.include({ channelId, concurrent: true, concurrentVersion: 2 });
				if (restart === 0)
					expect(restoredStatus.reservedChannelIds).to.include(channelId);
				r.handleNewBlock(tip);
				await r.connectPeer(s.getNodeId(), '127.0.0.1', peerPort);
				await until(
					() =>
						r.getChannelManager().getChannel(sr.id)?.getState() ===
						ChannelState.NORMAL
							? true
							: undefined,
					'receiver reestablish'
				);
				await until(
					() =>
						r.getPayment(Buffer.from(invoice.paymentHash, 'hex'))?.status ===
						PaymentStatus.COMPLETED
							? true
							: undefined,
					'voucher credit'
				);
				const received = await api(
					daemon,
					'GET',
					`/invoice?paymentHash=${invoice.paymentHash}`
				);
				expect(received.status).to.equal('PAID');
				const channel = (await api(daemon, 'GET', '/channels')).find(
					(entry: any) => entry.channelId === channelId
				);
				expect(channel.localBalanceSats).to.equal(301000);
				const payment = r.getPayment(Buffer.from(invoice.paymentHash, 'hex'))!;
				if (restart === 0) completedAt = payment.completedAt;
				else expect(payment.completedAt).to.equal(completedAt);
				const payments = daemon.node
					.getStorage()
					.loadAllPayments()
					.filter(
						(entry) =>
							entry.paymentHash === invoice.paymentHash &&
							entry.payment.status === PaymentStatus.COMPLETED
					);
				expect(payments).to.have.length(1);
				await until(
					() =>
						daemon!.node
							.getOfflineReceive()
							.status()
							.reservedChannelIds.includes(channelId)
							? undefined
							: true,
					'automatic reservation release'
				);
				expect(
					(await api(daemon, 'GET', '/receive/status')).reservedChannelIds
				).not.to.include(channelId);
				await daemon.stop();
				daemon = undefined;
				await until(
					() =>
						!s.listPeers().some((peer) => peer.pubkey === r.getNodeId())
							? true
							: undefined,
					'restart disconnect'
				);
			}
			console.log(
				JSON.stringify({
					transport: 'TCP',
					api: 'HTTP',
					fundingTxid: sr.txid,
					receiverBalanceSats: 301000,
					creditedMsat: '100000000',
					restarts: 2,
					completedAt
				})
			);
		} catch (error) {
			throw new Error(`${(error as Error).message}: ${JSON.stringify(errors)}`);
		} finally {
			await daemon?.stop();
			service.stop();
			s.destroy();
			p.destroy();
			storage.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
