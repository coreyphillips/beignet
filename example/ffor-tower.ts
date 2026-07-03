/**
 * FFOR Variant B tower, run standalone.
 *
 * Demonstrates that the tower (src/lightning/ffor/tower.ts) is a self-contained
 * agent with no coupling to ChannelManager: this process constructs one, serves
 * it over a trivial TCP JSON-lines transport, and needs nothing else from
 * beignet's channel machinery. In production the transport is HTTPS / onion /
 * Noise (spec §9.4 leaves it out of scope); this is the minimal working shape.
 *
 *   npx ts-node example/ffor-tower.ts [port]
 *
 * Wire protocol (one JSON object per line):
 *   -> {"op":"provision","provisioning":{...}}          (R, hex-encoded buffers)
 *   -> {"op":"release","package":"<hex>"}               (S)
 *   <- {"ok":true,"seq":1,"preimage":"<hex>"} | {"ok":false,"error":"..."}
 *   -> {"op":"fetch","epochId":"<hex>","nonce":"<hex>","signature":"<hex>"}  (R)
 *   <- {"ok":true,"lastReleased":j,"packages":[...],"preimages":[...]}
 *
 * This entry intentionally keeps (de)serialization inline and minimal — it is a
 * demonstration of standalone startup, not a production transport.
 */

import * as net from 'net';
import { FforTower, MemoryTowerStore } from '../src/lightning/ffor/tower';
import { IChannelBasepoints } from '../src/lightning/keys/derivation';

const PORT = Number(process.argv[2] ?? 9944);

const tower = new FforTower(new MemoryTowerStore());

function hb(hex: string): Buffer {
	return Buffer.from(hex, 'hex');
}
function basepoints(o: Record<string, string>): IChannelBasepoints {
	return {
		fundingPubkey: hb(o.fundingPubkey),
		revocationBasepoint: hb(o.revocationBasepoint),
		paymentBasepoint: hb(o.paymentBasepoint),
		delayedPaymentBasepoint: hb(o.delayedPaymentBasepoint),
		htlcBasepoint: hb(o.htlcBasepoint),
		firstPerCommitmentPoint: hb(o.firstPerCommitmentPoint)
	};
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function handle(msg: any): unknown {
	switch (msg.op) {
		case 'provision': {
			const p = msg.provisioning;
			tower.provision({
				epochId: hb(p.epochId),
				params: {
					...p.params,
					budgetMsat: BigInt(p.params.budgetMsat),
					minPaymentMsat: BigInt(p.params.minPaymentMsat),
					escapeGranularityMsat: BigInt(p.params.escapeGranularityMsat),
					rPerCommitmentPoints: p.params.rPerCommitmentPoints.map(hb),
					paymentHashes: p.params.paymentHashes.map(hb),
					towerNodeId: p.params.towerNodeId
						? hb(p.params.towerNodeId)
						: undefined
				},
				preimages: p.preimages.map(hb),
				channel: {
					...p.channel,
					fundingTxid: hb(p.channel.fundingTxid),
					fundingSatoshis: BigInt(p.channel.fundingSatoshis),
					channelType: hb(p.channel.channelType),
					rBasepoints: basepoints(p.channel.rBasepoints),
					sBasepoints: basepoints(p.channel.sBasepoints),
					preEpochRLocalMsat: BigInt(p.channel.preEpochRLocalMsat),
					preEpochSLocalMsat: BigInt(p.channel.preEpochSLocalMsat),
					nR: BigInt(p.channel.nR),
					n0: BigInt(p.channel.n0),
					sPerCommitmentPointN0: hb(p.channel.sPerCommitmentPointN0)
				},
				rNodeId: hb(p.rNodeId),
				sNodeId: hb(p.sNodeId),
				revocationBasepointSecret: p.revocationBasepointSecret
					? hb(p.revocationBasepointSecret)
					: undefined,
				sweepScript: p.sweepScript ? hb(p.sweepScript) : undefined
			});
			return { ok: true };
		}
		case 'height':
			tower.setBlockHeight(Number(msg.height));
			return { ok: true };
		case 'release': {
			const r = tower.handleReleaseRequest(hb(msg.package));
			return r.ok
				? { ok: true, seq: r.seq, preimage: r.preimage.toString('hex') }
				: { ok: false, error: r.error };
		}
		case 'fetch': {
			const resp = tower.handleFetch({
				epochId: hb(msg.epochId),
				nonce: hb(msg.nonce),
				signature: hb(msg.signature)
			});
			return {
				ok: resp.ok,
				error: resp.error,
				lastReleased: resp.lastReleased,
				packages: resp.packages.map((b) => b.toString('hex')),
				preimages: resp.preimages.map((b) => b.toString('hex'))
			};
		}
		default:
			return { ok: false, error: `unknown op ${msg.op}` };
	}
}

const server = net.createServer((socket) => {
	let buf = '';
	socket.on('data', (chunk) => {
		buf += chunk.toString('utf8');
		let nl: number;
		while ((nl = buf.indexOf('\n')) >= 0) {
			const line = buf.slice(0, nl).trim();
			buf = buf.slice(nl + 1);
			if (!line) continue;
			let reply: unknown;
			try {
				reply = handle(JSON.parse(line));
			} catch (e) {
				reply = { ok: false, error: (e as Error).message };
			}
			socket.write(JSON.stringify(reply) + '\n');
		}
	});
});

server.listen(PORT, () => {
	// eslint-disable-next-line no-console
	console.log(`FFOR tower listening on tcp://127.0.0.1:${PORT}`);
	// eslint-disable-next-line no-console
	console.log('Ops: provision | height | release | fetch (JSON lines).');
});
