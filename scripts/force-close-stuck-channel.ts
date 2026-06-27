/**
 * One-shot recovery: force-close a channel by id and wait for the commitment
 * broadcast. Usage:
 *   npx ts-node scripts/force-close-stuck-channel.ts <mnemonic...> <channelIdHex> \
 *     [--electrum-host H] [--electrum-port P]
 */
import { BeignetNode } from '../src/cli/beignet-node';

const main = async (): Promise<void> => {
	const args = process.argv.slice(2);
	const hostIdx = args.indexOf('--electrum-host');
	const portIdx = args.indexOf('--electrum-port');
	const electrumHost = hostIdx >= 0 ? args[hostIdx + 1] : undefined;
	const electrumPort = portIdx >= 0 ? Number(args[portIdx + 1]) : undefined;
	const positional = args.filter(
		(a, i) => !a.startsWith('--') && i !== hostIdx + 1 && i !== portIdx + 1
	);
	const channelId = positional[positional.length - 1];
	const mnemonic = positional.slice(0, -1).join(' ');
	if (!/^[0-9a-f]{64}$/.test(channelId)) {
		throw new Error(
			`last positional arg must be a 64-hex channel id, got: ${channelId}`
		);
	}

	console.log(
		`[recover] starting node (electrum ${electrumHost}:${electrumPort})...`
	);
	const node = await BeignetNode.create({
		mnemonic,
		network: 'mainnet',
		electrumHost,
		electrumPort,
		electrumTls: false,
		preferAnchors: true
	});
	let lastBroadcastError: string | null = null;
	node.on('node:error', (e) => {
		console.log(`[node:error] ${e.code}: ${e.message}`);
		if (e.code === 'BROADCAST_FAILED') lastBroadcastError = e.message;
	});

	// The wallet connects to electrum lazily; broadcasting over a dead
	// connection fails. Wait for a live connection first.
	for (let i = 0; i < 30 && !node.getHealth().electrumConnected; i++) {
		await new Promise((r) => setTimeout(r, 2_000));
	}
	console.log(
		'[recover] electrumConnected:',
		node.getHealth().electrumConnected
	);

	const channels = node.listChannels();
	const target = channels.find((c) => c.channelId === channelId);
	console.log(
		'[recover] channel state:',
		target?.state,
		'localBalance:',
		target?.localBalanceSats
	);

	let result: { ok: boolean; error?: string; commitmentTxid?: string } = {
		ok: false
	};
	for (let attempt = 1; attempt <= 3; attempt++) {
		lastBroadcastError = null;
		result = node.forceCloseChannel(channelId);
		console.log(
			`[recover] forceCloseChannel attempt ${attempt}:`,
			JSON.stringify(result)
		);
		await new Promise((r) => setTimeout(r, 5_000));
		if (result.ok && !lastBroadcastError) break;
	}

	const after = node.listChannels().find((c) => c.channelId === channelId);
	console.log(
		'[recover] state after:',
		after?.state,
		'broadcastError:',
		lastBroadcastError
	);

	await node.gracefulShutdown();
	process.exit(result.ok && !lastBroadcastError ? 0 : 1);
};

main().catch((err) => {
	console.error('[recover] failed:', err);
	process.exit(1);
});
