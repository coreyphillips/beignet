/** A host application supplies its wallet-scoped RPC connection and approval UI. */
import {
	BitcoinCoreWalletAdapter,
	DirectFundingClient,
	createPeerTransportRegistry
} from 'beignet/direct-funding';
import type {
	BitcoinCoreRpc,
	Network,
	IDfSendResult
} from 'beignet/direct-funding';
import {
	FileDirectFundingStorage,
	NodePeerMessaging
} from 'beignet/direct-funding/node';

export interface IPayWithBitcoinCoreOptions {
	rpc: BitcoinCoreRpc;
	network: Network;
	request: string;
	storageDirectory: string;
	/** Required only when neither the envelope nor its URI specifies an amount. */
	amountSat?: bigint;
	maxTotalFeeSat: bigint;
	approve(details: {
		receiverNodeId: string;
		amountSat: bigint;
		maxTotalFeeSat: bigint;
	}): Promise<boolean>;
}

export async function payWithBitcoinCore(
	options: IPayWithBitcoinCoreOptions
): Promise<IDfSendResult | null> {
	const storage = new FileDirectFundingStorage(options.storageDirectory);
	const peers = new NodePeerMessaging({ network: options.network });
	const registry = createPeerTransportRegistry(peers);
	let wallet: BitcoinCoreWalletAdapter | undefined;
	let client: DirectFundingClient | undefined;
	try {
		wallet = await BitcoinCoreWalletAdapter.create({
			rpc: options.rpc,
			network: options.network,
			storage
		});
		client = new DirectFundingClient({
			wallet,
			registry,
			storage,
			network: options.network
		});
		const request = client.inspect(options.request);
		const amountSat =
			request.envelope.amountSat ?? request.uriAmountSat ?? options.amountSat;
		if (amountSat === undefined) throw new Error('an amount is required');
		if (
			!(await options.approve({
				receiverNodeId: request.envelope.receiverNodeId.toString('hex'),
				amountSat,
				maxTotalFeeSat: options.maxTotalFeeSat
			}))
		)
			return null;
		const result = await client.pay(options.request, {
			amountSat,
			maxTotalFeeSat: options.maxTotalFeeSat
		});
		// SIGNED_PENDING is an unresolved payment, even if the receipt is absent.
		// Keep this directory and call client.reconcile() on subsequent launches.
		return result;
	} finally {
		// The client's drain includes reservation releases a timed-out payment
		// can leave running, and then the wallet's own.
		await (client ?? wallet)?.waitForIdle();
		registry.destroy();
		peers.close();
		storage.close();
	}
}
