import {
	ECoinSelectPreference,
	generateMnemonic,
	Network,
	Wallet
} from '../src';
import { getData, onMessage, servers, setData } from './helpers';
import * as repl from 'repl';
import net from 'net';
import tls from 'tls';

const NETWORKS = new Map<
	string,
	Network.bitcoin | Network.testnet | Network.regtest
>([
	['mainnet', Network.bitcoin],
	['testnet', Network.testnet],
	['regtest', Network.regtest]
]);

const runExample = async (
	mnemonic = generateMnemonic(),
	networkName = 'regtest'
): Promise<void> => {
	const network = NETWORKS.get(networkName)!;
	console.log('Network: ', networkName);
	console.log('Mnemonic:', mnemonic);
	console.log(
		"This mnemonic is the wallet's only backup: write it down before funding it."
	);

	// Create Wallet
	const createWalletResponse = await Wallet.create({
		mnemonic,
		onMessage,
		network,
		storage: {
			getData,
			setData
		},
		electrumOptions: {
			net,
			tls,
			servers: servers[network]
		},
		gapLimitOptions: {
			lookAhead: 5,
			lookBehind: 5,
			lookAheadChange: 5,
			lookBehindChange: 5
		},
		coinSelectPreference: ECoinSelectPreference.small
	});
	if (createWalletResponse.isErr()) {
		console.error(
			'\nFailed to create wallet:',
			createWalletResponse.error.message
		);
		process.exit(1);
	}
	const wallet = createWalletResponse.value;

	// Get the wallet's balance.
	const balance = wallet.getBalance();
	console.log('\nBalance: ', balance);

	// Get a receiving address.
	const address = await wallet.getAddress();
	console.log('\nAddress:', address);

	// REPL
	console.log('\n--- REPL ---');
	console.log('Type help() for available commands.\n');

	const r = repl.start('> ');
	r.context.wallet = wallet;
	r.context.help = (): void => {
		console.log(`
  Wallet
    wallet.getBalance()                         Confirmed + unconfirmed balance (sats)
    wallet.getAddress()                         Receiving address (async)
    wallet.fetchNextAvailableAddress()          Next unused address data (async)
    wallet.refreshWallet()                      Resync wallet (async)
    wallet.validateAddress(addr)                Validate a bitcoin address

  Transactions & UTXOs
    wallet.transactions                         On-chain tx history by txid (values in BTC)
    wallet.unconfirmedTransactions              Txs with <6 confirmations
    wallet.listUtxos()                          All UTXOs, frozen ones included
    wallet.getBalanceBreakdown()                { total, spendable, frozen } (sats)
    wallet.fetchTransactionDetails(txid)        Full tx details (async)

  Fees
    wallet.fetchFeeEstimates()                  Fee estimates in sats/vB (async)
    wallet.getFeeInfo({ satsPerByte })          Fee info for a transaction

  Sending
    wallet.send({ address, amount, satsPerByte })
                                                Send sats (async)
    wallet.sendMax({ address, satsPerByte })    Send entire balance (async)
    wallet.createSignedTransaction({ address, amount, satsPerByte })
                                                Sign without sending (async)
    wallet.broadcastTransaction(txHex)          Broadcast a raw tx (async)

  Boosting (RBF)
    wallet.getBoostableTransactions()           Txs eligible for fee boosting
    wallet.canBoost(txid)                       Check if a tx can be boosted

  Lifecycle
    .exit                                       Exit REPL
`);
	};

	r.on('exit', () => {
		console.log('\nShutting down...');
		void wallet.stop().then(() => process.exit(0));
	});
};

// A bare network name picks the network (default regtest). Any other words
// are the mnemonic, quoted as one argument or not.
const args = process.argv.slice(2);
const words = args.filter((arg) => !NETWORKS.has(arg));
void runExample(
	words.length > 0 ? words.join(' ') : undefined,
	args.find((arg) => NETWORKS.has(arg))
);
