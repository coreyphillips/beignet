import {
	EAvailableNetworks,
	ECoinSelectPreference,
	generateMnemonic,
	Wallet
} from '../src';
import { getData, onMessage, servers, setData } from './helpers';
import * as repl from 'repl';
import net from 'net';
import tls from 'tls';

const network: EAvailableNetworks = EAvailableNetworks.mainnet;

const runExample = async (mnemonic = generateMnemonic()): Promise<void> => {
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
	if (createWalletResponse.isErr()) return;
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
    wallet.getNextAvailableAddress()            Next unused address data (async)
    wallet.refreshWallet()                      Resync wallet (async)
    wallet.validateAddress(addr)                Validate a bitcoin address

  Transactions & UTXOs
    wallet.transactions                         On-chain tx history (keyed by txid)
    wallet.unconfirmedTransactions              Txs with <6 confirmations
    wallet.listUtxos()                          Spendable UTXOs
    wallet.getTransactionDetails(txid)          Full tx details (async)

  Fees
    wallet.getFeeEstimates()                    Fee estimates in sats/vB (async)
    wallet.getFeeInfo({ satsPerByte })          Fee info for a transaction

  Sending
    wallet.send({ address, amount, satsPerByte, broadcast })
                                                Send sats (async). broadcast: false
                                                returns raw tx hex without sending.
    wallet.sendMax({ address, satsPerByte })    Send entire balance (async)
    wallet.electrum.broadcastTransaction({ rawTx })
                                                Broadcast a raw tx (async)

  Boosting (RBF)
    wallet.getBoostableTransactions()           Txs eligible for fee boosting
    wallet.canBoost(txid)                       Check if a tx can be boosted

  Lifecycle
    .exit                                       Exit REPL
`);
	};

	r.on('exit', async () => {
		console.log('\nShutting down...');
		await wallet.stop();
		process.exit(0);
	});
};

const mnemonic = process.argv[2];
runExample(mnemonic).then();
