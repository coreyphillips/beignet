import { EAvailableNetworks, TSaveWalletDataType } from '../types';
import { Wallet } from '../wallet';
import * as bitcoin from 'bitcoinjs-lib';
import { IHedgehogData, TKeyPairs, TScriptElement } from '../types/hedgehog';
import { defaultHedgehogData } from '../shapes/hedgehog';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import crypto from 'crypto';
import { Networks } from '@cmdcode/tapscript';

const ecpair = ECPairFactory(ecc);
const PATH = "m/1991'/0'/0'/0/0";

const getTapscriptNetwork = (network: EAvailableNetworks): Networks => {
	switch (network) {
		case EAvailableNetworks.bitcoin:
			return 'main';
		case EAvailableNetworks.testnet:
			return 'testnet';
		case EAvailableNetworks.regtest:
			return 'regtest';
		default:
			throw new Error('Invalid network');
	}
};

export class Hedgehog {
	private readonly _wallet: Wallet;
	private _data: IHedgehogData = {};
	public network: EAvailableNetworks;
	public tapscriptNetwork: Networks;
	public nodeId: string;
	public keypairs: TKeyPairs = {};
	private _saveWalletData: TSaveWalletDataType;

	constructor({
		wallet,
		network,
		saveWalletData
	}: {
		wallet: Wallet;
		network: EAvailableNetworks;
		saveWalletData: TSaveWalletDataType;
	}) {
		this._wallet = wallet;
		this.network = network;
		this.tapscriptNetwork = getTapscriptNetwork(network);
		this.nodeId = wallet.getNodeId();
		this._saveWalletData = saveWalletData;

		const privkeyWIF = this._wallet.getPrivateKey(PATH);
		const keyPair = ecpair.fromWIF(privkeyWIF, bitcoin.networks.bitcoin);
		const privateKey = this.bytesToHex(keyPair.privateKey!);
		const pubkeyBuffer = ecc.pointFromScalar(keyPair.privateKey!, true);
		if (!pubkeyBuffer) throw new Error('Invalid pubkey');
		const pubkey = this.bytesToHex(pubkeyBuffer).substring(2);
		const preimageBuffer = crypto.randomBytes(32);
		const preImage = this.bytesToHex(preimageBuffer);
		const hash = this.rmd160(this.hexToBytes(preImage));
		this.keypairs[pubkey] = { privateKey, preImage };

		console.log('Your pubkey/hash pair:');
		console.log(JSON.stringify([pubkey, hash]));
	}

	public get data(): IHedgehogData {
		return this._data;
	}

	public get wallet(): Wallet {
		return this._wallet;
	}

	public get channels(): IHedgehogData {
		return this._wallet.data.channels;
	}

	async saveChannelData(channel = defaultHedgehogData): Promise<string> {
		const { channel_id } = channel;
		this.channels[channel_id] = channel;
		return this._saveWalletData('channels', this.channels);
	}

	// Method to convert hex string to byte array
	hexToBytes(hex: string): Uint8Array {
		const matches = hex.match(/.{1,2}/g);
		if (matches === null) {
			return new Uint8Array(); // Return an empty Uint8Array if no matches are found
		}
		return Uint8Array.from(matches.map((byte) => parseInt(byte, 16)));
	}

	// Method to convert byte array to hex string
	bytesToHex(bytes: Uint8Array): string {
		return bytes.reduce(
			(str, byte) => str + byte.toString(16).padStart(2, '0'),
			''
		);
	}

	// Method to calculate RIPEMD160 hash of a string or byte array
	rmd160(input: string | Uint8Array): string {
		// If input is a string, convert it to Uint8Array
		if (typeof input === 'string') {
			input = new TextEncoder().encode(input);
		}
		// Convert Uint8Array to Buffer
		const bufferInput = Buffer.from(input);
		// Calculate RIPEMD160 hash
		const hash = bitcoin.crypto.ripemd160(bufferInput);
		// Convert the hash to hex string
		return this.bytesToHex(hash);
	}

	// Method to check if a hex string is valid
	isValidHex(hex: string): boolean {
		if (!hex) return false;

		// Check if the length is even
		if (hex.length % 2 !== 0) return false;

		// Validate hexadecimal string
		if (!/^[0-9a-fA-F]+$/.test(hex)) return false;

		try {
			// Convert hex string to BigInt and back to string
			const bigint = BigInt('0x' + hex);
			const prepad = bigint.toString(16).padStart(hex.length, '0');
			return prepad.toLowerCase() === hex.toLowerCase();
		} catch (e) {
			return false;
		}
	}

	// Method to create transaction input
	getVin(
		txid: string,
		vout: number,
		amnt: number,
		addy: string,
		sequence?: number
	): any {
		const input = {
			txid,
			vout,
			prevout: {
				value: amnt,
				scriptPubKey: bitcoin.address.toOutputScript(addy)
			}
		};
		if (sequence) input['sequence'] = sequence;
		return input;
	}

	// Method to create transaction output
	getVout(amnt: number, addy: string): any {
		// Implementation will be added here
		return {
			value: amnt,
			scriptPubKey: bitcoin.address.toOutputScript(addy)
		};
	}

	// Method to create an address
	async makeAddress(
		chan_id: string,
		scripts: TScriptElement[][]
	): Promise<any> {
		// const address = await this.wallet.getAddressByPath({
		// 	path: PATH,
		// 	addressType: EAddressType.p2tr
		// });
		// if (address.isErr()) throw new Error('Error creating address');
		// const publicKey: string = address.value.publicKey;
		// const tree = scripts.map((s) => Tap.encodeScript(s));
		// const [tpubkey] = Tap.getPubKey(publicKey, { tree });
		// return Address.p2tr.fromPubKey(tpubkey, this.tapscriptNetwork);
	}

	// Method to create Alice's revocation script
	makeAlicesRevocationScript(chan_id: string): TScriptElement[][] {
		const { alices_pubkey, alices_revocation_hashes, bobs_pubkey } =
			this.data[chan_id];
		return [
			[
				alices_pubkey,
				'OP_CHECKSIG',
				bobs_pubkey,
				'OP_CHECKSIGADD',
				2,
				'OP_EQUAL'
			],
			[
				'OP_RIPEMD160',
				alices_revocation_hashes[alices_revocation_hashes.length - 1],
				'OP_EQUALVERIFY',
				bobs_pubkey,
				'OP_CHECKSIG'
			],
			//TODO: change the 10 to 4032
			[10, 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', bobs_pubkey, 'OP_CHECKSIG']
		];
	}

	// Method to create Bob's revocation script
	makeBobsRevocationScript(chan_id: string): TScriptElement[][] {
		const { alices_pubkey, bobs_revocation_hashes, bobs_pubkey } =
			this.data[chan_id];
		return [
			[
				alices_pubkey,
				'OP_CHECKSIG',
				bobs_pubkey,
				'OP_CHECKSIGADD',
				2,
				'OP_EQUAL'
			],
			[
				'OP_RIPEMD160',
				bobs_revocation_hashes[bobs_revocation_hashes.length - 1],
				'OP_EQUALVERIFY',
				alices_pubkey,
				'OP_CHECKSIG'
			],
			//TODO: change the 10 to 4032
			[10, 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', alices_pubkey, 'OP_CHECKSIG']
		];
	}

	// Method to open a channel
	async openChannel(push_all_funds_to_counterparty: boolean): Promise<void> {
		// Implementation will be added here
	}

	// Method to send funds
	send(chan_id: string, amnt?: number, opening?: boolean) {
		// Implementation will be added here
		return {};
	}

	// Method to receive funds
	async receive(data?: any): Promise<boolean> {
		// Implementation will be added here
		return false;
	}

	// Method to close a channel
	closeChannel(chan_id: string): void {
		console.log('Broadcast this transaction to initiate a force closure:');
		console.log(this.data[chan_id].latest_force_close_txs[0]);
		//TODO: change the 5 to a 2016
		console.log(
			'Wait 5 blocks and broadcast this transaction to finalize the force closure:'
		);
		console.log(this.data[chan_id].latest_force_close_txs[1]);
	}
}
