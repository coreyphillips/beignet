import { EAvailableNetworks } from '../types';
import { Wallet } from '../wallet';
import * as bitcoin from 'bitcoinjs-lib';
import { IHedgehogData } from '../types/hedgehog';

export class Hedgehog {
	private readonly _wallet: Wallet;
	private _data: IHedgehogData = {};
	public network: EAvailableNetworks;
	public nodeId: string;

	constructor({
		wallet,
		network
	}: {
		wallet: Wallet;
		network: EAvailableNetworks;
	}) {
		this._wallet = wallet;
		this.network = network;
		this.nodeId = wallet.getNodeId();
	}

	public get data(): IHedgehogData {
		return this._data;
	}

	public get wallet(): Wallet {
		return this._wallet;
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
	makeAddress(chan_id: string, scripts: any[]): string {
		// Implementation will be added here
		return '';
	}

	// Method to create Alice's revocation script
	makeAlicesRevocationScript(chan_id: string): any[] {
		// Implementation will be added here
		return [];
	}

	// Method to create Bob's revocation script
	makeBobsRevocationScript(chan_id: string): any[] {
		// Implementation will be added here
		return [];
	}

	// Method to open a channel
	async openChannel(push_all_funds_to_counterparty: boolean): Promise<void> {
		// Implementation will be added here
	}

	// Method to send funds
	send(chan_id: string, amnt?: number, opening?: boolean): {} {
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
		// Implementation will be added here
	}
}
