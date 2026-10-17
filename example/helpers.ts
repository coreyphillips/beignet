import { promises as fs } from 'fs';
import {
	TGetData,
	TSetData,
	IWalletData,
	EAvailableNetworks,
	EProtocol
} from '../src';
import { err, Result, ok } from '../src';

// The TGetData contract: ok(undefined) for a key never saved, and the wallet
// applies its own default. A file that exists but cannot be read or parsed is
// an err, so Wallet.create stops instead of saving defaults over it.
export const getData: TGetData = async <K extends keyof IWalletData>(
	key: string
): Promise<Result<IWalletData[K]>> => {
	try {
		const data = await fs.readFile(`example/walletData/${key}.json`, 'utf8');
		return ok(JSON.parse(data) as IWalletData[K]);
	} catch (e) {
		if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
			return ok(undefined as unknown as IWalletData[K]);
		}
		return err(e instanceof Error ? e : String(e));
	}
};

export const setData: TSetData = async <K extends keyof IWalletData>(
	key: string,
	value: IWalletData[K]
): Promise<Result<boolean>> => {
	try {
		const dir = 'example/walletData';
		// Ensure that the directory exists
		await fs.mkdir(dir, { recursive: true });

		await fs.writeFile(`${dir}/${key}.json`, JSON.stringify(value, null, 2));
		return ok(true);
	} catch (e) {
		return err(e);
	}
};

export const deleteDirectory = async (
	dir = 'example/walletData'
): Promise<void> => {
	try {
		await fs.rm(dir, { recursive: true, force: true });
	} catch (e) {
		console.error(`Error deleting directory ${dir}: ${e}`);
	}
};

export const onMessage = (id: unknown, data: unknown): void => {
	console.log(id);
	console.dir(data, { depth: null });
};

export const servers = {
	[EAvailableNetworks.mainnet]: [
		{
			host: '35.187.18.233',
			ssl: 8900,
			tcp: 8911,
			protocol: EProtocol.ssl
		}
	],
	[EAvailableNetworks.testnet]: [
		{
			host: 'testnet.aranguren.org',
			ssl: 51002,
			tcp: 51001,
			protocol: EProtocol.ssl
		}
	],
	[EAvailableNetworks.regtest]: [
		{
			host: '35.233.47.252',
			ssl: 18484,
			tcp: 18483,
			protocol: EProtocol.tcp
		}
	]
};
