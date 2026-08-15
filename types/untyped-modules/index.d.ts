/**
 * Ambient declarations for dependencies that ship no types.
 *
 * This folder is wired in through tsconfig's typeRoots so the declarations are
 * auto-included in every compilation, including per-file ts-node compiles at
 * test runtime, where a .d.ts that is never imported would otherwise not load.
 *
 * Runtime deps (bip21, bitcoin-units, lodash.clonedeep) are typed as far as
 * this codebase uses them. Modules typed as any (rn-electrum-client, sinon,
 * bw-electrum-client) match how the code compiled before noImplicitAny;
 * replacing them with real types (e.g. @types/sinon) is tracked as follow-up
 * strictness work.
 */

declare module 'lodash.clonedeep' {
	function cloneDeep<T>(value: T): T;
	export = cloneDeep;
}

declare module 'bitcoin-units' {
	interface BitcoinUnit {
		to(unit: string): BitcoinUnit;
		value(): number;
	}
	function bitcoinUnits(value: number, unit: string): BitcoinUnit;
	export = bitcoinUnits;
}

declare module 'bip21' {
	// encode validates amount via isFinite, so the package's documented
	// numeric amount and a fixed-notation numeric string both work.
	interface Bip21EncodeOptions {
		amount?: number | string;
		label?: string;
		message?: string;
		[key: string]: string | number | undefined;
	}
	// decode runs options.amount through Number(); the other query
	// parameters come out of qs.parse as strings.
	interface Bip21DecodeOptions {
		amount?: number;
		label?: string;
		message?: string;
		[key: string]: string | number | undefined;
	}
	export function encode(
		address: string,
		options?: Bip21EncodeOptions,
		urnScheme?: string
	): string;
	export function decode(
		uri: string,
		urnScheme?: string
	): { address: string; options: Bip21DecodeOptions };
}

declare module 'rn-electrum-client/helpers';

declare module 'sinon' {
	namespace sinon {
		type SinonSandbox = any;
		type SinonStub = any;
		function createSandbox(): any;
		function restore(): void;
		function spy(...args: any[]): any;
		function stub(...args: any[]): any;
	}
	export = sinon;
}

declare module 'bw-electrum-client';
