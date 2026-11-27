/**
 * Lazy access to the modules and members that #2151 Step 3a adds, so that on
 * a tree without them each test fails on its own with "not implemented:
 * <name>" instead of the whole file failing at load time. The types come from
 * the modules themselves, so the tests compile once the code exists.
 */
import path from 'path';

type TermsModule =
	typeof import('../../../src/lightning/channel/asset-conversion-terms');
type TransportModule =
	typeof import('../../../src/lightning/channel/asset-conversion-transport');
type FeaturesModule =
	typeof import('../../../src/lightning/features/asset-conversion');

const SRC = path.join(__dirname, '..', '..', '..', 'src', 'lightning');

function load<T>(rel: string): T {
	const file = path.join(SRC, rel);
	try {
		return require(file) as T;
	} catch (error) {
		const e = error as NodeJS.ErrnoException;
		if (e?.code === 'MODULE_NOT_FOUND' && String(e.message).includes(file))
			throw new Error('not implemented: src/lightning/' + rel);
		throw error;
	}
}

/** `src/lightning/channel/asset-conversion-terms.ts` (section 3). */
export const conversionTerms = (): TermsModule =>
	load<TermsModule>('channel/asset-conversion-terms');
/** `src/lightning/channel/asset-conversion-transport.ts` (section 6). */
export const conversionTransport = (): TransportModule =>
	load<TransportModule>('channel/asset-conversion-transport');
/** `src/lightning/features/asset-conversion.ts` (section 1). */
export const conversionFeatures = (): FeaturesModule =>
	load<FeaturesModule>('features/asset-conversion');

/**
 * A member that Step 3a adds to an existing module or object, read when the
 * test runs. Throws "not implemented: <where>.<key>" while it is missing.
 */
export function member<T extends object, K extends keyof T>(
	owner: T,
	key: K,
	where: string
): NonNullable<T[K]> {
	const value = owner[key];
	if (value === undefined || value === null)
		throw new Error('not implemented: ' + where + '.' + String(key));
	return value as NonNullable<T[K]>;
}

/** A method on an instance that Step 3a adds, bound to it. */
export function method<A extends unknown[], R>(
	owner: object,
	key: string,
	where: string
): (...args: A) => R {
	const fn = (owner as Record<string, unknown>)[key];
	if (typeof fn !== 'function')
		throw new Error('not implemented: ' + where + '.' + key);
	return (fn as (...args: A) => R).bind(owner);
}
