/**
 * Loading host extensions from disk for the CLI (docs/EXTENSIONS.md).
 *
 * An extension is code that runs inside the process holding the keys, so
 * the only way to name one is the way the operator starts the daemon: the
 * --extension flag or BEIGNET_EXTENSIONS. Nothing here reads config.json,
 * and no route can add one. A path that cannot be trusted, or a module that
 * is not an extension, refuses the start: the operator asked for something
 * the daemon cannot do, and starting without it would hide that.
 */

import * as fs from 'fs';
import * as path from 'path';
import { BeignetError } from './errors';
import type { IBeignetExtension, ExtensionNetwork } from './extension';
import {
	ENGINE_VERSION,
	EXTENSION_API_VERSION,
	validateExtensions
} from './extension';

/** What a module's `beignetExtension` factory is called with. */
export interface IExtensionLoadContext {
	network: ExtensionNetwork;
	/** The daemon's environment, for the extension's own settings. */
	env: Readonly<Record<string, string | undefined>>;
	/** The engine's package version. */
	engineVersion: string;
	/** The extension contract this engine provides. */
	api: number;
}

function refuse(file: string, message: string): never {
	throw new BeignetError('INVALID_PARAMS', `Extension ${file}: ${message}`);
}

/** The paths named by BEIGNET_EXTENSIONS: absolute, comma separated. */
export function extensionPathsFromEnv(value: string | undefined): string[] {
	if (!value) return [];
	return value
		.split(',')
		.map((entry) => entry.trim())
		.filter((entry) => entry.length > 0);
}

/**
 * Refuse a file another local user could have written: it, and the
 * directory that names it, must belong to this user or root and be
 * writable by no one else. Windows has no such bits, so nothing is checked
 * there.
 */
function assertTrustedPath(file: string, real: string): void {
	if (process.platform === 'win32' || typeof process.getuid !== 'function') {
		return;
	}
	const uid = process.getuid();
	for (const target of [real, path.dirname(real)]) {
		const stat = fs.statSync(target);
		if (stat.uid !== uid && stat.uid !== 0) {
			refuse(file, `${target} belongs to another user`);
		}
		if ((stat.mode & 0o022) !== 0) {
			refuse(
				file,
				`${target} is writable by its group or by everyone; run chmod go-w on it`
			);
		}
	}
}

/**
 * Load the extension each path names. A module exports `beignetExtension`:
 * the extension itself, or a function that takes IExtensionLoadContext and
 * returns it (or a promise for it). Throws INVALID_PARAMS for a path that
 * is relative, missing or untrusted, for a module that does not load, and
 * for a description validateExtensions refuses.
 */
export async function loadExtensions(
	files: readonly string[],
	context: Pick<IExtensionLoadContext, 'network' | 'env'>
): Promise<IBeignetExtension[]> {
	const loaded: IBeignetExtension[] = [];
	const seen = new Set<string>();
	for (const file of files) {
		if (!path.isAbsolute(file)) refuse(file, 'the path must be absolute');
		let real: string;
		try {
			real = fs.realpathSync(file);
		} catch {
			refuse(file, 'no such file');
		}
		if (!fs.statSync(real).isFile()) refuse(file, 'not a file');
		if (seen.has(real)) refuse(file, 'listed twice');
		seen.add(real);
		assertTrustedPath(file, real);
		let exported: unknown;
		try {
			// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
			const mod = require(real) as { beignetExtension?: unknown };
			exported = mod?.beignetExtension;
		} catch (err) {
			refuse(
				file,
				`could not be loaded (${
					err instanceof Error ? err.message : String(err)
				})`
			);
		}
		if (exported === undefined || exported === null) {
			refuse(file, 'the module does not export beignetExtension');
		}
		let extension: unknown = exported;
		if (typeof exported === 'function') {
			try {
				extension = await (exported as (ctx: IExtensionLoadContext) => unknown)(
					{
						network: context.network,
						env: context.env,
						engineVersion: ENGINE_VERSION,
						api: EXTENSION_API_VERSION
					}
				);
			} catch (err) {
				refuse(
					file,
					`beignetExtension() failed (${
						err instanceof Error ? err.message : String(err)
					})`
				);
			}
		}
		loaded.push(extension as IBeignetExtension);
	}
	validateExtensions(loaded);
	return loaded;
}
