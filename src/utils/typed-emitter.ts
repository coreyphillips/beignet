import { EventEmitter } from 'events';

/**
 * An event map: each key is an event name, each value the signature of its
 * listeners. Written as a mapped constraint rather than a string index
 * signature so an interface satisfies it.
 */
export type EventMap<E> = {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any -- unknown[] would reject every listener with a typed parameter
	[K in keyof E]: (...args: any[]) => void;
};

/**
 * An EventEmitter whose event names and listener signatures come from a map.
 * A listener on an event the map does not declare does not compile, and
 * neither does an emit whose arguments do not match. The installed
 * @types/node has no generic EventEmitter, so the typed signatures are
 * declared here; at runtime each one is the base method.
 */
export class TypedEmitter<E extends EventMap<E>> extends EventEmitter {
	on<K extends keyof E & string>(event: K, listener: E[K]): this {
		return super.on(event, listener);
	}

	once<K extends keyof E & string>(event: K, listener: E[K]): this {
		return super.once(event, listener);
	}

	addListener<K extends keyof E & string>(event: K, listener: E[K]): this {
		return super.addListener(event, listener);
	}

	prependListener<K extends keyof E & string>(event: K, listener: E[K]): this {
		return super.prependListener(event, listener);
	}

	prependOnceListener<K extends keyof E & string>(
		event: K,
		listener: E[K]
	): this {
		return super.prependOnceListener(event, listener);
	}

	off<K extends keyof E & string>(event: K, listener: E[K]): this {
		return super.off(event, listener);
	}

	removeListener<K extends keyof E & string>(event: K, listener: E[K]): this {
		return super.removeListener(event, listener);
	}

	removeAllListeners<K extends keyof E & string>(event?: K): this {
		return event === undefined
			? super.removeAllListeners()
			: super.removeAllListeners(event);
	}

	emit<K extends keyof E & string>(
		event: K,
		...args: Parameters<E[K]>
	): boolean {
		return super.emit(event, ...args);
	}

	listenerCount<K extends keyof E & string>(event: K): number {
		return super.listenerCount(event);
	}

	listeners<K extends keyof E & string>(event: K): E[K][] {
		return super.listeners(event) as E[K][];
	}

	/** Includes the wrappers once() installs; each takes the same arguments. */
	rawListeners<K extends keyof E & string>(event: K): E[K][] {
		return super.rawListeners(event) as E[K][];
	}
}
