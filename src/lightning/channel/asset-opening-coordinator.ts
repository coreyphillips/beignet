import type { Transaction } from 'bitcoinjs-lib';
import { ASSET_OPENING_TYPE_HEX } from '../features/asset-opening';
import {
	encodeOpenChannel2Message,
	encodeAcceptChannel2Message
} from '../message/dual-funding';
import { BeignetCustomSubtype } from '../message/custom';
import { MessageType } from '../message/types';
import type { Channel } from './channel';
import {
	AssetOpeningSession,
	type IAssetOpeningStart
} from './asset-opening-session';
import type { IAuxiliaryDualFunding } from './asset-opening-provider';
import type { IFinalOpeningCandidate } from '../storage/final-opening-candidate';
import type { IFinalOpeningRuntime } from './final-opening-runtime';

export function completeAssetOpeningHost(
	host: IAuxiliaryDualFunding | undefined
): host is IAuxiliaryDualFunding {
	return (
		host?.version === 1 &&
		(
			[
				'contribution',
				'propose',
				'abandon',
				'describe',
				'prepare',
				'signExits',
				'verifyExits',
				'signFunding',
				'confirmFunding',
				'retractFunding',
				'recoverOutput'
			] as const
		).every((method) => typeof host[method] === 'function')
	);
}

export class AssetOpeningCoordinator {
	private sessions = new Map<string, AssetOpeningSession>();
	constructor(
		private readonly runtime: IFinalOpeningRuntime,
		private readonly host: IAuxiliaryDualFunding,
		private readonly send: (peer: string, type: number, raw: Buffer) => void,
		private readonly unspent: (tx: Transaction, i: number) => Promise<boolean>,
		private readonly accepted: (
			peer: string,
			c: IFinalOpeningCandidate,
			nonce: Buffer,
			early?: Buffer,
			reestablish?: Buffer,
			reconnected?: boolean
		) => void,
		private readonly error: (peer: string, id: Buffer, reason: string) => void
	) {
		for (const id of runtime.storage.listAssetOpenStages()) {
			if (runtime.storage.loadFinalOpeningSession(id)) continue;
			const raw = runtime.storage.loadAssetOpenStage(id, 'start');
			if (!raw) throw new Error('Missing asset opening restart terms');
			const session = this.make(
				JSON.parse(raw.toString()) as IAssetOpeningStart
			);
			if (session.id !== id) throw new Error('Invalid saved opening identity');
			this.sessions.set(id, session);
			session.waitForPeer();
		}
	}

	contribution(peer: string, isInitiator: boolean, opener: bigint): bigint {
		if (this.runtime.storage.listAssetOpenStages().length >= 8)
			throw new Error('Too many unfinished asset openings');
		const answer = this.host.contribution(peer, isInitiator, opener);
		if (
			typeof answer !== 'bigint' ||
			answer < 0n ||
			answer > 2100000000000000n ||
			(isInitiator && answer !== opener)
		)
			throw new Error('Asset opening refused by the local contribution policy');
		return answer;
	}

	private make(start: IAssetOpeningStart): AssetOpeningSession {
		const s: AssetOpeningSession = new AssetOpeningSession(
			start,
			this.runtime,
			this.host,
			this.send,
			this.unspent,
			(c, nonce, early, reestablish, reconnected) =>
				this.accepted(start.peer, c, nonce, early, reestablish, reconnected),
			(reason) => {
				this.error(start.peer, Buffer.from(s.id, 'hex'), reason);
			},
			() => this.sessions.delete(s.id)
		);
		return s;
	}
	register(channel: Channel, peer: string): void {
		const v2 = channel.getDualFundingSession(),
			open = v2?.getOpenMsg(),
			accept = v2?.getAcceptMsg();
		if (
			!v2 ||
			!open ||
			!accept ||
			open.channelType?.toString('hex') !== ASSET_OPENING_TYPE_HEX ||
			typeof channel.channelKeyIndex !== 'number'
		)
			throw new Error('Missing asset opening terms');
		const start = {
			peer,
			index: channel.channelKeyIndex,
			initiator: v2.isInitiator(),
			open: encodeOpenChannel2Message(open).toString('hex'),
			accept: encodeAcceptChannel2Message(accept).toString('hex'),
			deadline: Date.now() + 120000
		};
		const s = this.make(start);
		if (this.sessions.has(s.id))
			throw new Error('Duplicate asset opening attempt');
		this.runtime.storage.saveAssetOpenStage(
			s.id,
			'start',
			Buffer.from(JSON.stringify(start))
		);
		this.sessions.set(s.id, s);
		s.begin();
	}
	peers(): string[] {
		return [
			...new Set(
				this.runtime.storage.listAssetOpenStages().map((id) => {
					const raw = this.runtime.storage.loadAssetOpenStage(id, 'start');
					if (!raw) throw new Error('Missing asset opening restart terms');
					return (JSON.parse(raw.toString()) as IAssetOpeningStart).peer;
				})
			)
		];
	}
	destroy(): void {
		for (const s of this.sessions.values()) s.detach();
		this.sessions.clear();
	}
	pending(id: string): boolean {
		return this.sessions.has(id);
	}
	disconnect(peer: string): void {
		for (const s of this.sessions.values())
			if (s.start.peer === peer) s.pause();
	}
	reconnect(peer: string): void {
		for (const id of this.runtime.storage.listAssetOpenStages()) {
			const raw = this.runtime.storage.loadAssetOpenStage(id, 'start');
			if (!raw) continue;
			const start = JSON.parse(raw.toString()) as IAssetOpeningStart;
			if (start.peer !== peer) continue;
			if (this.runtime.storage.loadFinalOpeningExit(id)) {
				this.sessions.get(id)?.detach();
				this.runtime.storage.saveAssetOpenStage(
					id,
					'finished',
					Buffer.alloc(0)
				);
				this.sessions.delete(id);
				continue;
			}
			let s = this.sessions.get(id);
			if (!s) {
				s = this.make(start);
				if (s.id !== id) throw new Error('Invalid saved opening identity');
				this.sessions.set(id, s);
			}
			if (this.runtime.storage.loadFinalOpeningSession(id)) s.replayAdmitted();
			else s.resume();
		}
	}

	custom(peer: string, subtype: number, raw: Buffer): void {
		const start = subtype === BeignetCustomSubtype.ASSET_OPEN_CONSENT ? 1 : 2;
		if (raw.length < start + 32) return;
		const s = this.sessions.get(
			raw.subarray(start, start + 32).toString('hex')
		);
		if (s?.start.peer === peer) s.custom(subtype, raw);
	}

	handle(peer: string, type: number, raw: Buffer): boolean {
		if (raw.length < 32) return false;
		const id = raw.subarray(0, 32).toString('hex'),
			s = this.sessions.get(id);
		if (!s || s.start.peer !== peer) return false;
		if (this.runtime.storage.loadFinalOpeningSession(id)) {
			if (this.runtime.storage.loadFinalOpeningExit(id)) {
				s.detach();
				this.runtime.storage.saveAssetOpenStage(
					id,
					'finished',
					Buffer.alloc(0)
				);
				this.sessions.delete(id);
			}
			return false;
		}
		if (
			type === MessageType.TX_ADD_INPUT ||
			type === MessageType.TX_ADD_OUTPUT ||
			type === MessageType.TX_COMPLETE ||
			type === MessageType.COMMITMENT_SIGNED ||
			type === MessageType.TX_REMOVE_INPUT ||
			type === MessageType.TX_REMOVE_OUTPUT
		) {
			s.interactive(type, raw);
			return true;
		}
		if (type === MessageType.CHANNEL_REESTABLISH) {
			s.recordReestablish(raw);
			return true;
		}
		if (type === MessageType.TX_ABORT || type === MessageType.ERROR) {
			s.abort('Peer abandoned asset opening');
			return true;
		}
		return false;
	}
}
