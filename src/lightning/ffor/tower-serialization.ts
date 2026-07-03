/**
 * Durable-tower serialization (FFOR M7.0).
 *
 * A durable tower must persist the FULL provisioning bundle, not just the
 * settlement record: after a restart R is offline and cannot re-provision, so
 * without the preimages + channel statics + points the tower could neither
 * release preimages nor verify new packages (spec §9.4, restart contract).
 *
 * All buffers serialize as hex, all bigints as strings, exactly like the
 * node's own channel-state serialization (./storage/serialization). The
 * IChannelBasepoints / IChannelConfig round-trip helpers are reused so the
 * channel statics survive byte-for-byte.
 */

import * as bitcoin from 'bitcoinjs-lib';
import {
	bufToHex,
	hexToBuf,
	bigintToStr,
	strToBigint,
	serializeChannelConfig,
	deserializeChannelConfig,
	serializeBasepoints,
	deserializeBasepoints,
	ISerializedChannelConfig,
	ISerializedBasepoints
} from '../storage/serialization';
import { IFforEpochParams } from './types';
import {
	IFforTowerProvisioning,
	IFforTowerChannelStatics,
	IFforTowerRecord
} from './tower';

// ─────────────── IFforEpochParams ───────────────

export interface ISerializedFforParams {
	variant: number;
	budgetMsat: string;
	maxPayments: number;
	minPaymentMsat: string;
	settlementDeadline: number;
	voucherExpiry: number;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	escapeGranularityMsat: string;
	rPerCommitmentPoints: string[];
	paymentHashes?: string[];
	towerNodeId?: string;
	towerUri?: string;
}

export function serializeFforParams(
	p: IFforEpochParams
): ISerializedFforParams {
	return {
		variant: p.variant,
		budgetMsat: bigintToStr(p.budgetMsat),
		maxPayments: p.maxPayments,
		minPaymentMsat: bigintToStr(p.minPaymentMsat),
		settlementDeadline: p.settlementDeadline,
		voucherExpiry: p.voucherExpiry,
		feeBaseMsat: p.feeBaseMsat,
		feeProportionalMillionths: p.feeProportionalMillionths,
		escapeGranularityMsat: bigintToStr(p.escapeGranularityMsat),
		rPerCommitmentPoints: p.rPerCommitmentPoints.map((b) => b.toString('hex')),
		...(p.paymentHashes
			? { paymentHashes: p.paymentHashes.map((b) => b.toString('hex')) }
			: {}),
		...(p.towerNodeId ? { towerNodeId: p.towerNodeId.toString('hex') } : {}),
		...(p.towerUri !== undefined ? { towerUri: p.towerUri } : {})
	};
}

export function deserializeFforParams(
	s: ISerializedFforParams
): IFforEpochParams {
	return {
		variant: s.variant,
		budgetMsat: strToBigint(s.budgetMsat),
		maxPayments: s.maxPayments,
		minPaymentMsat: strToBigint(s.minPaymentMsat),
		settlementDeadline: s.settlementDeadline,
		voucherExpiry: s.voucherExpiry,
		feeBaseMsat: s.feeBaseMsat,
		feeProportionalMillionths: s.feeProportionalMillionths,
		escapeGranularityMsat: strToBigint(s.escapeGranularityMsat),
		rPerCommitmentPoints: s.rPerCommitmentPoints.map((h) =>
			Buffer.from(h, 'hex')
		),
		...(s.paymentHashes
			? { paymentHashes: s.paymentHashes.map((h) => Buffer.from(h, 'hex')) }
			: {}),
		...(s.towerNodeId
			? { towerNodeId: Buffer.from(s.towerNodeId, 'hex') }
			: {}),
		...(s.towerUri !== undefined ? { towerUri: s.towerUri } : {})
	};
}

// ─────────────── bitcoin.Network (by name) ───────────────

/**
 * Networks are shared singletons keyed by name; persist the name and re-resolve
 * so the deserialized object is the exact bitcoinjs-lib singleton (its identity
 * matters to callers that compare against bitcoin.networks.*).
 */
function networkName(n: bitcoin.Network): string {
	if (n === bitcoin.networks.bitcoin) return 'bitcoin';
	if (n === bitcoin.networks.testnet) return 'testnet';
	if (n === bitcoin.networks.regtest) return 'regtest';
	// Match by value for a structurally-equal but non-identical object.
	if (n.bech32 === 'bc') return 'bitcoin';
	if (n.bech32 === 'tb') return 'testnet';
	if (n.bech32 === 'bcrt') return 'regtest';
	return 'bitcoin';
}
function networkFromName(name: string): bitcoin.Network {
	switch (name) {
		case 'testnet':
			return bitcoin.networks.testnet;
		case 'regtest':
			return bitcoin.networks.regtest;
		default:
			return bitcoin.networks.bitcoin;
	}
}

// ─────────────── IFforTowerChannelStatics ───────────────

export interface ISerializedTowerChannelStatics {
	fundingTxid: string;
	fundingOutputIndex: number;
	fundingSatoshis: string;
	channelType: string;
	rIsOpener: boolean;
	rBasepoints: ISerializedBasepoints;
	sBasepoints: ISerializedBasepoints;
	rConfig: ISerializedChannelConfig;
	sConfig: ISerializedChannelConfig;
	preEpochRLocalMsat: string;
	preEpochSLocalMsat: string;
	nR: string;
	n0: string;
	sPerCommitmentPointN0: string;
	sPerCommitmentPointN0Plus1?: string | null;
	sIsOpener?: boolean;
	sToSelfDelay?: number;
	sLeaseExpiry?: number;
	frozenFeeratePerKw: number;
}

function serializeChannelStatics(
	c: IFforTowerChannelStatics
): ISerializedTowerChannelStatics {
	return {
		fundingTxid: c.fundingTxid.toString('hex'),
		fundingOutputIndex: c.fundingOutputIndex,
		fundingSatoshis: bigintToStr(c.fundingSatoshis),
		channelType: c.channelType.toString('hex'),
		rIsOpener: c.rIsOpener,
		rBasepoints: serializeBasepoints(c.rBasepoints),
		sBasepoints: serializeBasepoints(c.sBasepoints),
		rConfig: serializeChannelConfig(c.rConfig),
		sConfig: serializeChannelConfig(c.sConfig),
		preEpochRLocalMsat: bigintToStr(c.preEpochRLocalMsat),
		preEpochSLocalMsat: bigintToStr(c.preEpochSLocalMsat),
		nR: bigintToStr(c.nR),
		n0: bigintToStr(c.n0),
		sPerCommitmentPointN0: c.sPerCommitmentPointN0.toString('hex'),
		sPerCommitmentPointN0Plus1: bufToHex(c.sPerCommitmentPointN0Plus1),
		sIsOpener: c.sIsOpener,
		sToSelfDelay: c.sToSelfDelay,
		sLeaseExpiry: c.sLeaseExpiry,
		frozenFeeratePerKw: c.frozenFeeratePerKw
	};
}

function deserializeChannelStatics(
	s: ISerializedTowerChannelStatics
): IFforTowerChannelStatics {
	return {
		fundingTxid: Buffer.from(s.fundingTxid, 'hex'),
		fundingOutputIndex: s.fundingOutputIndex,
		fundingSatoshis: strToBigint(s.fundingSatoshis),
		channelType: Buffer.from(s.channelType, 'hex'),
		rIsOpener: s.rIsOpener,
		rBasepoints: deserializeBasepoints(s.rBasepoints),
		sBasepoints: deserializeBasepoints(s.sBasepoints),
		rConfig: deserializeChannelConfig(s.rConfig),
		sConfig: deserializeChannelConfig(s.sConfig),
		preEpochRLocalMsat: strToBigint(s.preEpochRLocalMsat),
		preEpochSLocalMsat: strToBigint(s.preEpochSLocalMsat),
		nR: strToBigint(s.nR),
		n0: strToBigint(s.n0),
		sPerCommitmentPointN0: Buffer.from(s.sPerCommitmentPointN0, 'hex'),
		sPerCommitmentPointN0Plus1:
			hexToBuf(s.sPerCommitmentPointN0Plus1) ?? undefined,
		sIsOpener: s.sIsOpener,
		sToSelfDelay: s.sToSelfDelay,
		sLeaseExpiry: s.sLeaseExpiry,
		frozenFeeratePerKw: s.frozenFeeratePerKw
	};
}

// ─────────────── IFforTowerProvisioning ───────────────

export interface ISerializedTowerProvisioning {
	epochId: string;
	params: ISerializedFforParams;
	preimages: string[];
	channel: ISerializedTowerChannelStatics;
	rNodeId: string;
	sNodeId: string;
	revocationBasepointSecret?: string | null;
	sweepScript?: string | null;
	network?: string;
}

export function serializeTowerProvisioning(
	p: IFforTowerProvisioning
): ISerializedTowerProvisioning {
	return {
		epochId: p.epochId.toString('hex'),
		params: serializeFforParams(p.params),
		preimages: p.preimages.map((b) => b.toString('hex')),
		channel: serializeChannelStatics(p.channel),
		rNodeId: p.rNodeId.toString('hex'),
		sNodeId: p.sNodeId.toString('hex'),
		revocationBasepointSecret: bufToHex(p.revocationBasepointSecret),
		sweepScript: bufToHex(p.sweepScript),
		...(p.network ? { network: networkName(p.network) } : {})
	};
}

export function deserializeTowerProvisioning(
	s: ISerializedTowerProvisioning
): IFforTowerProvisioning {
	return {
		epochId: Buffer.from(s.epochId, 'hex'),
		params: deserializeFforParams(s.params),
		preimages: s.preimages.map((h) => Buffer.from(h, 'hex')),
		channel: deserializeChannelStatics(s.channel),
		rNodeId: Buffer.from(s.rNodeId, 'hex'),
		sNodeId: Buffer.from(s.sNodeId, 'hex'),
		revocationBasepointSecret:
			hexToBuf(s.revocationBasepointSecret) ?? undefined,
		sweepScript: hexToBuf(s.sweepScript) ?? undefined,
		...(s.network ? { network: networkFromName(s.network) } : {})
	};
}

// ─────────────── IFforTowerRecord (already hex/strings) ───────────────

export interface ISerializedTowerRecord {
	epochIdHex: string;
	lastReleased: number;
	packagesHex: string[];
	revocationSecretN0Hex: string | null;
}

export function serializeTowerRecord(
	r: IFforTowerRecord
): ISerializedTowerRecord {
	return {
		epochIdHex: r.epochIdHex,
		lastReleased: r.lastReleased,
		packagesHex: [...r.packagesHex],
		revocationSecretN0Hex: r.revocationSecretN0Hex
	};
}

export function deserializeTowerRecord(
	s: ISerializedTowerRecord
): IFforTowerRecord {
	return {
		epochIdHex: s.epochIdHex,
		lastReleased: s.lastReleased,
		packagesHex: [...s.packagesHex],
		revocationSecretN0Hex: s.revocationSecretN0Hex
	};
}
