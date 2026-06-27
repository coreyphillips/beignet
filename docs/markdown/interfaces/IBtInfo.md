[beignet](../README.md) / IBtInfo

# Interface: IBtInfo

## Table of contents

### Properties

- [nodes](IBtInfo.md#nodes)
- [onchain](IBtInfo.md#onchain)
- [options](IBtInfo.md#options)
- [version](IBtInfo.md#version)
- [versions](IBtInfo.md#versions)

## Properties

### nodes

• **nodes**: `ILspNode`[]

Available nodes.

#### Defined in

[types/wallet.ts:541](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/types/wallet.ts#L541)

___

### onchain

• **onchain**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `feeRates` | { `fast`: `number` ; `mid`: `number` ; `slow`: `number`  } |
| `feeRates.fast` | `number` |
| `feeRates.mid` | `number` |
| `feeRates.slow` | `number` |
| `network` | [`EAvailableNetworks`](../enums/EAvailableNetworks.md) |

#### Defined in

[types/wallet.ts:593](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/types/wallet.ts#L593)

___

### options

• **options**: `Object`

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `max0ConfClientBalanceSat` | `number` | Maximum clientBalanceSat that is accepted as 0conf/turbochannel. |
| `maxChannelSizeSat` | `number` | Maximum channel size |
| `maxClientBalanceSat` | `number` | Maximum clientBalanceSat in general. |
| `maxExpiryWeeks` | `number` | Maximum channel lease time in weeks. |
| `minChannelSizeSat` | `number` | Minimum channel size |
| `minExpiryWeeks` | `number` | Minimum channel lease time in weeks. |
| `minHighRiskPaymentConfirmations` | `number` | Minimum payment confirmations for high value payments. |
| `minPaymentConfirmations` | `number` | Minimum payment confirmation for safe payments. |

#### Defined in

[types/wallet.ts:542](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/types/wallet.ts#L542)

___

### version

• **version**: `number`

**`Deprecated`**

Use the `versions` object instead.

#### Defined in

[types/wallet.ts:537](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/types/wallet.ts#L537)

___

### versions

• **versions**: `Object`

SemVer versions of the micro services.

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `btc` | `string` | SemVer versions of the btc micro services. |
| `http` | `string` | SemVer versions of the http micro services. |
| `ln2` | `string` | SemVer versions of the ln2 micro services. |

#### Defined in

[types/wallet.ts:579](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/types/wallet.ts#L579)
