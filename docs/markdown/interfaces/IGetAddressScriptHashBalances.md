[beignet](../README.md) / IGetAddressScriptHashBalances

# Interface: IGetAddressScriptHashBalances

## Table of contents

### Properties

- [data](IGetAddressScriptHashBalances.md#data)
- [error](IGetAddressScriptHashBalances.md#error)
- [id](IGetAddressScriptHashBalances.md#id)
- [method](IGetAddressScriptHashBalances.md#method)
- [network](IGetAddressScriptHashBalances.md#network)

## Properties

### data

• **data**: `string` \| { `data`: `Record`<`string`, `unknown`\> ; `id`: `number` ; `jsonrpc`: `string` ; `param`: `string` ; `result`: { `confirmed`: `number` ; `unconfirmed`: `number`  }  }[]

#### Defined in

[types/electrum.ts:91](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/electrum.ts#L91)

___

### error

• **error**: `boolean`

#### Defined in

[types/electrum.ts:90](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/electrum.ts#L90)

___

### id

• **id**: `number`

#### Defined in

[types/electrum.ts:103](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/electrum.ts#L103)

___

### method

• **method**: `string`

#### Defined in

[types/electrum.ts:104](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/electrum.ts#L104)

___

### network

• **network**: [`EElectrumNetworks`](../enums/EElectrumNetworks.md)

#### Defined in

[types/electrum.ts:105](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/electrum.ts#L105)
