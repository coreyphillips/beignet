[beignet](../README.md) / Transaction

# Class: Transaction

## Table of contents

### Constructors

- [constructor](Transaction.md#constructor)

### Properties

- [\_data](Transaction.md#_data)
- [\_wallet](Transaction.md#_wallet)

### Accessors

- [data](Transaction.md#data)

### Methods

- [addExternalInputs](Transaction.md#addexternalinputs)
- [addInput](Transaction.md#addinput)
- [addOutput](Transaction.md#addoutput)
- [applyAutoCoinSelect](Transaction.md#applyautocoinselect)
- [autoCoinSelect](Transaction.md#autocoinselect)
- [createPsbtFromTransactionData](Transaction.md#createpsbtfromtransactiondata)
- [createTransaction](Transaction.md#createtransaction)
- [estimateTransactionCosts](Transaction.md#estimatetransactioncosts)
- [getMaxSatsPerByte](Transaction.md#getmaxsatsperbyte)
- [getMaxSendAmount](Transaction.md#getmaxsendamount)
- [getTotalFee](Transaction.md#gettotalfee)
- [getTotalFeeObj](Transaction.md#gettotalfeeobj)
- [getTransactionInputValue](Transaction.md#gettransactioninputvalue)
- [getTransactionOutputValue](Transaction.md#gettransactionoutputvalue)
- [removeBlackListedUtxos](Transaction.md#removeblacklistedutxos)
- [resetSendTransaction](Transaction.md#resetsendtransaction)
- [sendMax](Transaction.md#sendmax)
- [setupCpfp](Transaction.md#setupcpfp)
- [setupRbf](Transaction.md#setuprbf)
- [setupTransaction](Transaction.md#setuptransaction)
- [signPsbt](Transaction.md#signpsbt)
- [updateFee](Transaction.md#updatefee)
- [updateSendTransaction](Transaction.md#updatesendtransaction)

## Constructors

### constructor

• **new Transaction**(`«destructured»`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `wallet` | [`Wallet`](Wallet.md) |

#### Defined in

[transaction/index.ts:52](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L52)

## Properties

### \_data

• `Private` **\_data**: [`ISendTransaction`](../interfaces/ISendTransaction.md)

#### Defined in

[transaction/index.ts:49](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L49)

___

### \_wallet

• `Private` `Readonly` **\_wallet**: [`Wallet`](Wallet.md)

#### Defined in

[transaction/index.ts:50](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L50)

## Accessors

### data

• `get` **data**(): [`ISendTransaction`](../interfaces/ISendTransaction.md)

#### Returns

[`ISendTransaction`](../interfaces/ISendTransaction.md)

#### Defined in

[transaction/index.ts:57](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L57)

## Methods

### addExternalInputs

▸ **addExternalInputs**(`«destructured»`): [`Result`](../README.md#result)<[`IUtxo`](../interfaces/IUtxo.md)[]\>

Adds external inputs to the current transaction.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `inputs` | [`IUtxo`](../interfaces/IUtxo.md)[] |
| › `keyPair` | `BIP32Interface` \| `ECPairInterface` |

#### Returns

[`Result`](../README.md#result)<[`IUtxo`](../interfaces/IUtxo.md)[]\>

#### Defined in

[transaction/index.ts:859](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L859)

___

### addInput

▸ **addInput**(`«destructured»`): `Promise`<[`Result`](../README.md#result)<`string`\>\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | [`IAddInput`](../interfaces/IAddInput.md) |

#### Returns

`Promise`<[`Result`](../README.md#result)<`string`\>\>

#### Defined in

[transaction/index.ts:746](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L746)

___

### addOutput

▸ **addOutput**(`«destructured»`): `Promise`<[`Result`](../README.md#result)<`string`\>\>

Adds an output at the specified index to the current transaction.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | [`IOutput`](../interfaces/IOutput.md) |

#### Returns

`Promise`<[`Result`](../README.md#result)<`string`\>\>

#### Defined in

[transaction/index.ts:908](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L908)

___

### applyAutoCoinSelect

▸ **applyAutoCoinSelect**(`«destructured»`): `Promise`<[`Result`](../README.md#result)<[`ISendTransaction`](../interfaces/ISendTransaction.md)\>\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `coinSelectRes` | [`ICoinSelectResponse`](../interfaces/ICoinSelectResponse.md) |

#### Returns

`Promise`<[`Result`](../README.md#result)<[`ISendTransaction`](../interfaces/ISendTransaction.md)\>\>

#### Defined in

[transaction/index.ts:180](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L180)

___

### autoCoinSelect

▸ **autoCoinSelect**(`«destructured»`): [`Result`](../README.md#result)<[`ICoinSelectResponse`](../interfaces/ICoinSelectResponse.md)\>

Selects coins for transaction construction based on provided parameters.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `changeAddress?` | `string` |
| › `coinSelectPreference?` | [`ECoinSelectPreference`](../enums/ECoinSelectPreference.md) |
| › `inputs` | [`IUtxo`](../interfaces/IUtxo.md)[] |
| › `message?` | `string` |
| › `outputs` | [`IOutput`](../interfaces/IOutput.md)[] |
| › `satsPerByte?` | `number` |

#### Returns

[`Result`](../README.md#result)<[`ICoinSelectResponse`](../interfaces/ICoinSelectResponse.md)\>

#### Defined in

[transaction/index.ts:1408](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L1408)

___

### createPsbtFromTransactionData

▸ **createPsbtFromTransactionData**(`«destructured»`): `Promise`<[`Result`](../README.md#result)<`Psbt`\>\>

Returns a PSBT that includes unsigned funding inputs.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `bip32Interface?` | `BIP32Interface` |
| › `shuffleTargets?` | `boolean` |
| › `transactionData` | [`ISendTransaction`](../interfaces/ISendTransaction.md) |

#### Returns

`Promise`<[`Result`](../README.md#result)<`Psbt`\>\>

#### Defined in

[transaction/index.ts:607](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L607)

___

### createTransaction

▸ **createTransaction**(`«destructured»?`): `Promise`<[`Result`](../README.md#result)<{ `hex`: `string` ; `id`: `string`  }\>\>

Creates complete signed transaction using the transaction data store

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | [`ICreateTransaction`](../interfaces/ICreateTransaction.md) |

#### Returns

`Promise`<[`Result`](../README.md#result)<{ `hex`: `string` ; `id`: `string`  }\>\>

#### Defined in

[transaction/index.ts:440](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L440)

___

### estimateTransactionCosts

▸ **estimateTransactionCosts**(`«destructured»?`): [`Result`](../README.md#result)<{ `amount`: `number` ; `fee`: `number` ; `satsPerByte`: `number`  }\>

Calculates the max amount able to send for onchain/lightning

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `customFeeRate?` | `number` |
| › `transaction?` | [`ISendTransaction`](../interfaces/ISendTransaction.md) |

#### Returns

[`Result`](../README.md#result)<{ `amount`: `number` ; `fee`: `number` ; `satsPerByte`: `number`  }\>

#### Defined in

[transaction/index.ts:1138](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L1138)

___

### getMaxSatsPerByte

▸ **getMaxSatsPerByte**(`«destructured»`): `number`

Returns the maximum sats per byte that can be used for a given transaction.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `balance?` | `number` |
| › `transactionByteCount` | `number` |

#### Returns

`number`

#### Defined in

[transaction/index.ts:423](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L423)

___

### getMaxSendAmount

▸ **getMaxSendAmount**(`«destructured»`): [`Result`](../README.md#result)<{ `amount`: `number` ; `fee`: `number`  }\>

Calculates the max amount able to send for the provided/current onchain transaction.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `satsPerByte` | `number` |
| › `selectedFeeId?` | [`EFeeId`](../enums/EFeeId.md) |
| › `transaction?` | [`ISendTransaction`](../interfaces/ISendTransaction.md) |

#### Returns

[`Result`](../README.md#result)<{ `amount`: `number` ; `fee`: `number`  }\>

#### Defined in

[transaction/index.ts:1205](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L1205)

___

### getTotalFee

▸ **getTotalFee**(`«destructured»?`): `number`

Attempt to estimate the current fee for a given transaction and its UTXO's

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `coinSelectPreference?` | [`ECoinSelectPreference`](../enums/ECoinSelectPreference.md) |
| › `fundingLightning?` | `boolean` |
| › `message?` | `string` |
| › `satsPerByte` | `number` |
| › `transaction?` | `Partial`<[`ISendTransaction`](../interfaces/ISendTransaction.md)\> |

#### Returns

`number`

#### Defined in

[transaction/index.ts:236](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L236)

___

### getTotalFeeObj

▸ **getTotalFeeObj**(`«destructured»?`): [`Result`](../README.md#result)<[`TGetTotalFeeObj`](../README.md#tgettotalfeeobj)\>

Attempt to estimate the current fee for a given transaction and its UTXO's

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `coinSelectPreference?` | [`ECoinSelectPreference`](../enums/ECoinSelectPreference.md) |
| › `fundingLightning?` | `boolean` |
| › `message?` | `string` |
| › `satsPerByte?` | `number` |
| › `transaction?` | `Partial`<[`ISendTransaction`](../interfaces/ISendTransaction.md)\> |

#### Returns

[`Result`](../README.md#result)<[`TGetTotalFeeObj`](../README.md#tgettotalfeeobj)\>

#### Defined in

[transaction/index.ts:309](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L309)

___

### getTransactionInputValue

▸ **getTransactionInputValue**(`inputs?`): `number`

Returns total value of all utxos.

#### Parameters

| Name | Type |
| :------ | :------ |
| `inputs?` | `Object` |
| `inputs.inputs?` | [`IUtxo`](../interfaces/IUtxo.md)[] |

#### Returns

`number`

#### Defined in

[transaction/index.ts:535](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L535)

___

### getTransactionOutputValue

▸ **getTransactionOutputValue**(`outputs?`): `number`

Returns total value of all outputs. Excludes any value that would be sent to the change address.

#### Parameters

| Name | Type |
| :------ | :------ |
| `outputs?` | `Object` |
| `outputs.outputs?` | [`IOutput`](../interfaces/IOutput.md)[] |

#### Returns

`number`

#### Defined in

[transaction/index.ts:932](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L932)

___

### removeBlackListedUtxos

▸ **removeBlackListedUtxos**(`utxos?`): [`IUtxo`](../interfaces/IUtxo.md)[]

Removes blacklisted UTXO's from the UTXO array.

#### Parameters

| Name | Type |
| :------ | :------ |
| `utxos?` | [`IUtxo`](../interfaces/IUtxo.md)[] |

#### Returns

[`IUtxo`](../interfaces/IUtxo.md)[]

#### Defined in

[transaction/index.ts:211](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L211)

___

### resetSendTransaction

▸ **resetSendTransaction**(): `Promise`<[`Result`](../README.md#result)<`string`\>\>

This completely resets the send transaction state.

#### Returns

`Promise`<[`Result`](../README.md#result)<`string`\>\>

#### Defined in

[transaction/index.ts:201](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L201)

___

### sendMax

▸ **sendMax**(`«destructured»?`): `Promise`<[`Result`](../README.md#result)<`string`\>\>

Toggles the max amount to the provided output index.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `address?` | `string` |
| › `index?` | `number` |
| › `rbf?` | `boolean` |
| › `satsPerByte?` | `number` |
| › `transaction?` | [`ISendTransaction`](../interfaces/ISendTransaction.md) |

#### Returns

`Promise`<[`Result`](../README.md#result)<`string`\>\>

#### Defined in

[transaction/index.ts:1069](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L1069)

___

### setupCpfp

▸ **setupCpfp**(`«destructured»?`): `Promise`<[`Result`](../README.md#result)<[`ISendTransaction`](../interfaces/ISendTransaction.md)\>\>

Sets up a CPFP transaction.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `satsPerByte?` | `number` |
| › `txid?` | `string` |

#### Returns

`Promise`<[`Result`](../README.md#result)<[`ISendTransaction`](../interfaces/ISendTransaction.md)\>\>

#### Defined in

[transaction/index.ts:1256](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L1256)

___

### setupRbf

▸ **setupRbf**(`txid`): `Promise`<[`Result`](../README.md#result)<[`ISendTransaction`](../interfaces/ISendTransaction.md)\>\>

Sets up a transaction for RBF.

#### Parameters

| Name | Type |
| :------ | :------ |
| `txid` | `Object` |
| `txid.txid` | `string` |

#### Returns

`Promise`<[`Result`](../README.md#result)<[`ISendTransaction`](../interfaces/ISendTransaction.md)\>\>

#### Defined in

[transaction/index.ts:1327](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L1327)

___

### setupTransaction

▸ **setupTransaction**(`«destructured»?`): `Promise`<[`TSetupTransactionResponse`](../README.md#tsetuptransactionresponse)\>

Sets up a transaction for a given wallet by gathering inputs, setting the next available change address as an output and sets up the baseline fee structure.
This function will not override previously set transaction data. To do that you'll need to call resetSendTransaction.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | [`ISetupTransaction`](../interfaces/ISetupTransaction.md) |

#### Returns

`Promise`<[`TSetupTransactionResponse`](../README.md#tsetuptransactionresponse)\>

#### Defined in

[transaction/index.ts:71](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L71)

___

### signPsbt

▸ **signPsbt**(`«destructured»`): `Promise`<[`Result`](../README.md#result)<`Psbt`\>\>

Loops through inputs and signs them

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `bip32Interface` | `BIP32Interface` |
| › `psbt` | `Psbt` |

#### Returns

`Promise`<[`Result`](../README.md#result)<`Psbt`\>\>

#### Defined in

[transaction/index.ts:559](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L559)

___

### updateFee

▸ **updateFee**(`«destructured»?`): [`Result`](../README.md#result)<{ `fee`: `number`  }\>

Updates the fee for the current transaction by the specified amount.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `index?` | `number` |
| › `satsPerByte` | `number` |
| › `selectedFeeId?` | [`EFeeId`](../enums/EFeeId.md) |
| › `transaction?` | [`ISendTransaction`](../interfaces/ISendTransaction.md) |

#### Returns

[`Result`](../README.md#result)<{ `fee`: `number`  }\>

#### Defined in

[transaction/index.ts:995](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L995)

___

### updateSendTransaction

▸ **updateSendTransaction**(`transaction`): [`Result`](../README.md#result)<`string`\>

This updates the transaction state used for sending.

#### Parameters

| Name | Type |
| :------ | :------ |
| `transaction` | `Object` |
| `transaction.transaction` | `Partial`<[`ISendTransaction`](../interfaces/ISendTransaction.md)\> |

#### Returns

[`Result`](../README.md#result)<`string`\>

#### Defined in

[transaction/index.ts:957](https://github.com/coreyphillips/beignet/blob/8a84ec1/src/transaction/index.ts#L957)
