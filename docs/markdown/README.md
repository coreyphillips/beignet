beignet

# beignet

## Table of contents

### Enumerations

- [EAddressType](enums/EAddressType.md)
- [EAvailableNetworks](enums/EAvailableNetworks.md)
- [EBoostType](enums/EBoostType.md)
- [EFeeId](enums/EFeeId.md)
- [EPaymentType](enums/EPaymentType.md)
- [EProtocol](enums/EProtocol.md)
- [EUnit](enums/EUnit.md)

### Classes

- [Electrum](classes/Electrum.md)
- [Transaction](classes/Transaction.md)
- [Wallet](classes/Wallet.md)

### Interfaces

- [IAddInput](interfaces/IAddInput.md)
- [IAddress](interfaces/IAddress.md)
- [IAddressData](interfaces/IAddressData.md)
- [IAddressType](interfaces/IAddressType.md)
- [IAddressTypeData](interfaces/IAddressTypeData.md)
- [IAddresses](interfaces/IAddresses.md)
- [IConnectToElectrumRes](interfaces/IConnectToElectrumRes.md)
- [ICreateTransaction](interfaces/ICreateTransaction.md)
- [IElectrumGetAddressBalanceRes](interfaces/IElectrumGetAddressBalanceRes.md)
- [IExchangeRates](interfaces/IExchangeRates.md)
- [IFees](interfaces/IFees.md)
- [IFormattedPeerData](interfaces/IFormattedPeerData.md)
- [IFormattedTransaction](interfaces/IFormattedTransaction.md)
- [IFormattedTransactions](interfaces/IFormattedTransactions.md)
- [IGenerateAddresses](interfaces/IGenerateAddresses.md)
- [IGenerateAddressesResponse](interfaces/IGenerateAddressesResponse.md)
- [IGetAddress](interfaces/IGetAddress.md)
- [IGetAddressBalanceRes](interfaces/IGetAddressBalanceRes.md)
- [IGetAddressByPath](interfaces/IGetAddressByPath.md)
- [IGetAddressHistoryResponse](interfaces/IGetAddressHistoryResponse.md)
- [IGetAddressResponse](interfaces/IGetAddressResponse.md)
- [IGetAddressScriptHashesHistoryResponse](interfaces/IGetAddressScriptHashesHistoryResponse.md)
- [IGetDerivationPath](interfaces/IGetDerivationPath.md)
- [IGetFeeEstimatesResponse](interfaces/IGetFeeEstimatesResponse.md)
- [IGetHeaderResponse](interfaces/IGetHeaderResponse.md)
- [IGetNextAvailableAddressResponse](interfaces/IGetNextAvailableAddressResponse.md)
- [IGetTransactions](interfaces/IGetTransactions.md)
- [IGetTransactionsFromInputs](interfaces/IGetTransactionsFromInputs.md)
- [IGetUtxosResponse](interfaces/IGetUtxosResponse.md)
- [IHeader](interfaces/IHeader.md)
- [IIndexes](interfaces/IIndexes.md)
- [IKeyDerivationPath](interfaces/IKeyDerivationPath.md)
- [IKeyDerivationPathData](interfaces/IKeyDerivationPathData.md)
- [INewBlock](interfaces/INewBlock.md)
- [IOutput](interfaces/IOutput.md)
- [ISend](interfaces/ISend.md)
- [ISendTransaction](interfaces/ISendTransaction.md)
- [ISendTx](interfaces/ISendTx.md)
- [ISetupTransaction](interfaces/ISetupTransaction.md)
- [ISubscribeToAddress](interfaces/ISubscribeToAddress.md)
- [ISubscribeToHeader](interfaces/ISubscribeToHeader.md)
- [ITargets](interfaces/ITargets.md)
- [ITransaction](interfaces/ITransaction.md)
- [ITxHash](interfaces/ITxHash.md)
- [ITxHashes](interfaces/ITxHashes.md)
- [IUtxo](interfaces/IUtxo.md)
- [IVin](interfaces/IVin.md)
- [IVout](interfaces/IVout.md)
- [IWallet](interfaces/IWallet.md)
- [IWalletData](interfaces/IWalletData.md)

### Type Aliases

- [ElectrumConnectionPubSub](README.md#electrumconnectionpubsub)
- [ElectrumConnectionSubscription](README.md#electrumconnectionsubscription)
- [InputData](README.md#inputdata)
- [ObjectKeys](README.md#objectkeys)
- [Result](README.md#result)
- [TAddressIndexInfo](README.md#taddressindexinfo)
- [TAddressLabel](README.md#taddresslabel)
- [TAddressType](README.md#taddresstype)
- [TAddressTypeContent](README.md#taddresstypecontent)
- [TAddressTypes](README.md#taddresstypes)
- [TAvailableNetworks](README.md#tavailablenetworks)
- [TElectrumNetworks](README.md#telectrumnetworks)
- [TGetByteCountInput](README.md#tgetbytecountinput)
- [TGetByteCountInputs](README.md#tgetbytecountinputs)
- [TGetByteCountOutput](README.md#tgetbytecountoutput)
- [TGetByteCountOutputs](README.md#tgetbytecountoutputs)
- [TGetData](README.md#tgetdata)
- [TKeyDerivationAccount](README.md#tkeyderivationaccount)
- [TKeyDerivationChange](README.md#tkeyderivationchange)
- [TKeyDerivationCoinType](README.md#tkeyderivationcointype)
- [TKeyDerivationIndex](README.md#tkeyderivationindex)
- [TKeyDerivationPurpose](README.md#tkeyderivationpurpose)
- [TMessageDataMap](README.md#tmessagedatamap)
- [TMessageKeys](README.md#tmessagekeys)
- [TOnMessage](README.md#tonmessage)
- [TProcessUnconfirmedTransactions](README.md#tprocessunconfirmedtransactions)
- [TProtocol](README.md#tprotocol)
- [TServer](README.md#tserver)
- [TSetData](README.md#tsetdata)
- [TSetupTransactionResponse](README.md#tsetuptransactionresponse)
- [TStorage](README.md#tstorage)
- [TSubscribedReceive](README.md#tsubscribedreceive)
- [TTransactionMessage](README.md#ttransactionmessage)
- [TTxResponse](README.md#ttxresponse)
- [TTxResult](README.md#ttxresult)
- [TUnspentAddressScriptHashData](README.md#tunspentaddressscripthashdata)
- [TWalletDataKeys](README.md#twalletdatakeys)

### Variables

- [defaultElectrumPorts](README.md#defaultelectrumports)
- [electrumConnection](README.md#electrumconnection)
- [mostUsedExchangeTickers](README.md#mostusedexchangetickers)

### Functions

- [availableNetworks](README.md#availablenetworks)
- [constructByteCountParam](README.md#constructbytecountparam)
- [err](README.md#err)
- [formatKeyDerivationPath](README.md#formatkeyderivationpath)
- [formatPeerData](README.md#formatpeerdata)
- [generateMnemonic](README.md#generatemnemonic)
- [getAddressFromScriptPubKey](README.md#getaddressfromscriptpubkey)
- [getAddressTypeFromPath](README.md#getaddresstypefrompath)
- [getByteCount](README.md#getbytecount)
- [getDataFallback](README.md#getdatafallback)
- [getDefaultPort](README.md#getdefaultport)
- [getDefaultWalletData](README.md#getdefaultwalletdata)
- [getDefaultWalletDataKeys](README.md#getdefaultwalletdatakeys)
- [getExchangeRates](README.md#getexchangerates)
- [getHighestUsedIndexFromTxHashes](README.md#gethighestusedindexfromtxhashes)
- [getKeyDerivationPath](README.md#getkeyderivationpath)
- [getKeyDerivationPathObject](README.md#getkeyderivationpathobject)
- [getKeyDerivationPathString](README.md#getkeyderivationpathstring)
- [getKeyValue](README.md#getkeyvalue)
- [getPeers](README.md#getpeers)
- [getProtocolForPort](README.md#getprotocolforport)
- [getScriptHash](README.md#getscripthash)
- [getSha256](README.md#getsha256)
- [isValidBech32mEncodedString](README.md#isvalidbech32mencodedstring)
- [objectKeys](README.md#objectkeys-1)
- [ok](README.md#ok)
- [parseOnChainPaymentRequest](README.md#parseonchainpaymentrequest)
- [reduceValue](README.md#reducevalue)
- [removeDustOutputs](README.md#removedustoutputs)
- [setReplaceByFee](README.md#setreplacebyfee)
- [shuffleArray](README.md#shufflearray)
- [validateAddress](README.md#validateaddress)
- [validateMnemonic](README.md#validatemnemonic)

## Type Aliases

### ElectrumConnectionPubSub

Ƭ **ElectrumConnectionPubSub**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `publish` | (`isConnected`: `boolean`) => `void` |
| `subscribe` | (`callback`: (`isConnected`: `boolean`) => `void`) => [`ElectrumConnectionSubscription`](README.md#electrumconnectionsubscription) |

#### Defined in

[types/electrum.ts:124](https://github.com/synonymdev/beignet/blob/8f99086/src/types/electrum.ts#L124)

___

### ElectrumConnectionSubscription

Ƭ **ElectrumConnectionSubscription**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `remove` | () => `void` |

#### Defined in

[types/electrum.ts:131](https://github.com/synonymdev/beignet/blob/8f99086/src/types/electrum.ts#L131)

___

### InputData

Ƭ **InputData**: `Object`

#### Index signature

▪ [key: `string`]: { `addresses`: `string`[] ; `value`: `number`  }

#### Defined in

[types/wallet.ts:347](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L347)

___

### ObjectKeys

Ƭ **ObjectKeys**<`T`\>: \`${Exclude<keyof T, symbol\>}\`

#### Type parameters

| Name | Type |
| :------ | :------ |
| `T` | extends `object` |

#### Defined in

[types/wallet.ts:419](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L419)

___

### Result

Ƭ **Result**<`T`\>: `Ok`<`T`\> \| `Err`<`T`\>

Represents a result that can be successful (Ok) or contain an error (Err).

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[utils/result.ts:4](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/result.ts#L4)

___

### TAddressIndexInfo

Ƭ **TAddressIndexInfo**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `addressIndex` | [`IAddress`](interfaces/IAddress.md) |
| `changeAddressIndex` | [`IAddress`](interfaces/IAddress.md) |
| `lastUsedAddressIndex` | [`IAddress`](interfaces/IAddress.md) |
| `lastUsedChangeAddressIndex` | [`IAddress`](interfaces/IAddress.md) |

#### Defined in

[types/wallet.ts:440](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L440)

___

### TAddressLabel

Ƭ **TAddressLabel**: ``"bech32"`` \| ``"segwit"`` \| ``"legacy"``

#### Defined in

[types/wallet.ts:7](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L7)

___

### TAddressType

Ƭ **TAddressType**: ``"p2wpkh"`` \| ``"p2sh"`` \| ``"p2pkh"``

#### Defined in

[types/wallet.ts:6](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L6)

___

### TAddressTypeContent

Ƭ **TAddressTypeContent**<`T`\>: { [key in EAddressType]: T }

#### Type parameters

| Name |
| :------ |
| `T` |

#### Defined in

[types/wallet.ts:38](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L38)

___

### TAddressTypes

Ƭ **TAddressTypes**: { [key in EAddressType]: Readonly<IAddressTypeData\> }

#### Defined in

[types/wallet.ts:13](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L13)

___

### TAvailableNetworks

Ƭ **TAvailableNetworks**: ``"bitcoin"`` \| ``"testnet"`` \| ``"regtest"``

#### Defined in

[types/wallet.ts:5](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L5)

___

### TElectrumNetworks

Ƭ **TElectrumNetworks**: ``"bitcoin"`` \| ``"bitcoinTestnet"`` \| ``"bitcoinRegtest"``

#### Defined in

[types/electrum.ts:9](https://github.com/synonymdev/beignet/blob/8f99086/src/types/electrum.ts#L9)

___

### TGetByteCountInput

Ƭ **TGetByteCountInput**: \`MULTISIG-P2SH:${number}-${number}\` \| \`MULTISIG-P2WSH:${number}-${number}\` \| \`MULTISIG-P2SH-P2WSH:${number}-${number}\` \| ``"P2SH-P2WPKH"`` \| ``"P2PKH"`` \| ``"p2pkh"`` \| ``"P2WPKH"`` \| ``"p2wpkh"`` \| ``"P2SH"`` \| ``"p2sh"`` \| ``"P2TR"`` \| ``"p2tr"``

#### Defined in

[types/wallet.ts:362](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L362)

___

### TGetByteCountInputs

Ƭ **TGetByteCountInputs**: { [key in TGetByteCountInput]?: number }

#### Defined in

[types/wallet.ts:354](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L354)

___

### TGetByteCountOutput

Ƭ **TGetByteCountOutput**: ``"P2SH"`` \| ``"P2PKH"`` \| ``"P2WPKH"`` \| ``"P2WSH"`` \| ``"p2wpkh"`` \| ``"p2sh"`` \| ``"p2pkh"`` \| ``"P2TR"`` \| ``"p2tr"``

#### Defined in

[types/wallet.ts:376](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L376)

___

### TGetByteCountOutputs

Ƭ **TGetByteCountOutputs**: { [key in TGetByteCountOutput]?: number }

#### Defined in

[types/wallet.ts:358](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L358)

___

### TGetData

Ƭ **TGetData**: <K\>(`key`: `string`) => `Promise`<[`Result`](README.md#result)<[`IWalletData`](interfaces/IWalletData.md)[`K`]\>\>

#### Type declaration

▸ <`K`\>(`key`): `Promise`<[`Result`](README.md#result)<[`IWalletData`](interfaces/IWalletData.md)[`K`]\>\>

##### Type parameters

| Name | Type |
| :------ | :------ |
| `K` | extends keyof [`IWalletData`](interfaces/IWalletData.md) |

##### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |

##### Returns

`Promise`<[`Result`](README.md#result)<[`IWalletData`](interfaces/IWalletData.md)[`K`]\>\>

#### Defined in

[types/wallet.ts:159](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L159)

___

### TKeyDerivationAccount

Ƭ **TKeyDerivationAccount**: ``"0"`` \| `string`

#### Defined in

[types/wallet.ts:10](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L10)

___

### TKeyDerivationChange

Ƭ **TKeyDerivationChange**: ``"0"`` \| ``"1"``

#### Defined in

[types/wallet.ts:11](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L11)

___

### TKeyDerivationCoinType

Ƭ **TKeyDerivationCoinType**: ``"0"`` \| ``"1"`` \| `string`

#### Defined in

[types/wallet.ts:9](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L9)

___

### TKeyDerivationIndex

Ƭ **TKeyDerivationIndex**: `string`

#### Defined in

[types/wallet.ts:12](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L12)

___

### TKeyDerivationPurpose

Ƭ **TKeyDerivationPurpose**: ``"84"`` \| ``"49"`` \| ``"44"`` \| `string`

#### Defined in

[types/wallet.ts:8](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L8)

___

### TMessageDataMap

Ƭ **TMessageDataMap**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `newBlock` | [`INewBlock`](interfaces/INewBlock.md) |
| `transactionConfirmed` | [`TTransactionMessage`](README.md#ttransactionmessage) |
| `transactionReceived` | [`TTransactionMessage`](README.md#ttransactionmessage) |
| `transactionSent` | [`TTransactionMessage`](README.md#ttransactionmessage) |

#### Defined in

[types/wallet.ts:403](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L403)

___

### TMessageKeys

Ƭ **TMessageKeys**: keyof [`TMessageDataMap`](README.md#tmessagedatamap)

#### Defined in

[types/wallet.ts:427](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L427)

___

### TOnMessage

Ƭ **TOnMessage**: <K\>(`key`: `K`, `data`: [`TMessageDataMap`](README.md#tmessagedatamap)[`K`]) => `void`

#### Type declaration

▸ <`K`\>(`key`, `data`): `void`

##### Type parameters

| Name | Type |
| :------ | :------ |
| `K` | extends keyof [`TMessageDataMap`](README.md#tmessagedatamap) |

##### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `K` |
| `data` | [`TMessageDataMap`](README.md#tmessagedatamap)[`K`] |

##### Returns

`void`

#### Defined in

[types/wallet.ts:422](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L422)

___

### TProcessUnconfirmedTransactions

Ƭ **TProcessUnconfirmedTransactions**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `ghostTxs` | `string`[] |
| `outdatedTxs` | [`IUtxo`](interfaces/IUtxo.md)[] |
| `unconfirmedTxs` | [`IFormattedTransactions`](interfaces/IFormattedTransactions.md) |

#### Defined in

[types/wallet.ts:325](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L325)

___

### TProtocol

Ƭ **TProtocol**: ``"tcp"`` \| ``"ssl"``

#### Defined in

[types/electrum.ts:25](https://github.com/synonymdev/beignet/blob/8f99086/src/types/electrum.ts#L25)

___

### TServer

Ƭ **TServer**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `protocol` | [`EProtocol`](enums/EProtocol.md) |
| `ssl` | `number` |
| `tcp` | `number` |

#### Defined in

[types/electrum.ts:19](https://github.com/synonymdev/beignet/blob/8f99086/src/types/electrum.ts#L19)

___

### TSetData

Ƭ **TSetData**: <K\>(`key`: `string`, `value`: [`IWalletData`](interfaces/IWalletData.md)[`K`]) => `Promise`<[`Result`](README.md#result)<`boolean`\>\>

#### Type declaration

▸ <`K`\>(`key`, `value`): `Promise`<[`Result`](README.md#result)<`boolean`\>\>

##### Type parameters

| Name | Type |
| :------ | :------ |
| `K` | extends keyof [`IWalletData`](interfaces/IWalletData.md) |

##### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |
| `value` | [`IWalletData`](interfaces/IWalletData.md)[`K`] |

##### Returns

`Promise`<[`Result`](README.md#result)<`boolean`\>\>

#### Defined in

[types/wallet.ts:162](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L162)

___

### TSetupTransactionResponse

Ƭ **TSetupTransactionResponse**: `Promise`<[`Result`](README.md#result)<`Partial`<[`ISendTransaction`](interfaces/ISendTransaction.md)\>\>\>

#### Defined in

[types/transaction.ts:36](https://github.com/synonymdev/beignet/blob/8f99086/src/types/transaction.ts#L36)

___

### TStorage

Ƭ **TStorage**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `getData` | [`TGetData`](README.md#tgetdata) |
| `setData` | [`TSetData`](README.md#tsetdata) |

#### Defined in

[types/wallet.ts:447](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L447)

___

### TSubscribedReceive

Ƭ **TSubscribedReceive**: [`string`, `string`]

#### Defined in

[types/electrum.ts:114](https://github.com/synonymdev/beignet/blob/8f99086/src/types/electrum.ts#L114)

___

### TTransactionMessage

Ƭ **TTransactionMessage**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `address` | [`IAddress`](interfaces/IAddress.md) |
| `balance` | [`IGetAddressBalanceRes`](interfaces/IGetAddressBalanceRes.md) |
| `txs` | [`TTxResult`](README.md#ttxresult)[] |

#### Defined in

[types/wallet.ts:410](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L410)

___

### TTxResponse

Ƭ **TTxResponse**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `data` | [`IAddress`](interfaces/IAddress.md) |
| `id` | `number` |
| `jsonrpc` | `string` |
| `param` | `string` |
| `result` | [`TTxResult`](README.md#ttxresult)[] |

#### Defined in

[types/electrum.ts:53](https://github.com/synonymdev/beignet/blob/8f99086/src/types/electrum.ts#L53)

___

### TTxResult

Ƭ **TTxResult**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `height` | `number` |
| `tx_hash` | `string` |

#### Defined in

[types/electrum.ts:40](https://github.com/synonymdev/beignet/blob/8f99086/src/types/electrum.ts#L40)

___

### TUnspentAddressScriptHashData

Ƭ **TUnspentAddressScriptHashData**: `Object`

#### Index signature

▪ [x: `string`]: [`IUtxo`](interfaces/IUtxo.md) \| [`IAddress`](interfaces/IAddress.md)

#### Defined in

[types/electrum.ts:36](https://github.com/synonymdev/beignet/blob/8f99086/src/types/electrum.ts#L36)

___

### TWalletDataKeys

Ƭ **TWalletDataKeys**: keyof [`IWalletData`](interfaces/IWalletData.md)

#### Defined in

[types/wallet.ts:157](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L157)

## Variables

### defaultElectrumPorts

• `Const` **defaultElectrumPorts**: `string`[]

#### Defined in

[utils/electrum.ts:14](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/electrum.ts#L14)

___

### electrumConnection

• `Const` **electrumConnection**: [`ElectrumConnectionPubSub`](README.md#electrumconnectionpubsub)

Background task that checks the connection to the Electrum server with a PubSub
If connection was lost this will try to reconnect in the specified interval

**`Param`**

#### Defined in

[utils/electrum.ts:135](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/electrum.ts#L135)

___

### mostUsedExchangeTickers

• `Const` **mostUsedExchangeTickers**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `CAD` | { `currencySymbol`: `string` = '$'; `quote`: `string` = 'CAD'; `quoteName`: `string` = 'Canadian Dollar' } |
| `CAD.currencySymbol` | `string` |
| `CAD.quote` | `string` |
| `CAD.quoteName` | `string` |
| `CNY` | { `currencySymbol`: `string` = '¥'; `quote`: `string` = 'CNY'; `quoteName`: `string` = 'Chinese Yuan Renminbi' } |
| `CNY.currencySymbol` | `string` |
| `CNY.quote` | `string` |
| `CNY.quoteName` | `string` |
| `EUR` | { `currencySymbol`: `string` = '€'; `quote`: `string` = 'EUR'; `quoteName`: `string` = 'Euro' } |
| `EUR.currencySymbol` | `string` |
| `EUR.quote` | `string` |
| `EUR.quoteName` | `string` |
| `GBP` | { `currencySymbol`: `string` = '£'; `quote`: `string` = 'GBP'; `quoteName`: `string` = 'Great British Pound' } |
| `GBP.currencySymbol` | `string` |
| `GBP.quote` | `string` |
| `GBP.quoteName` | `string` |
| `USD` | { `currencySymbol`: `string` = '$'; `quote`: `string` = 'USD'; `quoteName`: `string` = 'US Dollar' } |
| `USD.currencySymbol` | `string` |
| `USD.quote` | `string` |
| `USD.quoteName` | `string` |

#### Defined in

[utils/exchange-rate.ts:5](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/exchange-rate.ts#L5)

## Functions

### availableNetworks

▸ **availableNetworks**(): [`EAvailableNetworks`](enums/EAvailableNetworks.md)[]

Returns an array of all available networks from the networks object.

#### Returns

[`EAvailableNetworks`](enums/EAvailableNetworks.md)[]

#### Defined in

[utils/wallet.ts:204](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L204)

___

### constructByteCountParam

▸ **constructByteCountParam**(`addresses`): [`TGetByteCountInputs`](README.md#tgetbytecountinputs) \| [`TGetByteCountOutputs`](README.md#tgetbytecountoutputs)

Constructs the parameter for getByteCount via an array of addresses.

#### Parameters

| Name | Type |
| :------ | :------ |
| `addresses` | `string`[] |

#### Returns

[`TGetByteCountInputs`](README.md#tgetbytecountinputs) \| [`TGetByteCountOutputs`](README.md#tgetbytecountoutputs)

y

#### Defined in

[utils/transaction.ts:142](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/transaction.ts#L142)

___

### err

▸ **err**<`T`\>(`error`): `Err`<`T`\>

Construct a new Err result value.

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `error` | `string` \| `Error` | The error message or Error object to be wrapped in an Err result. |

#### Returns

`Err`<`T`\>

An Err result containing the given error.

#### Defined in

[utils/result.ts:74](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/result.ts#L74)

___

### formatKeyDerivationPath

▸ **formatKeyDerivationPath**(`«destructured»`): [`Result`](README.md#result)<[`IKeyDerivationPathData`](interfaces/IKeyDerivationPathData.md)\>

Formats and returns the provided derivation path string and object.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `addressType?` | [`EAddressType`](enums/EAddressType.md) |
| › `changeAddress?` | `boolean` |
| › `index?` | `string` |
| › `network` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |
| › `path` | `string` \| [`IKeyDerivationPath`](interfaces/IKeyDerivationPath.md) |
| › `purpose?` | `string` |

#### Returns

[`Result`](README.md#result)<[`IKeyDerivationPathData`](interfaces/IKeyDerivationPathData.md)\>

Derivation Path Data

#### Defined in

[utils/wallet.ts:69](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L69)

___

### formatPeerData

▸ **formatPeerData**(`data`): [`Result`](README.md#result)<[`IFormattedPeerData`](interfaces/IFormattedPeerData.md)\>

Formats the peer data response from an Electrum server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `data` | [`string`, `string`, [`string`, `string`, `string`]] |

#### Returns

[`Result`](README.md#result)<[`IFormattedPeerData`](interfaces/IFormattedPeerData.md)\>

Result<IFormattedPeerData>

#### Defined in

[utils/electrum.ts:59](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/electrum.ts#L59)

___

### generateMnemonic

▸ **generateMnemonic**(`strength?`, `rng?`, `wordlist?`): `string`

Extends bip39's generateMnemonic function.

#### Parameters

| Name | Type |
| :------ | :------ |
| `strength?` | `number` |
| `rng?` | (`size`: `number`) => `Buffer` |
| `wordlist?` | `string`[] |

#### Returns

`string`

#### Defined in

[utils/helpers.ts:152](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/helpers.ts#L152)

___

### getAddressFromScriptPubKey

▸ **getAddressFromScriptPubKey**(`scriptPubKey`, `selectedNetwork`): `string`

Get address for a given scriptPubKey.

#### Parameters

| Name | Type |
| :------ | :------ |
| `scriptPubKey` | `string` |
| `selectedNetwork` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |

#### Returns

`string`

#### Defined in

[utils/helpers.ts:16](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/helpers.ts#L16)

___

### getAddressTypeFromPath

▸ **getAddressTypeFromPath**(`path`): [`Result`](README.md#result)<[`EAddressType`](enums/EAddressType.md)\>

Returns the address type from the specified derivation path.

#### Parameters

| Name | Type |
| :------ | :------ |
| `path` | `string` \| [`IKeyDerivationPath`](interfaces/IKeyDerivationPath.md) |

#### Returns

[`Result`](README.md#result)<[`EAddressType`](enums/EAddressType.md)\>

#### Defined in

[utils/derivation-path.ts:149](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/derivation-path.ts#L149)

___

### getByteCount

▸ **getByteCount**(`inputs`, `outputs`, `message?`): `number`

#### Parameters

| Name | Type |
| :------ | :------ |
| `inputs` | [`TGetByteCountInputs`](README.md#tgetbytecountinputs) |
| `outputs` | [`TGetByteCountOutputs`](README.md#tgetbytecountoutputs) |
| `message?` | `string` |

#### Returns

`number`

#### Defined in

[utils/transaction.ts:172](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/transaction.ts#L172)

___

### getDataFallback

▸ **getDataFallback**<`K`\>(`key`): `Promise`<[`Result`](README.md#result)<[`IWalletData`](interfaces/IWalletData.md)[`K`]\>\>

#### Type parameters

| Name | Type |
| :------ | :------ |
| `K` | extends keyof [`IWalletData`](interfaces/IWalletData.md) |

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |

#### Returns

`Promise`<[`Result`](README.md#result)<[`IWalletData`](interfaces/IWalletData.md)[`K`]\>\>

#### Defined in

[types/wallet.ts:159](https://github.com/synonymdev/beignet/blob/8f99086/src/types/wallet.ts#L159)

___

### getDefaultPort

▸ **getDefaultPort**(`selectedNetwork?`, `protocol?`): `number`

Returns the default port for the given network and protocol.

#### Parameters

| Name | Type |
| :------ | :------ |
| `selectedNetwork?` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |
| `protocol?` | [`TProtocol`](README.md#tprotocol) |

#### Returns

`number`

#### Defined in

[utils/electrum.ts:22](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/electrum.ts#L22)

___

### getDefaultWalletData

▸ **getDefaultWalletData**(): [`IWalletData`](interfaces/IWalletData.md)

Returns the default wallet data object.

#### Returns

[`IWalletData`](interfaces/IWalletData.md)

#### Defined in

[utils/wallet.ts:28](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L28)

___

### getDefaultWalletDataKeys

▸ **getDefaultWalletDataKeys**(): keyof [`IWalletData`](interfaces/IWalletData.md)[]

Returns the keys from the default wallet data object.

#### Returns

keyof [`IWalletData`](interfaces/IWalletData.md)[]

#### Defined in

[utils/wallet.ts:36](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L36)

___

### getExchangeRates

▸ **getExchangeRates**(): `Promise`<[`Result`](README.md#result)<[`IExchangeRates`](interfaces/IExchangeRates.md)\>\>

Returns the exchange rate for the given currency

#### Returns

`Promise`<[`Result`](README.md#result)<[`IExchangeRates`](interfaces/IExchangeRates.md)\>\>

#### Defined in

[utils/exchange-rate.ts:45](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/exchange-rate.ts#L45)

___

### getHighestUsedIndexFromTxHashes

▸ **getHighestUsedIndexFromTxHashes**(`«destructured»`): [`Result`](README.md#result)<[`IIndexes`](interfaces/IIndexes.md)\>

Returns the highest used index from the provided txHashes.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `addressIndex` | [`IAddress`](interfaces/IAddress.md) |
| › `addresses` | [`IAddresses`](interfaces/IAddresses.md) |
| › `changeAddressIndex` | [`IAddress`](interfaces/IAddress.md) |
| › `changeAddresses` | [`IAddresses`](interfaces/IAddresses.md) |
| › `txHashes` | [`ITxHashes`](interfaces/ITxHashes.md)[] |

#### Returns

[`Result`](README.md#result)<[`IIndexes`](interfaces/IIndexes.md)\>

#### Defined in

[utils/wallet.ts:129](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L129)

___

### getKeyDerivationPath

▸ **getKeyDerivationPath**(`«destructured»`): [`Result`](README.md#result)<[`IKeyDerivationPath`](interfaces/IKeyDerivationPath.md)\>

Returns the derivation path object for the specified addressType and network.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `addressType` | [`EAddressType`](enums/EAddressType.md) |
| › `network?` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |

#### Returns

[`Result`](README.md#result)<[`IKeyDerivationPath`](interfaces/IKeyDerivationPath.md)\>

Result<IKeyDerivationPath>

#### Defined in

[utils/helpers.ts:98](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/helpers.ts#L98)

___

### getKeyDerivationPathObject

▸ **getKeyDerivationPathObject**(`«destructured»`): [`Result`](README.md#result)<[`IKeyDerivationPath`](interfaces/IKeyDerivationPath.md)\>

Parses a key derivation path in string format Ex: "m/84'/0'/0'/0/0" and returns IKeyDerivationPath.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `changeAddress?` | `boolean` |
| › `index?` | `string` |
| › `network?` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |
| › `path` | `string` |
| › `purpose?` | `string` |

#### Returns

[`Result`](README.md#result)<[`IKeyDerivationPath`](interfaces/IKeyDerivationPath.md)\>

#### Defined in

[utils/derivation-path.ts:22](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/derivation-path.ts#L22)

___

### getKeyDerivationPathString

▸ **getKeyDerivationPathString**(`«destructured»`): [`Result`](README.md#result)<`string`\>

Parses a key derivation path object and returns it in string format. Ex: "m/84'/0'/0'/0/0"

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `accountType?` | `string` \| `number` |
| › `addressType` | [`EAddressType`](enums/EAddressType.md) |
| › `changeAddress?` | `boolean` |
| › `index?` | `string` \| `number` |
| › `network` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |
| › `path?` | [`IKeyDerivationPath`](interfaces/IKeyDerivationPath.md) |
| › `purpose?` | `string` |

#### Returns

[`Result`](README.md#result)<`string`\>

#### Defined in

[utils/derivation-path.ts:81](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/derivation-path.ts#L81)

___

### getKeyValue

▸ **getKeyValue**(`key`): `string`

Returns last value between hyphens in a string.

#### Parameters

| Name | Type |
| :------ | :------ |
| `key` | `string` |

#### Returns

`string`

#### Defined in

[utils/wallet.ts:45](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L45)

___

### getPeers

▸ **getPeers**(`selectedNetwork?`): `Promise`<[`Result`](README.md#result)<[`IFormattedPeerData`](interfaces/IFormattedPeerData.md)[]\>\>

Returns an array of peers.
If unable to acquire peers from an Electrum server the method will default to the hardcoded peers in peers.json.

#### Parameters

| Name | Type |
| :------ | :------ |
| `selectedNetwork?` | `Object` |
| `selectedNetwork.selectedNetwork` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |

#### Returns

`Promise`<[`Result`](README.md#result)<[`IFormattedPeerData`](interfaces/IFormattedPeerData.md)[]\>\>

Promise<Result<IFormattedPeerData[]>>

#### Defined in

[utils/electrum.ts:96](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/electrum.ts#L96)

___

### getProtocolForPort

▸ **getProtocolForPort**(`port?`, `network?`): `undefined` \| [`TProtocol`](README.md#tprotocol)

Returns the protocol for the given network and default port.

#### Parameters

| Name | Type |
| :------ | :------ |
| `port?` | `string` |
| `network?` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |

#### Returns

`undefined` \| [`TProtocol`](README.md#tprotocol)

#### Defined in

[utils/electrum.ts:39](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/electrum.ts#L39)

___

### getScriptHash

▸ **getScriptHash**(`«destructured»`): `string`

Get scriptHash for a given address

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `address` | `string` |
| › `network` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |

#### Returns

`string`

#### Defined in

[utils/helpers.ts:127](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/helpers.ts#L127)

___

### getSha256

▸ **getSha256**(`str`): `string`

Get sha256 hash of a given string.

#### Parameters

| Name | Type |
| :------ | :------ |
| `str` | `string` |

#### Returns

`string`

#### Defined in

[utils/helpers.ts:32](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/helpers.ts#L32)

___

### isValidBech32mEncodedString

▸ **isValidBech32mEncodedString**(`address`): `Object`

Returns if the provided string is a valid Bech32m encoded string (taproot/p2tr address).

#### Parameters

| Name | Type |
| :------ | :------ |
| `address` | `string` |

#### Returns

`Object`

| Name | Type |
| :------ | :------ |
| `isValid` | `boolean` |
| `network` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |

#### Defined in

[utils/wallet.ts:182](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L182)

___

### objectKeys

▸ **objectKeys**<`Type`\>(`value`): \`${Exclude<keyof Type, symbol\>}\`[]

Returns the keys of a given object.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Type` | extends `object` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `value` | `Type` |

#### Returns

\`${Exclude<keyof Type, symbol\>}\`[]

#### Defined in

[utils/wallet.ts:56](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L56)

___

### ok

▸ **ok**<`T`\>(`value`): `Ok`<`T`\>

Construct a new Ok result value.

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `value` | `T` | The value to be wrapped in an Ok result. |

#### Returns

`Ok`<`T`\>

An Ok result containing the given value.

#### Defined in

[utils/result.ts:67](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/result.ts#L67)

___

### parseOnChainPaymentRequest

▸ **parseOnChainPaymentRequest**(`data`, `network?`): [`Result`](README.md#result)<{ `address`: `string` ; `message`: `string` ; `network`: [`EAvailableNetworks`](enums/EAvailableNetworks.md) ; `sats`: `number`  }\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `data` | `string` |
| `network?` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |

#### Returns

[`Result`](README.md#result)<{ `address`: `string` ; `message`: `string` ; `network`: [`EAvailableNetworks`](enums/EAvailableNetworks.md) ; `sats`: `number`  }\>

#### Defined in

[utils/transaction.ts:60](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/transaction.ts#L60)

___

### reduceValue

▸ **reduceValue**<`T`\>(`«destructured»`): [`Result`](README.md#result)<`number`\>

Sum a specific value in an array of objects.

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `arr` | `T`[] |
| › `value` | keyof `T` |

#### Returns

[`Result`](README.md#result)<`number`\>

#### Defined in

[utils/wallet.ts:213](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L213)

___

### removeDustOutputs

▸ **removeDustOutputs**(`outputs`): [`IOutput`](interfaces/IOutput.md)[]

Removes outputs that are below the dust limit.

#### Parameters

| Name | Type |
| :------ | :------ |
| `outputs` | [`IOutput`](interfaces/IOutput.md)[] |

#### Returns

[`IOutput`](interfaces/IOutput.md)[]

#### Defined in

[utils/transaction.ts:284](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/transaction.ts#L284)

___

### setReplaceByFee

▸ **setReplaceByFee**(`«destructured»`): `void`

Sets RBF for the provided psbt.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `psbt` | `Psbt` |
| › `setRbf` | `boolean` |

#### Returns

`void`

#### Defined in

[utils/transaction.ts:24](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/transaction.ts#L24)

___

### shuffleArray

▸ **shuffleArray**<`T`\>(`array`): `T`[]

Shuffles a given array.

#### Type parameters

| Name |
| :------ |
| `T` |

#### Parameters

| Name | Type |
| :------ | :------ |
| `array` | `T`[] |

#### Returns

`T`[]

#### Defined in

[utils/wallet.ts:241](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/wallet.ts#L241)

___

### validateAddress

▸ **validateAddress**(`«destructured»`): `Object`

Validate address for a given network.
If no address is provided, it will attempt to validate the address for all available networks.

#### Parameters

| Name | Type |
| :------ | :------ |
| `«destructured»` | `Object` |
| › `address` | `string` |
| › `network?` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |

#### Returns

`Object`

| Name | Type |
| :------ | :------ |
| `isValid` | `boolean` |
| `network` | [`EAvailableNetworks`](enums/EAvailableNetworks.md) |

#### Defined in

[utils/helpers.ts:45](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/helpers.ts#L45)

___

### validateMnemonic

▸ **validateMnemonic**(`mnemonic?`): `boolean`

Attempts to validate the provided mnemonic.

#### Parameters

| Name | Type | Default value |
| :------ | :------ | :------ |
| `mnemonic` | `string` | `''` |

#### Returns

`boolean`

#### Defined in

[utils/helpers.ts:165](https://github.com/synonymdev/beignet/blob/8f99086/src/utils/helpers.ts#L165)