[beignet](../README.md) / ITransaction

# Interface: ITransaction<T\>

## Type parameters

| Name |
| :------ |
| `T` |

## Table of contents

### Properties

- [data](ITransaction.md#data)
- [error](ITransaction.md#error)
- [id](ITransaction.md#id)
- [jsonrpc](ITransaction.md#jsonrpc)
- [param](ITransaction.md#param)
- [result](ITransaction.md#result)

## Properties

### data

• **data**: `T`

#### Defined in

[types/wallet.ts:338](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/wallet.ts#L338)

___

### error

• `Optional` **error**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `code` | `number` |
| `message` | `string` |

#### Defined in

[types/wallet.ts:340](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/wallet.ts#L340)

___

### id

• **id**: `number`

#### Defined in

[types/wallet.ts:335](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/wallet.ts#L335)

___

### jsonrpc

• **jsonrpc**: `string`

#### Defined in

[types/wallet.ts:336](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/wallet.ts#L336)

___

### param

• **param**: `string`

#### Defined in

[types/wallet.ts:337](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/wallet.ts#L337)

___

### result

• **result**: [`TTxDetails`](../README.md#ttxdetails)

#### Defined in

[types/wallet.ts:339](https://github.com/coreyphillips/beignet/blob/e43f953/src/types/wallet.ts#L339)
