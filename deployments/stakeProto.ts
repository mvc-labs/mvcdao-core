import UniqueProto = require('./uniqueProto');
import Common = require('./common');
import { mvc } from "mvc-scrypt"

function toBigIntLE(buf: Buffer) {
    const reversed = Buffer.from(buf);
    reversed.reverse();
    const hex = reversed.toString('hex');
    if (hex.length === 0) {
        return BigInt(0);
    }
    return BigInt(`0x${hex}`);
}

function toBufferLE(num: bigint, width: number) {
    const hex = num.toString(16);
    const buffer = Buffer.from(hex.padStart(width * 2, '0').slice(0, width * 2), 'hex');
    buffer.reverse();
    return buffer;
}

export class StakeInfo {
    rewardAmountFactor: bigint
    rewardBeginTime: number
    rewardEndTime: number
    withdrawLockInterval: number
    rewardAmountPerSecond: bigint
    lastRewardTime: number
    poolTokenAmount: bigint
    unlockingPoolTokenAmount: bigint
    accPoolPerShare: bigint
    userDataMerkleRoot: Buffer

    constructor() {
        this.rewardAmountFactor = BigInt(0)
        this.withdrawLockInterval = 0
        this.rewardAmountPerSecond = BigInt(0)
        this.lastRewardTime = 0
        this.poolTokenAmount = BigInt(0)
        this.unlockingPoolTokenAmount = BigInt(0)
        this.accPoolPerShare = BigInt(0)
        this.userDataMerkleRoot = Buffer.alloc(0)
    }
}

const OP_PUSH_DATA_LEN = 3
const REWARD_AMOUNT_FACTOR_LEN = 8
const WITHDRAW_LOCK_INTERVAL_LEN = 4
const REWARD_AMOUNT_PER_SECOND_LEN = 8
const TIMESTAMP_LEN = 4
const POOL_TOKEN_AMOUNT_LEN = 8
export const ACC_POOL_PER_SHARE_LEN = 16
const USER_DATA_MERKLE_ROOT_LEN = 32
const BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_LEN = 20
const CONTRACT_HASH_LEN = 20
const CONTRACT_HASH_ROOT_LEN = 20
const OWNER_ADDRESS_LEN = 20

const HASH_MERKLE_ROOT_OFFSET = UniqueProto.FIX_HEADER_LEN + CONTRACT_HASH_ROOT_LEN;
const STAKE_REWARD_TOKEN_HOLDER_HASH_OFFSET = HASH_MERKLE_ROOT_OFFSET + CONTRACT_HASH_LEN;
const STAKE_TOKEN_HOLDER_HASH_OFFSET = STAKE_REWARD_TOKEN_HOLDER_HASH_OFFSET + CONTRACT_HASH_LEN;
const BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET = STAKE_TOKEN_HOLDER_HASH_OFFSET + BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_LEN;
const USER_DATA_MERKLE_ROOT_OFFSET = BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET + USER_DATA_MERKLE_ROOT_LEN;
const ACC_POOL_PER_SHARE_OFFSET = USER_DATA_MERKLE_ROOT_OFFSET + ACC_POOL_PER_SHARE_LEN;
const UNLOCKING_POOL_TOKEN_AMOUNT_OFFSET = ACC_POOL_PER_SHARE_OFFSET + POOL_TOKEN_AMOUNT_LEN;
const POOL_TOKEN_AMOUNT_OFFSET = UNLOCKING_POOL_TOKEN_AMOUNT_OFFSET + POOL_TOKEN_AMOUNT_LEN;
const LAST_REWARD_BLOCK_OFFSET = POOL_TOKEN_AMOUNT_OFFSET + TIMESTAMP_LEN;
const REWARD_AMOUNT_PER_SECOND_OFFSET = LAST_REWARD_BLOCK_OFFSET + REWARD_AMOUNT_PER_SECOND_LEN;
const WITHDRAW_LOCK_INTERVAL_OFFSET = REWARD_AMOUNT_PER_SECOND_OFFSET + WITHDRAW_LOCK_INTERVAL_LEN
const REWARD_END_TIME_OFFSET = WITHDRAW_LOCK_INTERVAL_OFFSET + TIMESTAMP_LEN
const REWARD_BEGIN_TIME_OFFSET = REWARD_END_TIME_OFFSET + TIMESTAMP_LEN
const REWARD_AMOUNT_FACTOR_OFFSET = REWARD_BEGIN_TIME_OFFSET + REWARD_AMOUNT_FACTOR_LEN 
const OWNER_ADDRESS_OFFSET = REWARD_AMOUNT_FACTOR_OFFSET + OWNER_ADDRESS_LEN

const DATA_OFFSET = OWNER_ADDRESS_OFFSET

export const CUSTOM_DATA_LEN = DATA_OFFSET - UniqueProto.FIX_HEADER_LEN

export const STAKE_UNLOCK_FROM_CONTRACT = 1
export const STAKE_UNLOCK_FROM_ADMIN = 2

export const OP_UPDATE_CONTRACT = 0
export const OP_DEPOSIT = 1
export const OP_WITHDRAW = 2
export const OP_PRE_WITHDRAW = 3
export const OP_FINISH_WITHDRAW = 4
export const OP_HARVEST = 5
export const OP_ADMIN = 6
export const OP_VOTE = 7
export const OP_MERGE = 1000

export const OP_PRE_WITHDRAW2 = 21
export const OP_FINISH_WITHDRAW2 = 31
export const OP_HARVEST2 = 41
export const OP_ADMIN2 = 51
export const OP_VOTE2 = 61

export const OP_CREATE_VOTE = 5000

export const TREE_HEIGHT = 25

export const getDataLen = function() {
    return DATA_OFFSET
}

export const getOwnerAddress = function (script: Buffer) {
    return script.subarray(script.length - OWNER_ADDRESS_OFFSET, script.length - OWNER_ADDRESS_OFFSET + OWNER_ADDRESS_LEN)
}

export const getRewardAmountFactor = function (script: Buffer) {
    return script.readBigUInt64LE(script.length - REWARD_AMOUNT_FACTOR_OFFSET)
}

export const getRewardBeginTime = function (script: Buffer) {
    return script.readUInt32LE(script.length - REWARD_BEGIN_TIME_OFFSET)
}

export const getRewardEndTime = function (script: Buffer) {
    return script.readUInt32LE(script.length - REWARD_END_TIME_OFFSET)
}

export const getWithdrawLockInterval = function (script: Buffer) {
    return script.readUInt32LE(script.length - WITHDRAW_LOCK_INTERVAL_OFFSET)
}

export const getRewardAmountPerSecond = function (script: Buffer) {
    return script.readBigUInt64LE(script.length - REWARD_AMOUNT_PER_SECOND_OFFSET)
}

export const getLastRewardBlock = function (script: Buffer) {
    return script.readUInt32LE(script.length - LAST_REWARD_BLOCK_OFFSET)
}

export const getPoolTokenAmount = function (script: Buffer) {
    return script.readBigUInt64LE(script.length - POOL_TOKEN_AMOUNT_OFFSET)
}

export const getUnlockingPoolTokenAmount = function (script: Buffer) {
    return script.readBigUInt64LE(script.length - UNLOCKING_POOL_TOKEN_AMOUNT_OFFSET)
}

export const getAccPoolPerShare = function (script: Buffer) {
    const buf = script.subarray(script.length - ACC_POOL_PER_SHARE_OFFSET, script.length - ACC_POOL_PER_SHARE_OFFSET + ACC_POOL_PER_SHARE_LEN)
    return toBigIntLE(buf)
}

export const getUserDataMerkleRoot = function (script: Buffer) {
    return script.subarray(script.length - USER_DATA_MERKLE_ROOT_OFFSET, script.length - USER_DATA_MERKLE_ROOT_OFFSET + USER_DATA_MERKLE_ROOT_LEN)
}

export const getBlockNumRabinPubKeyHashArrayHash = function (script: Buffer) {
    return script.subarray(script.length - BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET, script.length - BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET + BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_LEN)
}

export const getStakeTokenHolderHash = function (script: Buffer) {
    return script.subarray(script.length - STAKE_TOKEN_HOLDER_HASH_OFFSET, script.length - STAKE_TOKEN_HOLDER_HASH_OFFSET + CONTRACT_HASH_LEN)
}

export const getStakeRewardTokenHolderHash = function (script: Buffer) {
    return script.subarray(script.length - STAKE_REWARD_TOKEN_HOLDER_HASH_OFFSET, script.length - STAKE_REWARD_TOKEN_HOLDER_HASH_OFFSET + CONTRACT_HASH_LEN)
}

export const getStakeInfo = function (script: Buffer) {
    const info: any = {}
    info.rewardAmountFactor = getRewardAmountFactor(script)
    info.withdrawLockInterval = getWithdrawLockInterval(script)
    info.rewardAmountPerSecond = getRewardAmountPerSecond(script);
    info.lastRewardTime = getLastRewardBlock(script);
    info.poolTokenAmount = getPoolTokenAmount(script);
    info.unlockingPoolTokenAmount = getUnlockingPoolTokenAmount(script)
    info.accPoolPerShare = getAccPoolPerShare(script);
    info.userDataMerkleRoot = getUserDataMerkleRoot(script);
    return info;
}

export const getNewStakeScript = function (script: Buffer, lastRewardTime: number, poolTokenAmount: bigint, unlockingPoolTokenAmount, accPoolPerShare: bigint, userDataMerkleRoot: Buffer) {
    return Buffer.concat([
        script.subarray(0, script.length - LAST_REWARD_BLOCK_OFFSET),
        Common.getUInt32Buf(lastRewardTime),
        Common.getUInt64Buf(poolTokenAmount),
        Common.getUInt64Buf(unlockingPoolTokenAmount),
        toBufferLE(accPoolPerShare, ACC_POOL_PER_SHARE_LEN),
        userDataMerkleRoot,
        script.subarray(script.length - USER_DATA_MERKLE_ROOT_OFFSET + USER_DATA_MERKLE_ROOT_LEN)
    ])
}

export const getNewStakeScript2 = function (script: Buffer, rewardAmountPerSecond: bigint, lastRewardTime: number, poolTokenAmount: bigint, unlockingPoolTokenAmount: bigint, accPoolPerShare: bigint, userDataMerkleRoot: Buffer) {
    return Buffer.concat([
        script.subarray(0, script.length - REWARD_AMOUNT_PER_SECOND_OFFSET),
        Common.getUInt64Buf(rewardAmountPerSecond),
        Common.getUInt32Buf(lastRewardTime),
        Common.getUInt64Buf(poolTokenAmount),
        Common.getUInt64Buf(unlockingPoolTokenAmount),
        toBufferLE(accPoolPerShare, ACC_POOL_PER_SHARE_LEN),
        userDataMerkleRoot,
        script.subarray(script.length - USER_DATA_MERKLE_ROOT_OFFSET + USER_DATA_MERKLE_ROOT_LEN)
    ])
}

export const getNewStakeScriptFromAdmin = function (script: Buffer, rewardAmountPerSecond: bigint, lastRewardTime: number, withdrawLockInterval: number) {
    return Buffer.concat([
        script.subarray(0, script.length - WITHDRAW_LOCK_INTERVAL_OFFSET),
        Common.getUInt32Buf(withdrawLockInterval),
        Common.getUInt64Buf(rewardAmountPerSecond),
        Common.getUInt32Buf(lastRewardTime),
        script.subarray(script.length - LAST_REWARD_BLOCK_OFFSET + TIMESTAMP_LEN)
    ])
}

export const getNewStakeScriptFromContractHashRoot = function (script: Buffer, contractHashRoot: Buffer) {
    return Buffer.concat([
        script.subarray(0, script.length - HASH_MERKLE_ROOT_OFFSET),
        contractHashRoot,
        script.subarray(script.length - HASH_MERKLE_ROOT_OFFSET + CONTRACT_HASH_ROOT_LEN)
    ])
} 

export const getContractCode = function(scriptBuf) {
  const dataLen = getDataLen()
  return scriptBuf.subarray(0, scriptBuf.length - dataLen - 2)
}

export const getContractCodeHash = function(scriptBuf) {
  return mvc.crypto.Hash.sha256ripemd160(getContractCode(scriptBuf))
}