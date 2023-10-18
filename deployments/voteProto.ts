import UniqueProto = require('./uniqueProto')

export const OP_STAKE_VOTE = 0

// opreturn: ownerAddress(20 bytes) + minVoteAmount<8 bytes> + beginBlockTime<4 bytes> + endBlockTime<4 bytes> + userDataMerkleRoot<20 bytes> + voteDataHashRoot<20 bytes> + blockHeightRabinPubKeyHashArrayHash<20 bytes> + contractHashRoot<20 bytes>

const OWNER_ADDRESS_LEN = 20
const MIN_VOTE_AMOUNT_LEN = 8
const BLOCK_NUM_LEN = 4
const USER_DATA_MERKLE_ROOT_LEN = 20
const VOTE_DATA_HASH_ROOT_LEN = 20
const BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_LEN = 20
const CONTRACT_HASH_ROOT_LEN = 20

const CONTRACT_HASH_ROOT_OFFSET = UniqueProto.FIX_HEADER_LEN + CONTRACT_HASH_ROOT_LEN;
const BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET = CONTRACT_HASH_ROOT_OFFSET + BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_LEN;
const VOTE_DATA_HASH_ROOT_OFFSET = BLOCK_HEIGHT_RABIN_PUBKEY_HASH_ARRAY_HASH_OFFSET + VOTE_DATA_HASH_ROOT_LEN
const USER_DATA_MERKLE_ROOT_OFFSET = VOTE_DATA_HASH_ROOT_OFFSET + USER_DATA_MERKLE_ROOT_LEN;
const END_BLOCK_NUM_OFFSET = USER_DATA_MERKLE_ROOT_OFFSET + BLOCK_NUM_LEN
const BEGIN_BLOCK_NUM_OFFSET = END_BLOCK_NUM_OFFSET + BLOCK_NUM_LEN
const MIN_VOTE_AMOUNT_OFFSET = BEGIN_BLOCK_NUM_OFFSET + MIN_VOTE_AMOUNT_LEN
const OWNER_ADDRESS_OFFSET = MIN_VOTE_AMOUNT_OFFSET + OWNER_ADDRESS_LEN

const DATA_OFFSET = OWNER_ADDRESS_OFFSET
export const CUSTOM_DATA_LEN = DATA_OFFSET - UniqueProto.FIX_HEADER_LEN

export function getNewVoteScript(script: Buffer, userDataMerkleRoot: Buffer, voteDataHashRoot: Buffer) {
    return Buffer.concat([
        script.subarray(0, script.length - USER_DATA_MERKLE_ROOT_OFFSET),
        userDataMerkleRoot,
        voteDataHashRoot,
        script.subarray(script.length - VOTE_DATA_HASH_ROOT_OFFSET + VOTE_DATA_HASH_ROOT_LEN)
    ])
}

export function getUserDataMerkleRoot(script: Buffer) {
    return script.subarray(script.length - USER_DATA_MERKLE_ROOT_OFFSET, script.length - USER_DATA_MERKLE_ROOT_OFFSET + USER_DATA_MERKLE_ROOT_LEN)
}

export function getSumDataHashRoot(script: Buffer) {
    return script.subarray(script.length - VOTE_DATA_HASH_ROOT_OFFSET, script.length - VOTE_DATA_HASH_ROOT_OFFSET + VOTE_DATA_HASH_ROOT_LEN)
}