import ProtoHeader = require('./protoheader')
import { mvc } from "mvc-scrypt"
import Common = require('./common')

export const PROTO_TYPE = 2
export const PROTO_VERSION = 1

export const CUSTOM_DATA_SIZE_LEN = 4

export const GENESISTX_ID_OFFSET = ProtoHeader.PROTO_HEADER_OFFSET + ProtoHeader.GENESIS_TXID_LEN;

export const CUSTOM_DATA_SIZE_OFFSET = GENESISTX_ID_OFFSET + CUSTOM_DATA_SIZE_LEN;

export const FIX_HEADER_LEN = CUSTOM_DATA_SIZE_OFFSET;

export function getGenesisTxid(scriptBuf: Buffer) {
    return scriptBuf.subarray(scriptBuf.length - GENESISTX_ID_OFFSET, scriptBuf.length - GENESISTX_ID_OFFSET + ProtoHeader.GENESIS_TXID_LEN)
}

export function getUniqueID(scriptBuf: Buffer) {
    return mvc.crypto.Hash.sha256ripemd160(getGenesisTxid(scriptBuf))
}

export function getCustomDataLen(scriptBuf: Buffer) {
    return scriptBuf.readUInt32LE(scriptBuf.length - CUSTOM_DATA_SIZE_OFFSET)
}

export function getCustomData(scriptBuf: Buffer) {
    const dataLen = getCustomDataLen(scriptBuf)
    return scriptBuf.subarray(scriptBuf.length - dataLen - FIX_HEADER_LEN, scriptBuf.length - FIX_HEADER_LEN)
}

export function getDataLen(scriptBuf: Buffer) {
    const rawDataLen = getCustomDataLen(scriptBuf) + FIX_HEADER_LEN 
    return rawDataLen + Common.getOpPushDataLen(rawDataLen)
}

export function getScriptData(scriptBuf: Buffer) {
    const dataLen = getDataLen(scriptBuf)
    return scriptBuf.subarray(scriptBuf.length - dataLen, scriptBuf.length)
}

export function getScriptRawData(scriptBuf: Buffer) {
    const rawDataLen = getCustomDataLen(scriptBuf) + FIX_HEADER_LEN
    return scriptBuf.subarray(scriptBuf.length - rawDataLen, scriptBuf.length)
}

export function getScriptCode(scriptBuf: Buffer) {
    const dataLen = getDataLen(scriptBuf)
    return scriptBuf.subarray(0, scriptBuf.length - dataLen)
}

export function getScriptCodeHash(scriptBuf: Buffer) {
    const code = getScriptCode(scriptBuf)
    return mvc.crypto.Hash.sha256ripemd160(code)
}
