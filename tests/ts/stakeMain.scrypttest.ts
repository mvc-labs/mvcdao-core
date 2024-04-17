import { expect } from 'chai';
import { mvc, Bytes, getPreimage, toHex, Ripemd160, SigHashPreimage, PubKey, Sig, signTx, buildTypeClasses } from 'mvc-scrypt'
import { StakePool } from "../../deployments/stakePool";
import StakeProto  = require('../../deployments/stakeProto')
import { LeafNode, MerkleTreeData } from '../../deployments/stakeMerkleTree';
import { dummyTxId } from '../../scrypt_helper'

import { privateKey, privateKey2, privateKey3 } from '../../privateKey';
import Rabin = require('../../rabin/rabin')

import Proto = require('../../deployments/protoheader')
import TokenProto = require('../../deployments/tokenProto')
import Common = require('../../deployments/common')
import UniqueProto = require('../../deployments/uniqueProto')
import VoteProto = require('../../deployments/voteProto')
import { VoteDataTree } from '../../deployments/voteDataTree'
import { RabinUtils } from './rabinUtil';
import { createInputTx, unlockStakeMain, unlockUpdateContract, getTxOutputProofScrypt, getEmptyTxOutputProofScrypt } from './stakeTestHelper';
import { inputSatoshis } from '../../scrypt_helper'

const tokenName = Buffer.alloc(40, 0)
tokenName.write('test token')
const tokenSymbol = Buffer.alloc(20, 0)
tokenSymbol.write('ttn')

const adminPrivKey = privateKey3
const adminAddress = adminPrivKey.toAddress()
const adminPubKey = adminPrivKey.publicKey

const ownerPrivKey = privateKey
const ownerAddress = ownerPrivKey.toAddress()

const uniqueType = Common.getUInt32Buf(UniqueProto.PROTO_TYPE)
const uniqueVersion = Common.getUInt32Buf(UniqueProto.PROTO_VERSION)

const rewardTokenName = Buffer.alloc(40, 0)
rewardTokenName.write('test reward token')
const rewardTokenSymbol = Buffer.alloc(20, 0)
rewardTokenSymbol.write('trt')

const decimalNum = Common.getUInt8Buf(8)
const rewardAmountPerSecond = BigInt(100000000)
const rewardAmountFactor = BigInt(10000000000000000)
const withdrawLockInterval = 100
const minVoteAmount = BigInt(10000)

const address1 = privateKey.toAddress()
const address2 = privateKey2.toAddress()
const sigtype = mvc.crypto.Signature.SIGHASH_ALL | mvc.crypto.Signature.SIGHASH_FORKID

const blockHeightRabinPubKeyArray = RabinUtils.rabinPubKeyArray
const blockHeightRabinPubKeyHashArrayHash = RabinUtils.rabinPubKeyHashArrayHash
const blockHeightRabinPubKeyHashArray = RabinUtils.rabinPubKeyHashArray
const blockHeightRabinPubKeyIndexArray = RabinUtils.rabinPubKeyIndexArray
const blockHeightRabinPubKeyVerifyArray = RabinUtils.rabinPubKeyVerifyArray

const genContract = Common.genContract
const addInput = Common.addInput
const addOutput = Common.addOutput
const USE_DESC = false
const USE_RELEASE = false

const StakeMain = genContract('stake/stakeMain', USE_DESC, USE_RELEASE)
const StakeUpdateContract = genContract('stake/stakeUpdateContract', USE_DESC, USE_RELEASE)
const StakeDeposit = genContract('stake/stakeDeposit', USE_DESC, USE_RELEASE)
const StakeDepositMvc = genContract('stake/stakeDepositMvc', USE_DESC, USE_RELEASE)
const StakeWithdraw = genContract('stake/stakeWithdraw', USE_DESC, USE_RELEASE)
const StakeWithdrawMvc = genContract('stake/stakeWithdrawMvc', USE_DESC, USE_RELEASE)
const StakePreWithdraw = genContract('stake/stakePreWithdraw', USE_DESC, USE_RELEASE)
const StakeFinishWithdraw = genContract('stake/stakeFinishWithdraw', USE_DESC, USE_RELEASE)
const StakeFinishWithdrawMvc = genContract('stake/stakeFinishWithdrawMvc', USE_DESC, USE_RELEASE)
const StakeHarvest = genContract('stake/stakeHarvest', USE_DESC, USE_RELEASE)
const StakeAdmin = genContract('stake/stakeAdmin', USE_DESC, USE_RELEASE)
const StakeVote = genContract('stake/stakeVote', USE_DESC, USE_RELEASE)
const VoteMain = genContract('stake/voteMain', USE_DESC, USE_RELEASE)
const StakeMergeRewardToken = genContract('stake/stakeMergeRewardToken', USE_DESC, USE_RELEASE)
const StakeTokenHolder = genContract('stake/stakeTokenHolder', USE_DESC, USE_RELEASE)
const StakeRewardTokenHolder = genContract('stake/stakeRewardTokenHolder', USE_DESC, USE_RELEASE)
const Token = genContract('token/token', true, false)
const UnlockContractCheck = genContract('tokenUnlockContractCheck', true, false)

const jsonDescr = Common.loadDescription('../out/stakeDeposit_release_desc.json');
export const { TxInputProof, TxOutputProof, BlockRabinData } = buildTypeClasses(jsonDescr);

const rewardBeginTime = 100
const rewardEndTime = 100000000

let tokenSensibleID, rewardTokenSensibleID, stakeSensibleID, voteSensibleID, tokenCodeHash, rewardTokenCodeHash
let tokenID, rewardTokenID, stakeID

let transferCheckCodeHashArray, unlockContractCodeHashArray, genesisHash
let stakeUpdateContractCodeHash, stakeDepositCodeHash, stakeWithdrawCodeHash, stakePreWithdrawCodeHash, stakeFinishWithdrawCodeHash, stakeHarvestCodeHash, stakeTokenHolderHash, stakeRewardTokenHolderHash, stakeMainCodeHash, stakeAdminCodeHash, stakeVoteCodeHash,stakeMergeRewardTokenCodeHash, voteMainCodeHash, stakeDepositMvcCodeHash, stakeWithdrawMvcCodeHash, stakeFinishWithdrawMvcCodeHash

let contractHashRoot, contractHashArray
let voteContractHashRoot, voteContractHashArray
let voteUserDataMerkleTree

function getCodeHash(scriptCodeBuf: Buffer) {
    return mvc.crypto.Hash.sha256ripemd160(Buffer.concat([scriptCodeBuf, Buffer.from('6a', 'hex')])) 
}

function initContractHash() {

    tokenSensibleID = Buffer.concat([
        Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse()),
        Common.getUInt32Buf(11),
    ]).toString('hex')
    rewardTokenSensibleID = Buffer.concat([
        Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse()),
        Common.getUInt32Buf(22),
    ]).toString('hex')
    stakeSensibleID = Buffer.concat([
        Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse()),
        Buffer.alloc(4, 0),
    ]).toString('hex')
    voteSensibleID = Buffer.concat([
        Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse()),
        Common.getUInt32Buf(33),
    ]).toString('hex')

    const transferCheckCodeHash = new Bytes(Buffer.alloc(20, 0).toString('hex'))
    transferCheckCodeHashArray = [transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash]
    unlockContractCodeHashArray = transferCheckCodeHashArray
    genesisHash = Buffer.alloc(20, 0).toString('hex')

    tokenID = mvc.crypto.Hash.sha256ripemd160(Buffer.concat([
        Buffer.from(genesisHash, 'hex'),
        Buffer.from(tokenSensibleID, 'hex')
    ])).toString('hex')
    rewardTokenID = mvc.crypto.Hash.sha256ripemd160(Buffer.concat([
        Buffer.from(genesisHash, 'hex'),
        Buffer.from(rewardTokenSensibleID, 'hex')
    ])).toString('hex')
    stakeID = mvc.crypto.Hash.sha256ripemd160(Buffer.concat([
        Buffer.from(stakeSensibleID, 'hex')
    ])).toString('hex')

    const tokenContract = new Token(transferCheckCodeHashArray, unlockContractCodeHashArray)
    tokenCodeHash = getCodeHash(tokenContract.lockingScript.toBuffer()).toString('hex')
    rewardTokenCodeHash = tokenCodeHash

    const stakeUpdateContract = new StakeUpdateContract(new Bytes(stakeID))
    stakeUpdateContractCodeHash = getCodeHash(stakeUpdateContract.lockingScript.toBuffer()).toString('hex')

    const stakeVote = new StakeVote(new Bytes(stakeID))
    stakeVoteCodeHash = getCodeHash(stakeVote.lockingScript.toBuffer()).toString('hex')

    const stakeDeposit = new StakeDeposit(new Bytes(stakeID), new Bytes(tokenID), new Bytes(tokenCodeHash))
    stakeDepositCodeHash = getCodeHash(stakeDeposit.lockingScript.toBuffer()).toString('hex')

    const stakeDepositMvc = new StakeDepositMvc(new Bytes(stakeID))
    stakeDepositMvcCodeHash = getCodeHash(stakeDepositMvc.lockingScript.toBuffer()).toString('hex')

    const stakeWithdraw = new StakeWithdraw(new Bytes(stakeID), new Bytes(tokenID), new Bytes(tokenCodeHash), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    stakeWithdrawCodeHash = getCodeHash(stakeWithdraw.lockingScript.toBuffer()).toString('hex')

    const stakeWithdrawMvc = new StakeWithdrawMvc(new Bytes(stakeID), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    stakeWithdrawMvcCodeHash = getCodeHash(stakeWithdrawMvc.lockingScript.toBuffer()).toString('hex')

    const stakePreWithdraw = new StakePreWithdraw(new Bytes(stakeID), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    stakePreWithdrawCodeHash = getCodeHash(stakePreWithdraw.lockingScript.toBuffer()).toString('hex')

    const stakeFinishWithdraw = new StakeFinishWithdraw(new Bytes(stakeID), new Bytes(tokenID), new Bytes(tokenCodeHash), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    stakeFinishWithdrawCodeHash = getCodeHash(stakeFinishWithdraw.lockingScript.toBuffer()).toString('hex')

    const stakeFinishWithdrawMvc = new StakeFinishWithdrawMvc(new Bytes(stakeID), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    stakeFinishWithdrawMvcCodeHash = getCodeHash(stakeFinishWithdrawMvc.lockingScript.toBuffer()).toString('hex')

    const stakeHarvest = new StakeHarvest(new Bytes(stakeID), new Bytes(rewardTokenID), new Bytes(rewardTokenCodeHash))
    stakeHarvestCodeHash = getCodeHash(stakeHarvest.lockingScript.toBuffer()).toString('hex')

    const stakeAdmin = new StakeAdmin(new Bytes(stakeID), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    stakeAdminCodeHash = getCodeHash(stakeAdmin.lockingScript.toBuffer()).toString('hex')

    const stakeMergeRewardToken = new StakeMergeRewardToken(new Bytes(rewardTokenID), new Bytes(rewardTokenCodeHash))
    stakeMergeRewardTokenCodeHash = getCodeHash(stakeMergeRewardToken.lockingScript.toBuffer()).toString('hex')

    const stakeMain = new StakeMain()
    const code = stakeMain.lockingScript.toBuffer()
    stakeMainCodeHash = getCodeHash(code).toString('hex')

    const [stakeTokenHolder, tx] = createStakeTokenHolderContract()
    stakeTokenHolderHash = mvc.crypto.Hash.sha256ripemd160(stakeTokenHolder.lockingScript.toBuffer()).toString('hex')

    const [stakeRewardTokenHolder, tx2] = createStakeRewardTokenHolderContract()
    stakeRewardTokenHolderHash = mvc.crypto.Hash.sha256ripemd160(stakeRewardTokenHolder.lockingScript.toBuffer()).toString('hex')

    const voteMain = new VoteMain()
    voteMainCodeHash = getCodeHash(voteMain.lockingScript.toBuffer()).toString('hex')

    // create merkle tree
    contractHashArray = Buffer.concat([
        Buffer.from(stakeUpdateContractCodeHash, 'hex'),
        Buffer.from(stakeDepositCodeHash, 'hex'),
        Buffer.from(stakeWithdrawCodeHash, 'hex'),
        Buffer.from(stakePreWithdrawCodeHash, 'hex'),
        Buffer.from(stakeFinishWithdrawCodeHash, 'hex'),
        Buffer.from(stakeHarvestCodeHash, 'hex'),
        Buffer.from(stakeAdminCodeHash, 'hex'),
        Buffer.from(stakeVoteCodeHash, 'hex'),
    ])
    contractHashRoot = mvc.crypto.Hash.sha256ripemd160(contractHashArray)

    voteContractHashArray = Buffer.concat([
        Buffer.from(stakeVoteCodeHash, 'hex'),
    ])
    voteContractHashRoot = mvc.crypto.Hash.sha256ripemd160(voteContractHashArray)
}

function setMvcVersion() {
    // create merkle tree
    contractHashArray = Buffer.concat([
        Buffer.from(stakeUpdateContractCodeHash, 'hex'),
        Buffer.from(stakeDepositMvcCodeHash, 'hex'),
        Buffer.from(stakeWithdrawMvcCodeHash, 'hex'),
        Buffer.from(stakePreWithdrawCodeHash, 'hex'),
        Buffer.from(stakeFinishWithdrawMvcCodeHash, 'hex'),
        Buffer.from(stakeHarvestCodeHash, 'hex'),
        Buffer.from(stakeAdminCodeHash, 'hex'),
        Buffer.from(stakeVoteCodeHash, 'hex'),
    ])
    contractHashRoot = mvc.crypto.Hash.sha256ripemd160(contractHashArray)
}

function createStakeMain(lastRewardTime: number, poolTokenAmount: bigint, unlockingPoolTokenAmount: bigint, accPoolPerShare: bigint, userDataMerkleRoot: Buffer, lockInterval: number = withdrawLockInterval) {
    const stakeMain = new StakeMain()
    const data = Common.buildScriptData(Buffer.concat([
        ownerAddress.hashBuffer,
        Common.getUInt64Buf(rewardAmountFactor),
        Common.getUInt32Buf(rewardBeginTime),
        Common.getUInt32Buf(rewardEndTime),
        Common.getUInt32Buf(lockInterval),
        Common.getUInt64Buf(rewardAmountPerSecond),
        Common.getUInt32Buf(lastRewardTime),
        Common.getUInt64Buf(poolTokenAmount),
        Common.getUInt64Buf(unlockingPoolTokenAmount),
        Common.toBufferLE(accPoolPerShare, StakeProto.ACC_POOL_PER_SHARE_LEN),
        userDataMerkleRoot,
        blockHeightRabinPubKeyHashArrayHash,
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        contractHashRoot,
        Common.getUInt32Buf(StakeProto.CUSTOM_DATA_LEN),
        Buffer.from(stakeSensibleID, 'hex'),
        uniqueVersion,
        uniqueType,
        Proto.PROTO_FLAG,
    ]))
    stakeMain.setDataPart(data.toString('hex'))
    return stakeMain
}

function createBlockTimeRabinMsg(blockTime:number, outputPoint: Buffer) {
    const rabinMsg = Buffer.concat([
        Common.getUInt32Buf(1),
        Common.getUInt32Buf(blockTime),
        Common.getUInt32Buf(blockTime),
        Buffer.from('0000000000000000017fdc13e2cb097e688fc4d241ea3efa8a5d840201a9cd15', 'hex'), // block hash
        Buffer.from('4d5643', 'hex'),
        mvc.crypto.Hash.sha256ripemd160(outputPoint),
    ])

    let rabinPaddingArray: Bytes[] = []
    let rabinSigArray: BigInt[] = []
    for (let i = 0; i < RabinUtils.oracleVerifyNum; i++) {
        const idx = blockHeightRabinPubKeyIndexArray[i]
        const rabinPubKey = blockHeightRabinPubKeyArray[idx]
        const rabinPrivateKey = RabinUtils.rabinPrivateKeys[idx]
        let rabinSignResult = Rabin.sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
        const rabinSign = rabinSignResult.signature
        const rabinPadding = Buffer.alloc(rabinSignResult.paddingByteCount, 0)
        rabinPaddingArray.push(new Bytes(rabinPadding.toString('hex')))
        rabinSigArray.push(rabinSign)
    }
    return [rabinMsg, rabinPaddingArray, rabinSigArray] 
}

function createStakeDepositMvcContract(senderAddress: mvc.Address) {
    const stakeDeposit = new StakeDepositMvc(new Bytes(stakeID))
    const data = Common.buildScriptData(Buffer.concat([
        senderAddress.hashBuffer,
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeDeposit.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeDeposit.lockingScript)
    return [stakeDeposit, tx]
}

function unlockStakeDepositMvc( 
    tx: mvc.Transaction,
    prevouts: Buffer,
    depositContract,
    mvcAddAmount,
    // stake
    stakeTx: mvc.Transaction | undefined,
    // merkle proof
    oldLeaf: Buffer, 
    merklePath: Buffer,
    // output
    changeSatoshis: number,
    changeAddress: mvc.Address,
    curBlockTime: number,
    expected: boolean = true,
    wrongBlockRabinSig: boolean = false
) {

    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    let stakeTxProof = getEmptyTxOutputProofScrypt()
    let stakeScriptBuf = Buffer.alloc(0)
    let stakeOutputSatoshis = 0
    let tokenInputIndex = 1
    if (stakeTx) {
        tokenInputIndex = 2
        const stakeOutputIndex = tx.inputs[1].outputIndex
        output = stakeTx.outputs[stakeOutputIndex]
        stakeScriptBuf = output.script.toBuffer()
        stakeOutputSatoshis = output.satoshis
        stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)
    }

    const stakeOutputPoint = Buffer.concat([
        Common.getTxIdBuf(stakeTx.id), 
        Common.getUInt32Buf(0),
    ])
    const [blockHeightRabinMsg, blockHeightRabinPaddingArray, blockHeightRabinSigArray] = createBlockTimeRabinMsg(curBlockTime, stakeOutputPoint)
    if (wrongBlockRabinSig === true) {
        //@ts-ignore
        blockHeightRabinSigArray[0] += BigInt(1)
    }

    const blockRabinData = new BlockRabinData({
        msg: new Bytes(blockHeightRabinMsg.toString('hex')),
        paddingArray: <Bytes []>blockHeightRabinPaddingArray,
        sigArray: <bigint []>blockHeightRabinSigArray,
        pubKeyIndexArray: blockHeightRabinPubKeyIndexArray,
        pubKeyVerifyArray: blockHeightRabinPubKeyVerifyArray,
        pubKeyHashArray: new Bytes(blockHeightRabinPubKeyHashArray.toString('hex')),
    })

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    let result = depositContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        mvcAddAmount,
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // block height
        blockRabinData,
        // merkle
        new Bytes(oldLeaf.toString('hex')),
        new Bytes(merklePath.toString('hex')),
        // output
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeDepositContract(senderAddress: mvc.Address) {
    const stakeDeposit = new StakeDeposit(new Bytes(stakeID), new Bytes(tokenID), new Bytes(tokenCodeHash))
    const data = Common.buildScriptData(Buffer.concat([
        senderAddress.hashBuffer,
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeDeposit.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeDeposit.lockingScript)
    return [stakeDeposit, tx]
}

function unlockStakeDeposit( 
    tx: mvc.Transaction,
    prevouts: Buffer,
    depositContract,
    // stake
    stakeTx: mvc.Transaction | undefined,
    // token:
    tokenTx: mvc.Transaction,
    // poolToken
    poolTokenTx: mvc.Transaction | undefined,
    // merkle proof
    oldLeaf: Buffer, 
    merklePath: Buffer,
    // output
    changeSatoshis: number,
    changeAddress: mvc.Address,
    curBlockTime: number,
    isStakeMode: boolean,
    expected: boolean = true,
    wrongBlockRabinSig: boolean = false
) {

    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    let stakeTxProof = getEmptyTxOutputProofScrypt()
    let stakeScriptBuf = Buffer.alloc(0)
    let stakeOutputSatoshis = 0
    let tokenInputIndex = 1
    if (stakeTx) {
        tokenInputIndex = 2
        const stakeOutputIndex = tx.inputs[1].outputIndex
        output = stakeTx.outputs[stakeOutputIndex]
        stakeScriptBuf = output.script.toBuffer()
        stakeOutputSatoshis = output.satoshis
        stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)
    }

    const tokenOutputIndex = tx.inputs[tokenInputIndex].outputIndex
    output = tokenTx.outputs[tokenOutputIndex]
    const tokenOutputSatoshis = output.satoshis
    const tokenScriptBuf = output.script.toBuffer()
    const tokenTxProof = getTxOutputProofScrypt(tokenTx, tokenOutputIndex, true)

    let poolTokenTxProof = getEmptyTxOutputProofScrypt()
    if (poolTokenTx) {
        const poolTokenOutputIndex = tx.inputs[3].outputIndex
        poolTokenTxProof = getTxOutputProofScrypt(poolTokenTx, poolTokenOutputIndex, true)
    }

    const tokenOutputPoint = Buffer.concat([
        Common.getTxIdBuf(tokenTx.id), 
        Common.getUInt32Buf(0),
    ])
    const [blockHeightRabinMsg, blockHeightRabinPaddingArray, blockHeightRabinSigArray] = createBlockTimeRabinMsg(curBlockTime, tokenOutputPoint)
    if (wrongBlockRabinSig === true) {
        //@ts-ignore
        blockHeightRabinSigArray[0] += BigInt(1)
    }

    const blockRabinData = new BlockRabinData({
        msg: new Bytes(blockHeightRabinMsg.toString('hex')),
        paddingArray: <Bytes []>blockHeightRabinPaddingArray,
        sigArray: <bigint []>blockHeightRabinSigArray,
        pubKeyIndexArray: blockHeightRabinPubKeyIndexArray,
        pubKeyVerifyArray: blockHeightRabinPubKeyVerifyArray,
        pubKeyHashArray: new Bytes(blockHeightRabinPubKeyHashArray.toString('hex')),
    })

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    let result = depositContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // token
        new Bytes(tokenScriptBuf.toString('hex')),
        tokenTxProof,
        // pool token
        poolTokenTxProof,
        // block height
        blockRabinData,
        // merkle
        new Bytes(oldLeaf.toString('hex')),
        new Bytes(merklePath.toString('hex')),
        // output
        stakeOutputSatoshis, 
        tokenOutputSatoshis,
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
        isStakeMode,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeWithdrawMvcContract() {
    const stakeWithdraw = new StakeWithdrawMvc(new Bytes(stakeID), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeWithdraw.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeWithdraw.lockingScript)
    return [stakeWithdraw, tx]
}

function unlockStakeWithdrawMvc(
    tx: mvc.Transaction,
    prevouts: Buffer,
    withdrawContract,
    tokenRemoveAmount: BigInt,
    // sig
    senderPubKeyHex: string, 
    senderSigHex: string,
    // stake
    stakeTx: mvc.Transaction,
    // merkle proof
    oldLeaf: Buffer, 
    merklePath: Buffer,
    // output
    changeSatoshis: number,
    curBlockTime: number,
    expected: boolean = true,
) {
    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    const stakeOutputIndex = tx.inputs[1].outputIndex
    output = stakeTx.outputs[stakeOutputIndex]
    const stakeScriptBuf = output.script.toBuffer()
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)

    const stakeOutputPoint = Buffer.concat([
        Common.getTxIdBuf(stakeTx.id), 
        Common.getUInt32Buf(0),
    ])
    const [blockHeightRabinMsg, blockHeightRabinPaddingArray, blockHeightRabinSigArray] = createBlockTimeRabinMsg(curBlockTime, stakeOutputPoint)

    const blockRabinData = new BlockRabinData({
        msg: new Bytes(blockHeightRabinMsg.toString('hex')),
        paddingArray: <Bytes []>blockHeightRabinPaddingArray,
        sigArray: <bigint []>blockHeightRabinSigArray,
        pubKeyIndexArray: blockHeightRabinPubKeyIndexArray,
        pubKeyVerifyArray: blockHeightRabinPubKeyVerifyArray,
        pubKeyHashArray: new Bytes(blockHeightRabinPubKeyHashArray.toString('hex')),
    })

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    const result = withdrawContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // sig
        new PubKey(senderPubKeyHex),
        new Sig(senderSigHex),
        tokenRemoveAmount,
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // block height
        blockRabinData,
        // merkle
        new Bytes(oldLeaf.toString('hex')),
        new Bytes(merklePath.toString('hex')),
        // output
        changeSatoshis,
        new Bytes('')
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeWithdrawContract() {
    const stakeWithdraw = new StakeWithdraw(new Bytes(stakeID), new Bytes(tokenID), new Bytes(tokenCodeHash), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeWithdraw.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeWithdraw.lockingScript)
    return [stakeWithdraw, tx]
}

function unlockStakeWithdraw(
    tx: mvc.Transaction,
    prevouts: Buffer,
    withdrawContract,
    tokenRemoveAmount: BigInt,
    // sig
    senderPubKeyHex: string, 
    senderSigHex: string,
    // stake
    stakeTx: mvc.Transaction,
    // poolToken
    poolTokenTx: mvc.Transaction,
    // merkle proof
    oldLeaf: Buffer, 
    merklePath: Buffer,
    // output
    changeSatoshis: number,
    changeAddress: mvc.Address,
    curBlockTime: number,
    expected: boolean = true,
) {
    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    const stakeOutputIndex = tx.inputs[1].outputIndex
    output = stakeTx.outputs[stakeOutputIndex]
    const stakeScriptBuf = output.script.toBuffer()
    const stakeOutputSatoshis = output.satoshis
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)

    const poolTokenOutputIndex = tx.inputs[2].outputIndex
    output = poolTokenTx.outputs[poolTokenOutputIndex]
    const poolTokenScriptBuf = output.script.toBuffer()
    const poolTokenOutputSatoshis = output.satoshis
    const poolTokenTxProof = getTxOutputProofScrypt(poolTokenTx, poolTokenOutputIndex, true)

    const stakeOutputPoint = Buffer.concat([
        Common.getTxIdBuf(stakeTx.id), 
        Common.getUInt32Buf(0),
    ])
    const [blockHeightRabinMsg, blockHeightRabinPaddingArray, blockHeightRabinSigArray] = createBlockTimeRabinMsg(curBlockTime, stakeOutputPoint)

    const blockRabinData = new BlockRabinData({
        msg: new Bytes(blockHeightRabinMsg.toString('hex')),
        paddingArray: <Bytes []>blockHeightRabinPaddingArray,
        sigArray: <bigint []>blockHeightRabinSigArray,
        pubKeyIndexArray: blockHeightRabinPubKeyIndexArray,
        pubKeyVerifyArray: blockHeightRabinPubKeyVerifyArray,
        pubKeyHashArray: new Bytes(blockHeightRabinPubKeyHashArray.toString('hex')),
    })

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    const result = withdrawContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // sig
        new PubKey(senderPubKeyHex),
        new Sig(senderSigHex),
        tokenRemoveAmount,
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // pool token
        new Bytes(poolTokenScriptBuf.toString('hex')),
        poolTokenTxProof,
        // block height
        blockRabinData,
        // merkle
        new Bytes(oldLeaf.toString('hex')),
        new Bytes(merklePath.toString('hex')),
        // output
        stakeOutputSatoshis,
        poolTokenOutputSatoshis,
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
        new Bytes('')
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakePreWithdrawContract() {
    const stakeWithdraw = new StakePreWithdraw(new Bytes(stakeID), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeWithdraw.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeWithdraw.lockingScript)
    return [stakeWithdraw, tx]
}

function unlockStakePreWithdraw(
    tx: mvc.Transaction,
    prevouts: Buffer,
    preWithdrawContract,
    tokenRemoveAmount: BigInt,
    // sig
    senderPubKeyHex: string, 
    senderSigHex: string,
    // stake
    stakeTx: mvc.Transaction,
    // merkle proof
    oldLeaf: Buffer, 
    merklePath: Buffer,
    // output
    changeSatoshis: number,
    changeAddress: mvc.Address,
    curBlockTime: number,
    expected: boolean = true,
) {
    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    const stakeOutputIndex = tx.inputs[1].outputIndex
    output = stakeTx.outputs[stakeOutputIndex]
    const stakeScriptBuf = output.script.toBuffer()
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)

    const stakeOutputPoint = Buffer.concat([
        Common.getTxIdBuf(stakeTx.id), 
        Common.getUInt32Buf(0),
    ])
    const [blockHeightRabinMsg, blockHeightRabinPaddingArray, blockHeightRabinSigArray] = createBlockTimeRabinMsg(curBlockTime, stakeOutputPoint)

    const blockRabinData = new BlockRabinData({
        msg: new Bytes(blockHeightRabinMsg.toString('hex')),
        paddingArray: <Bytes []>blockHeightRabinPaddingArray,
        sigArray: <bigint []>blockHeightRabinSigArray,
        pubKeyIndexArray: blockHeightRabinPubKeyIndexArray,
        pubKeyVerifyArray: blockHeightRabinPubKeyVerifyArray,
        pubKeyHashArray: new Bytes(blockHeightRabinPubKeyHashArray.toString('hex')),
    })

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    const result = preWithdrawContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // sig
        new PubKey(senderPubKeyHex),
        new Sig(senderSigHex),
        tokenRemoveAmount,
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // block height
        blockRabinData,
        // merkle
        new Bytes(oldLeaf.toString('hex')),
        new Bytes(merklePath.toString('hex')),
        // output
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
        new Bytes('')
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeFinishWithdrawMvcContract() {
    const stakeWithdraw = new StakeFinishWithdrawMvc(new Bytes(stakeID), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeWithdraw.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeWithdraw.lockingScript)
    return [stakeWithdraw, tx]
}

function unlockStakeFinishWithdrawMvc(
    tx: mvc.Transaction,
    prevouts: Buffer,
    finishWithdrawContract,
    // sig
    pubKeyHex: string,
    sigHex: string,
    // stake
    stakeTx: mvc.Transaction,
    // merkle proof
    oldLeaf: Buffer, 
    merklePath: Buffer,
    // output
    changeSatoshis: number,
    curBlockTime: number,
    expected: boolean = true,
) {
    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    const stakeOutputIndex = tx.inputs[1].outputIndex
    output = stakeTx.outputs[stakeOutputIndex]
    const stakeScriptBuf = output.script.toBuffer()
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)

    const stakeOutputPoint = Buffer.concat([
        Common.getTxIdBuf(stakeTx.id), 
        Common.getUInt32Buf(0),
    ])
    const [blockHeightRabinMsg, blockHeightRabinPaddingArray, blockHeightRabinSigArray] = createBlockTimeRabinMsg(curBlockTime, stakeOutputPoint)

   const blockRabinData = new BlockRabinData({
        msg: new Bytes(blockHeightRabinMsg.toString('hex')),
        paddingArray: <Bytes []>blockHeightRabinPaddingArray,
        sigArray: <bigint []>blockHeightRabinSigArray,
        pubKeyIndexArray: blockHeightRabinPubKeyIndexArray,
        pubKeyVerifyArray: blockHeightRabinPubKeyVerifyArray,
        pubKeyHashArray: new Bytes(blockHeightRabinPubKeyHashArray.toString('hex')),
    }) 

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    const result = finishWithdrawContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // sig
        new PubKey(pubKeyHex),
        new Sig(sigHex),
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // block height
        blockRabinData,
        // merkle
        new Bytes(oldLeaf.toString('hex')),
        new Bytes(merklePath.toString('hex')),
        // output
        changeSatoshis,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeFinishWithdrawContract() {
    const stakeWithdraw = new StakeFinishWithdraw(new Bytes(stakeID), new Bytes(tokenID), new Bytes(tokenCodeHash), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeWithdraw.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeWithdraw.lockingScript)
    return [stakeWithdraw, tx]
}

function unlockStakeFinishWithdraw(
    tx: mvc.Transaction,
    prevouts: Buffer,
    finishWithdrawContract,
    // sig
    pubKeyHex: string,
    sigHex: string,
    // stake
    stakeTx: mvc.Transaction,
    // poolToken
    poolTokenTx: mvc.Transaction,
    // merkle proof
    oldLeaf: Buffer, 
    merklePath: Buffer,
    // output
    changeSatoshis: number,
    changeAddress: mvc.Address,
    curBlockTime: number,
    expected: boolean = true,
) {
    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    const stakeOutputIndex = tx.inputs[1].outputIndex
    output = stakeTx.outputs[stakeOutputIndex]
    const stakeScriptBuf = output.script.toBuffer()
    const stakeOutputSatoshis = output.satoshis
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)

    const poolTokenOutputIndex = tx.inputs[2].outputIndex
    output = poolTokenTx.outputs[poolTokenOutputIndex]
    const poolTokenScriptBuf = output.script.toBuffer()
    const poolTokenOutputSatoshis = output.satoshis
    const poolTokenTxProof = getTxOutputProofScrypt(poolTokenTx, poolTokenOutputIndex, true)

    const stakeOutputPoint = Buffer.concat([
        Common.getTxIdBuf(stakeTx.id), 
        Common.getUInt32Buf(0),
    ])
    const [blockHeightRabinMsg, blockHeightRabinPaddingArray, blockHeightRabinSigArray] = createBlockTimeRabinMsg(curBlockTime, stakeOutputPoint)

   const blockRabinData = new BlockRabinData({
        msg: new Bytes(blockHeightRabinMsg.toString('hex')),
        paddingArray: <Bytes []>blockHeightRabinPaddingArray,
        sigArray: <bigint []>blockHeightRabinSigArray,
        pubKeyIndexArray: blockHeightRabinPubKeyIndexArray,
        pubKeyVerifyArray: blockHeightRabinPubKeyVerifyArray,
        pubKeyHashArray: new Bytes(blockHeightRabinPubKeyHashArray.toString('hex')),
    }) 

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    const result = finishWithdrawContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // sig
        new PubKey(pubKeyHex),
        new Sig(sigHex),
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // pool token
        new Bytes(poolTokenScriptBuf.toString('hex')),
        poolTokenTxProof,
        // block height
        blockRabinData,
        // merkle
        new Bytes(oldLeaf.toString('hex')),
        new Bytes(merklePath.toString('hex')),
        // output
        stakeOutputSatoshis,
        poolTokenOutputSatoshis,
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeHarvestContract() {
    const stakeHarvest = new StakeHarvest(new Bytes(stakeID), new Bytes(rewardTokenID), new Bytes(rewardTokenCodeHash))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeHarvest.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeHarvest.lockingScript)
    return [stakeHarvest, tx]
}

function unlockStakeHarvest(
    tx: mvc.Transaction,
    prevouts: Buffer,
    harvestContract,
    // sig
    pubKeyHex: string,
    sigHex: string,
    // stake
    stakeTx: mvc.Transaction,
    // reardToken
    tokenTx: mvc.Transaction,
    // merkle proof
    oldLeaf: Buffer, 
    merklePath: Buffer,
    // output
    changeSatoshis: number,
    changeAddress: mvc.Address,
    curBlockTime: number,
    expected: boolean = true,
) {
    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    const stakeOutputIndex = tx.inputs[1].outputIndex
    output = stakeTx.outputs[stakeOutputIndex]
    const stakeScriptBuf = output.script.toBuffer()
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)

    const tokenOutputIndex = tx.inputs[2].outputIndex
    output = tokenTx.outputs[tokenOutputIndex]
    const tokenOutputSatoshis = output.satoshis
    const tokenScriptBuf = output.script.toBuffer()
    const tokenTxProof = getTxOutputProofScrypt(tokenTx, tokenOutputIndex, true)

    const stakeOutputPoint = Buffer.concat([
        Common.getTxIdBuf(stakeTx.id), 
        Common.getUInt32Buf(0),
    ])
    const [blockHeightRabinMsg, blockHeightRabinPaddingArray, blockHeightRabinSigArray] = createBlockTimeRabinMsg(curBlockTime, stakeOutputPoint)

    const blockRabinData = new BlockRabinData({
        msg: new Bytes(blockHeightRabinMsg.toString('hex')),
        paddingArray: <Bytes []>blockHeightRabinPaddingArray,
        sigArray: <bigint []>blockHeightRabinSigArray,
        pubKeyIndexArray: blockHeightRabinPubKeyIndexArray,
        pubKeyVerifyArray: blockHeightRabinPubKeyVerifyArray,
        pubKeyHashArray: new Bytes(blockHeightRabinPubKeyHashArray.toString('hex')),
    })

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    const result = harvestContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // sig
        new PubKey(pubKeyHex),
        new Sig(sigHex),
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // reward token
        new Bytes(tokenScriptBuf.toString('hex')),
        tokenTxProof,
        // block height
        blockRabinData,
        // merkle proof
        new Bytes(oldLeaf.toString('hex')),
        new Bytes(merklePath.toString('hex')),
        // output
        tokenOutputSatoshis,
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeTokenHolderContract() {
    const stakeTokenHolder = new StakeTokenHolder(new Bytes(stakeID))
    const data = Common.buildScriptData(Buffer.from(stakeMainCodeHash, 'hex'))
    stakeTokenHolder.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeTokenHolder.lockingScript)
    return [stakeTokenHolder, tx]
}

function unlockStakeTokenHolder(
    tx: mvc.Transaction,
    prevouts: Buffer,
    stakeTokenHolder,
    inputIndex: number,
    // stake
    stakeTx: mvc.Transaction,
    // opTx
    opContractTx: mvc.Transaction,
    mainContractHashArray: Buffer,
    op: number,
    expected: boolean = true
) {
    const inputSatoshis = (<mvc.Transaction.Output>tx.inputs[inputIndex].output).satoshis
    const preimage = getPreimage(tx, stakeTokenHolder.lockingScript.subScript(0), inputSatoshis, inputIndex, sigtype)

    const stakeOutputIndex = tx.inputs[1].outputIndex
    const stakeTxScript = stakeTx.outputs[stakeOutputIndex].script.toBuffer()
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)

    const contractOutputIndex = tx.inputs[0].outputIndex
    const opTxScript = opContractTx.outputs[contractOutputIndex].script.toBuffer()
    const opTxProof = getTxOutputProofScrypt(opContractTx, contractOutputIndex, true)

    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis
    }
    const result = stakeTokenHolder.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // stake
        new Bytes(stakeTxScript.toString('hex')),
        stakeTxProof,
        // op
        new Bytes(opTxScript.toString('hex')),
        opTxProof,
        new Bytes(mainContractHashArray.toString('hex')),
        op,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeRewardTokenHolderContract() {
    const stakeRewardTokenHolder = new StakeRewardTokenHolder(new Bytes(stakeID), new Bytes(stakeMergeRewardTokenCodeHash), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    const data = Common.buildScriptData(Buffer.from(stakeMainCodeHash, 'hex'))
    stakeRewardTokenHolder.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeRewardTokenHolder.lockingScript)
    return [stakeRewardTokenHolder, tx]
}

function unlockStakeRewardTokenHolder(
    tx: mvc.Transaction,
    prevouts: Buffer,
    rewardTokenHolder,
    inputIndex: number,
    // sig
    pubKeyHex: string,
    sigHex: string,
    // stake
    stakeTx: mvc.Transaction | undefined,
    // opTx
    opContractTx: mvc.Transaction | undefined,
    mainContractHashArray: Buffer,
    op: number,
    expected: boolean = true
) {
    const inputSatoshis = (<mvc.Transaction.Output>tx.inputs[inputIndex].output).satoshis
    const preimage = getPreimage(tx, rewardTokenHolder.lockingScript.subScript(0), inputSatoshis, inputIndex, sigtype)

    let stakeTxProof = getEmptyTxOutputProofScrypt()
    let stakeTxScript = Buffer.alloc(0)
    if (stakeTx) {
        const stakeOutputIndex = tx.inputs[1].outputIndex
        stakeTxScript = stakeTx.outputs[stakeOutputIndex].script.toBuffer()
        stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)
    }

    let opTxProof = getEmptyTxOutputProofScrypt()
    let opTxScript = Buffer.alloc(0)
    if (opContractTx) {
        const contractOutputIndex = tx.inputs[0].outputIndex
        opTxScript = opContractTx.outputs[contractOutputIndex].script.toBuffer()
        opTxProof = getTxOutputProofScrypt(opContractTx, contractOutputIndex, true)
    }

    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis
    }
    const result = rewardTokenHolder.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // sig
        new PubKey(pubKeyHex),
        new Sig(sigHex),
        // stake
        new Bytes(stakeTxScript.toString('hex')),
        stakeTxProof,
        // op
        new Bytes(opTxScript.toString('hex')),
        opTxProof,
        new Bytes(mainContractHashArray.toString('hex')),
        op,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeAdminContract() {
    const stakeAdmin = new StakeAdmin(new Bytes(stakeID), new Ripemd160(adminAddress.hashBuffer.toString('hex')))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeAdmin.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeAdmin.lockingScript)
    return [stakeAdmin, tx]
}

function unlockStakeAdmin(
    tx: mvc.Transaction,
    prevouts: Buffer,
    adminContract,
    inputIndex: number,
    // sig
    pubKeyHex: string,
    sigHex: string,
    // stake
    stakeTx: mvc.Transaction,
    // args
    rewardBeginTime: Number,
    rewardEndTime: Number,
    rewardAmountPerSecond: BigInt,
    lastRewardTime: Number,
    withdrawLockInterval: Number,
    // output
    changeAddress: mvc.Address,
    changeSatoshis: Number,
    expected: boolean = true
) {
    const inputSatoshis = (<mvc.Transaction.Output>tx.inputs[inputIndex].output).satoshis
    const preimage = getPreimage(tx, adminContract.lockingScript.subScript(0), inputSatoshis, inputIndex, sigtype)

    const stakeOutputIndex = tx.inputs[1].outputIndex
    let output = stakeTx.outputs[stakeOutputIndex]
    const stakeScriptBuf = output.script.toBuffer()
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    const result = adminContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // sig
        new PubKey(pubKeyHex),
        new Sig(sigHex),
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // args
        rewardBeginTime,
        rewardEndTime,
        rewardAmountPerSecond,
        lastRewardTime,
        withdrawLockInterval,
        // output
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createStakeVoteContract() {
    const stakeVote = new StakeVote(new Bytes(stakeID))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(voteMainCodeHash, 'hex'),
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeVote.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeVote.lockingScript)
    return [stakeVote, tx]
}

function unlockStakeVote(
    tx: mvc.Transaction, 
    prevouts: Buffer, 
    voteContract, 
    // sig 
    pubKeyHex: string,
    sigHex: string,
    // vote option
    confirmVote: boolean,
    voteOption: number,
    // stake tx
    stakeTx: mvc.Transaction,
    // vote tx
    voteTx: mvc.Transaction,
    // stake merkle
    stakeLeaf: Buffer,
    stakeMerklePath: Buffer,
    // vote merkle
    oldVoteLeaf: Buffer,
    voteMerklePath: Buffer,
    voteSumData: Buffer,
    curBlockTime: number,
    // output
    changeAddress: mvc.Address, 
    changeSatoshis: number, 
    expected: boolean = true
) {
    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    const stakeOutputIndex = tx.inputs[1].outputIndex
    output = stakeTx.outputs[stakeOutputIndex]
    const stakeScriptBuf = output.script.toBuffer()
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex, true)

    const voteOutputIndex = tx.inputs[2].outputIndex
    output = voteTx.outputs[voteOutputIndex]
    const voteOutputSatoshis = output.satoshis
    const voteScriptBuf = output.script.toBuffer()
    const voteTxProof = getTxOutputProofScrypt(voteTx, voteOutputIndex, true)

    const stakeOutputPoint = Buffer.concat([
        Common.getTxIdBuf(stakeTx.id), 
        Common.getUInt32Buf(0),
    ])
    const [blockHeightRabinMsg, blockHeightRabinPaddingArray, blockHeightRabinSigArray] = createBlockTimeRabinMsg(curBlockTime, stakeOutputPoint)

    const blockRabinData = new BlockRabinData({
        msg: new Bytes(blockHeightRabinMsg.toString('hex')),
        paddingArray: <Bytes []>blockHeightRabinPaddingArray,
        sigArray: <bigint []>blockHeightRabinSigArray,
        pubKeyIndexArray: blockHeightRabinPubKeyIndexArray,
        pubKeyVerifyArray: blockHeightRabinPubKeyVerifyArray,
        pubKeyHashArray: new Bytes(blockHeightRabinPubKeyHashArray.toString('hex')),
    })

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    const result = voteContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // sig
        new PubKey(pubKeyHex),
        new Sig(sigHex),
        // vote
        confirmVote,
        voteOption,
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // reward token
        new Bytes(voteScriptBuf.toString('hex')),
        voteTxProof,
        // block height
        blockRabinData,
        // merkle
        new Bytes(stakeLeaf.toString('hex')),
        new Bytes(stakeMerklePath.toString('hex')),
        // vote leaf
        new Bytes(oldVoteLeaf.toString('hex')),
        new Bytes(voteMerklePath.toString('hex')),
        // voteData
        new Bytes(voteSumData.toString('hex')),
        // output
        voteOutputSatoshis,
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
        new Bytes('')
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createVoteMainContract(beginBlockTime: number, endBlockTime: number, voteDataTree: VoteDataTree) {

    const voteMain = new VoteMain()
    const data = Common.buildScriptData(Buffer.concat([
        ownerAddress.hashBuffer,
        Common.getUInt64Buf(minVoteAmount),
        Common.getUInt32Buf(beginBlockTime),
        Common.getUInt32Buf(endBlockTime),
        voteDataTree.merkleRoot,
        voteDataTree.sumDataHashRoot,
        blockHeightRabinPubKeyHashArrayHash,
        voteContractHashRoot,
        Common.getUInt32Buf(VoteProto.CUSTOM_DATA_LEN),
        Buffer.from(voteSensibleID, 'hex'),
        uniqueVersion,
        uniqueType,
        Proto.PROTO_FLAG,
    ]))
    voteMain.setDataPart(data.toString('hex'))
    return voteMain
}

function unlockVoteMain(
    tx: mvc.Transaction,
    prevouts: Buffer,
    voteMain,
    inputIndex: number,
    contractTx: mvc.Transaction,
    voteTx: mvc.Transaction,
    prevVoteTxInputIndex: number,
    prevVoteTx: mvc.Transaction,
    op: number,
    contractHashArray: Buffer,
    voteSensibleID: string,
    expected: boolean = true
) {
    // voteMain unlock
    const voteOutputIndex = tx.inputs[inputIndex].outputIndex
    const inputSatoshis = voteTx.outputs[voteOutputIndex].satoshis
    const preimage = getPreimage(tx, voteMain.lockingScript.subScript(0), inputSatoshis, inputIndex, sigtype)
    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis
    }

    const contractTxOutputIndex = tx.inputs[0].outputIndex
    const contractTxScript = contractTx.outputs[contractTxOutputIndex].script.toBuffer()
    const contractTxProof = getTxOutputProofScrypt(contractTx, contractTxOutputIndex)

    const voteTxOutputProof = getTxOutputProofScrypt(voteTx, voteOutputIndex)

    const voteTxInputProof = new TxInputProof(Common.getTxInputProof(voteTx, prevVoteTxInputIndex)[0])

    const prevVoteOutputIndex = voteTx.inputs[prevVoteTxInputIndex].outputIndex
    const prevVoteTxProof = getTxOutputProofScrypt(prevVoteTx, prevVoteOutputIndex)

    let prevCustomData = new Bytes('')
    const sid = Common.genGenesisOutpoint(prevVoteTx.id, prevVoteOutputIndex)
    if (sid !== voteSensibleID) {
        const prevVoteScriptBuf = prevVoteTx.outputs[prevVoteOutputIndex].script.toBuffer()
        prevCustomData = new Bytes(UniqueProto.getCustomData(prevVoteScriptBuf).toString('hex'))
    }

    const result = voteMain.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // op contract hash proof
        contractTxProof,
        new Bytes(contractTxScript.toString('hex')),
        // main contract hash proof
        new Bytes(contractHashArray.toString('hex')),
        op,
        // stake 
        prevVoteTxInputIndex,
        voteTxOutputProof.txHeader,
        voteTxInputProof,
        prevVoteTxProof,
        prevCustomData
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createMergeRewardToken() {
    const stakeMergeRewardToken = new StakeMergeRewardToken(new Bytes(rewardTokenID), new Bytes(rewardTokenCodeHash))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    stakeMergeRewardToken.setDataPart(data.toString('hex'))
    const tx = createContracTx(stakeMergeRewardToken.lockingScript)
    return [stakeMergeRewardToken, tx]
}

function unlockStakeMergeRewardToken(
    tx: mvc.Transaction, 
    prevouts: Buffer, 
    stakeMergeRewardToken,
    // token tx
    tokenTxs: mvc.Transaction[],
    changeAddress: mvc.Address, 
    changeSatoshis: number, 
    expected: boolean = true
) {
    const inputIndex = 0
    const inputSatoshis = (<mvc.Transaction.Output>tx.inputs[inputIndex].output).satoshis
    const preimage = getPreimage(tx, stakeMergeRewardToken.lockingScript.subScript(0), inputSatoshis, inputIndex, sigtype)
    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }

    let rewardTokenScriptBuf
    let tokenOutputSatoshis
    let rewardTokenAmountArray: bigint[] = []
    let tokenTxProofs: any = []
    for (let i = 0; i < 2; i++) {
        const tokenOutputIndex = tx.inputs[i + 1].outputIndex
        let output = tokenTxs[i].outputs[tokenOutputIndex]
        rewardTokenScriptBuf = output.script.toBuffer()
        tokenOutputSatoshis = output.satoshis
        const txProof = getTxOutputProofScrypt(tokenTxs[i], tokenOutputIndex)
        tokenTxProofs.push(txProof)
        rewardTokenAmountArray.push(TokenProto.getTokenAmount(rewardTokenScriptBuf))
    }

    const result = stakeMergeRewardToken.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        new Bytes(rewardTokenScriptBuf.toString('hex')),
        rewardTokenAmountArray,
        // token tx proof
        tokenTxProofs,
        tokenOutputSatoshis,
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createTokenContract(addressBuf: Buffer, amount: bigint, IsRewardToken: boolean=false) {
    const token = new Token(transferCheckCodeHashArray, unlockContractCodeHashArray)
    const name = IsRewardToken ? rewardTokenName: tokenName
    const symbol = IsRewardToken ? rewardTokenSymbol: tokenSymbol
    const sensibleID = IsRewardToken ? rewardTokenSensibleID: tokenSensibleID
    const data = Common.buildScriptData(Buffer.concat([
        name,
        symbol,
        decimalNum,
        addressBuf,
        Common.getUInt64Buf(amount),
        Buffer.from(genesisHash, 'hex'),
        Buffer.from(sensibleID, 'hex'),
        Common.getUInt32Buf(TokenProto.PROTO_VERSION),
        Common.getUInt32Buf(TokenProto.PROTO_TYPE), // type
        Proto.PROTO_FLAG
    ]))
    token.setDataPart(data.toString('hex'))
    return token
}

function createContracTx(lockingScript) {
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    tx.addInput(new mvc.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 0,
        script: ''
    }), mvc.Script.buildPublicKeyHashOut(address1), inputSatoshis)
    tx.addOutput(new mvc.Transaction.Output({
        script: lockingScript,
        satoshis: inputSatoshis
    }))
    return tx
}

function createUnlockContractCheck(tokenInputIndexArray: number[], tokenOutputAmounts: bigint[], tokenOutputAddress: Buffer[], tid: string) {
    const nTokenOutputs = tokenOutputAmounts.length
    const unlockContractCheck = new UnlockContractCheck()

    const nTokenInputs = tokenInputIndexArray.length
    let tokenInputIndexBytes = Buffer.alloc(0)
    for (let i = 0; i < nTokenInputs; i++) {
        tokenInputIndexBytes = Buffer.concat([tokenInputIndexBytes, Common.getUInt32Buf(tokenInputIndexArray[i])]);
    }
    let receiverTokenAmountArray = Buffer.alloc(0)
    let recervierArray = Buffer.alloc(0)
    for (let i = 0; i < nTokenOutputs; i++) {
        recervierArray = Buffer.concat([recervierArray, tokenOutputAddress[i]])
        receiverTokenAmountArray = Buffer.concat([
            receiverTokenAmountArray,
            Common.getUInt64Buf(tokenOutputAmounts[i])
        ])
    }
    const data = Common.buildScriptData(Buffer.concat([
        tokenInputIndexBytes,
        Common.getUInt32Buf(nTokenInputs),
        receiverTokenAmountArray,
        recervierArray,
        Common.getUInt32Buf(nTokenOutputs),
        Buffer.from(tokenCodeHash, 'hex'),
        Buffer.from(tid, 'hex'),
    ]))
    unlockContractCheck.setDataPart(data.toString('hex'))

    return unlockContractCheck
}

function depositMvc(stakePool: StakePool, curBlockTime: number, tokenAddAmount: bigint, options: any = {}) {
    setMvcVersion()

    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION

    let prevouts = []
    const senderAddress = address1
    // input
    // stakeDeposit
    const [deposit, depositTx] = createStakeDepositMvcContract(senderAddress)
    addInput(tx, depositTx.id, 0, deposit.lockingScript, depositTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeOutputSatoshis = Number(stakePool.poolTokenAmount + stakePool.unlockingPoolTokenAmount) + inputSatoshis
    const stakeTx = createInputTx(stakeMain, prevStakeTx, stakeOutputSatoshis)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, inputSatoshis, prevouts)

    // mvc 
    addInput(tx, dummyTxId, 0, mvc.Script.buildPublicKeyHashOut(senderAddress), inputSatoshis + Number(tokenAddAmount), prevouts)

    let res
    // stakePool
    if (options.wrongSender || options.wrongBlockTime || options.tokenAmountAdd || options.wrongOldLeaf) {
        const tokenAmount = tokenAddAmount
        const address = options.wrongSender ? options.wrongSender.hashBuffer: senderAddress.hashBuffer
        stakePool.updatePool(curBlockTime)

        if (options.wrongOldLeaf) {
            const index = <number>stakePool.userData.leafMap.get(address.toString('hex'))      
            stakePool.userData.leafArray[index].tokenAmount += BigInt(100)
        }

        let data = stakePool.userData.get(address)
        if (!data) {
            data = LeafNode.initFromAddress(address, BigInt(0), BigInt(0))
        }

        if (options.tokenAmountAdd) {
            data.tokenAmount += options.tokenAmountAdd
        }

        data.addressBuf = address
        data.tokenAmount += tokenAmount
        data.rewardDebt += tokenAmount *  stakePool.accPoolPerShare / stakePool.rewardAmountFactor
        res = stakePool.userData.updateLeaf(data)
        stakePool.poolTokenAmount += tokenAmount
    } else {
        res = stakePool.deposit(senderAddress.hashBuffer, tokenAddAmount, curBlockTime)
    }
    const oldLeafBuf = res.oldLeafBuf
    const merklePath = res.merklePath

    const prevoutsBuf = Buffer.concat(prevouts)

    // output

    // stakeMain
    let scriptBuf = StakeProto.getNewStakeScript(stakeMain.lockingScript.toBuffer(), curBlockTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    let newStakeOutputSatoshis = stakeOutputSatoshis + Number(tokenAddAmount)
    if (options.wrongOutputSatoshis) {
        newStakeOutputSatoshis += 1
    }
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), newStakeOutputSatoshis)

    // change mvc(optional)

    // unlock contract
    // deposit
    unlockStakeDepositMvc(tx, prevoutsBuf, deposit, tokenAddAmount, stakeTx, <Buffer>oldLeafBuf, <Buffer>merklePath, 0, senderAddress, curBlockTime, options.expected, options.wrongBlockRabinSig)

    // stake
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, depositTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_DEPOSIT, contractHashArray, stakeSensibleID, options.stakeMainExpected)

}

function deposit(stakePool: StakePool, curBlockTime: number, tokenAddAmount: bigint, options: any = {}) {

    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION

    let prevouts = []
    const senderAddress = address1
    // input
    // stakeDeposit
    const [deposit, depositTx] = createStakeDepositContract(senderAddress)
    addInput(tx, depositTx.id, 0, deposit.lockingScript, depositTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeTx = createInputTx(stakeMain, prevStakeTx)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, inputSatoshis, prevouts)

    // token
    const depositHash = mvc.crypto.Hash.sha256ripemd160(deposit.lockingScript.toBuffer())
    const token = createTokenContract(depositHash, tokenAddAmount)
    const tokenTx = createInputTx(token, undefined)
    addInput(tx, tokenTx.id, 0, token.lockingScript, inputSatoshis, prevouts)

    // pool token
    let tokenInputArray = [1]
    let poolToken = mvc.Script()
    let stakeTokenHolder
    let poolTokenTx
    if (stakePool.poolTokenAmount + stakePool.unlockingPoolTokenAmount > BigInt(0)) {
        tokenInputArray = [1, 2]
        poolToken = createTokenContract(Buffer.from(stakeTokenHolderHash, 'hex'), stakePool.poolTokenAmount + stakePool.unlockingPoolTokenAmount)
        poolTokenTx = createInputTx(poolToken, undefined)
        addInput(tx, poolTokenTx.id, 0, poolToken.lockingScript, inputSatoshis, prevouts)

        // stakeTokenHolder
        const res = createStakeTokenHolderContract()
        stakeTokenHolder = res[0]
        const stakeTokenHolderTx = res[1]
        addInput(tx, stakeTokenHolderTx.id, 0, stakeTokenHolder.lockingScript, stakeTokenHolderTx.outputs[0].satoshis, prevouts)
    }

    // mvc (optional)

    let res
    // stakePool
    if (options.wrongSender || options.wrongBlockTime || options.tokenAmountAdd || options.wrongOldLeaf) {
        const tokenAmount = tokenAddAmount
        const address = options.wrongSender ? options.wrongSender.hashBuffer: senderAddress.hashBuffer
        stakePool.updatePool(curBlockTime)

        if (options.wrongOldLeaf) {
            const index = <number>stakePool.userData.leafMap.get(address.toString('hex'))      
            stakePool.userData.leafArray[index].tokenAmount += BigInt(100)
        }

        let data = stakePool.userData.get(address)
        if (!data) {
            data = LeafNode.initFromAddress(address, BigInt(0), BigInt(0))
        }

        if (options.tokenAmountAdd) {
            data.tokenAmount += options.tokenAmountAdd
        }

        data.addressBuf = address
        data.tokenAmount += tokenAmount
        data.rewardDebt += tokenAmount *  stakePool.accPoolPerShare / stakePool.rewardAmountFactor
        res = stakePool.userData.updateLeaf(data)
        stakePool.poolTokenAmount += tokenAmount
    } else {
        res = stakePool.deposit(senderAddress.hashBuffer, tokenAddAmount, curBlockTime)
    }
    const oldLeafBuf = res.oldLeafBuf
    const merklePath = res.merklePath

    // unlockFromContractCheck
    const unlockContractCheck = createUnlockContractCheck(tokenInputArray, [stakePool.poolTokenAmount,], [Buffer.from(stakeTokenHolderHash, 'hex')], tokenID)
    addInput(tx, dummyTxId, 0, unlockContractCheck.lockingScript, inputSatoshis, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output

    // stakeMain
    let scriptBuf = StakeProto.getNewStakeScript(stakeMain.lockingScript.toBuffer(), curBlockTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // pool token
    scriptBuf = TokenProto.getNewTokenScript(token.lockingScript.toBuffer(), Buffer.from(stakeTokenHolderHash, 'hex'), stakePool.poolTokenAmount + stakePool.unlockingPoolTokenAmount)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // change mvc(optional)

    // unlock contract
    // deposit
    unlockStakeDeposit(tx, prevoutsBuf, deposit, stakeTx, tokenTx, poolTokenTx, <Buffer>oldLeafBuf, <Buffer>merklePath, 0, senderAddress, curBlockTime, true, options.expected, options.wrongBlockRabinSig)

    // stake
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, depositTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_DEPOSIT, contractHashArray, stakeSensibleID, options.stakeMainExpected)

    // stakeTokenHolder
    if (stakePool.poolTokenAmount > tokenAddAmount) {
        unlockStakeTokenHolder(tx, prevoutsBuf, stakeTokenHolder, 4, stakeTx, depositTx, contractHashArray, StakeProto.OP_DEPOSIT)
    }
}

function refundDeposit(options: any = {}) {

    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION

    let prevouts = []
    const senderAddress = address1

    const tokenAddAmount = BigInt(100000)

    // input
    // stakeDeposit
    const [deposit, depositTx] = createStakeDepositContract(senderAddress)
    addInput(tx, depositTx.id, 0, deposit.lockingScript, depositTx.outputs[0].satoshis, prevouts)

    // token
    const depositHash = mvc.crypto.Hash.sha256ripemd160(deposit.lockingScript.toBuffer())
    const token = createTokenContract(depositHash, tokenAddAmount)
    const tokenTx = createInputTx(token, undefined)
    addInput(tx, tokenTx.id, 0, token.lockingScript, inputSatoshis, prevouts)

    // unlockFromContractCheck
    const tokenInputArray = [1]
    const unlockContractCheck = createUnlockContractCheck(tokenInputArray, [tokenAddAmount,], [senderAddress.hashBuffer], tokenID)
    addInput(tx, dummyTxId, 0, unlockContractCheck.lockingScript, inputSatoshis, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output

    // refund token
    let scriptBuf = TokenProto.getNewTokenScript(token.lockingScript.toBuffer(), senderAddress.hashBuffer, tokenAddAmount)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    const stakeTx = undefined
    const oldLeafBuf = Buffer.alloc(0)
    const merklePath = Buffer.alloc(0)
    // unlock contract
    unlockStakeDeposit(tx, prevoutsBuf, deposit, stakeTx, tokenTx, undefined, oldLeafBuf, merklePath, 0, senderAddress, 0, false, options.expected, options.wrongBlockRabinSig)
}

function testWithdrawMvc(stakePool: StakePool, curBlockTime: number, tokenRemoveAmount: bigint, options: any = {}) {
    setMvcVersion()

    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []
    const senderAddress = address1

    // input
    // stakePreWithdraw
    const [withdrawContract, withdrawTx] = createStakeWithdrawMvcContract()
    addInput(tx, withdrawTx.id, 0, withdrawContract.lockingScript, withdrawTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot, stakePool.withdrawLockInterval)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeOutputSatoshis = Number(stakePool.poolTokenAmount + stakePool.unlockingPoolTokenAmount) + inputSatoshis
    const stakeTx = createInputTx(stakeMain, prevStakeTx, stakeOutputSatoshis)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, stakeOutputSatoshis, prevouts)

    // mvc optional
    let res
    // update stakePool
    if (options.wrongSender !== undefined || options.wrongBlockTime) {
        const address = options.wrongSender || senderAddress
        const tokenAmount = tokenRemoveAmount
        let data = stakePool.userData.get(address.hashBuffer)
        if (data == undefined) {
            throw Error('illegal user')
        }
        stakePool.updatePool(curBlockTime)

        data.addressBuf = senderAddress.hashBuffer
        data.rewardDebt -= tokenAmount *  stakePool.accPoolPerShare / stakePool.rewardAmountFactor
        data.tokenAmount -= tokenAmount
        res = stakePool.userData.updateLeaf(data)
        res.tokenAmount = tokenAmount

        stakePool.poolTokenAmount -= tokenAmount
        stakePool.unlockingPoolTokenAmount += tokenAmount
    } else {
        res = stakePool.withdraw(senderAddress.hashBuffer, tokenRemoveAmount, curBlockTime)
    }
    const oldLeafBuf = res.oldLeafBuf
    const merklePath = res.merklePath

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    // stakeMain
    let scriptBuf = StakeProto.getNewStakeScript(stakeMain.lockingScript.toBuffer(), curBlockTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    let newStakeOutputSatoshis = stakeOutputSatoshis - Number(tokenRemoveAmount)
    if (options.wrongOutputSatoshis) {
        newStakeOutputSatoshis += 1
    }
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), newStakeOutputSatoshis)

    // change mvc(optional)
    const changeSatoshis = Number(tokenRemoveAmount)
    addOutput(tx, mvc.Script.buildPublicKeyHashOut(senderAddress), changeSatoshis)

    let senderPubKey = toHex(privateKey.publicKey)
    let senderSig = toHex(signTx(tx, privateKey, withdrawContract.lockingScript, inputSatoshis, 0))
    if (options.useAdmin) {
        senderPubKey = toHex(adminPrivKey.publicKey)
        senderSig = toHex(signTx(tx, adminPrivKey, withdrawContract.lockingScript, inputSatoshis, 0))
    } else if (options.useWrongPrivKey) {
        senderPubKey = toHex(privateKey2.publicKey)
        senderSig = toHex(signTx(tx, privateKey2, withdrawContract.lockingScript, inputSatoshis, 0))
    }
    // withdraw
    unlockStakeWithdrawMvc(tx, prevoutsBuf, withdrawContract, tokenRemoveAmount, senderPubKey, senderSig, stakeTx, <Buffer>oldLeafBuf, <Buffer>merklePath, changeSatoshis, curBlockTime, options.expected)

    // stake
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, withdrawTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_WITHDRAW, contractHashArray, stakeSensibleID, options.stakeMainExpected)

}

function testWithdraw(stakePool: StakePool, curBlockTime: number, tokenRemoveAmount: bigint, options: any = {}) {
    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []
    const senderAddress = address1

    // input
    // stakePreWithdraw
    const [withdrawContract, withdrawTx] = createStakeWithdrawContract()
    addInput(tx, withdrawTx.id, 0, withdrawContract.lockingScript, withdrawTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot, stakePool.withdrawLockInterval)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeTx = createInputTx(stakeMain, prevStakeTx)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, inputSatoshis, prevouts)

    // pool token
    const tokenInputAmount = stakePool.poolTokenAmount + stakePool.unlockingPoolTokenAmount
    const poolToken = createTokenContract(Buffer.from(stakeTokenHolderHash, 'hex'), tokenInputAmount)
    const poolTokenTx = createInputTx(poolToken, undefined)
    addInput(tx, poolTokenTx.id, 0, poolToken.lockingScript, inputSatoshis, prevouts)

    // stakeTokenHolder
    const [stakeTokenHolder, stakeTokenHolderTx] = createStakeTokenHolderContract()
    addInput(tx, stakeTokenHolderTx.id, 0, stakeTokenHolder.lockingScript, stakeTokenHolderTx.outputs[0].satoshis, prevouts)

    // mvc optional
    let res
    // update stakePool
    if (options.wrongSender !== undefined || options.wrongBlockTime) {
        const address = options.wrongSender || senderAddress
        const tokenAmount = tokenRemoveAmount
        let data = stakePool.userData.get(address.hashBuffer)
        if (data == undefined) {
            throw Error('illegal user')
        }
        stakePool.updatePool(curBlockTime)

        data.addressBuf = senderAddress.hashBuffer
        data.rewardDebt -= tokenAmount *  stakePool.accPoolPerShare / stakePool.rewardAmountFactor
        data.tokenAmount -= tokenAmount
        res = stakePool.userData.updateLeaf(data)
        res.tokenAmount = tokenAmount

        stakePool.poolTokenAmount -= tokenAmount
        stakePool.unlockingPoolTokenAmount += tokenAmount
    } else {
        res = stakePool.withdraw(senderAddress.hashBuffer, tokenRemoveAmount, curBlockTime)
    }
    const oldLeafBuf = res.oldLeafBuf
    const merklePath = res.merklePath

    let tokenOutputAmounts = [res.tokenAmount]
    let tokenRemainAmount = tokenInputAmount - <bigint>res.tokenAmount
    let tokenOutputAddress = [senderAddress.hashBuffer]
    if (tokenRemainAmount > BigInt(0)) {
        tokenOutputAmounts.push(tokenRemainAmount)
        tokenOutputAddress.push(Buffer.from(stakeTokenHolderHash, 'hex'))
    }
    // unlockFromContractCheck
    const unlockContractCheck = createUnlockContractCheck([2], tokenOutputAmounts, tokenOutputAddress, tokenID)
    addInput(tx, dummyTxId, 0, unlockContractCheck.lockingScript, inputSatoshis, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    // stakeMain
    let scriptBuf = StakeProto.getNewStakeScript(stakeMain.lockingScript.toBuffer(), curBlockTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // user token
    scriptBuf = TokenProto.getNewTokenScript(poolToken.lockingScript.toBuffer(), senderAddress.hashBuffer, res.tokenAmount)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // pool token
    if (tokenRemainAmount > BigInt(0)) {
        scriptBuf = TokenProto.getNewTokenScript(poolToken.lockingScript.toBuffer(), Buffer.from(stakeTokenHolderHash, 'hex'), tokenRemainAmount)
        addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)
    }

    // change mvc(optional)

    let senderPubKey = toHex(privateKey.publicKey)
    let senderSig = toHex(signTx(tx, privateKey, withdrawContract.lockingScript, inputSatoshis, 0))
    if (options.useAdmin) {
        senderPubKey = toHex(adminPrivKey.publicKey)
        senderSig = toHex(signTx(tx, adminPrivKey, withdrawContract.lockingScript, inputSatoshis, 0))
    } else if (options.useWrongPrivKey) {
        senderPubKey = toHex(privateKey2.publicKey)
        senderSig = toHex(signTx(tx, privateKey2, withdrawContract.lockingScript, inputSatoshis, 0))
    }
    // withdraw
    unlockStakeWithdraw(tx, prevoutsBuf, withdrawContract, tokenRemoveAmount, senderPubKey, senderSig, stakeTx, poolTokenTx, <Buffer>oldLeafBuf, <Buffer>merklePath, 0, senderAddress, curBlockTime, options.expected)

    // stake
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, withdrawTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_WITHDRAW, contractHashArray, stakeSensibleID, options.stakeMainExpected)

    // stakeTokenHolder
    unlockStakeTokenHolder(tx, prevoutsBuf, stakeTokenHolder, 3, stakeTx, withdrawTx, contractHashArray, StakeProto.OP_WITHDRAW)
}

function preWithdraw(stakePool: StakePool, curBlockTime: number, tokenRemoveAmount: bigint, options: any = {}) {
    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []
    const senderAddress = address1

    // input
    // stakePreWithdraw
    const [withdrawContract, withdrawTx] = createStakePreWithdrawContract()
    addInput(tx, withdrawTx.id, 0, withdrawContract.lockingScript, withdrawTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeTx = createInputTx(stakeMain, prevStakeTx)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, inputSatoshis, prevouts)

    // mvc optional
    let res
    // update stakePool
    if (options.wrongSender !== undefined || options.wrongBlockTime) {
        const address = options.wrongSender || senderAddress
        const tokenAmount = tokenRemoveAmount
        let data = stakePool.userData.get(address.hashBuffer)
        if (data == undefined) {
            throw Error('illegal user')
        }
        stakePool.updatePool(curBlockTime)

        data.addressBuf = senderAddress.hashBuffer
        data.rewardDebt -= tokenAmount *  stakePool.accPoolPerShare / stakePool.rewardAmountFactor
        data.tokenAmount -= tokenAmount
        res = stakePool.userData.updateLeaf(data)

        stakePool.poolTokenAmount -= tokenAmount
        stakePool.unlockingPoolTokenAmount += tokenAmount
    } else {
        res = stakePool.preWithdraw(senderAddress.hashBuffer, tokenRemoveAmount, curBlockTime)
    }
    const oldLeafBuf = res.oldLeafBuf
    const merklePath = res.merklePath

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    // stakeMain
    let scriptBuf = StakeProto.getNewStakeScript(stakeMain.lockingScript.toBuffer(), curBlockTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // change mvc(optional)

    let senderPubKey = toHex(privateKey.publicKey)
    let senderSig = toHex(signTx(tx, privateKey, withdrawContract.lockingScript, inputSatoshis, 0))
    if (options.useAdmin) {
        senderPubKey = toHex(adminPrivKey.publicKey)
        senderSig = toHex(signTx(tx, adminPrivKey, withdrawContract.lockingScript, inputSatoshis, 0))
    } else if (options.useWrongPrivKey) {
        senderPubKey = toHex(privateKey2.publicKey)
        senderSig = toHex(signTx(tx, privateKey2, withdrawContract.lockingScript, inputSatoshis, 0))
    }
    // withdraw
    unlockStakePreWithdraw(tx, prevoutsBuf, withdrawContract, tokenRemoveAmount, senderPubKey, senderSig, stakeTx, <Buffer>oldLeafBuf, <Buffer>merklePath, 0, senderAddress, curBlockTime, options.expected)

    // stake
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, withdrawTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_PRE_WITHDRAW, contractHashArray, stakeSensibleID, options.stakeMainExpected)
}

function testFinishWithdrawMvc(stakePool: StakePool, curBlockTime: number, options: any = {}) {
    setMvcVersion()

    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []
    const senderAddress = address1

    // input
    // stakeWithdraw
    const [withdrawContract, withdrawTx] = createStakeFinishWithdrawMvcContract()
    addInput(tx, withdrawTx.id, 0, withdrawContract.lockingScript, withdrawTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeOutputSatoshis = Number(stakePool.poolTokenAmount + stakePool.unlockingPoolTokenAmount) + inputSatoshis
    const stakeTx = createInputTx(stakeMain, prevStakeTx, stakeOutputSatoshis)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, stakeOutputSatoshis, prevouts)

    // mvc optional
    let res
    // update stakePool
    if (options.wrongSender !== undefined || options.wrongBlockTime) {
        const address = options.wrongSender || senderAddress
        let data = stakePool.userData.get(address.hashBuffer)
        if (data == undefined) {
            throw Error('illegal user')
        }
        stakePool.updatePool(curBlockTime)

        const tokenAmount = data.getAllExpiredUnlocking(curBlockTime)
        res = stakePool.userData.updateLeaf(data)
        res.tokenAmount = tokenAmount
        stakePool.unlockingPoolTokenAmount -= tokenAmount
    } else {
        res = stakePool.finishWithdraw(senderAddress.hashBuffer, curBlockTime)
    }
    const oldLeafBuf = res.oldLeafBuf
    const merklePath = res.merklePath

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    // stakeMain
    let scriptBuf = StakeProto.getNewStakeScript(stakeMain.lockingScript.toBuffer(), curBlockTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)

    let newStakeOutputSatoshis = stakeOutputSatoshis - Number(res.tokenAmount)
    if (options.wrongOutputSatoshis) {
        newStakeOutputSatoshis += 1
    }
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), newStakeOutputSatoshis)

    // change mvc(optional)
    const changeSatoshis = Number(res.tokenAmount)
    addOutput(tx, mvc.Script.buildPublicKeyHashOut(senderAddress), changeSatoshis)

    let senderPubKey = toHex(privateKey.publicKey)
    let senderSig = toHex(signTx(tx, privateKey, withdrawContract.lockingScript, inputSatoshis, 0))
    if (options.useAdmin) {
        senderPubKey = toHex(privateKey3.publicKey)
        senderSig = toHex(signTx(tx, privateKey3, withdrawContract.lockingScript, inputSatoshis, 0))
    } else if (options.useWrongPrivKey) {
        senderPubKey = toHex(privateKey2.publicKey)
        senderSig = toHex(signTx(tx, privateKey2, withdrawContract.lockingScript, inputSatoshis, 0))
    }
    // withdraw
    unlockStakeFinishWithdrawMvc(tx, prevoutsBuf, withdrawContract, senderPubKey, senderSig, stakeTx, <Buffer>oldLeafBuf, <Buffer>merklePath, changeSatoshis, curBlockTime, options.expected)

    // stake
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, withdrawTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_FINISH_WITHDRAW, contractHashArray, stakeSensibleID, options.stakeMainExpected)
}

//TODO: fix the deposit and withdraw math floor error
//TODO: rewardDept is minus?

function testFinishWithdraw(stakePool: StakePool, curBlockTime: number, options: any = {}) {
    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []
    const senderAddress = address1

    // input
    // stakeWithdraw
    const [withdrawContract, withdrawTx] = createStakeFinishWithdrawContract()
    addInput(tx, withdrawTx.id, 0, withdrawContract.lockingScript, withdrawTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeTx = createInputTx(stakeMain, prevStakeTx)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, inputSatoshis, prevouts)

    // pool token
    const tokenInputAmount = stakePool.poolTokenAmount + stakePool.unlockingPoolTokenAmount
    const poolToken = createTokenContract(Buffer.from(stakeTokenHolderHash, 'hex'), tokenInputAmount)
    const poolTokenTx = createInputTx(poolToken, undefined)
    addInput(tx, poolTokenTx.id, 0, poolToken.lockingScript, inputSatoshis, prevouts)

    // stakeTokenHolder
    const [stakeTokenHolder, stakeTokenHolderTx] = createStakeTokenHolderContract()
    addInput(tx, stakeTokenHolderTx.id, 0, stakeTokenHolder.lockingScript, stakeTokenHolderTx.outputs[0].satoshis, prevouts)

    // mvc optional
    let res
    // update stakePool
    if (options.wrongSender !== undefined || options.wrongBlockTime) {
        const address = options.wrongSender || senderAddress
        let data = stakePool.userData.get(address.hashBuffer)
        if (data == undefined) {
            throw Error('illegal user')
        }
        stakePool.updatePool(curBlockTime)

        const tokenAmount = data.getAllExpiredUnlocking(curBlockTime)
        res = stakePool.userData.updateLeaf(data)
        res.tokenAmount = tokenAmount
        stakePool.unlockingPoolTokenAmount -= tokenAmount
    } else {
        res = stakePool.finishWithdraw(senderAddress.hashBuffer, curBlockTime)
    }
    const oldLeafBuf = res.oldLeafBuf
    const merklePath = res.merklePath

    let tokenOutputAmounts = [res.tokenAmount]
    let tokenRemainAmount = tokenInputAmount - <bigint>res.tokenAmount
    let tokenOutputAddress = [senderAddress.hashBuffer]
    if (tokenRemainAmount > BigInt(0)) {
        tokenOutputAmounts.push(tokenRemainAmount)
        tokenOutputAddress.push(Buffer.from(stakeTokenHolderHash, 'hex'))
    }
    // unlockFromContractCheck
    const unlockContractCheck = createUnlockContractCheck([2], tokenOutputAmounts, tokenOutputAddress, tokenID)
    addInput(tx, dummyTxId, 0, unlockContractCheck.lockingScript, inputSatoshis, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    // stakeMain
    let scriptBuf = StakeProto.getNewStakeScript(stakeMain.lockingScript.toBuffer(), curBlockTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // user token
    scriptBuf = TokenProto.getNewTokenScript(poolToken.lockingScript.toBuffer(), senderAddress.hashBuffer, res.tokenAmount)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // pool token
    if (tokenRemainAmount > BigInt(0)) {
        scriptBuf = TokenProto.getNewTokenScript(poolToken.lockingScript.toBuffer(), Buffer.from(stakeTokenHolderHash, 'hex'), tokenRemainAmount)
        addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)
    }

    // change mvc(optional)

    let senderPubKey = toHex(privateKey.publicKey)
    let senderSig = toHex(signTx(tx, privateKey, withdrawContract.lockingScript, inputSatoshis, 0))
    if (options.useAdmin) {
        senderPubKey = toHex(privateKey3.publicKey)
        senderSig = toHex(signTx(tx, privateKey3, withdrawContract.lockingScript, inputSatoshis, 0))
    } else if (options.useWrongPrivKey) {
        senderPubKey = toHex(privateKey2.publicKey)
        senderSig = toHex(signTx(tx, privateKey2, withdrawContract.lockingScript, inputSatoshis, 0))
    }
    // withdraw
    unlockStakeFinishWithdraw(tx, prevoutsBuf, withdrawContract, senderPubKey, senderSig, stakeTx, poolTokenTx, <Buffer>oldLeafBuf, <Buffer>merklePath, 0, senderAddress, curBlockTime, options.expected)

    // stake
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, withdrawTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_FINISH_WITHDRAW, contractHashArray, stakeSensibleID, options.stakeMainExpected)

    // stakeTokenHolder
    unlockStakeTokenHolder(tx, prevoutsBuf, stakeTokenHolder, 3, stakeTx, withdrawTx, contractHashArray, StakeProto.OP_FINISH_WITHDRAW)
}

function harvest(stakePool: StakePool, curBlockTime: number, options: any = {}) {
    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []
    const senderAddress = address1

    // input
    // harvest
    const [harvestContract, harvestTx] = createStakeHarvestContract()
    addInput(tx, harvestTx.id, 0, harvestContract.lockingScript, harvestTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeTx = createInputTx(stakeMain, prevStakeTx)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, inputSatoshis, prevouts)

    const rewardTokenAmount = BigInt(2 ** 60)
    // pool reward token
    const poolRewardToken = createTokenContract(Buffer.from(stakeRewardTokenHolderHash, 'hex'), rewardTokenAmount, true)
    const rewardTokenTx = createInputTx(poolRewardToken, undefined)
    addInput(tx, rewardTokenTx.id, 0, poolRewardToken.lockingScript, inputSatoshis, prevouts)

    // stakeRewardTokenHolder
    const [stakeRewardTokenHolder, stakeRewardTokenHolderTx] = createStakeRewardTokenHolderContract()
    addInput(tx, stakeRewardTokenHolderTx.id, 0, stakeRewardTokenHolder.lockingScript, stakeRewardTokenHolderTx.outputs[0].satoshis, prevouts)

    // mvc optional

    // update stakePool
    let res
    if (options.wrongSender !== undefined || options.wrongBlockTime) {
        const address = options.wrongSender || senderAddress
        let data = stakePool.userData.get(address.hashBuffer)
        if (!data) {
            throw Error('illegal user')
        }

        stakePool.updatePool(curBlockTime)

        const accReward = data.tokenAmount * stakePool.accPoolPerShare / stakePool.rewardAmountFactor
        const pendingReward = accReward - data.rewardDebt

        data.rewardDebt = accReward

        if (pendingReward < BigInt(0)) {
            throw Error('pendingReward is illegal ' + String(pendingReward))
        }

        res = stakePool.userData.updateLeaf(data)
        res.pendingReward = pendingReward
    } else {
        res = stakePool.harvest(senderAddress.hashBuffer, curBlockTime)
    }
    let pendingReward = res.pendingReward 
    const oldLeafBuf = res.oldLeafBuf
    const merklePath = res.merklePath

    pendingReward = <BigInt>pendingReward

    // unlockFromContractCheck
    let tokenOutputAmounts = [pendingReward]
    let tokenOutputAddress = [senderAddress.hashBuffer]
    let remainRewardTokenAmount: bigint = rewardTokenAmount - pendingReward
    if (remainRewardTokenAmount > BigInt(0)) {
        tokenOutputAmounts.push(remainRewardTokenAmount)
        tokenOutputAddress.push(Buffer.from(stakeRewardTokenHolderHash, 'hex'))
    }
    const unlockContractCheck = createUnlockContractCheck([2], tokenOutputAmounts, tokenOutputAddress, rewardTokenID)
    addInput(tx, dummyTxId, 0, unlockContractCheck.lockingScript, inputSatoshis, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    // stakeMain
    let scriptBuf = StakeProto.getNewStakeScript(stakeMain.lockingScript.toBuffer(), curBlockTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // user token
    scriptBuf = TokenProto.getNewTokenScript(poolRewardToken.lockingScript.toBuffer(), senderAddress.hashBuffer, pendingReward)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // pool token
    if (remainRewardTokenAmount > BigInt(0)) {
        scriptBuf = TokenProto.getNewTokenScript(poolRewardToken.lockingScript.toBuffer(), Buffer.from(stakeRewardTokenHolderHash, 'hex'), remainRewardTokenAmount)
        addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)
    }

    // change mvc(optional)

    // verify
    // harvest
    const senderPubKey = toHex(privateKey.publicKey)
    const senderSig = toHex(signTx(tx, privateKey, harvestContract.lockingScript, inputSatoshis, 0))
    unlockStakeHarvest(tx, prevoutsBuf, harvestContract, senderPubKey, senderSig, stakeTx, rewardTokenTx, <Buffer>oldLeafBuf, <Buffer>merklePath, 0, senderAddress, curBlockTime, options.expected)

    // stake
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, harvestTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_HARVEST, contractHashArray, stakeSensibleID, options.stakeMainExpected)

    // stakeRewardTokenHolder
    let pubKeyHex = toHex(privateKey.publicKey)
    let sigHex = toHex(signTx(tx, privateKey, harvestContract.lockingScript, inputSatoshis, 0))
    unlockStakeRewardTokenHolder(tx, prevoutsBuf, stakeRewardTokenHolder, 3, pubKeyHex, sigHex, stakeTx, harvestTx, contractHashArray, StakeProto.STAKE_UNLOCK_FROM_CONTRACT)
}

function admin(stakePool: StakePool, rewardAmountPerSecond: bigint, lastRewardTime: number, options: any = {}) {
    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []

    // input
    // harvest
    const [adminContract, adminTx] = createStakeAdminContract()
    addInput(tx, adminTx.id, 0, adminContract.lockingScript, adminTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeTx = createInputTx(stakeMain, prevStakeTx)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, inputSatoshis, prevouts)

    // mvc optional

    const prevoutsBuf = Buffer.concat(prevouts)

    const withdrawInterval = options.withdrawLockInterval !== undefined ? options.withdrawLockInterval : withdrawLockInterval
    // output
    let scriptBuf = StakeProto.getNewStakeScriptFromAdmin(stakeMain.lockingScript.toBuffer(), rewardAmountPerSecond, lastRewardTime, withdrawInterval)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // verify
    // admin
    const privKey = options.wrongPrivKey || adminPrivKey
    const senderAddress = privKey.toAddress()
    const pubKey = toHex(privKey.publicKey)
    const adminSig = toHex(signTx(tx, privKey, adminContract.lockingScript, inputSatoshis, 0))
    unlockStakeAdmin(tx, prevoutsBuf, adminContract, 0, pubKey, adminSig, stakeTx, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, lastRewardTime, withdrawInterval, senderAddress, 0, options.expected)

    // stake
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, adminTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_ADMIN, contractHashArray, stakeSensibleID, options.stakeMainExpected)
}

function mergeRewardToken(rewardTokenAmountArray: bigint[], options: any = {}) {
    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []

    // input
    // mergeRewardToken
    const [mergeRewardTokenContract, mergeRewardTokenTx] = createMergeRewardToken()
    addInput(tx, mergeRewardTokenTx.id, 0,mergeRewardTokenContract.lockingScript, mergeRewardTokenTx.outputs[0].satoshis, prevouts)

    // pool reward token
    let sumInputTokenAmount = BigInt(0)
    let poolRewardTokenTxs: any = []
    let poolRewardToken
    for (let i = 0; i < 2; i++) {
        poolRewardToken = createTokenContract(Buffer.from(stakeRewardTokenHolderHash, 'hex'), rewardTokenAmountArray[i], true)
        const tokenTx = createInputTx(poolRewardToken, undefined)
        addInput(tx, tokenTx.id, 0, poolRewardToken.lockingScript, inputSatoshis, prevouts)
        poolRewardTokenTxs.push(tokenTx)
        sumInputTokenAmount += rewardTokenAmountArray[i]
    }

    // stakeRewardTokenHolder
    const [stakeRewardTokenHolder, stakeRewardTokenHolderTx] = createStakeRewardTokenHolderContract()
    addInput(tx, stakeRewardTokenHolderTx.id, 0, stakeRewardTokenHolder.lockingScript, stakeRewardTokenHolderTx.outputs[0].satoshis, prevouts)

    // mvc optional

    // unlockFromContractCheck
    let tokenOutputAmounts = [sumInputTokenAmount]
    let tokenOutputAddress = [Buffer.from(stakeRewardTokenHolderHash, 'hex')]
    const unlockContractCheck = createUnlockContractCheck([1, 2], tokenOutputAmounts, tokenOutputAddress, rewardTokenID)
    addInput(tx, dummyTxId, 0, unlockContractCheck.lockingScript, inputSatoshis, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    const addressBuf = options.wrongAddress? options.wrongAddress.hashBuffer: Buffer.from(stakeRewardTokenHolderHash, 'hex')
    let scriptBuf = TokenProto.getNewTokenScript(poolRewardToken.lockingScript.toBuffer(), addressBuf, sumInputTokenAmount)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // verify

    // mergeRewardToken
    unlockStakeMergeRewardToken(tx, prevoutsBuf, mergeRewardTokenContract, poolRewardTokenTxs, address1, 0, options.expected)

    // poolRewrdTokenHolder
    const pubKeyHex = Buffer.alloc(33, 0).toString('hex')
    const sigHex = Buffer.alloc(72, 0).toString('hex')
    unlockStakeRewardTokenHolder(tx, prevoutsBuf, stakeRewardTokenHolder, 3, pubKeyHex, sigHex, undefined, mergeRewardTokenTx, Buffer.alloc(0), StakeProto.STAKE_UNLOCK_FROM_CONTRACT)
}

function takeBackRewardToken(options: any = {}) {
    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []

    // inputs
    // stakeRewardTokenHolder
    const [stakeRewardTokenHolder, stakeRewardTokenHolderTx] = createStakeRewardTokenHolderContract()
    addInput(tx, stakeRewardTokenHolderTx.id, 0, stakeRewardTokenHolder.lockingScript, stakeRewardTokenHolderTx.outputs[0].satoshis, prevouts)

    // poolRewardToken
    const rewardTokenAmount = BigInt(100000)
    let poolRewardToken = createTokenContract(Buffer.from(stakeRewardTokenHolderHash, 'hex'), rewardTokenAmount, true)
    if (options.otherToken) {
        console.log('takeBack other token instead of pool token')
        poolRewardToken = createTokenContract(Buffer.from(stakeRewardTokenHolderHash, 'hex'), rewardTokenAmount, false)
    }
    addInput(tx, dummyTxId, 0, poolRewardToken.lockingScript, inputSatoshis, prevouts)

    if (options.moreInput) {
        addInput(tx, dummyTxId, 0, mvc.Script.buildPublicKeyHashOut(address1), inputSatoshis, prevouts)
    }

    const privKey = options.wrongPrivKey || adminPrivKey

    // unlockFromContractCheck
    let tokenOutputAmounts = [rewardTokenAmount]
    let tokenOutputAddress = [privKey.toAddress().hashBuffer]
    const unlockContractCheck = createUnlockContractCheck([1], tokenOutputAmounts, tokenOutputAddress, rewardTokenID)
    addInput(tx, dummyTxId, 0, unlockContractCheck.lockingScript, inputSatoshis, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // output
    let scriptBuf = TokenProto.getNewTokenScript(poolRewardToken.lockingScript.toBuffer(), privKey.toAddress().hashBuffer, rewardTokenAmount)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    const pubKeyHex = toHex(adminPubKey)
    const sigHex = toHex(signTx(tx, privKey, stakeRewardTokenHolder.lockingScript, inputSatoshis, 0))
    unlockStakeRewardTokenHolder(tx, prevoutsBuf, stakeRewardTokenHolder, 0, pubKeyHex, sigHex, undefined, undefined, Buffer.alloc(0), StakeProto.STAKE_UNLOCK_FROM_ADMIN, options.expected)
}

function createUpdateContract() {
    const updateContract = new StakeUpdateContract(new Bytes(stakeID))
    const data = Common.buildScriptData(Buffer.concat([
        Buffer.from(stakeTokenHolderHash, 'hex'),
        Buffer.from(stakeRewardTokenHolderHash, 'hex'),
        Buffer.from(stakeMainCodeHash, 'hex'),
    ]))
    updateContract.setDataPart(data.toString('hex'))

    const tx = createContracTx(updateContract.lockingScript)
    return [updateContract, tx]
}

function testUpdateContractRoot(stakePool: StakePool, newConctractHashRoot: Buffer, curBlockTime: number, options: any = {}) {

    let prevouts = []

    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION

    // updateContract
    const [updateContract, updateContractTx] = createUpdateContract()
    addInput(tx, updateContractTx.id, 0, updateContract.lockingScript, updateContractTx.outputs[0].satoshis, prevouts)

    // stake
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeTx = createInputTx(stakeMain, prevStakeTx)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, inputSatoshis, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // change mvc(option)
    const changeSatoshis = 0
    const changeAddress = ownerAddress

    // output
    let scriptBuf = StakeProto.getNewStakeScriptFromContractHashRoot(stakeMain.lockingScript.toBuffer(), newConctractHashRoot)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // verify    
    let privKey = ownerPrivKey
    if (options.wrongPrivKey) {
        privKey = options.wrongPrivKey
    }
    const ownerPubKeyHex = toHex(ownerPrivKey.publicKey)
    const ownerSigHex = toHex(signTx(tx, privKey, updateContract.lockingScript, inputSatoshis, 0, sigtype))
    unlockUpdateContract(tx, prevoutsBuf, updateContract, newConctractHashRoot, ownerPubKeyHex, ownerSigHex, stakeTx, changeSatoshis, changeAddress, options.expect)

    // stakeMain
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, updateContractTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_UPDATE_CONTRACT, contractHashArray, stakeSensibleID, options.stakeMainExpected)

    return tx
}

function testUpdateContractHashRoot(options: any = {}) {
    contractHashArray = Buffer.concat([
        Buffer.from(stakeUpdateContractCodeHash, 'hex'),
        Buffer.from(stakeDepositCodeHash, 'hex'),
    ])
    contractHashRoot = mvc.crypto.Hash.sha256ripemd160(contractHashArray)

    let stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)

    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)

    deposit(stakePool, rewardBeginTime + 1, BigInt(10000), {stakeMain})
    preWithdraw(stakePool, rewardBeginTime + 1, BigInt(10000), {stakeMain, expected: false, stakeMainExpected: false, tokenHolderExpected: false})

    contractHashArray = Buffer.concat([
        Buffer.from(stakeUpdateContractCodeHash, 'hex'),
        Buffer.from(stakeDepositCodeHash, 'hex'),
        Buffer.from(stakeWithdrawCodeHash, 'hex'),
        Buffer.from(stakePreWithdrawCodeHash, 'hex'),
        Buffer.from(stakeFinishWithdrawCodeHash, 'hex'),
        Buffer.from(stakeHarvestCodeHash, 'hex'),
        Buffer.from(stakeAdminCodeHash, 'hex'),
        Buffer.from(stakeVoteCodeHash, 'hex'),
    ])
    contractHashRoot = mvc.crypto.Hash.sha256ripemd160(contractHashArray)

    //let res = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot, 0)
    //stakeMain = res.stakeMain
    //testDeposit(stakePool, 1, BigInt(10000), {stakeMain})
    //testWithdraw(stakePool, 1, BigInt(10000), {stakeMain, stakeMainExpected: true})
}

function vote(stakePool: StakePool, curBlockTime: number, voteDataTree: VoteDataTree, voteOption, confirmVote, options: any = {}) {
    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts = []
    const senderAddress = address1
    let beginBlockTime = curBlockTime
    let endBlockTime = beginBlockTime + 10
    
    // input
    // stakeVote
    const [stakeVoteContract, stakeVoteTx] = createStakeVoteContract()
    addInput(tx, stakeVoteTx.id, 0, stakeVoteContract.lockingScript, stakeVoteTx.outputs[0].satoshis, prevouts)

    // stakeMain
    let stakeMain = createStakeMain(stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, stakePool.userDataMerkleRoot)
    if (options.stakeMain) {
        stakeMain = options.stakeMain
    }
    const prevStakeTx = createInputTx(stakeMain, undefined)
    const stakeTx = createInputTx(stakeMain, prevStakeTx)
    addInput(tx, stakeTx.id, 0, stakeMain.lockingScript, inputSatoshis, prevouts)

    // voteMain
    let voteMain = createVoteMainContract(beginBlockTime, endBlockTime, voteDataTree)
    const prevVoteTx = createInputTx(voteMain, undefined)
    const voteTx = createInputTx(voteMain, prevVoteTx)
    addInput(tx, voteTx.id, 0, voteMain.lockingScript, inputSatoshis, prevouts)

    const prevoutsBuf = Buffer.concat(prevouts)

    // mvc options

    const oldVoteSumData = voteDataTree.serializeSumData()
    // update voteDataTree
    const voteAmount = stakePool.getUserTokenAmount(senderAddress.hashBuffer)
    const voteRes = voteDataTree.vote(senderAddress.hashBuffer, voteOption, confirmVote, voteAmount)

    // output
    // stake
    addOutput(tx, stakeMain.lockingScript, inputSatoshis)

    // voteMain
    let scriptBuf = VoteProto.getNewVoteScript(voteMain.lockingScript.toBuffer(), voteDataTree.merkleRoot, voteDataTree.sumDataHashRoot)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // unlock

    // stakeVote
    const pubKeyHex = toHex(privateKey.publicKey)
    const sigHex = toHex(signTx(tx, privateKey, stakeVoteContract.lockingScript, inputSatoshis, 0, sigtype))
    let stakeLeafNode = stakePool.getUserInfo(senderAddress.hashBuffer)
    if (!stakeLeafNode) {
        stakeLeafNode = LeafNode.EmptyLeafNode()
    }
    const stakeLeaf = stakeLeafNode.serialize()
    const stakeMerklePath = <Buffer>stakePool.getUserMerklePath(senderAddress.hashBuffer)
    unlockStakeVote(tx, prevoutsBuf, stakeVoteContract, pubKeyHex, sigHex, confirmVote, voteOption, stakeTx, voteTx, stakeLeaf, stakeMerklePath, voteRes.oldLeafBuf, voteRes.merklePath, oldVoteSumData, curBlockTime, senderAddress, 0, options.expected)

    // stakeMain
    const prevStakeTxInputIndex = 0
    unlockStakeMain(tx, prevoutsBuf, stakeMain, 1, stakeVoteTx, stakeTx, prevStakeTxInputIndex, prevStakeTx, StakeProto.OP_VOTE, contractHashArray, stakeSensibleID, options.stakeMainExpected)

    // voteMain
    const prevVoteTxInputIndex = 0
    unlockVoteMain(tx, prevoutsBuf, voteMain, 2, stakeVoteTx, voteTx, prevVoteTxInputIndex, prevVoteTx, VoteProto.OP_STAKE_VOTE, voteContractHashArray, voteSensibleID, options.voteMainExpected)
}

describe('Test stake contract unlock In Javascript', () => {
    let stakePool: StakePool

    before(() => {
        initContractHash()
    });

    beforeEach(() => {
        stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
    })

    it('rr1: should success when refund deposit', () => {
        refundDeposit()
    })

    //TODO: refund to wrong address

    it('d1: should success when deposit', () => {
        deposit(stakePool, 1, BigInt(10000))
    })

    it('d2: should success when deposit with poolTokenAmount', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(10000), 0)
        deposit(stakePool, 10, BigInt(10000))
    })

    it('d3: should success when deposit update', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 0)
        deposit(stakePool, 7, BigInt(10000))
    })

    it('d4: should failed when curBlockTime less than lastRewardTime', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 2, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
        stakePool.deposit(address2.hashBuffer, BigInt(10000), 2)
        deposit(stakePool, 1, BigInt(10000), {wrongBlockTime: true, expected: false})
    })

    it('d5: should failed when deposit with wrong rabin sig', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 2, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
        stakePool.deposit(address2.hashBuffer, BigInt(10000), 2)
        deposit(stakePool, 2, BigInt(10000), {wrongBlockRabinSig: true, expected: false})
    })

    it('d6: should failed when deposit with wrongSender', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(10000), 0)
        deposit(stakePool, 1, BigInt(10000), {wrongSender: address2, expected: false})
    })

    it('d7: should failed when deposit with tokenAmountAdd', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 0)
        deposit(stakePool, 1, BigInt(10000), {tokenAmountAdd: BigInt(1000), expected: false})
    })

    it('d8: should failed when deposit with wrong oldLeaf', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 0)
        deposit(stakePool, 1, BigInt(10000), {wrongOldLeaf: true, expected: false})
    })

    it('d9: should success when deposit with huge rewardDebt', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(1), rewardBeginTime)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(1), 10000000 + rewardBeginTime)
        deposit(stakePool, 10000004 + rewardBeginTime, BigInt(100000000000))
        const num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt

        const remain = <bigint>num - BigInt('99999999999000000000000000')
        expect(remain).equal(BigInt(0))
    })

    it('d010: should success when deposit after unlock', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(10000000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(10000), 1)
        deposit(stakePool, 10000004, BigInt(100000000000))
    })

    it('d011: should success when deposit after unlock', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(10000000), 0)
        stakePool.preWithdraw(address2.hashBuffer, BigInt(10000000), 1)
        stakePool.harvest(address2.hashBuffer, 1)
        deposit(stakePool, 2, BigInt(100000000000))
    })

    it('d012: should success when test rewardBeginTime and rewardEndTime', () => {
        deposit(stakePool, 2, BigInt(100000000000))
        let num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt
        expect(num).equal(0n)

        preWithdraw(stakePool, rewardBeginTime - 1, BigInt(100000000000))
        num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt
        expect(num).equal(0n)

        deposit(stakePool, rewardBeginTime + 100, BigInt(10000))
        num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt

        harvest(stakePool, rewardEndTime + 10000)
        num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt
        const res = BigInt(rewardEndTime - rewardBeginTime - 100) * rewardAmountPerSecond
        expect(num).equal(res)
    })

    it('w0: should success when withdraw', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        testWithdraw(stakePool, 1, BigInt(10000))
    })

    it('w1: should success when withdraw all', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        testWithdraw(stakePool, 1, BigInt(100000))
    })

    it('w2: should failed when withdaw others', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address2.hashBuffer, BigInt(100000), 0)
        testWithdraw(stakePool, 1, BigInt(10000), {wrongSender: address2, expected: false})
    })

    it('w3: should failed when withdraw with wrong curBlockTime', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 2, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 2)
        testWithdraw(stakePool, 1, BigInt(10000), {wrongBlockTime: true, expected: false})
    })

    it('w4: should success when withdraw use admin key', async () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        testWithdraw(stakePool, 1, BigInt(100000), {useAdmin: true})
    })

    it('w5: should failed when withdraw use wrong priv key', async () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        testWithdraw(stakePool, 1, BigInt(100000), {useWrongPrivKey: true, expected: false})
    })

    it('wp00: should success when pre withdraw', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        preWithdraw(stakePool, 1, BigInt(10000))
    })

    it('wp1: should success when pre withdraw all', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        preWithdraw(stakePool, 1, BigInt(100000))
    })

    it('wp2: should failed when pre withdaw others', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(100000), 0)
        preWithdraw(stakePool, 1, BigInt(10000), {wrongSender: address2, expected: false})
    })

    it('wp3: should failed when pre withdraw with wrong curBlockTime', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 2, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 2)
        preWithdraw(stakePool, 1, BigInt(10000), {wrongBlockTime: true, expected: false})
    })

    it('wp4: should success when pre withdraw use admin key', async () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        preWithdraw(stakePool, 1, BigInt(100000), {useAdmin: true})
    })

    it('wp5: should failed when pre withdraw use wrong priv key', async () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        preWithdraw(stakePool, 1, BigInt(100000), {useWrongPrivKey: true, expected: false})
    })

    // finishWithdraw
    it('wf1: should success when finish withdraw', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(50000), 1)
        testFinishWithdraw(stakePool, 1 + withdrawLockInterval)
    })

    it('wf2: should success when finish withdraw all', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(100000), 1)
        testFinishWithdraw(stakePool, 1 + withdrawLockInterval)
    })

    it('wf3: should success when finish withdraw much times', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        for (let i = 0; i < 10; i++) {
            stakePool.preWithdraw(address1.hashBuffer, BigInt(5000), 1)
        }
        testFinishWithdraw(stakePool, 1 + withdrawLockInterval)
    })

    it('wf4: should success when finish withdraw with wrong privKey', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(50000), 1)
        testFinishWithdraw(stakePool, 1 + withdrawLockInterval, {useWrongPrivKey: true, expected: false})
    })

    it('wf5: should success when finish withdraw with admin privKey', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(50000), 1)
        testFinishWithdraw(stakePool, 1 + withdrawLockInterval, {useAdmin: true, expected: true})
    })

    it('wf6: should success when finish withdraw with wrong sender', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address2.hashBuffer, BigInt(50000), 1)
        testFinishWithdraw(stakePool, 1 + withdrawLockInterval, {wrongSender: address2, expected: false})
    })

    it('wf7: should success when change withdrawLockInterval', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        let curBlockTime = 1
        stakePool.preWithdraw(address1.hashBuffer, BigInt(1000), curBlockTime)
        curBlockTime = 50
        stakePool.preWithdraw(address1.hashBuffer, BigInt(4000), curBlockTime)
        const newWithdrawLockInterval = 50
        stakePool.admin(rewardAmountPerSecond, curBlockTime, newWithdrawLockInterval)
        curBlockTime = 70
        stakePool.preWithdraw(address1.hashBuffer, BigInt(2000), curBlockTime)

        curBlockTime = 130
        testFinishWithdraw(stakePool, curBlockTime)

        const userInfo = stakePool.getUserInfo(address1.hashBuffer)
        expect(userInfo?.unlockingTokens.length).equal(1)
        expect(userInfo?.unlockingTokens[0].amount).equal(BigInt(4000))
        expect(userInfo?.unlockingTokens[0].expired).equal(150)
    })

    it('wf8: should success when change withdrawLockInterval', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        let curBlockTime = 1
        stakePool.preWithdraw(address1.hashBuffer, BigInt(1000), curBlockTime)
        curBlockTime = 50
        for (let i = 0; i < 4; i++) {
            stakePool.preWithdraw(address1.hashBuffer, BigInt(4000 + i), curBlockTime)
        }
        const newWithdrawLockInterval = 50
        stakePool.admin(rewardAmountPerSecond, curBlockTime, newWithdrawLockInterval)
        curBlockTime = 70
        stakePool.preWithdraw(address1.hashBuffer, BigInt(2000), curBlockTime)

        curBlockTime = 130
        testFinishWithdraw(stakePool, curBlockTime)

        let userInfo = stakePool.getUserInfo(address1.hashBuffer)
        expect(userInfo?.unlockingTokens.length).equal(5)
        expect(userInfo?.unlockingTokens[4].amount).equal(BigInt(2000))
        expect(userInfo?.unlockingTokens[4].expired).equal(120)

        curBlockTime = 150
        testFinishWithdraw(stakePool, curBlockTime)
        userInfo = stakePool.getUserInfo(address1.hashBuffer)
        expect(userInfo?.unlockingTokens.length).equal(0)
    })

    it('h1: should success when harvest', async () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        await harvest(stakePool, 1 + rewardBeginTime)
    })

    it('h2: should failed when harvest with wrong curBlockTime', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 2, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 2 + rewardBeginTime)
        harvest(stakePool, 1 + rewardBeginTime, {wrongBlockTime: true, expected: false})
    })

    it('h3: should failed when harvest with wrong sender', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(100000), 0)
        harvest(stakePool, 1 + rewardBeginTime, {wrongSender: address2, expected: false})
    })

    it('h4: should success when harvest', async () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), rewardBeginTime)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(100000), 5 + rewardBeginTime)
        await harvest(stakePool, 6 + rewardBeginTime)
    })

    it('a1: should success when admin', () => {
        admin(stakePool, BigInt(9999), 2)
    })

    it('a2: should failed when admin with wrong privateKey', () => {
        admin(stakePool, BigInt(9999), 2, {wrongPrivKey: privateKey2, expected: false})
    })

    it('a3: should failed when setting withdrawLockInterval to 0', () => {
        admin(stakePool, BigInt(9999), 2, {withdrawLockInterval: 0, expected: false})
    })

    it('m1: should success when merge reward token', () => {
        mergeRewardToken([BigInt(100), BigInt(300)])
    })

    it('m2: should success when merge reward token with wrong address', () => {
        mergeRewardToken([BigInt(100), BigInt(300)], {wrongAddress: address1, expected: false})
    })

    it('t00: should success when take back reward token', () => {
        takeBackRewardToken()
    })

    it('t1: should success when take back other reward token', () => {
        takeBackRewardToken({otherToken: true})
    })

    it('t2: should failed when take back reward token with more input', () => {
        takeBackRewardToken({moreInput: true, expected: false})
    })

    it('t3: should failed when take back reward token with wrong privateKey', () => {
        takeBackRewardToken({wrongPrivKey: privateKey2, expected: false})
    })

    // vote
    it('v1: should success when vote', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        const curBlockTime = 1
        const voteSumData = [BigInt(0), BigInt(0)]
        const voteDataTree = new VoteDataTree([], voteSumData)
        const voteOption = 0
        const confirmVote = true
        vote(stakePool, curBlockTime, voteDataTree, voteOption, confirmVote)
    })

    it('v2: should success when cancel vote', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        const curBlockTime = 1
        const voteSumData = [BigInt(0), BigInt(0)]
        const voteDataTree = new VoteDataTree([], voteSumData)
        voteDataTree.vote(address1.hashBuffer, 0, true, BigInt(100000))
        const voteOption = 0
        const confirmVote = false
        vote(stakePool, curBlockTime, voteDataTree, voteOption, confirmVote)
    })

    it('v3: should success when vote different option again', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        const curBlockTime = 1
        const voteSumData = [BigInt(0), BigInt(0)]
        const voteDataTree = new VoteDataTree([], voteSumData)
        voteDataTree.vote(address1.hashBuffer, 0, true, BigInt(100000))
        const voteOption = 1
        const confirmVote = true
        vote(stakePool, curBlockTime, voteDataTree, voteOption, confirmVote)
    })

    it('v4: should success when vote the same option again', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        const curBlockTime = 1
        const voteSumData = [BigInt(0), BigInt(0)]
        const voteDataTree = new VoteDataTree([], voteSumData)
        voteDataTree.vote(address1.hashBuffer, 0, true, BigInt(10000))
        const voteOption = 0
        const confirmVote = true
        vote(stakePool, curBlockTime, voteDataTree, voteOption, confirmVote)
    })

    /*it('v5: should failed when vote with wrong address', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
        stakePool.deposit(address2.hashBuffer, BigInt(100000), 0)
        const curBlockTime = 1
        const voteSumData = [BigInt(0), BigInt(0)]
        const voteDataTree = new VoteDataTree([], voteSumData)
        const voteOption = 0
        const confirmVote = true
        vote(stakePool, curBlockTime, voteDataTree, voteOption, confirmVote, {expected: false})
    })*/

    it('uc1: should succeed when update hashMerkleRoot', () => {
        const newHashMerkleRoot = Buffer.alloc(32, 0)
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
        testUpdateContractRoot(stakePool, newHashMerkleRoot, 1)
    })

    it('uc2: should failed when update contractHashRoot with wrong priv key', () => {
        const newHashMerkleRoot = Buffer.alloc(32, 0)
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
        testUpdateContractRoot(stakePool, newHashMerkleRoot, 1, {wrongPrivKey: privateKey2, expect: false})
    })

    it('uc3: should succeed when update stakeMain to right hashMerkleRoot', () => {
        testUpdateContractHashRoot()
    })

    it('dm1: should success when deposit', () => {
        depositMvc(stakePool, 1, BigInt(10000))
    })

    it('dm2: should success when deposit with poolTokenAmount', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(10000), 0)
        depositMvc(stakePool, 10, BigInt(10000))
    })

    it('dm3: should success when deposit update', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 0)
        depositMvc(stakePool, 7, BigInt(10000))
    })

    it('dm4: should failed when curBlockTime less than lastRewardTime', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 2, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
        stakePool.deposit(address2.hashBuffer, BigInt(10000), 2)
        depositMvc(stakePool, 1, BigInt(10000), {wrongBlockTime: true, expected: false})
    })

    it('dm5: should failed when deposit with wrong rabin sig', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 2, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), withdrawLockInterval)
        stakePool.deposit(address2.hashBuffer, BigInt(10000), 2)
        depositMvc(stakePool, 2, BigInt(10000), {wrongBlockRabinSig: true, expected: false})
    })

    it('dm6: should failed when deposit with wrongSender', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(10000), 0)
        depositMvc(stakePool, 1, BigInt(10000), {wrongSender: address2, expected: false})
    })

    it('dm7: should failed when deposit with tokenAmountAdd', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 0)
        depositMvc(stakePool, 1, BigInt(10000), {tokenAmountAdd: BigInt(1000), expected: false})
    })

    it('dm8: should failed when deposit with wrong oldLeaf', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 0)
        depositMvc(stakePool, 1, BigInt(10000), {wrongOldLeaf: true, expected: false})
    })

    it('dm9: should success when deposit with huge rewardDebt', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(1), rewardBeginTime)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(1), 10000000 + rewardBeginTime)
        depositMvc(stakePool, 10000004 + rewardBeginTime, BigInt(100000000000))
        const num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt

        const remain = <bigint>num - BigInt('99999999999000000000000000')
        expect(remain).equal(BigInt(0))
    })

    it('dm010: should success when deposit after unlock', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(10000000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(10000), 1)
        depositMvc(stakePool, 10000004, BigInt(100000000000))
    })

    it('dm011: should success when deposit after unlock', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(10000000), 0)
        stakePool.preWithdraw(address2.hashBuffer, BigInt(10000000), 1)
        stakePool.harvest(address2.hashBuffer, 1)
        depositMvc(stakePool, 2, BigInt(100000000000))
    })

    it('dm012: should success when test rewardBeginTime and rewardEndTime', () => {
        depositMvc(stakePool, 2, BigInt(100000000000))
        let num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt
        expect(num).equal(0n)

        preWithdraw(stakePool, rewardBeginTime - 1, BigInt(100000000000))
        num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt
        expect(num).equal(0n)

        depositMvc(stakePool, rewardBeginTime + 100, BigInt(10000))
        num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt

        harvest(stakePool, rewardEndTime + 10000)
        num = stakePool.getUserInfo(address1.hashBuffer)?.rewardDebt
        const res = BigInt(rewardEndTime - rewardBeginTime - 100) * rewardAmountPerSecond
        expect(num).equal(res)
    })

    it('dm013: should failed when deposit with wrong output satoshis', () => {
        depositMvc(stakePool, 1, BigInt(10000), {wrongOutputSatoshis: true, expected: false})
    })

    it('wm1: should success when withdraw all', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        testWithdrawMvc(stakePool, 1, BigInt(100000))
    })

    it('wm2: should failed when withdaw others', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address2.hashBuffer, BigInt(100000), 0)
        testWithdrawMvc(stakePool, 1, BigInt(10000), {wrongSender: address2, expected: false})
    })

    it('wm3: should failed when withdraw with wrong curBlockTime', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 2, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(10000), 2)
        testWithdrawMvc(stakePool, 1, BigInt(10000), {wrongBlockTime: true, expected: false})
    })

    it('wm4: should success when withdraw use admin key', async () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        testWithdrawMvc(stakePool, 1, BigInt(100000), {useAdmin: true})
    })

    it('wm5: should failed when withdraw use wrong priv key', async () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        testWithdrawMvc(stakePool, 1, BigInt(100000), {useWrongPrivKey: true, expected: false})
    })

    it('wm6: should failed when withdraw with wrong output satoshis', () => {
        const stakePool = new StakePool(rewardAmountFactor, rewardBeginTime, rewardEndTime, rewardAmountPerSecond, 0, BigInt(0), BigInt(0), BigInt(0), new MerkleTreeData(Buffer.alloc(0), StakeProto.TREE_HEIGHT), 0)
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        testWithdrawMvc(stakePool, 1, BigInt(100000), {wrongOutputSatoshis: true, expected: false})
    })

    // finishWithdrawMvc
    it('wfm1: should success when finish withdraw', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(50000), 1)
        testFinishWithdrawMvc(stakePool, 1 + withdrawLockInterval)
    })

    it('wfm2: should success when finish withdraw all', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(100000), 1)
        testFinishWithdrawMvc(stakePool, 1 + withdrawLockInterval)
    })

    it('wfm3: should success when finish withdraw much times', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        for (let i = 0; i < 10; i++) {
            stakePool.preWithdraw(address1.hashBuffer, BigInt(5000), 1)
        }
        testFinishWithdrawMvc(stakePool, 1 + withdrawLockInterval)
    })

    it('wfm4: should success when finish withdraw with wrong privKey', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(50000), 1)
        testFinishWithdrawMvc(stakePool, 1 + withdrawLockInterval, {useWrongPrivKey: true, expected: false})
    })

    it('wfm5: should success when finish withdraw with admin privKey', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(50000), 1)
        testFinishWithdrawMvc(stakePool, 1 + withdrawLockInterval, {useAdmin: true, expected: true})
    })

    it('wfm6: should success when finish withdraw with wrong sender', () => {
        stakePool.deposit(address2.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address2.hashBuffer, BigInt(50000), 1)
        testFinishWithdrawMvc(stakePool, 1 + withdrawLockInterval, {wrongSender: address2, expected: false})
    })

    it('wfm7: should failed when finish withdraw with wrong output satoshis', () => {
        stakePool.deposit(address1.hashBuffer, BigInt(100000), 0)
        stakePool.preWithdraw(address1.hashBuffer, BigInt(50000), 1)
        testFinishWithdrawMvc(stakePool, 1 + withdrawLockInterval, {wrongOutputSatoshis: true, expected: false})
    })
});