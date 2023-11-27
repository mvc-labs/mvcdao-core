
import { expect } from 'chai';
import { mvc, getPreimage, toHex, SigHashPreimage, signTx, PubKey, Sig, Bytes, Ripemd160, buildTypeClasses } from 'mvc-scrypt'
import Common = require('../../deployments/common')
import UniqueProto = require('../../deployments/uniqueProto')
import { inputSatoshis, dummyTxId } from '../../scrypt_helper'

import { privateKey } from '../../privateKey'

const sigtype = Common.SIG_HASH_ALL

//const TxUtil = Common.genContract('txUtil', false, false)
const jsonDescr = Common.loadDescription('./fixture/autoGen/token_desc.json');
export const { TxInputProof, TxOutputProof } = buildTypeClasses(jsonDescr);
const addInput = Common.addInput
const address1 = privateKey.toAddress()

export function getTxOutputProofScrypt(tx: mvc.Transaction, outputIndex: number, emptyScriptHash: boolean = false) {
    const res = new TxOutputProof(Common.getTxOutputProof(tx, outputIndex, emptyScriptHash))
    return res
}

export function getEmptyTxOutputProofScrypt() {
    return new TxOutputProof(Common.getEmptyTxOutputProof())
}

export function createInputTx(contract, prevTx: mvc.Transaction | undefined, outputSatoshis: number = inputSatoshis) {
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    if (prevTx) {
        addInput(tx, prevTx.id, 0, prevTx.outputs[0].script, inputSatoshis, [])
    } else {
        addInput(tx, dummyTxId, 0, mvc.Script.buildPublicKeyHashOut(address1), inputSatoshis, [], true)
    }
    tx.addOutput(new mvc.Transaction.Output({
        script: contract.lockingScript,
        satoshis: outputSatoshis,
    }))
    return tx
}

export  function unlockStakeMain(
    tx: mvc.Transaction,
    prevouts: Buffer,
    stakeMain,
    inputIndex: number,
    contractTx: mvc.Transaction,
    stakeTx: mvc.Transaction,
    prevStakeTxInputIndex: number,
    prevStakeTx: mvc.Transaction,
    op: number,
    contractHashArray: Buffer,
    stakeSensibleID: string,
    expected: boolean = true) {

    // stakeMain unlock
    const stakeOutputIndex = tx.inputs[inputIndex].outputIndex
    const inputSatoshis = stakeTx.outputs[stakeOutputIndex].satoshis
    const preimage = getPreimage(tx, stakeMain.lockingScript.subScript(0), inputSatoshis, inputIndex, sigtype)
    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis
    }

    const contractTxOutputIndex = tx.inputs[0].outputIndex
    const contractTxScript = contractTx.outputs[contractTxOutputIndex].script.toBuffer()
    const contractTxProof = getTxOutputProofScrypt(contractTx, contractTxOutputIndex)

    const stakeTxOutputProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex)

    const stakeTxInputProof = new TxInputProof(Common.getTxInputProof(stakeTx, prevStakeTxInputIndex)[0])

    const prevStakeOutputIndex = stakeTx.inputs[prevStakeTxInputIndex].outputIndex
    const prevStakeTxProof = getTxOutputProofScrypt(prevStakeTx, prevStakeOutputIndex)

    let prevCustomData = new Bytes('')
    const sid = Common.genGenesisOutpoint(prevStakeTx.id, prevStakeOutputIndex)
    if (sid !== stakeSensibleID) {
        const prevStakeScriptBuf = prevStakeTx.outputs[prevStakeOutputIndex].script.toBuffer()
        prevCustomData = new Bytes(UniqueProto.getCustomData(prevStakeScriptBuf).toString('hex'))
    }

    const result = stakeMain.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // op contract hash proof
        contractTxProof,
        new Bytes(contractTxScript.toString('hex')),
        // main contract hash proof
        new Bytes(contractHashArray.toString('hex')),
        op,
        // stake 
        prevStakeTxInputIndex,
        stakeTxOutputProof.txHeader,
        stakeTxInputProof,
        prevStakeTxProof,
        prevCustomData
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

export function unlockUpdateContract(
    tx: mvc.Transaction,
    prevouts: Buffer,
    updateContract,
    newConctractHashRoot: Buffer,
    // sig
    ownerPubKeyHex: string,
    ownerSigHex: string,
    // stake
    stakeTx: mvc.Transaction,
    //
    changeSatoshis: number,
    changeAddress: mvc.Address,
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
    const stakeOutputSatoshis = output.satoshis
    const stakeScriptBuf = output.script.toBuffer()
    const stakeTxProof = getTxOutputProofScrypt(stakeTx, stakeOutputIndex)

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }

    const result = updateContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        new Bytes(newConctractHashRoot.toString('hex')),
        // sig
        new PubKey(ownerPubKeyHex),
        new Sig(ownerSigHex),
        // stake
        new Bytes(stakeScriptBuf.toString('hex')),
        stakeTxProof,
        // output
        stakeOutputSatoshis,
        changeSatoshis,
        new Ripemd160(changeAddress.hashBuffer.toString('hex'))
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}