import { MerkleTreiLeaf, MerkleTreiTree } from "./merkleTreiTree"
import Common = require('./common')
import { mvc } from "mvc-scrypt"

export class VoteLeafNode implements MerkleTreiLeaf {
    address: Buffer
    voteOption: number
    voteAmount: bigint

    static size() {
        return 30
    }

    constructor(addressBuf: Buffer, voteOption: number, voteAmount: bigint) {
        this.address = addressBuf
        this.voteOption = voteOption
        this.voteAmount = voteAmount
    }

    key(): bigint {
        return Common.toBigIntLE(this.address)
    }

    keyBuffer() {
        return this.address
    }

    serialize() {
        return Buffer.concat([
            this.keyBuffer(), 
            Common.getUInt16Buf(this.voteOption),
            Common.getUInt64Buf(this.voteAmount)
        ])
    }
    
    getDataToDb() {
        return { 
            address: this.address.toString('hex'),
            voteOption: this.voteOption,
            voteAmount: this.voteAmount.toString()
        }
    }

    clone() {
        const leaf = new VoteLeafNode(this.address, this.voteOption, this.voteAmount)
        return leaf
    }
}

export class VoteDataTree {
    dataTree: MerkleTreiTree
    voteSumData: bigint[]

    constructor(leafArray: VoteLeafNode[], voteSumData: bigint[]) {
        this.dataTree = new MerkleTreiTree(leafArray, VoteLeafNode.size())
        this.voteSumData = voteSumData
    }

    static initFromTree(voteDataTree: VoteDataTree) {
        const leafArray: VoteLeafNode[] = []
        for (const node of voteDataTree.dataTree.leafNodes.values()) {
            leafArray.push((<VoteLeafNode>node).clone())
        }
        const voteSumData: bigint[] = []
        for (const amount of voteDataTree.voteSumData) { 
            voteSumData.push(amount)
        }
        const newTree = new VoteDataTree(leafArray, voteSumData)
        return newTree
    }

    getNode(address: Buffer) {
        const key = Common.toBigIntLE(address)
        return this.dataTree.getNode(key)
    }

    get merkleRoot() {
        return this.dataTree.merkleRoot
    }

    get sumDataHashRoot() {
        return mvc.crypto.Hash.sha256ripemd160(this.serializeSumData())
    }

    get size() {
        return this.dataTree.size
    }

    vote(address: Buffer, voteOption: number, confirmVote: boolean, voteAmount: bigint) {
        let oldLeaf = this.getNode(address)
        if (!oldLeaf) {
            oldLeaf = new VoteLeafNode(address, 0, BigInt(0))
        }

        const voteLeaf = <VoteLeafNode>oldLeaf

        // cancel old vote
        this.updateVoteSumData(voteLeaf.voteOption, -voteLeaf.voteAmount)
        let newVoteLeaf = new VoteLeafNode(address, 0, BigInt(0))
        if (confirmVote) {
            this.updateVoteSumData(voteOption, voteAmount)
            newVoteLeaf = new VoteLeafNode(address, voteOption, voteAmount)
        }

        return this.dataTree.updateLeafNode(newVoteLeaf)
    }

    updateVoteSumData(voteOption: number, changeAmount: bigint) {
        this.voteSumData[voteOption] += changeAmount
    }

    serializeSumData() {
        let buf = Buffer.alloc(0)
        for (const amount of this.voteSumData) {
            buf = Buffer.concat([
                buf,
                Common.getUInt64Buf(amount)
            ])
        }
        return buf
    }

    compare(dataTree: VoteDataTree) {
        if (this.merkleRoot.compare(dataTree.merkleRoot) === 0) {
            return true
        }
        return false
    }
}