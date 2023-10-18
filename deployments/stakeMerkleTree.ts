import { mvc } from 'mvc-scrypt'
import Common = require('./common')

const LEFT_FLAG = Buffer.from('01', 'hex')
const RIGHT_FLAG = Buffer.from('00', 'hex')

const WITHDRAW_LIMIT = 5

interface UnlockingTokenInfo {
    expired: number,
    amount: bigint,
}

const LEAF_DATA_VERSION = 0
const LEAF_NODE_HEADER_SIZE = 76

export class LeafNode {
    version: number
    addressBuf: Buffer
    tokenAmount: bigint
    rewardDebt: bigint
    delegateeBuf: Buffer
    delegatedVotes: bigint
    unlockingTokens: UnlockingTokenInfo[]


    constructor(data: Buffer) {
        this.version = 0
        this.addressBuf = Buffer.alloc(0)
        this.tokenAmount = BigInt(0)
        this.rewardDebt = BigInt(0)
        this.delegateeBuf = Buffer.alloc(0)
        this.delegatedVotes = 0n
        this.unlockingTokens = []
        this.unserialize(data)
    }

    static EmptyLeafNode() {
        const leaf = new LeafNode(Buffer.alloc(LEAF_NODE_HEADER_SIZE, 0))
        return leaf
    }

    static initFromAddress(address: Buffer, amount: bigint, rewardDebt: bigint) {
        const leaf = LeafNode.EmptyLeafNode()
        leaf.version = LEAF_DATA_VERSION
        leaf.addressBuf = address
        leaf.tokenAmount = amount
        leaf.rewardDebt = rewardDebt
        leaf.delegateeBuf = Buffer.alloc(20, 0)
        leaf.delegatedVotes = 0n
        return leaf
    }

    static initFromLeaf(leaf: LeafNode) {
        const newLeaf = new LeafNode(leaf.serialize())
        return newLeaf
    }

    get hash() {
        return mvc.crypto.Hash.sha256(this.serialize())
    }

    key() {
        return this.addressBuf.toString('hex')
    }

    size() {
        return LEAF_NODE_HEADER_SIZE + this.unlockingTokens.length * 12
    }

    addUnlocking(amount: bigint, expired: number) {
        this.unlockingTokens.push({amount, expired})
    }

    getUnlocking() {
        return this.unlockingTokens
    }

    getAllExpiredUnlocking(curBlockNum: number, dryRun: boolean = false) {
        let sum: bigint = BigInt(0)
        let n = Math.min(this.unlockingTokens.length, WITHDRAW_LIMIT)
        let pos = 0
        for (let i = 0; i < n; i++) {
            const info = this.unlockingTokens[i]
            if (info.expired > curBlockNum) {
                pos = i - 1
                break;
            } else {
                pos = i
                sum += info.amount
            }
        }
        if (!dryRun) {
            this.unlockingTokens = this.unlockingTokens.slice(pos + 1)
        }
        return sum
    }

    serialize() {
        let buf = Buffer.concat([
            Common.getUInt32Buf(this.version),
            this.addressBuf,
            Common.getUInt64Buf(this.tokenAmount),
            Common.int128ToBuf(this.rewardDebt),
            this.delegateeBuf,
            Common.getUInt64Buf(this.delegatedVotes),
        ])
        for(const info of this.unlockingTokens) {
            buf = Buffer.concat([
                buf,
                Common.getUInt32Buf(info.expired),
                Common.getUInt64Buf(info.amount),
            ])
        } 
        return buf
    }

    unserialize(data: Buffer) {
        this.version = data.readUInt32LE(0)
        this.addressBuf = data.subarray(4, 24)
        this.tokenAmount = data.readBigUInt64LE(24)
        this.rewardDebt = Common.bufToInt128(data.subarray(32, 48))
        this.delegateeBuf = data.subarray(48, 68)
        this.delegatedVotes = data.readBigUInt64LE(68)
        const n = Math.floor((data.length - LEAF_NODE_HEADER_SIZE) / 12)
        let pos = LEAF_NODE_HEADER_SIZE
        for (let i = 0; i < n; i++) {
            const expired = data.readUInt32LE(pos)
            const amount = data.readBigUInt64LE(pos + 4)
            this.unlockingTokens.push({amount, expired})
            pos += 12
        }
    }

    isEmpty() {
        if (this.tokenAmount === BigInt(0) && this.rewardDebt === BigInt(0) && this.unlockingTokens.length === 0 && this.delegatedVotes === 0n) {
            return true
        }
        return false
    }

    toString() {
        const data = {
            version: this.version,
            address: this.addressBuf.toString('hex'),
            tokenAmount: this.tokenAmount.toString(),
            rewardDebt: this.rewardDebt.toString(),
            delegatee: this.delegateeBuf.toString('hex'),
            delegatedVotes: this.delegatedVotes.toString(),
        }
        return JSON.stringify(data)
    }
}

export class MerkleTreeData {
    leafArray: LeafNode[] = []
    height: number
    leafMap: Map<string, number>
    emptyHashs: Buffer[] = []
    hashNodes: Buffer[][] = []
    maxLeafSize: number

    constructor(leafData: Buffer, height: number) {

        this.height = height
        this.maxLeafSize = Math.pow(2, this.height - 1)
        this.leafMap = new Map()

        let pos = 0
        while (pos < leafData.length) {
            const leafNodeLen = leafData.readUInt32LE(pos)
            const leafNodeData = leafData.subarray(pos + 4, pos + 4 + leafNodeLen)
            pos += 4 + leafNodeLen
            const leafNode = new LeafNode(leafNodeData)
            this.leafArray.push(leafNode)
            this.leafMap.set(leafNode.key(), this.leafArray.length - 1)
        }

        const emptyNodeBuf = LeafNode.EmptyLeafNode().serialize()
        let emptyHash = mvc.crypto.Hash.sha256(emptyNodeBuf)
        this.emptyHashs.push(emptyHash)
        for (let i = 1; i < height; i++) {
            const prevHash = this.emptyHashs[i - 1]
            this.emptyHashs[i] = this.getHash(prevHash, prevHash)
        }

        this.buildMerkleTree()
    }

    getHash(buf1: Buffer, buf2: Buffer) {
        return mvc.crypto.Hash.sha256(Buffer.concat([buf1, buf2]))
    }

    get merkleRoot() {
        return this.hashNodes[this.hashNodes.length - 1][0]
    }

    get size() {
        return this.leafArray.length
    }

    get addressCount() {
        return this.leafArray.length
    }

    buildMerkleTree() {
        this.hashNodes = []
        let prevHash: Buffer[] = []
        let curHash: Buffer[] = []

        for (let i = 0; i < this.leafArray.length; i++) {
            prevHash.push(this.leafArray[i].hash)
        }
        if (prevHash.length > 0) {
            this.hashNodes.push(prevHash)
        } else {
            this.hashNodes.push([this.emptyHashs[0]])
        }

        for (let i = 1; i < this.height; i++) {
            prevHash = this.hashNodes[i - 1]
            curHash = []
            for (let j = 0; j < prevHash.length; ) {
                if (j + 1 < prevHash.length) {
                    curHash.push(this.getHash(prevHash[j], prevHash[j + 1]))
                } else {
                    curHash.push(this.getHash(prevHash[j], this.emptyHashs[i - 1]))
                }
                j += 2
            }
            this.hashNodes.push(curHash)
        }
    }

    updateLeafBuf(leafBuf: Buffer, leafIndex: number|undefined) {
        let leafNode = new LeafNode(leafBuf)
        this.updateLeaf(leafNode, leafIndex)
    }

    updateLeaf(leafNode: LeafNode, leafIndex: number|undefined = -1) {
        if (leafIndex < 0) {
            leafIndex = this.leafMap.get(leafNode.key())
        }
        let oldLeafBuf: Buffer

        // leafNode already in the tree 
        if (leafIndex !== undefined) {
            const oldLeaf = this.leafArray[leafIndex]
            this.leafMap.delete(oldLeaf.key())
            oldLeafBuf = oldLeaf.serialize()
            this.leafArray[leafIndex] = leafNode
        } else {
            let emptyIndex = -1
            for (let i = 0; i < this.leafArray.length; i++) {
                if (this.leafArray[i].isEmpty()) {
                    emptyIndex = i
                    break
                }
            }
            // find empty node
            if (emptyIndex >= 0) {

                const emptyNode = this.leafArray[emptyIndex]
                if (!emptyNode.isEmpty()) {
                    throw Error('empty node illeage' + String(emptyNode.toString()))
                }
                oldLeafBuf = emptyNode.serialize()
                this.leafArray[emptyIndex] = leafNode
                this.leafMap.delete(emptyNode.key())

                leafIndex = emptyIndex
            } else {
                // check size
                if (this.leafArray.length >= this.maxLeafSize) {
                    throw new Error("merkle tree is full")
                }
                oldLeafBuf = LeafNode.EmptyLeafNode().serialize()
                this.leafArray.push(leafNode)
                leafIndex = this.leafArray.length - 1
            }
        }
        this.leafMap.set(leafNode.key(), leafIndex)

        // return merkle path
        const merklePath = this.updateMerkleTree(leafNode, leafIndex)
        return {oldLeafBuf, merklePath, leafIndex}
    }

    calMerkleRoot(leafNode: Buffer, merklePath: Buffer) {
        const height = Math.floor(merklePath.length / 33)

        let merkleValue = mvc.crypto.Hash.sha256(leafNode)
        console.log('merkleValue: ', merkleValue.toString('hex'), leafNode.toString('hex'))
        for (let i = 0; i < height; i++) {
            const neighbor = merklePath.subarray(i * 33, i * 33 + 32)
            const left = merklePath.readUInt8(i * 33 + 32)

            if (left === 1) {
                merkleValue = this.getHash(merkleValue, neighbor)
            } else {
                merkleValue = this.getHash(neighbor, merkleValue)
            }
            console.log('merkleValue: ', merkleValue.toString('hex'))
        }
        return merkleValue
    }

    updateMerkleTree(leafNode: LeafNode, leafIndex: number) {
        let prevHash = this.hashNodes[0]
        let paths: Buffer[] = []

        if (leafIndex < prevHash.length) {
            prevHash[leafIndex] = leafNode.hash
        } else {
            prevHash.push(leafNode.hash)
        }

        let prevIndex = leafIndex

        for (let i = 1; i < this.height; i++) {
            prevHash = this.hashNodes[i - 1]
            const curHash = this.hashNodes[i]

            const curIndex = Math.floor(prevIndex / 2)
            // right node
            if (prevIndex % 2 === 1) {
                const newHash = this.getHash(prevHash[prevIndex - 1], prevHash[prevIndex])
                curHash[curIndex] = newHash
                paths.push(Buffer.concat([prevHash[prevIndex - 1], RIGHT_FLAG]))
            } else { // left node
                // new add
                let newHash
                if (curIndex >= curHash.length) {
                    newHash = this.getHash(prevHash[prevIndex], this.emptyHashs[i - 1])
                    if (curHash.length !== curIndex) {
                        throw Error('wrong curHash')
                    }
                    curHash.push(newHash)
                    paths.push(Buffer.concat([this.emptyHashs[i - 1], LEFT_FLAG]))
                } else {
                    if (prevHash.length > prevIndex + 1) {
                        newHash = this.getHash(prevHash[prevIndex], prevHash[prevIndex + 1])
                        paths.push(Buffer.concat([prevHash[prevIndex + 1], LEFT_FLAG]))
                    } else {
                        newHash = this.getHash(prevHash[prevIndex], this.emptyHashs[i - 1])
                        paths.push(Buffer.concat([this.emptyHashs[i - 1], LEFT_FLAG]))
                    }
                    curHash[curIndex] = newHash
                }
            }
            prevIndex = curIndex
        }

        // push
        //paths.push(Buffer.concat([this.hashNodes[this.hashNodes.length - 1][0], ROOT_FLAG]))
        return Buffer.concat(paths)
    }

    has(key: Buffer) {
        return this.leafMap.has(key.toString('hex'))
    }

    get(key: Buffer) {
        const index = this.leafMap.get(key.toString('hex'))
        if (index !== undefined) {
            return new LeafNode(this.leafArray[index].serialize())
        }
        return undefined
    }

    getMerklePath(key: Buffer) {

        const leafIndex = this.leafMap.get(key.toString('hex'))
        if (leafIndex == undefined) {
            return undefined
        }

        const leafNode = this.leafArray[leafIndex]

        let prevHash = this.hashNodes[0]
        let paths: Buffer[] = []

        if (leafIndex < prevHash.length) {
            prevHash[leafIndex] = leafNode.hash
        } else {
            prevHash.push(leafNode.hash)
        }

        let prevIndex = leafIndex

        for (let i = 1; i < this.height; i++) {
            prevHash = this.hashNodes[i - 1]
            const curHash = this.hashNodes[i]

            const curIndex = Math.floor(prevIndex / 2)
            // right node
            if (prevIndex % 2 === 1) {
                paths.push(Buffer.concat([prevHash[prevIndex - 1], RIGHT_FLAG]))
            } else { // left node
                if (curIndex >= curHash.length) {
                    paths.push(Buffer.concat([this.emptyHashs[i - 1], LEFT_FLAG]))
                } else {
                    if (prevHash.length > prevIndex + 1) {
                        paths.push(Buffer.concat([prevHash[prevIndex + 1], LEFT_FLAG]))
                    } else {
                        paths.push(Buffer.concat([this.emptyHashs[i - 1], LEFT_FLAG]))
                    }
                }
            }
            prevIndex = curIndex
        }

        // push
        //paths.push(Buffer.concat([this.hashNodes[this.hashNodes.length - 1][0], ROOT_FLAG]))
        return Buffer.concat(paths)
    }

    serializeLeaf() {
        let data = Buffer.alloc(0)
        for (const leaf of this.leafArray) {
            const leafData = leaf.serialize()
            data = Buffer.concat([
                data,
                Common.getUInt32Buf(leafData.length),
                leafData
            ])
        }
        return data
    }
}