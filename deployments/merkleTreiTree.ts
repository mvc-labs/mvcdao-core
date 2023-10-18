import { mvc } from 'mvc-scrypt'
import Common = require('./common')

export interface MerkleTreiLeaf {
    key(): bigint
    serialize(): Buffer
}

export class MerkleTreiNode {
    nodeMap: Map<number, Buffer>

    constructor() {
        this.nodeMap = new Map<number, Buffer>()
    }

    addSubNode(key: number, value: Buffer) {
        this.nodeMap.set(key, value)
    }

    getHash(emptyHash: Buffer) {
        const bufArray: Buffer[] = []
        for (let i = 0; i < 256; i++) {
            const node = this.nodeMap.get(i)
            if (node) {
                bufArray.push(node)
            } else {
                bufArray.push(emptyHash)
            }
        }
        return hashFunc(Buffer.concat(bufArray))
    }

    getNeighbors(subIndex: number, emptyHash: Buffer) {
        const leftNum = subIndex
        let neighbors: Buffer[] = []
        for (let i = 0; i < leftNum; i++) {
            let node = this.nodeMap.get(i) || emptyHash
            neighbors.push(node)
        }

        for (let i = subIndex + 1; i < 256; i++) {
            let node = this.nodeMap.get(i) || emptyHash
            neighbors.push(node)
        }
        return Buffer.concat(neighbors)
    }
}

export function hashFunc(buf: Buffer) {
    return mvc.crypto.Hash.sha256ripemd160(buf)
}

const HEIGHT = 20
const NODE_SLOT_NUM = 256

export class MerkleTreiTree {

    leafNodes: Map<bigint, MerkleTreiLeaf>
    emptyHashs: Buffer[] = []
    hashNodeSets: Map<bigint, MerkleTreiNode>[] = []
    leafSize: number

    constructor(leafNodeArray: MerkleTreiLeaf[], leafSize: number) {

        this.leafNodes = new Map<bigint, MerkleTreiLeaf>()
        this.leafSize = leafSize

        for (const leafNode of leafNodeArray) {
            this.addLeafNode(leafNode)
        }
        
        const emptyNodeBuf = Buffer.alloc(leafSize, 0)
        let emptyHash = hashFunc(emptyNodeBuf)
        this.emptyHashs.push(emptyHash)
        for (let i = 1; i < HEIGHT; i++) {
            const prevHash = this.emptyHashs[i - 1]
            const hashArray = Array(NODE_SLOT_NUM).fill(prevHash)
            const data = Buffer.concat(hashArray)
            this.emptyHashs[i] = hashFunc(data)
        }

        this.buildMerkleTree()
    }

    get merkleRoot() {
        return this.hashNodeSets[this.hashNodeSets.length - 1].values().next().value.getHash(this.emptyHashs[this.hashNodeSets.length - 1])
    }

    get size() {
        return this.leafNodes.size
    }

    addLeafNode(leafNode: MerkleTreiLeaf) {
        const key = leafNode.key()
        this.leafNodes.set(key, leafNode)
    }

    getNodeIndex(key: bigint) {
        const index = key / BigInt(NODE_SLOT_NUM)
        const subIndex = Number(key % BigInt(NODE_SLOT_NUM))
        return {index, subIndex}
    }

    buildMerkleTree() {

        let prevHashSets = new Map<bigint, MerkleTreiNode>()
        let curHashSets = new Map<bigint, MerkleTreiNode>()

        for (const entry of this.leafNodes.entries()) {
            const key = entry[0]
            const node = entry[1]
            const {index, subIndex} = this.getNodeIndex(key)
            let prevHashSet = prevHashSets.get(index)
            if (!prevHashSet) {
                prevHashSet = new MerkleTreiNode()
                prevHashSets.set(index, prevHashSet)
            }
            prevHashSet.addSubNode(subIndex, hashFunc(node.serialize()))
        }

        if (prevHashSets.size < 1) {
            prevHashSets.set(BigInt(0), new MerkleTreiNode())
        }

        this.hashNodeSets.push(prevHashSets)

        for (let i = 1; i < HEIGHT; i++) {
            prevHashSets = this.hashNodeSets[i - 1]
            curHashSets = new Map<bigint, MerkleTreiNode>()

            for (const entry of prevHashSets.entries()) {
                const key = entry[0]
                const value = entry[1]
                const {index, subIndex} = this.getNodeIndex(key)
                let curHashSet = curHashSets.get(index)
                if (!curHashSet) {
                    curHashSet = new MerkleTreiNode()
                    curHashSets.set(index, curHashSet)
                }
                curHashSet.addSubNode(subIndex, value.getHash(this.emptyHashs[i - 1]))
            }
            this.hashNodeSets.push(curHashSets)
        }

    }

    updateLeafNode(leafNode: MerkleTreiLeaf) {
        const key = leafNode.key()
        
        // find node
        let oldLeafBuf: Buffer
        if (this.leafNodes.has(key)) {
            oldLeafBuf = (<MerkleTreiLeaf>this.leafNodes.get(key)).serialize()
        } else {
            oldLeafBuf = Buffer.alloc(this.leafSize, 0)
        }
        //console.log('old leaf hash:', hashFunc(oldLeafBuf).toString('hex'))
        this.leafNodes.set(key, leafNode)

        const merklePath = this.updateTree(leafNode)
        return {oldLeafBuf, merklePath, newLeafBuf: leafNode.serialize()}
    }

    updateTree(leaf: MerkleTreiLeaf) {
        const key = leaf.key()
        const {index, subIndex} = this.getNodeIndex(key)
        let prevHashNode = this.hashNodeSets[0].get(index)
        if (!prevHashNode) {
            prevHashNode = new MerkleTreiNode()
            this.hashNodeSets[0].set(index, prevHashNode)
        }
        prevHashNode.addSubNode(subIndex, hashFunc(leaf.serialize()))
        //console.log('hash 0:', hashFunc(leaf.serialize()).toString('hex'))
        let paths: Buffer[] = []
        paths.push(prevHashNode.getNeighbors(subIndex, this.emptyHashs[0]))

        let prevIndex = index
        for (let i = 1; i < HEIGHT; i++) {
            const {index, subIndex} = this.getNodeIndex(prevIndex)
            let curHashNode = this.hashNodeSets[i].get(index)
            if (!curHashNode) {
                curHashNode = new MerkleTreiNode()
                this.hashNodeSets[i].set(index, curHashNode)
            }
            //console.log('hash :', i, prevHashNode.getHash(this.emptyHashs[i - 1]).toString('hex'), subIndex, index)
            curHashNode.addSubNode(subIndex, prevHashNode.getHash(this.emptyHashs[i - 1]))
            paths.push(curHashNode.getNeighbors(subIndex, this.emptyHashs[i]))
            prevIndex = index
            prevHashNode = curHashNode
        }
        return Buffer.concat(paths)
    }

    getNode(key: bigint) {
        return this.leafNodes.get(key)
    }
}