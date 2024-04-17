import { LeafNode, MerkleTreeData } from './stakeMerkleTree'

export class StakePool {

    userData: MerkleTreeData
    lastRewardTime: number
    poolTokenAmount: bigint 
    unlockingPoolTokenAmount: bigint
    accPoolPerShare: bigint
    rewardAmountPerSecond: bigint
    rewardBeginTime: number
    rewardEndTime: number
    rewardAmountFactor: bigint
    withdrawLockInterval: number

    constructor(rewardAmountFactor: bigint, rewardBeginTime: number, rewardEndTime: number, rewardAmountPerSecond: bigint, lastRewardTime: number, poolTokenAmount: bigint, unlockingPoolTokenAmount: bigint, accPoolPerShare: bigint, userDataMerkleTree: MerkleTreeData, withdrawLockInterval: number) {

        this.userData = userDataMerkleTree
        this.rewardAmountFactor = rewardAmountFactor
        this.rewardBeginTime = rewardBeginTime
        this.rewardEndTime = rewardEndTime
        this.rewardAmountPerSecond = rewardAmountPerSecond
        this.lastRewardTime = lastRewardTime
        this.poolTokenAmount = poolTokenAmount
        this.unlockingPoolTokenAmount = unlockingPoolTokenAmount
        this.accPoolPerShare = accPoolPerShare
        this.withdrawLockInterval = withdrawLockInterval
    }

    static initFromStake(stakePool: StakePool) {
        // copy userdata
        const newUserData = new MerkleTreeData(stakePool.userData.serializeLeaf(), stakePool.userData.height)
        const newStakePool = new StakePool(stakePool.rewardAmountFactor, stakePool.rewardBeginTime, stakePool.rewardEndTime, stakePool.rewardAmountPerSecond, stakePool.lastRewardTime, stakePool.poolTokenAmount, stakePool.unlockingPoolTokenAmount, stakePool.accPoolPerShare, newUserData, stakePool.withdrawLockInterval)
        return newStakePool
    }

    get userDataMerkleRoot() {
        return this.userData.merkleRoot
    }

    getStakeInfo() {
        return {
            rewardAmountFactor: this.rewardAmountFactor,
            rewardBeginTime: this.rewardBeginTime,
            rewardEndTime: this.rewardEndTime,
            withdrawLockInterval: this.withdrawLockInterval,
            rewardAmountPerSecond: this.rewardAmountPerSecond,
            lastRewardTime: this.lastRewardTime,
            poolTokenAmount: this.poolTokenAmount,
            unlockingPoolTokenAmount: this.unlockingPoolTokenAmount,
            accPoolPerShare: this.accPoolPerShare,
            userDataMerkleRoot: this.userDataMerkleRoot,
        }
    }

    get addressCount() {
        return this.userData.addressCount
    }

    updatePool(curBlockTime: number) {

        if (this.poolTokenAmount > BigInt(0) && curBlockTime > this.lastRewardTime && curBlockTime > this.rewardBeginTime) {
            const perBlockReward = this.rewardAmountPerSecond * this.rewardAmountFactor
            const endTime = Math.min(curBlockTime, this.rewardEndTime)
            const startTime = Math.max(this.lastRewardTime, this.rewardBeginTime)
            let timeOffset = BigInt(endTime - startTime)
            if (timeOffset > BigInt(0)) {
                this.accPoolPerShare = this.accPoolPerShare + timeOffset * perBlockReward / this.poolTokenAmount
            }
        }

        if (curBlockTime > this.lastRewardTime) {
            this.lastRewardTime = curBlockTime
        }
    }

    deposit(address: Buffer, tokenAmount: bigint, curBlockTime: number) {
        let res = false
        if (tokenAmount <= BigInt(0)) {
            return {res}
        }

        if (curBlockTime < this.lastRewardTime) {
            return {res}
        }

        this.updatePool(curBlockTime)

        let data = this.userData.get(address)
        if (!data) {
            data = LeafNode.initFromAddress(address, BigInt(0), BigInt(0))
        }
        
        data.tokenAmount += tokenAmount
        data.rewardDebt += tokenAmount *  this.accPoolPerShare / this.rewardAmountFactor
        if (data.rewardDebt > BigInt('0x008' + '0'.repeat(31))) {
            throw Error('rewardDebt is illegal' + data.rewardDebt.toString())
        }
        const {oldLeafBuf, merklePath, leafIndex} = this.userData.updateLeaf(data)

        this.poolTokenAmount += tokenAmount

        return {res: true, oldLeafBuf, merklePath, leafIndex, newLeaf: data}
    }

    withdraw(address: Buffer, tokenAmount: bigint, curBlockTime: number) {
        let res = false
        if (this.withdrawLockInterval !== 0) {
            return {res}
        }

        if (curBlockTime < this.lastRewardTime) {
            return {res}
        }

        if (tokenAmount <= BigInt(0)) {
            return {res}
        }

        let data = this.userData.get(address)
        if (!data) {
            return {res}
        }
        data = <LeafNode>data

        if (data.tokenAmount < tokenAmount) {
            return {res}
        }

        this.updatePool(curBlockTime)

        data.rewardDebt -= tokenAmount *  this.accPoolPerShare / this.rewardAmountFactor
        data.tokenAmount -= tokenAmount
        const {oldLeafBuf, merklePath, leafIndex} = this.userData.updateLeaf(data)

        this.poolTokenAmount -= tokenAmount

        return {res: true, oldLeafBuf, merklePath, leafIndex, newLeaf: data, tokenAmount}
    }

    preWithdraw(address: Buffer, tokenAmount: bigint, curBlockTime: number) {
        let res = false

        if (this.withdrawLockInterval === 0) {
            return {res}
        }

        if (curBlockTime < this.lastRewardTime) {
            return {res}
        }

        if (tokenAmount <= BigInt(0)) {
            return {res}
        }

        let data = this.userData.get(address)
        if (!data) {
            return {res}
        }
        data = <LeafNode>data

        if (data.tokenAmount < tokenAmount) {
            return {res}
        }

        this.updatePool(curBlockTime)

        data.rewardDebt -= tokenAmount *  this.accPoolPerShare / this.rewardAmountFactor
        data.tokenAmount -= tokenAmount
        const expired = curBlockTime + this.withdrawLockInterval
        data.addUnlocking(tokenAmount, expired)
        const {oldLeafBuf, merklePath, leafIndex} = this.userData.updateLeaf(data)

        this.poolTokenAmount -= tokenAmount
        this.unlockingPoolTokenAmount += tokenAmount

        return {res: true, oldLeafBuf, merklePath, leafIndex, newLeaf: data}
    }

    finishWithdraw(address: Buffer, curBlockTime: number) {
        let res = false

        if (this.withdrawLockInterval === 0) {
            return {res}
        }

        if (curBlockTime < this.lastRewardTime) {
            return {res}
        }

        let data = this.userData.get(address)
        if (!data) {
            return {res}
        }
        data = <LeafNode>data

        this.updatePool(curBlockTime)

        const tokenAmount = data.getAllExpiredUnlocking(curBlockTime)
        if (tokenAmount == BigInt(0)) {
            return {res}
        }
        const {oldLeafBuf, merklePath, leafIndex} = this.userData.updateLeaf(data)

        this.unlockingPoolTokenAmount -= tokenAmount

        return {res: true, oldLeafBuf, merklePath, leafIndex, newLeaf: data, tokenAmount}
    }

    harvest(address: Buffer, curBlockTime: number) {
        let res = false
        if (curBlockTime < this.lastRewardTime) {
            return {res}
        }

        let data = this.userData.get(address)
        if (!data) {
            return {res}
        }

        this.updatePool(curBlockTime)

        const accReward: bigint = data.tokenAmount * this.accPoolPerShare / this.rewardAmountFactor
        const pendingReward: bigint  = accReward - data.rewardDebt

        data.rewardDebt = accReward
        if (data.rewardDebt > BigInt('0x008' + '0'.repeat(31))) {
            throw Error('rewardDebt is illegal' + data.rewardDebt.toString())
        }

        if (pendingReward < BigInt(0)) {
            throw Error('pendingReward is illegal ' + String(pendingReward))
        }

        const {oldLeafBuf, merklePath, leafIndex} = this.userData.updateLeaf(data)

        return {res: true, pendingReward, oldLeafBuf, merklePath, leafIndex, newLeaf: data}
    }

    admin(rewardAmountPerSecond: bigint, lastRewardTime: number, withdrawLockInterval: number) {
        this.rewardAmountPerSecond = rewardAmountPerSecond
        this.lastRewardTime = lastRewardTime
        this.withdrawLockInterval = withdrawLockInterval
    }

    getUserTokenAmount(address: Buffer) {
        const leafData = this.userData.get(address)
        if (leafData) {
            return leafData.tokenAmount
        }
        return BigInt(0)
    }

    getUserWithdrawAmount(address: Buffer, curBlockTime: number) {
        const leafData = this.userData.get(address)
        if (leafData) {
            return leafData.getAllExpiredUnlocking(curBlockTime, true)
        }
        return BigInt(0)
    }

    getUserInfo(address: Buffer) {
        const leafData = this.userData.get(address)
        return leafData
    }

    getUserMerklePath(address: Buffer) {
        return this.userData.getMerklePath(address)
    }

    compare(stakePool: StakePool) {
        if (this.userDataMerkleRoot.compare(stakePool.userDataMerkleRoot) !== 0) {
            return 1
        }

        if (this.lastRewardTime !== stakePool.lastRewardTime) {
            return 1
        }

        if (this.poolTokenAmount !== stakePool.poolTokenAmount) {
            return 1
        }

        if (this.accPoolPerShare !== stakePool.accPoolPerShare) {
            return 1
        }

        if (this.withdrawLockInterval !== stakePool.withdrawLockInterval) {
            return 1
        }

        if (this.rewardAmountPerSecond !== stakePool.rewardAmountPerSecond) {
            return 1
        }

        if (this.rewardAmountFactor !== stakePool.rewardAmountFactor) {
            return 1
        }
        return 0
    }
}
