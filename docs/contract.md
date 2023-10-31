# Stake 

## stakeMain:
> * `stakeMain.scrypt`: unique合约，存放stake状态

### 数据格式

数据排布：

ownerAddress(20 bytes) + rewardAmountFactor<8 bytes> + rewardBeginTime(4 bytes) + rewardEndBlock(4 bytes) + withdrawLockInterval<4 bytes> + rewardAmountPerSecond<8 bytes> + lastRewardTime<4 bytes> + poolTokenAmount<8 bytes> + unlockingPoolTokenAmount<8 bytes> + accPoolPerShare<16 bytes> + userDataMerkleRoot<32 bytes> + <blockHeightRabinPubKeyHashArrayHash<20 bytes> + stakeTokenHolderHash<20 bytes> + stakeRewardTokenHolderHash<20 bytes> + <contractHashRoot<20 bytes>>

> * ownerAddress: 合约的root地址，更新合约需要此地址对应的私钥签名。
> * rewardAmountFactor: 一个常数，在奖励的计算中用来减少大数计算误差。
> * rewardBeginTime: 时间戳，奖励开始时间。
> * rewardEndTime: 时间戳，奖励结束时间。
> * withdrawLockInterval: 解锁的时间，单位秒。
> * rewardAmountPerSecond: 每秒奖励的token数。
> * lastRewardTime: 最近一次更新奖励的时间戳。
> * poolTokenAmount: 质押的token总数，不包括解锁中的token。
> * unlockingPoolTokenAmount: 处于解锁中的token总数。
> * accPoolPerShare：累计的奖励系数。
> * userDataMerkleRoot: 用户质押数据的merkle tree root。此Merkle树的逻辑参考文件`deployments/stakeMerkleTree.ts`。
> * blockHeightRabinPubKeyHashArrayHash: 区块高度时间oracle的公钥hash
> * stakeTokenHolderHash: 存放质押token的合约地址。
> * stakeRewardTokenHolderHash： 存放奖励token的合约地址。
> * contractHashRoot: stake所有的合约hash。
```
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

```

## deposit:
质押
> `stakeDeposit.scrypt`: 质押token
> `stakeDepositMvc.scrypt`: 质押Space

stake使用一颗merkle树来存储每个地址的质押的token数据，树的root保存在stakeMain合约中(userDataMerkleRoot)。具体的质押逻辑参考文件`deployments/stakePool.ts`

## withdraw:
只有在withdrawInterval等于0的情况下，才能调用
> * `stakeWithdraw.scrypt`: 提取质押的token
> * `stakeWithdrawMvc.scrypt`: 提取质押的space

## preWithdraw:
只有在withdrawInterval不等于0的情况下，才能调用
> * `stakePreWithdraw.scrypt`: 解锁质押的token
> * `stakePreWithdrawMvc.scrypt`: 解锁质押的space

## finishWithdraw:
只有在withdrawInterval不等于0的情况下，才能调用
> * `stakeFinishWithdraw.scrypt`: 提取已经解锁完毕的token

> * `stakeFinishWithdrawMvc.scrypt`: 提取已经解锁完毕的space

## harvest:
> * `stakeHavest.scrypt`: 提取奖励

## Admin:
> * `stakeAdmin.scrypt`: 修改一些参数

## UpdateContract:
> * `stakeUpdateContract.scrypt`: 更新合约参数

## Vote:
> * `stakeVote.scrypt`: 投票

## stakeTokenHolder:
> * `stakeTokenHolder.scrypt`: 质押的token存放在此合约hash

## stakeRewardTokenHolder:
> * `stakeRewardTokenHolder.scrypt`: 奖励的token存放在此合约哈希。

## stakeMergeRewardToken.scrypt:
> * `stakeMergeRewardToken.scrypt`: 将存放在奖励合约的token utxo进行合并。

## VoteMain:
> * `voteMain.scrypt`: unique合约，存放vote状态

数据排布：
ownerAddress(20 bytes) + minVoteAmount<8 bytes> + beginBlockTime<4 bytes> + endBlockTime<4 bytes> + userDataMerkleRoot<20 bytes> + voteDataHashRoot<20 bytes> + blockHeightRabinPubKeyHashArrayHash<20 bytes> + contractHashRoot<20 bytes>

> * ownerAddress: 目前没有使用。
> * minVoteAmount: 最小的投票数量。
> * beginBlockTime: 投票开始的时间戳。
> * endBlockTime: 投票结束的时间戳。
> * userDataMerkleRoot: 用户投票数据树的根。树的具体逻辑参考`deployments/voteDataTree.ts`。
> * voteDataHashRoot: 总的投票数据的hash。
> * blockHeightRabinPubKeyHashArrayHash: 区块高度时间oracle的公钥hash
> * contractHashRoot: vote所有的合约hash。