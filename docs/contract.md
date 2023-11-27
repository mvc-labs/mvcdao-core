# Stake 

## stakeMain:
> * `stakeMain.scrypt`: A unique contract, storing the stake status.

### Data Format

Data layout：

ownerAddress(20 bytes) + rewardAmountFactor<8 bytes> + rewardBeginTime(4 bytes) + rewardEndBlock(4 bytes) + withdrawLockInterval<4 bytes> + rewardAmountPerSecond<8 bytes> + lastRewardTime<4 bytes> + poolTokenAmount<8 bytes> + unlockingPoolTokenAmount<8 bytes> + accPoolPerShare<16 bytes> + userDataMerkleRoot<32 bytes> + <blockHeightRabinPubKeyHashArrayHash<20 bytes> + stakeTokenHolderHash<20 bytes> + stakeRewardTokenHolderHash<20 bytes> + <contractHashRoot<20 bytes>>

> * ownerAddress: The root address of the contract; updating the contract requires the private key signature corresponding to this address.
> * rewardAmountFactor: A constant used to reduce large number calculation errors in reward calculations.
> * rewardBeginTime: Timestamp for when the reward begins.
> * rewardEndTime: Timestamp for when the reward ends.
> * withdrawLockInterval: The unlock time in seconds.
> * rewardAmountPerSecond: The number of tokens awarded per second.
> * lastRewardTime: Timestamp of the most recent reward update.
> * poolTokenAmount: The total amount of staked tokens, excluding tokens that are unlocking.
> * unlockingPoolTokenAmount: The total amount of tokens that are unlocking.
> * accPoolPerShare：Accumulated reward coefficient.
> * userDataMerkleRoot: The Merkle tree root of user stake data. Refer to the file `deployments/stakeMerkleTree.ts` for the logic of this Merkle tree.
> * blockHeightRabinPubKeyHashArrayHash: Public key hash of the block height time oracle.
> * stakeTokenHolderHash: Contract address where staked tokens are held.
> * stakeRewardTokenHolderHash：Contract address where reward tokens are held.
> * contractHashRoot: Hash of all stake contracts.
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
Staking
> `stakeDeposit.scrypt`: Stake tokens.
> `stakeDepositMvc.scrypt`: Stake Space.

Stake uses a Merkle tree to store the token data staked by each address, with the tree root saved in the stakeMain contract (userDataMerkleRoot). Refer to the file deployments/stakePool.ts for the specific staking logic.

## withdraw:
Can only be called when withdrawInterval equals 0.
> * `stakeWithdraw.scrypt`: Withdraw staked tokens.
> * `stakeWithdrawMvc.scrypt`: Withdraw staked space.

## preWithdraw:
Can only be called when withdrawInterval is not 0.
> * `stakePreWithdraw.scrypt`: Unlock staked tokens.
> * `stakePreWithdrawMvc.scrypt`: Unlock staked space.

## finishWithdraw:
Can only be called when withdrawInterval is not 0.
> * `stakeFinishWithdraw.scrypt`: Withdraw tokens that have been fully unlocked.

> * `stakeFinishWithdrawMvc.scrypt`: Withdraw space that has been fully unlocked.

## harvest:
> * `stakeHavest.scrypt`: Withdraw rewards.

## Admin:
> * `stakeAdmin.scrypt`: Modify some parameters.

## UpdateContract:
> * `stakeUpdateContract.scrypt`: Update contract parameters.

## Vote:
> * `stakeVote.scrypt`: Voting.

## stakeTokenHolder:
> * `stakeTokenHolder.scrypt`: The contract hash where staked tokens are stored.

## stakeRewardTokenHolder:
> * `stakeRewardTokenHolder.scrypt`: The contract hash where reward tokens are stored.

## stakeMergeRewardToken.scrypt:
> * `stakeMergeRewardToken.scrypt`: Merge token UTXOs stored in the reward contract.

## VoteMain:
> * `voteMain.scrypt`: A unique contract, storing the vote status.

Data layout:
ownerAddress(20 bytes) + minVoteAmount<8 bytes> + beginBlockTime<4 bytes> + endBlockTime<4 bytes> + userDataMerkleRoot<20 bytes> + voteDataHashRoot<20 bytes> + blockHeightRabinPubKeyHashArrayHash<20 bytes> + contractHashRoot<20 bytes>

> * ownerAddress: Currently not in use.
> * minVoteAmount: The minimum number of votes.
> * beginBlockTime: The timestamp for when voting begins.
> * endBlockTime: The timestamp for when voting ends.
> * userDataMerkleRoot: The root of the user voting data tree. Refer to deployments/voteDataTree.ts for the specific logic of this tree.
> * voteDataHashRoot: The hash of the overall voting data.
> * blockHeightRabinPubKeyHashArrayHash: The public key hash of the block height time oracle.
> * contractHashRoot: The hash of all vote contracts.