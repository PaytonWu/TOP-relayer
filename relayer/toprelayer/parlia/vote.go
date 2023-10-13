package parlia

import "github.com/ethereum/go-ethereum/common"

// VoteData represents the vote range that validator voted for fast finality.
type VoteData struct {
	SourceNumber uint64      // The source block number should be the latest justified block number.
	SourceHash   common.Hash // The block hash of the source block.
	TargetNumber uint64      // The target block number which validator wants to vote for.
	TargetHash   common.Hash // The block hash of the target block.
}

type BLSPublicKey [BLSPublicKeyLength]byte
type BLSSignature [BLSSignatureLength]byte
type ValidatorsBitSet uint64
