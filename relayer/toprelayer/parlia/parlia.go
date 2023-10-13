package parlia

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/wonderivan/logger"
	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	inMemorySnapshots  = 128  // Number of recent snapshots to keep in memory
	inMemorySignatures = 4096 // Number of recent block signatures to keep in memory

	checkpointInterval = 1024 // Number of blocks after which to save the snapshot to the database

	extraVanity      = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal        = 65 // Fixed number of extra-data suffix bytes reserved for signer seal
	nextForkHashSize = 4  // Fixed number of extra-data suffix bytes reserved for nextForkHash.

	maxValidators = 21 // Max validators allowed to seal.

	BLSPublicKeyLength = 48
	BLSSignatureLength = 96

	MaxAttestationExtraLength = 256

	validatorBytesLength = common.AddressLength + BLSPublicKeyLength
	validatorNumberSize  = 1 // Fixed number of extra prefix bytes reserved for validator number after Luban
)

var (
	uncleHash  = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
	diffInTurn = big.NewInt(2)            // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1)            // Block difficulty for out-of-turn signatures
	bscChainid = big.NewInt(56)
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errOutOfRangeChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errOutOfRangeChain = errors.New("out of range or non-contiguous chain")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")
)

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigCache *lru.ARCCache, chainId *big.Int) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigCache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header, chainId).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigCache.Add(hash, signer)
	return signer, nil
}

// ParliaRLP returns the rlp bytes which needs to be signed for the parlia
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func ParliaRLP(header *types.Header, chainId *big.Int) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header, chainId)
	return b.Bytes()
}

// Parlia is the consensus engine of BSC
type Parlia struct {
	// db          ethdb.Database // Database to store and retrieve snapshot checkpoints

	recentSnaps *lru.ARCCache // Snapshots for recent block to speed up
	signatures  *lru.ARCCache // Signatures of recent blocks to speed up mining
	client      *ethclient.Client
}

// New creates a Parlia consensus engine.
func New(client *ethclient.Client) *Parlia {
	// Allocate the snapshot caches and create the engine
	recentSnaps, err := lru.NewARC(inMemorySnapshots)
	if err != nil {
		panic(err)
	}
	signatures, err := lru.NewARC(inMemorySignatures)
	if err != nil {
		panic(err)
	}
	c := &Parlia{
		recentSnaps: recentSnaps,
		signatures:  signatures,
		client:      client,
	}

	return c
}

func (c *Parlia) Init(height uint64) error {
	var baseEpochHeight uint64
	if height < Epoch {
		baseEpochHeight = 0
	} else {
		if height%Epoch >= ValidatorNum {
			baseEpochHeight = height / Epoch * Epoch
		} else {
			baseEpochHeight = (height/Epoch - 1) * Epoch
		}
	}

	logger.Info("initialing congress snapshot from %v to %v", baseEpochHeight, height)
	// init baseheight
	{
		preEpochHeader, err := c.client.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(baseEpochHeight-Epoch))
		if err != nil {
			logger.Error(err)
			return err
		}
		baseEpochHeader, err := c.client.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(baseEpochHeight))
		if err != nil {
			logger.Error(err)
			return err
		}
		hash := baseEpochHeader.Hash()
		validatorBytes := getValidatorBytesFromHeader(baseEpochHeader)
		lastValidators := make([]common.Address, (len(preEpochHeader.Extra)-extraVanity-extraSeal)/common.AddressLength)
		for i := 0; i < len(lastValidators); i++ {
			copy(lastValidators[i][:], preEpochHeader.Extra[extraVanity+i*common.AddressLength:])
		}
		validators := make([]common.Address, (len(baseEpochHeader.Extra)-extraVanity-extraSeal)/common.AddressLength)
		for i := 0; i < len(validators); i++ {
			copy(validators[i][:], baseEpochHeader.Extra[extraVanity+i*common.AddressLength:])
		}
		snap := newSnapshot(c.signatures, baseEpochHeight, hash, lastValidators, validators)
		c.recentSnaps.Add(snap.Hash, snap)
	}

	for i := baseEpochHeight + 1; i <= height; i++ {
		header, err := c.client.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(i))
		if err != nil {
			logger.Error(err)
			return err
		}
		snap, err := c.GetLastSnap(header.Number.Uint64()-1, header.ParentHash)
		if err != nil {
			logger.Error(err)
			return err
		}
		err = c.Apply(snap, header)
		if err != nil {
			logger.Error(err)
			return err
		}
		time.Sleep(time.Millisecond * 100)
	}
	return nil
}

func (c *Parlia) GetLastSnap(number uint64, hash common.Hash) (*Snapshot, error) {
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := c.recentSnaps.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// TODO: db
		if number%checkpointInterval == 0 {
		}
		if number == 0 || (number%Epoch == 0 && len(headers) >= int(maxValidators)) {
			lastCheckpoint, err := c.client.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(number-200))
			if err != nil {
				logger.Error(err)
				return nil, err
			}
			if lastCheckpoint == nil {
				logger.Error(err)
				return nil, fmt.Errorf("header is nil")
			}
			checkpoint, err := c.client.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(number))
			if err != nil {
				logger.Error(err)
				return nil, err
			}
			if checkpoint == nil {
				logger.Error(err)
				return nil, fmt.Errorf("header is nil")
			}
			hash := checkpoint.Hash()
			lastValidators := make([]common.Address, (len(lastCheckpoint.Extra)-extraVanity-extraSeal)/common.AddressLength)
			for i := 0; i < len(lastValidators); i++ {
				copy(lastValidators[i][:], lastCheckpoint.Extra[extraVanity+i*common.AddressLength:])
			}
			validators := make([]common.Address, (len(checkpoint.Extra)-extraVanity-extraSeal)/common.AddressLength)
			for i := 0; i < len(validators); i++ {
				copy(validators[i][:], checkpoint.Extra[extraVanity+i*common.AddressLength:])
			}
			snap = newSnapshot(c.signatures, number, hash, lastValidators, validators)
			// TODO:db
			break
		}
		h, err := c.client.HeaderByHash(context.Background(), hash)
		if err != nil {
			logger.Error(err)
			return nil, fmt.Errorf("HeaderByHash error")
		}
		headers = append(headers, h)
		number, hash = number-1, h.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers, bscChainid)
	if err != nil {
		return nil, err
	}
	c.recentSnaps.Add(snap.Hash, snap)
	logger.Debug(snap)
	// TODO:db
	return snap, err
}

func (c *Parlia) GetLastSnapBytes(header *types.Header) ([]byte, error) {
	snap, err := c.GetLastSnap(header.Number.Uint64()-1, header.ParentHash)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	bytes, err := encodeSnapshot(header, snap)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	return bytes, nil
}

func (c *Parlia) Apply(snap *Snapshot, header *types.Header) error {
	var headers []*types.Header
	headers = append(headers, header)
	snap, err := snap.apply(headers, bscChainid)
	if err != nil {
		return err
	}
	c.recentSnaps.Add(snap.Hash, snap)
	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (p *Parlia) SealHash(header *types.Header) common.Hash {
	return SealHash(header, bscChainid)
}

// getValidatorBytesFromHeader returns the validators bytes extracted from the header's extra field if exists.
// The validators bytes would be contained only in the epoch block's header, and its each validator bytes length is fixed.
// On luban fork, we introduce vote attestation into the header's extra field, so extra format is different from before.
// Before luban fork: |---Extra Vanity---|---Validators Bytes (or Empty)---|---Extra Seal---|
// After luban fork:  |---Extra Vanity---|---Validators Number and Validators Bytes (or Empty)---|---Vote Attestation (or Empty)---|---Extra Seal---|
func getValidatorBytesFromHeader(header *types.Header) []byte {
	if len(header.Extra) <= extraVanity+extraSeal {
		return nil
	}

	// only supports Luban hard fork

	if header.Number.Uint64()%Epoch != 0 {
		return nil
	}
	num := int(header.Extra[extraVanity])
	if num == 0 || len(header.Extra) <= extraVanity+extraSeal+num*validatorBytesLength {
		return nil
	}
	start := extraVanity + validatorNumberSize
	end := start + num*validatorBytesLength
	return header.Extra[start:end]
}

// ===========================     utility function        ==========================
// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header, chainId *big.Int) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, chainId)
	hasher.Sum(hash[:0])
	return hash
}

func encodeSigHeader(w io.Writer, header *types.Header, chainId *big.Int) {
	err := rlp.Encode(w, []interface{}{
		chainId,
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra, // this will panic if extra is too short, should check before calling encodeSigHeader
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}
