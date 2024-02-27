package ethereum

import (
	"fmt"
	ssz "github.com/prysmaticlabs/fastssz"
	fieldparams "github.com/prysmaticlabs/prysm/v4/config/fieldparams"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/interfaces"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"strings"
	"toprelayer/relayer/toprelayer/ethtypes"
	"toprelayer/rpc/ethereum/light_client"
)

const (
	ONE_EPOCH_IN_SLOTS = 32
	HEADER_BATCH_SIZE  = 128

	SLOTS_PER_EPOCH   = 32
	EPOCHS_PER_PERIOD = 256

	ERROR_NO_BLOCK_FOR_SLOT = "not find requested block"
)

const (
	BeaconBlockBodyTreeDepth  uint64 = 4
	ExecutionPayloadTreeDepth uint64 = 4

	L1BeaconBlockBodyTreeExecutionPayloadIndex uint64 = 9
	L1BeaconBlockBodyProofSize                 uint64 = BeaconBlockBodyTreeDepth

	L2ExecutionPayloadTreeExecutionBlockIndex uint64 = 12
	L2ExecutionPayloadProofSize               uint64 = ExecutionPayloadTreeDepth
)

func GetPeriodForSlot(slot primitives.Slot) uint64 {
	return uint64(slot) / (SLOTS_PER_EPOCH * EPOCHS_PER_PERIOD)
}

func epochInPeriodForPeriod(period uint64) primitives.Epoch {
	batch := period * EPOCHS_PER_PERIOD / 154
	return primitives.Epoch((batch+1)*154 - (period * EPOCHS_PER_PERIOD))
}

func GetFinalizedSlotForPeriod(period uint64) primitives.Slot {
	epoch := epochInPeriodForPeriod(period)
	return primitives.Slot(period*EPOCHS_PER_PERIOD*SLOTS_PER_EPOCH + uint64(epoch)*ONE_EPOCH_IN_SLOTS)
}

func IsErrorNoBlockForSlot(err error) bool {
	return strings.Contains(err.Error(), ERROR_NO_BLOCK_FOR_SLOT)
}

func getBeforeSlotInSamePeriod(finalizedSlot primitives.Slot) (primitives.Slot, error) {
	slot := finalizedSlot - 3*ONE_EPOCH_IN_SLOTS

	if GetPeriodForSlot(slot) != GetPeriodForSlot(finalizedSlot) {
		return slot, fmt.Errorf("not an available slot:%d,it should be bigger", finalizedSlot)
	}
	return slot, nil
}

func getAttestationSlot(lastFinalizedSlotOnTop primitives.Slot) primitives.Slot {
	nextFinalizedSlot := lastFinalizedSlotOnTop + ONE_EPOCH_IN_SLOTS
	return nextFinalizedSlot + 2*ONE_EPOCH_IN_SLOTS
}

func BytesHashTreeRoot(data []byte, lenLimit int, remark string) ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	if size := len(data); size != lenLimit {
		ssz.DefaultHasherPool.Put(hh)
		return [32]byte{}, ssz.ErrBytesLengthFn("--."+remark, size, lenLimit)
	}
	hh.PutBytes(data)
	root, err := hh.HashRoot()
	ssz.DefaultHasherPool.Put(hh)
	return root, err
}

func vecObjectHashTreeRootWith(hh *ssz.Hasher, data []ssz.HashRoot, lenLimit uint64) (err error) {
	subIdx := hh.Index()
	num := uint64(len(data))
	if num > lenLimit {
		err = ssz.ErrIncorrectListSize
		return
	}
	for _, elem := range data {
		if err = elem.HashTreeRootWith(hh); err != nil {
			return
		}
	}
	if ssz.EnableVectorizedHTR {
		hh.MerkleizeWithMixinVectorizedHTR(subIdx, num, lenLimit)
	} else {
		hh.MerkleizeWithMixin(subIdx, num, lenLimit)
	}
	return nil
}

func VecObjectHashTreeRoot(data []ssz.HashRoot, lenLimit uint64) ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	if err := vecObjectHashTreeRootWith(hh, data, lenLimit); err != nil {
		ssz.DefaultHasherPool.Put(hh)
		return [32]byte{}, err
	}
	root, err := hh.HashRoot()
	ssz.DefaultHasherPool.Put(hh)
	return root, err
}

func BeaconBlockBodyMerkleTreeNew(b interfaces.ReadOnlyBeaconBlockBody) (MerkleTreeNode, error) {
	leaves := make([][32]byte, 11)
	// field 0
	randao := b.RandaoReveal()
	if hashRoot, err := BytesHashTreeRoot(randao[:], len(randao), "RandaoReveal"); err != nil {
		return nil, err
	} else {
		leaves[0] = hashRoot
	}
	// field 1
	if hashRoot, err := b.Eth1Data().HashTreeRoot(); err != nil {
		return nil, err
	} else {
		leaves[1] = hashRoot
	}

	// field 2
	graffiti := b.Graffiti()
	if hashRoot, err := BytesHashTreeRoot(graffiti[:], len(graffiti), "Graffiti"); err != nil {
		return nil, err
	} else {
		leaves[2] = hashRoot
	}

	// field 3
	hrs := make([]ssz.HashRoot, len(b.ProposerSlashings()))
	for i, v := range b.ProposerSlashings() {
		hrs[i] = v
	}
	if hashRoot, err := VecObjectHashTreeRoot(hrs, 16); err != nil {
		return nil, err
	} else {
		leaves[3] = hashRoot
	}

	// field 4
	hrs = make([]ssz.HashRoot, len(b.AttesterSlashings()))
	for i, v := range b.AttesterSlashings() {
		hrs[i] = v
	}
	if hashRoot, err := VecObjectHashTreeRoot(hrs, 2); err != nil {
		return nil, err
	} else {
		leaves[4] = hashRoot
	}

	// field 5
	hrs = make([]ssz.HashRoot, len(b.Attestations()))
	for i, v := range b.Attestations() {
		hrs[i] = v
	}
	if hashRoot, err := VecObjectHashTreeRoot(hrs, 128); err != nil {
		return nil, err
	} else {
		leaves[5] = hashRoot
	}

	// field 6
	hrs = make([]ssz.HashRoot, len(b.Deposits()))
	for i, v := range b.Deposits() {
		hrs[i] = v
	}
	if hashRoot, err := VecObjectHashTreeRoot(hrs, 16); err != nil {
		return nil, err
	} else {
		leaves[6] = hashRoot
	}

	// field 7
	hrs = make([]ssz.HashRoot, len(b.VoluntaryExits()))
	for i, v := range b.VoluntaryExits() {
		hrs[i] = v
	}
	if hashRoot, err := VecObjectHashTreeRoot(hrs, 16); err != nil {
		return nil, err
	} else {
		leaves[7] = hashRoot
	}

	// field 8
	syncAggregate, err := b.SyncAggregate()
	if err != nil {
		return nil, err
	}
	if hashRoot, err := syncAggregate.HashTreeRoot(); err != nil {
		return nil, err
	} else {
		leaves[8] = hashRoot
	}

	// field 9
	executionPayload, err := b.Execution()
	if err != nil {
		return nil, err
	}
	if hashRoot, err := executionPayload.HashTreeRoot(); err != nil {
		return nil, err
	} else {
		leaves[9] = hashRoot
	}

	// field 10
	blsToExecutionChanges, err := b.BLSToExecutionChanges()
	if err != nil {
		return nil, err
	}
	hrs = make([]ssz.HashRoot, len(blsToExecutionChanges))
	for i, v := range blsToExecutionChanges {
		hrs[i] = v
	}
	if hashRoot, err := VecObjectHashTreeRoot(hrs, 16); err != nil {
		return nil, err
	} else {
		leaves[10] = hashRoot
	}
	return create(leaves, BeaconBlockBodyTreeDepth), nil
}

func Uint64HashTreeRoot(data uint64) ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	hh.PutUint64(data)
	root, err := hh.HashRoot()
	ssz.DefaultHasherPool.Put(hh)
	return root, err
}

func specialFieldExtraDataHashTreeRoot(extraData []byte) ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	elemIdx := hh.Index()
	byteLen := uint64(len(extraData))
	if byteLen > 32 {
		ssz.DefaultHasherPool.Put(hh)
		return [32]byte{}, ssz.ErrIncorrectListSize
	}
	hh.PutBytes(extraData)
	if ssz.EnableVectorizedHTR {
		hh.MerkleizeWithMixinVectorizedHTR(elemIdx, byteLen, (32+31)/32)
	} else {
		hh.MerkleizeWithMixin(elemIdx, byteLen, (32+31)/32)
	}
	root, err := hh.HashRoot()
	ssz.DefaultHasherPool.Put(hh)
	return root, err
}

func specialFieldTransactionsHashTreeRoot(transactions [][]byte) ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	subIdx := hh.Index()
	num := uint64(len(transactions))
	if num > 1048576 {
		ssz.DefaultHasherPool.Put(hh)
		return [32]byte{}, ssz.ErrIncorrectListSize
	}
	for _, elem := range transactions {
		{
			elemIdx := hh.Index()
			byteLen := uint64(len(elem))
			if byteLen > 1073741824 {
				ssz.DefaultHasherPool.Put(hh)
				return [32]byte{}, ssz.ErrIncorrectListSize
			}
			hh.AppendBytes32(elem)
			if ssz.EnableVectorizedHTR {
				hh.MerkleizeWithMixinVectorizedHTR(elemIdx, byteLen, (1073741824+31)/32)
			} else {
				hh.MerkleizeWithMixin(elemIdx, byteLen, (1073741824+31)/32)
			}
		}
	}
	if ssz.EnableVectorizedHTR {
		hh.MerkleizeWithMixinVectorizedHTR(subIdx, num, 1048576)
	} else {
		hh.MerkleizeWithMixin(subIdx, num, 1048576)
	}
	root, err := hh.HashRoot()
	ssz.DefaultHasherPool.Put(hh)
	return root, err
}

func ExecutionPayloadMerkleTreeNew(executionData interfaces.ExecutionData) (MerkleTreeNode, error) {

	leaves := make([][32]byte, 15)
	// field 0
	parentHash := executionData.ParentHash()
	if hashRoot, err := BytesHashTreeRoot(parentHash, len(parentHash), "ParentHash"); err != nil {
		return nil, err
	} else {
		leaves[0] = hashRoot
	}

	// field 1
	feeRecipient := executionData.FeeRecipient()
	if hashRoot, err := BytesHashTreeRoot(feeRecipient, len(feeRecipient), "FeeRecipient"); err != nil {
		return nil, err
	} else {
		leaves[1] = hashRoot
	}

	// field 2
	stateRoot := executionData.StateRoot()
	if hashRoot, err := BytesHashTreeRoot(stateRoot, len(stateRoot), "StateRoot"); err != nil {
		return nil, err
	} else {
		leaves[2] = hashRoot
	}

	// field 3
	receiptsRoot := executionData.ReceiptsRoot()
	if hashRoot, err := BytesHashTreeRoot(receiptsRoot, len(receiptsRoot), "ReceiptsRoot"); err != nil {
		return nil, err
	} else {
		leaves[3] = hashRoot
	}

	// field 4
	logsBloom := executionData.LogsBloom()
	if hashRoot, err := BytesHashTreeRoot(logsBloom, len(logsBloom), "LogsBloom"); err != nil {
		return nil, err
	} else {
		leaves[4] = hashRoot
	}

	// field 5
	prevRandao := executionData.PrevRandao()
	if hashRoot, err := BytesHashTreeRoot(prevRandao, len(prevRandao), "PrevRandao"); err != nil {
		return nil, err
	} else {
		leaves[5] = hashRoot
	}

	// field 6
	if hashRoot, err := Uint64HashTreeRoot(executionData.BlockNumber()); err != nil {
		return nil, err
	} else {
		leaves[6] = hashRoot
	}

	// field 7
	if hashRoot, err := Uint64HashTreeRoot(executionData.GasLimit()); err != nil {
		return nil, err
	} else {
		leaves[7] = hashRoot
	}

	// field 8
	if hashRoot, err := Uint64HashTreeRoot(executionData.GasUsed()); err != nil {
		return nil, err
	} else {
		leaves[8] = hashRoot
	}

	// field 9
	if hashRoot, err := Uint64HashTreeRoot(executionData.Timestamp()); err != nil {
		return nil, err
	} else {
		leaves[9] = hashRoot
	}

	// field 10
	if hashRoot, err := specialFieldExtraDataHashTreeRoot(executionData.ExtraData()); err != nil {
		return nil, err
	} else {
		leaves[10] = hashRoot
	}

	// field 11
	baseFeePerGas := executionData.BaseFeePerGas()
	if hashRoot, err := BytesHashTreeRoot(baseFeePerGas, len(baseFeePerGas), "BaseFeePerGas"); err != nil {
		return nil, err
	} else {
		leaves[11] = hashRoot
	}

	// field 12
	blockHash := executionData.BlockHash()
	if hashRoot, err := BytesHashTreeRoot(blockHash, len(blockHash), "BlockHash"); err != nil {
		return nil, err
	} else {
		leaves[12] = hashRoot
	}

	// field 13
	transactions, err := executionData.Transactions()
	if err != nil {
		return nil, err
	}
	if hashRoot, err := specialFieldTransactionsHashTreeRoot(transactions); err != nil {
		return nil, err
	} else {
		leaves[13] = hashRoot
	}

	// field 14
	withdrawals, err := executionData.Withdrawals()
	hrs := make([]ssz.HashRoot, len(withdrawals))
	for i, v := range withdrawals {
		hrs[i] = v
	}
	if hashRoot, err := VecObjectHashTreeRoot(hrs, 16); err != nil {
		return nil, err
	} else {
		leaves[14] = hashRoot
	}
	return create(leaves, BeaconBlockBodyTreeDepth), nil
}

func beaconBlockHeaderConvert(header *eth.BeaconBlockHeader) *light_client.BeaconBlockHeader {
	return &light_client.BeaconBlockHeader{
		Slot:          header.Slot,
		ProposerIndex: header.ProposerIndex,
		ParentRoot:    [32]byte(header.ParentRoot),
		StateRoot:     [32]byte(header.StateRoot),
		BodyRoot:      [32]byte(header.BodyRoot),
	}
}

func convertEth2LightClientUpdate(lcu *ethtypes.LightClientUpdate) *light_client.LightClientUpdate {
	var executionHashBranch = make([][fieldparams.RootLength]byte, len(lcu.FinalizedUpdate.HeaderUpdate.ExecutionHashBranch))
	for i, v := range lcu.FinalizedUpdate.HeaderUpdate.ExecutionHashBranch {
		executionHashBranch[i] = v
	}

	ret := &light_client.LightClientUpdate{
		AttestedBeaconHeader: beaconBlockHeaderConvert(lcu.AttestedBeaconHeader),
		SyncAggregate: &light_client.SyncAggregate{
			SyncCommitteeBits:      [fieldparams.SyncAggregateSyncCommitteeBytesLength]byte(lcu.SyncAggregate.SyncCommitteeBits),
			SyncCommitteeSignature: [fieldparams.BLSSignatureLength]byte(lcu.SyncAggregate.SyncCommitteeSignature),
		},
		SignatureSlot: primitives.Slot(lcu.SignatureSlot),
		FinalityUpdate: &light_client.FinalizedHeaderUpdate{
			HeaderUpdate: &light_client.HeaderUpdate{
				BeaconHeader:        beaconBlockHeaderConvert(lcu.FinalizedUpdate.HeaderUpdate.BeaconHeader),
				ExecutionBlockHash:  lcu.FinalizedUpdate.HeaderUpdate.ExecutionBlockHash,
				ExecutionHashBranch: executionHashBranch,
			},
			FinalityBranch: lcu.FinalizedUpdate.FinalityBranch,
		},
	}
	if lcu.NextSyncCommitteeUpdate != nil {
		ret.NextSyncCommitteeUpdate = &light_client.SyncCommitteeUpdate{
			NextSyncCommittee:       lcu.NextSyncCommitteeUpdate.NextSyncCommittee,
			NextSyncCommitteeBranch: lcu.NextSyncCommitteeUpdate.NextSyncCommitteeBranch,
		}
	}
	return ret
}
