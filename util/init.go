package util

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"strconv"
	"toprelayer/relayer/toprelayer/parlia"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/wonderivan/logger"

	beaconrpc "toprelayer/rpc/ethbeacon_rpc"

	primitives "github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
)

const ()

type ExtendedBeaconBlockHeader struct {
	Header             *beaconrpc.BeaconBlockHeader
	BeaconBlockRoot    []byte
	ExecutionBlockHash []byte
}

func (h *ExtendedBeaconBlockHeader) Encode() ([]byte, error) {
	headerBytes, err := h.Header.Encode()
	if err != nil {
		return nil, err
	}
	b1, err := rlp.EncodeToBytes(headerBytes)
	if err != nil {
		return nil, err
	}
	b2, err := rlp.EncodeToBytes(h.BeaconBlockRoot)
	if err != nil {
		return nil, err
	}
	b3, err := rlp.EncodeToBytes(h.ExecutionBlockHash)
	if err != nil {
		return nil, err
	}
	var rlpBytes []byte
	rlpBytes = append(rlpBytes, b1...)
	rlpBytes = append(rlpBytes, b2...)
	rlpBytes = append(rlpBytes, b3...)
	return rlpBytes, nil
}

type InitInput struct {
	FinalizedExecutionHeader *types.Header
	FinalizedBeaconHeader    *ExtendedBeaconBlockHeader
	CurrentSyncCommittee     *eth.SyncCommittee
	NextSyncCommittee        *eth.SyncCommittee
}

func (init *InitInput) Encode() ([]byte, error) {
	exeHeader, err := rlp.EncodeToBytes(init.FinalizedExecutionHeader)
	if err != nil {
		return nil, err
	}
	b1, err := rlp.EncodeToBytes(exeHeader)
	if err != nil {
		return nil, err
	}
	finHeader, err := init.FinalizedBeaconHeader.Encode()
	if err != nil {
		return nil, err
	}
	b2, err := rlp.EncodeToBytes(finHeader)
	if err != nil {
		return nil, err
	}
	cur, err := rlp.EncodeToBytes(init.CurrentSyncCommittee)
	if err != nil {
		return nil, err
	}
	b3, err := rlp.EncodeToBytes(cur)
	if err != nil {
		return nil, err
	}
	next, err := rlp.EncodeToBytes(init.NextSyncCommittee)
	if err != nil {
		return nil, err
	}
	b4, err := rlp.EncodeToBytes(next)
	if err != nil {
		return nil, err
	}
	var rlpBytes []byte
	rlpBytes = append(rlpBytes, b1...)
	rlpBytes = append(rlpBytes, b2...)
	rlpBytes = append(rlpBytes, b3...)
	rlpBytes = append(rlpBytes, b4...)
	return rlpBytes, nil
}

func getEthInitData(eth1, prysm string) ([]byte, error) {
	beaconrpcclient, err := beaconrpc.NewBeaconGrpcClient(prysm)
	if err != nil {
		logger.Error("getEthInitData NewBeaconGrpcClient error:", err)
		return nil, err
	}
	ethrpcclient, err := ethclient.Dial(eth1)
	if err != nil {
		logger.Error("getEthInitData ethclient.Dial error:", err)
		return nil, err
	}
	lastUpdate, err := beaconrpcclient.GetLastFinalizedLightClientUpdateV2WithNextSyncCommittee()
	if err != nil {
		logger.Error("getEthInitData GetLightClientUpdate error:", err)
		return nil, err
	}
	lastSlot := lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.Slot
	lastPeriod := beaconrpc.GetPeriodForSlot(lastSlot)
	prevUpdate, err := beaconrpcclient.GetNextSyncCommitteeUpdateV2(lastPeriod - 1)
	if err != nil {
		logger.Error(fmt.Sprintf("getEthInitData GetNextSyncCommitteeUpdate lastSlot:%d ，err：%s", lastSlot, err.Error()))
		return nil, err
	}

	var beaconHeader eth.BeaconBlockHeader
	beaconHeader.Slot = primitives.Slot(lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.Slot)
	beaconHeader.ProposerIndex = primitives.ValidatorIndex(lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.ProposerIndex)
	beaconHeader.BodyRoot = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.BodyRoot
	beaconHeader.ParentRoot = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.ParentRoot
	beaconHeader.StateRoot = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.StateRoot
	root, err := beaconHeader.HashTreeRoot()
	if err != nil {
		logger.Error("getEthInitData HashTreeRoot error:", err)
		return nil, err
	}
	finalizedHeader := new(ExtendedBeaconBlockHeader)
	finalizedHeader.BeaconBlockRoot = root[:]
	finalizedHeader.Header = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader // 2381600
	finalizedHeader.ExecutionBlockHash = lastUpdate.FinalizedUpdate.HeaderUpdate.ExecutionBlockHash

	finalitySlot := lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.Slot
	finalizeBody, err := beaconrpcclient.GetBeaconBlockBodyForBlockId(strconv.FormatUint(finalitySlot, 10))
	if err != nil {
		logger.Error("getEthInitData GetBeaconBlockBodyForBlockId error:", err)
		return nil, err
	}
	number := finalizeBody.GetExecutionPayload().BlockNumber

	header, err := ethrpcclient.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(number))
	if err != nil {
		logger.Error("getEthInitData HeaderByNumber error:", err)
		return nil, err
	}

	initParam := new(InitInput)
	initParam.FinalizedExecutionHeader = header
	initParam.FinalizedBeaconHeader = finalizedHeader
	initParam.NextSyncCommittee = lastUpdate.NextSyncCommitteeUpdate.NextSyncCommittee
	initParam.CurrentSyncCommittee = prevUpdate.NextSyncCommittee
	// 2203865 2203776
	// d15331da6463ec89f54bbaeda39d6dd20f575dd990ecd92bd5f98121767862c6
	h := common.Bytes2Hex(initParam.FinalizedExecutionHeader.Hash().Bytes())
	fmt.Println("eth header hash:", h)
	ExecutionBlockHash := common.Bytes2Hex(initParam.FinalizedBeaconHeader.ExecutionBlockHash)
	fmt.Println("ExecutionBlockHash hash:", ExecutionBlockHash)
	bytes, err := initParam.Encode()
	if err != nil {
		logger.Error("getEthInitData initParam.Encode error:", err)
		return nil, err
	}
	return bytes, nil
}

func getEthInitDataWithHeight(eth1, prysm, slot string) ([]byte, error) {
	beaconrpcclient, err := beaconrpc.NewBeaconGrpcClient(prysm)
	if err != nil {
		logger.Error("getEthInitData NewBeaconGrpcClient error:", err)
		return nil, err
	}
	ethrpcclient, err := ethclient.Dial(eth1)
	if err != nil {
		logger.Error("getEthInitData ethclient.Dial error:", err)
		return nil, err
	}
	lastSlot, err := strconv.ParseUint(slot, 0, 64)
	if err != nil {
		logger.Error("ParseInt error:", err)
		return nil, err
	}
	lastPeriod := beaconrpc.GetPeriodForSlot(lastSlot)
	// 269 2203865
	lastUpdate, err := beaconrpcclient.GetLightClientUpdateV2(lastPeriod)
	if err != nil {
		logger.Error("getEthInitData GetLightClientUpdate error:", err)
		return nil, err
	}
	prevUpdate, err := beaconrpcclient.GetNextSyncCommitteeUpdateV2(lastPeriod - 1)
	if err != nil {
		logger.Error("getEthInitData GetNextSyncCommitteeUpdate error:", err)
		return nil, err
	}

	var beaconHeader eth.BeaconBlockHeader
	beaconHeader.Slot = primitives.Slot(lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.Slot)
	beaconHeader.ProposerIndex = primitives.ValidatorIndex(lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.ProposerIndex)
	beaconHeader.BodyRoot = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.BodyRoot
	beaconHeader.ParentRoot = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.ParentRoot
	beaconHeader.StateRoot = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.StateRoot
	root, err := beaconHeader.HashTreeRoot()
	if err != nil {
		logger.Error("getEthInitData HashTreeRoot error:", err)
		return nil, err
	}
	finalizedHeader := new(ExtendedBeaconBlockHeader)
	finalizedHeader.BeaconBlockRoot = root[:]
	finalizedHeader.Header = lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader
	finalizedHeader.ExecutionBlockHash = lastUpdate.FinalizedUpdate.HeaderUpdate.ExecutionBlockHash

	finalitySlot := lastUpdate.FinalizedUpdate.HeaderUpdate.BeaconHeader.Slot
	finalizeBody, err := beaconrpcclient.GetBeaconBlockBodyForBlockId(strconv.FormatUint(finalitySlot, 10))
	if err != nil {
		logger.Error("getEthInitData GetBeaconBlockBodyForBlockId error:", err)
		return nil, err
	}
	number := finalizeBody.GetExecutionPayload().BlockNumber

	header, err := ethrpcclient.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(number))
	if err != nil {
		logger.Error("getEthInitData HeaderByNumber error:", err)
		return nil, err
	}

	initParam := new(InitInput)
	initParam.FinalizedExecutionHeader = header
	initParam.FinalizedBeaconHeader = finalizedHeader
	initParam.NextSyncCommittee = lastUpdate.NextSyncCommitteeUpdate.NextSyncCommittee
	initParam.CurrentSyncCommittee = prevUpdate.NextSyncCommittee

	bytes, err := initParam.Encode()
	if err != nil {
		logger.Error("getEthInitData initParam.Encode error:", err)
		return nil, err
	}
	return bytes, nil
}

func getHecoInitData(url string) ([]byte, error) {
	ethsdk, err := ethclient.Dial(url)
	if err != nil {
		logger.Error("getBscOrHecoInitDataWithHeight ethsdk create error:", err)
		return nil, err
	}
	height, err := ethsdk.BlockNumber(context.Background())
	if err != nil {
		logger.Error("getBscOrHecoInitDataWithHeight BlockNumber error:", err)
		return nil, err
	}

	height = (height - 11) / 200 * 200

	logger.Info("init with height: %v - %v", height, height+11)
	var batch []byte
	for i := height; i <= height+11; i++ {
		header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(i))
		if err != nil {
			logger.Error("getBscOrHecoInitDataWithHeight HeaderByNumber error:", err)
			return nil, err
		}
		rlp_bytes, err := rlp.EncodeToBytes(header)
		if err != nil {
			logger.Error("getBscOrHecoInitDataWithHeight EncodeToBytes error:", err)
			return nil, err
		}
		batch = append(batch, rlp_bytes...)
	}

	return batch, nil
}

func getHecoInitDataWithHeight(url, h string) ([]byte, error) {
	height, err := strconv.ParseUint(h, 0, 64)
	if err != nil {
		logger.Error("getBscOrHecoInitDataWithHeight ParseInt error:", err)
		return nil, err
	}
	ethsdk, err := ethclient.Dial(url)
	if err != nil {
		logger.Error("getBscOrHecoInitDataWithHeight ethsdk create error:", err)
		return nil, err
	}
	height = (height - 11) / 200 * 200

	logger.Info("init with height: %v - %v", height, height+11)
	var batch []byte
	for i := height; i <= height+11; i++ {
		header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(i))
		if err != nil {
			logger.Error("getBscOrHecoInitDataWithHeight HeaderByNumber error:", err)
			return nil, err
		}
		rlp_bytes, err := rlp.EncodeToBytes(header)
		if err != nil {
			logger.Error("getBscOrHecoInitDataWithHeight EncodeToBytes error:", err)
			return nil, err
		}
		batch = append(batch, rlp_bytes...)
	}

	return batch, nil
}

func getBscInitData(url string) ([]byte, error) {
	ethClient, err := ethclient.Dial(url)
	if err != nil {
		logger.Error("getBscInitData create error:", err)
		return nil, err
	}
	lastHeight, err := ethClient.BlockNumber(context.Background())
	if err != nil {
		logger.Error("getBscInitData BlockNumber error:", err)
		return nil, err
	}

	limit := parlia.ValidatorNum / 2
	// make sure to find the epoch that has the authority data that can be used to verify the header.
	effectiveEpochHeight := (lastHeight - (limit + 1)) / parlia.Epoch * parlia.Epoch

	if effectiveEpochHeight < parlia.Epoch {
		logger.Error("param error")
		return nil, nil
	}
	preEffectiveEpochHeight := effectiveEpochHeight - parlia.Epoch

	logger.Info("init with height: %v - %v", effectiveEpochHeight, effectiveEpochHeight+(limit+1))
	var batch []byte
	preEffectiveEpochHeader, err := ethClient.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(preEffectiveEpochHeight))
	if err != nil {
		logger.Error("getBscInitData HeaderByNumber error:", err)
		return nil, err
	}
	headerBytes, err := rlp.EncodeToBytes(preEffectiveEpochHeader)
	if err != nil {
		logger.Error("getBscInitData EncodeToBytes error:", err)
		return nil, err
	}
	batch = append(batch, headerBytes...)
	for i := effectiveEpochHeight; i <= effectiveEpochHeight+limit+1; i++ {
		header, err := ethClient.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(i))
		if err != nil {
			logger.Error("getBscInitData HeaderByNumber error:", err)
			return nil, err
		}
		rlpBytes, err := rlp.EncodeToBytes(header)
		if err != nil {
			logger.Error("getBscInitData EncodeToBytes error:", err)
			return nil, err
		}
		batch = append(batch, rlpBytes...)
	}

	return batch, nil
}

func getBscInitDataWithHeight(url, h string) ([]byte, error) {
	height, err := strconv.ParseUint(h, 0, 64)
	if err != nil {
		logger.Error("getBscOrHecoInitDataWithHeight ParseInt error:", err)
		return nil, err
	}
	ethsdk, err := ethclient.Dial(url)
	if err != nil {
		logger.Error("getBscOrHecoInitDataWithHeight ethsdk create error:", err)
		return nil, err
	}
	height = (height - 11) / 200 * 200

	if height <= 200 {
		logger.Error("param error")
		return nil, nil
	}

	logger.Info("init with height: %v - %v", height, height+11)
	var batch []byte
	header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(height-200))
	if err != nil {
		logger.Error("getBscOrHecoInitDataWithHeight HeaderByNumber error:", err)
		return nil, err
	}
	rlp_bytes, err := rlp.EncodeToBytes(header)
	if err != nil {
		logger.Error("getBscOrHecoInitDataWithHeight EncodeToBytes error:", err)
		return nil, err
	}
	batch = append(batch, rlp_bytes...)
	for i := height; i <= height+11; i++ {
		header, err := ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(i))
		if err != nil {
			logger.Error("getBscOrHecoInitDataWithHeight HeaderByNumber error:", err)
			return nil, err
		}
		rlp_bytes, err := rlp.EncodeToBytes(header)
		if err != nil {
			logger.Error("getBscOrHecoInitDataWithHeight EncodeToBytes error:", err)
			return nil, err
		}
		batch = append(batch, rlp_bytes...)
	}

	return batch, nil
}
