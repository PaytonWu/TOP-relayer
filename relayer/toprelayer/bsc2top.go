package toprelayer

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
	"toprelayer/config"
	ethbridge "toprelayer/contract/top/ethclient"
	"toprelayer/relayer/toprelayer/parlia"
	"toprelayer/wallet"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/wonderivan/logger"
)

var (
	bscClientContract = common.HexToAddress("0xff00000000000000000000000000000000000003")
)

type Bsc2TopRelayer struct {
	wallet        *wallet.Wallet
	ethsdk        *ethclient.Client
	transactor    *ethbridge.EthClientTransactor
	callerSession *ethbridge.EthClientCallerSession
	parlia        *parlia.Parlia
}

func (relayer *Bsc2TopRelayer) Init(cfg *config.Relayer, listenUrl []string, pass string) error {
	w, err := wallet.NewEthWallet(cfg.Url[0], listenUrl[0], cfg.KeyPath, pass)
	if err != nil {
		logger.Error("Bsc2TopRelayer NewWallet error:", err)
		return err
	}
	relayer.wallet = w

	relayer.ethsdk, err = ethclient.Dial(listenUrl[0])
	if err != nil {
		logger.Error("Bsc2TopRelayer ethsdk create error:", listenUrl)
		return err
	}

	topEthClient, err := ethclient.Dial(cfg.Url[0])
	if err != nil {
		logger.Error("Bsc2TopRelayer new topethlient error:", err)
		return err
	}
	relayer.transactor, err = ethbridge.NewEthClientTransactor(bscClientContract, topEthClient)
	if err != nil {
		logger.Error("Bsc2TopRelayer NewEthClientTransactor error:", err)
		return err
	}

	relayer.callerSession = new(ethbridge.EthClientCallerSession)
	relayer.callerSession.Contract, err = ethbridge.NewEthClientCaller(bscClientContract, topEthClient)
	if err != nil {
		logger.Error("Bsc2TopRelayer NewEthClientCaller error:", err)
		return err
	}
	relayer.callerSession.CallOpts = bind.CallOpts{
		Pending:     false,
		From:        relayer.wallet.Address(),
		BlockNumber: nil,
		Context:     context.Background(),
	}

	relayer.parlia = parlia.New(relayer.ethsdk)

	return nil
}

func (et *Bsc2TopRelayer) submitEthHeader(header []byte) error {
	nonce, err := et.wallet.NonceAt(context.Background(), et.wallet.Address(), nil)
	if err != nil {
		logger.Error("Bsc2TopRelayer NonceAt error:", err)
		return err
	}
	gasPrice, err := et.wallet.SuggestGasPrice(context.Background())
	if err != nil {
		logger.Error("Bsc2TopRelayer SuggestGasPrice error:", err)
		return err
	}
	packHeader, err := ethbridge.PackSyncParam(header)
	if err != nil {
		logger.Error("Bsc2TopRelayer PackSyncParam error:", err)
		return err
	}
	gaslimit, err := et.wallet.EstimateGas(context.Background(), &bscClientContract, packHeader)
	if err != nil {
		logger.Error("Bsc2TopRelayer EstimateGas error:", err)
		return err
	}
	//must init ops as bellow
	ops := &bind.TransactOpts{
		From:      et.wallet.Address(),
		Nonce:     big.NewInt(0).SetUint64(nonce),
		GasLimit:  gaslimit,
		GasFeeCap: gasPrice,
		GasTipCap: big.NewInt(0),
		Signer:    et.signTransaction,
		Context:   context.Background(),
		NoSend:    false,
	}
	sigTx, err := et.transactor.Sync(ops, header)
	if err != nil {
		logger.Error("Bsc2TopRelayer sync error:", err)
		return err
	}

	logger.Info("Bsc2TopRelayer tx info, account[%v] nonce:%v,capfee:%v,hash:%v,size:%v", et.wallet.Address(), nonce, gasPrice, sigTx.Hash(), len(header))
	return nil
}

// callback function to sign tx before send.
func (et *Bsc2TopRelayer) signTransaction(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
	acc := et.wallet.Address()
	if strings.EqualFold(acc.Hex(), addr.Hex()) {
		stx, err := et.wallet.SignTx(tx)
		if err != nil {
			return nil, err
		}
		return stx, nil
	}
	return nil, fmt.Errorf("TopRelayer address:%v not available", addr)
}

func (et *Bsc2TopRelayer) StartRelayer(wg *sync.WaitGroup) error {
	logger.Info("Bsc2TopRelayer start... subBatch: %v certaintyBlocks: %v", BATCH_NUM, CONFIRM_NUM)
	defer wg.Done()

	done := make(chan struct{})
	defer close(done)

	go func(done chan struct{}) {
		timeoutDuration := time.Duration(FATALTIMEOUT) * time.Hour
		timeout := time.NewTimer(timeoutDuration)
		defer timeout.Stop()
		logger.Debug("Bsc2TopRelayer set timeout: %v hours", FATALTIMEOUT)
		var delay time.Duration = time.Duration(1)

		for {
			destHeight, err := et.callerSession.GetHeight()
			if err != nil {
				logger.Error("Bsc2TopRelayer get height error:", err)
				time.Sleep(time.Second * time.Duration(ERRDELAY))
				continue
			}
			logger.Info("Bsc2TopRelayer check dest TOP Height:", destHeight)
			if destHeight != 0 {
				err = et.parlia.Init(destHeight)
				if err == nil {
					break
				} else {
					logger.Error("Bsc2TopRelayer BSC init error:", err)
				}
			} else {
				logger.Info("Bsc2TopRelayer not init yet")
			}
			time.Sleep(time.Second * time.Duration(ERRDELAY))
		}

		for {
			time.Sleep(time.Second * delay)
			select {
			case <-timeout.C:
				done <- struct{}{}
				return
			default:
				destHeight, err := et.callerSession.GetHeight()
				if err != nil {
					logger.Error("Bsc2TopRelayer get height error:", err)
					delay = time.Duration(ERRDELAY)
					break
				}
				logger.Info("Bsc2TopRelayer check dest TOP Height:", destHeight)
				if destHeight == 0 {
					if set := timeout.Reset(timeoutDuration); !set {
						logger.Error("Bsc2TopRelayer reset timeout falied!")
						delay = time.Duration(ERRDELAY)
						break
					}
					logger.Info("Bsc2TopRelayer not init yet")
					delay = time.Duration(ERRDELAY)
					break
				}
				srcHeight, err := et.ethsdk.BlockNumber(context.Background())
				if err != nil {
					logger.Error("Bsc2TopRelayer get number error:", err)
					delay = time.Duration(ERRDELAY)
					break
				}
				logger.Info("Bsc2TopRelayer check src BSC Height:", srcHeight)

				if destHeight+1+CONFIRM_NUM > srcHeight {
					if set := timeout.Reset(timeoutDuration); !set {
						logger.Error("Bsc2TopRelayer reset timeout falied!")
						delay = time.Duration(ERRDELAY)
						break
					}
					logger.Debug("Bsc2TopRelayer waiting src BSC update, delay")
					delay = time.Duration(WAITDELAY)
					break
				}

				// check fork
				checkError := false
				for {
					header, err := et.ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(destHeight))
					if err != nil {
						logger.Error("Bsc2TopRelayer HeaderByNumber error:", err)
						checkError = true
						break
					}
					// get known hashes with destHeight, mock now
					isKnown, err := et.callerSession.IsKnown(header.Number, header.Hash())
					if err != nil {
						logger.Error("Bsc2TopRelayer IsKnown error:", err)
						checkError = true
						break
					}
					if isKnown {
						logger.Debug("%v hash is known", header.Number)
						break
					} else {
						logger.Warn("%v hash is not known", header.Number)
						destHeight -= 1
					}
				}
				if checkError {
					delay = time.Duration(ERRDELAY)
					break
				}

				syncStartHeight := destHeight + 1
				syncNum := srcHeight - CONFIRM_NUM - destHeight
				if syncNum > BATCH_NUM {
					syncNum = BATCH_NUM
				}
				syncEndHeight := syncStartHeight + syncNum - 1
				logger.Info("Bsc2TopRelayer sync from %v to %v", syncStartHeight, syncEndHeight)

				err = et.signAndSendTransactions(syncStartHeight, syncEndHeight)
				if err != nil {
					logger.Error("Bsc2TopRelayer signAndSendTransactions failed:", err)
					delay = time.Duration(ERRDELAY)
					break
				}
				if set := timeout.Reset(timeoutDuration); !set {
					logger.Error("Bsc2TopRelayer reset timeout falied!")
					delay = time.Duration(ERRDELAY)
					break
				}
				logger.Info("Bsc2TopRelayer sync round finish")
				if syncNum == BATCH_NUM {
					delay = time.Duration(SUCCESSDELAY)
				} else {
					delay = time.Duration(WAITDELAY)
				}
				// break
			}
		}
	}(done)

	<-done
	logger.Error("Bsc2TopRelayer timeout")
	return nil
}

func (et *Bsc2TopRelayer) signAndSendTransactions(lo, hi uint64) error {
	var batch []byte
	for h := lo; h <= hi; h++ {
		header, err := et.ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(h))
		if err != nil {
			logger.Error(err)
			break
		}
		rlpBytes, err := et.parlia.GetLastSnapBytes(header)
		if err != nil {
			logger.Error(err)
			return err
		}
		batch = append(batch, rlpBytes...)
	}

	// maybe verify block
	// if et.chainId == topChainId {
	// 	for _, header := range headers {
	// 		et.verifyBlocks(header)
	// 	}
	// }
	if len(batch) > 0 {
		err := et.submitEthHeader(batch)
		if err != nil {
			logger.Error("Bsc2TopRelayer submitHeaders failed:", err)
			return err
		}
	}

	return nil
}

func (et *Bsc2TopRelayer) GetInitData() ([]byte, error) {
	destHeight, err := et.callerSession.GetHeight()
	if err != nil {
		logger.Error("Bsc2TopRelayer get height error:", err)
		return nil, err
	}
	height := (destHeight - (parlia.ValidatorNum/2 + 1)) / parlia.Epoch * parlia.Epoch
	logger.Error("BSC init with height: %v - %v", height, height+11)
	var batch []byte
	for i := height; i <= height+11; i++ {
		header, err := et.ethsdk.HeaderByNumber(context.Background(), big.NewInt(0).SetUint64(i))
		if err != nil {
			logger.Error("Bsc2TopRelayer HeaderByNumber error:", err)
			return nil, err
		}
		rlpBytes, err := rlp.EncodeToBytes(header)
		if err != nil {
			logger.Error("Bsc2TopRelayer EncodeToBytes error:", err)
			return nil, err
		}
		batch = append(batch, rlpBytes...)
	}

	return batch, nil
}
