/**
 * Copyright (C) 2021 The poly network Authors
 * This file is part of The poly network library.
 *
 * The poly network is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The poly network is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the poly network.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"poly_bridge_sdk"
	"strings"
	"sync"
	"time"

	"encoding/hex"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/polynetwork/arb-relayer/config"
	"github.com/polynetwork/arb-relayer/pkg/db"
	"github.com/polynetwork/arb-relayer/pkg/log"
	"github.com/polynetwork/eth-contracts/go_abi/eccd_abi"
	"github.com/polynetwork/eth-contracts/go_abi/eccm_abi"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	polytypes "github.com/polynetwork/poly/core/types"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/zhiqiangxu/util"
)

type PolyToArb struct {
	wg              sync.WaitGroup
	conf            *config.Config
	polySdk         *sdk.PolySdk
	bridgeSdk       *poly_bridge_sdk.BridgeFeeCheck
	bdb             *db.BoltDB
	clients         []*ethclient.Client
	ccmContractAddr ethcommon.Address
	ccmContracts    []*eccm_abi.EthCrossChainManager
	ccdContracts    []*eccd_abi.EthCrossChainData
	ccmAbi          abi.ABI
	ks              *EthKeyStore
	txWorkCh        chan *txWork
	idx             int
}

func NewPolyToArb(polySdk *sdk.PolySdk, conf *config.Config) *PolyToArb {
	return &PolyToArb{polySdk: polySdk, conf: conf, txWorkCh: make(chan *txWork, 10)}
}

func (p *PolyToArb) init(ctx context.Context) (err error) {
	p.bridgeSdk = poly_bridge_sdk.NewBridgeFeeCheck(p.conf.BridgeConfig.RestURL, 5)

	var clients []*ethclient.Client
	for _, node := range p.conf.ArbConfig.RestURL {
		client, err := ethclient.Dial(node)
		if err != nil {
			log.Fatalf("ethclient.Dial failed:%v", err)
		}

		clients = append(clients, client)
	}
	p.clients = clients

	bdb, err := db.NewBoltDB(p.conf.BoltDbPath)
	if err != nil {
		return
	}
	p.bdb = bdb

	ccmContractAddr := ethcommon.HexToAddress(p.conf.ArbConfig.ECCMContractAddress)
	p.ccmContractAddr = ccmContractAddr
	p.ccmContracts = make([]*eccm_abi.EthCrossChainManager, len(clients))
	for i := 0; i < len(p.clients); i++ {
		contract, err := eccm_abi.NewEthCrossChainManager(ccmContractAddr, p.clients[i])
		if err != nil {
			return err
		}
		p.ccmContracts[i] = contract
	}

	ccdContractAddr := ethcommon.HexToAddress(p.conf.ArbConfig.ECCDContractAddress)
	p.ccdContracts = make([]*eccd_abi.EthCrossChainData, len(clients))
	for i := 0; i < len(p.clients); i++ {
		contract, err := eccd_abi.NewEthCrossChainData(ccdContractAddr, p.clients[i])
		if err != nil {
			return err
		}
		p.ccdContracts[i] = contract
	}

	p.ccmAbi, err = abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return
	}

	start := time.Now()
	chainID, err := clients[0].ChainID(context.Background())
	if err != nil {
		log.Fatalf("clients[0].ChainID failed:%v", err)
	}
	log.Infof("ChainID() took %v", time.Now().Sub(start).String())

	ks := NewEthKeyStore(p.conf.ArbConfig.KeyStorePath, p.conf.ArbConfig.KeyStorePwdSet, chainID)
	p.ks = ks

	util.GoFunc(&p.wg, func() { p.startTxWorkers(ctx) })
	return
}

const POLY_USEFUL_BLOCK_NUM = 1

func (p *PolyToArb) Start(ctx context.Context) {
	err := p.init(ctx)
	if err != nil {
		log.Fatalf("PolyToArb.init failed: %v", err)
	}
	nextPolyHeight := p.bdb.GetPolyHeight()
	if p.conf.ForceConfig.PolyHeight > 0 {
		nextPolyHeight = p.conf.ForceConfig.PolyHeight
	}
	ticker := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-ticker.C:
			height, err := p.polySdk.GetCurrentBlockHeight()
			if err != nil {
				log.Warnf("GetCurrentBlockHeight failed:%v", err)
				continue
			}
			if height < nextPolyHeight+POLY_USEFUL_BLOCK_NUM {
				continue
			}

			for nextPolyHeight < height-POLY_USEFUL_BLOCK_NUM {
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}
					log.Infof("handling poly height:%d", nextPolyHeight)
					err = p.handleDepositEvents(ctx, nextPolyHeight)
					if err != nil {
						log.Warnf("handleDepositEvents failed:%v", err)
						sleep()
						continue
					}
					nextPolyHeight++
				}
			}

			err = p.bdb.UpdatePolyHeight(nextPolyHeight)
			if err != nil {
				log.Warnf("UpdateArbHeight failed:%v", err)
			}
		case <-ctx.Done():
			log.Info("quiting from signal...")
			p.wg.Wait()
			log.Info("quited...")
			return
		}
	}
}

func (p *PolyToArb) handleDepositEvents(ctx context.Context, height uint32) (err error) {
	p.idx = randIdx(len(p.clients))
	lastEpoch, err := p.findLatestHeight()
	if err != nil {
		log.Errorf("handleDepositEvents - findLatestHeight failed: %v", err)
		return
	}
	hdr, err := p.polySdk.GetHeaderByHeight(height + 1)
	if err != nil {
		log.Errorf("handleDepositEvents - GetHeaderByHeight on height :%d failed", height)
		return
	}

	isCurr := lastEpoch <= height
	isEpoch, pubkList, err := p.IsEpoch(hdr)
	if err != nil {
		log.Errorf("falied to check isEpoch: %v", err)
		return
	}
	var (
		anchor *polytypes.Header
		hp     string
	)
	if !isCurr {
		anchor, _ = p.polySdk.GetHeaderByHeight(lastEpoch + 1)
		proof, _ := p.polySdk.GetMerkleProof(height+1, lastEpoch+1)
		hp = proof.AuditPath
	} else if isEpoch {
		anchor, _ = p.polySdk.GetHeaderByHeight(height + 2)
		proof, _ := p.polySdk.GetMerkleProof(height+1, height+2)
		hp = proof.AuditPath
	}

	cnt := 0
	events, err := p.polySdk.GetSmartContractEventByBlock(height)
	if err != nil {
		log.Errorf("GetSmartContractEventByBlock failed: %v", err)
		return
	}
	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress == p.conf.PolyConfig.EntranceContractAddress {
				states := notify.States.([]interface{})
				method, _ := states[0].(string)
				if method != "makeProof" {
					continue
				}
				if uint64(states[2].(float64)) != p.conf.ArbConfig.SideChainId {
					continue
				}
				proof, err := p.polySdk.GetCrossStatesProof(hdr.Height-1, states[5].(string))
				if err != nil {
					log.Errorf("handleDepositEvents - failed to get proof for poly_hash %s key %s: %v", event.TxHash, states[5].(string), err)
					continue
				}
				auditpath, _ := hex.DecodeString(proof.AuditPath)
				value, _, _, _ := ParseAuditpath(auditpath)
				param := &common2.ToMerkleValue{}
				if err := param.Deserialization(common.NewZeroCopySource(value)); err != nil {
					log.Errorf("handleDepositEvents - failed to deserialize poly_hash %s MakeTxParam (value: %x, err: %v)", event.TxHash, value, err)
					continue
				}

				if param.MakeTxParam.ToChainID != p.conf.ArbConfig.SideChainId {
					log.Errorf("ignored because ToChainID not match for poly_hash %s, got %d expect %d", event.TxHash, param.MakeTxParam.ToChainID, p.conf.ArbConfig.SideChainId)
					continue
				}
				if !p.conf.IsWhitelistMethod(param.MakeTxParam.Method) {
					log.Errorf("Invalid target contract method %s", param.MakeTxParam.Method)
					continue
				}
				if !p.isPaid(param) {
					log.Infof("%v skipped because not paid", event.TxHash)
					continue
				}
				log.Infof("%v is paid, start processing", event.TxHash)

				txData := p.makeTx(hdr, param, hp, anchor, auditpath)
				if len(txData) == 0 {
					continue
				}

				p.sendTx(ctx, txData, event.TxHash)
			}
		}
	}

	if cnt == 0 && isEpoch && isCurr {
		return p.commitHeader(hdr, pubkList)
	}
	return
}

func (p *PolyToArb) sendTx(ctx context.Context, txData []byte, polyTxHash string) {
	select {
	case p.txWorkCh <- &txWork{txData: txData, polyTxHash: polyTxHash}:
	case <-ctx.Done():
	}
}

func (p *PolyToArb) startTxWorkers(ctx context.Context) {
	var wg sync.WaitGroup
	for _, account := range p.ks.GetAccounts() {
		util.GoFunc(&wg, func() { p.startTxWorker(ctx, account) })
	}
	wg.Wait()
}

type txWork struct {
	txData     []byte
	polyTxHash string
}

func (p *PolyToArb) startTxWorker(ctx context.Context, account accounts.Account) {
	for {
		select {
		case work := <-p.txWorkCh:
			func() {
				duration := time.Second * 20
				timerCtx, cancelFunc := context.WithTimeout(context.Background(), duration)
				defer cancelFunc()

				start := time.Now()
				for {
					if time.Since(start) > duration {
						break
					}
					idx := randIdx(len(p.clients))
					client := p.clients[idx]

					gasPrice, err := client.SuggestGasPrice(timerCtx)
					if err != nil {
						log.Errorf("SuggestGasPrice failed:%v", err)
						continue
					}

					callMsg := ethereum.CallMsg{
						From: account.Address, To: &p.ccmContractAddr, Gas: 0, GasPrice: gasPrice,
						Value: big.NewInt(0), Data: work.txData,
					}
					gasLimit, err := client.EstimateGas(timerCtx, callMsg)
					if err != nil {
						log.Errorf("client.EstimateGas failed:%v polyTxHash:%s", err, work.polyTxHash)
						continue
					}

					nonce := p.getNonce(account.Address)
					tx := types.NewTransaction(nonce, p.ccmContractAddr, big.NewInt(0), gasLimit, gasPrice, work.txData)
					signedtx, err := p.ks.SignTransaction(tx, account)
					if err != nil {
						log.Fatalf("keyStore.SignTransaction failed:%v", err)
					}

					err = client.SendTransaction(timerCtx, signedtx)
					if err != nil {
						log.Errorf("SendTransaction failed:%v, polyTxHash:%s", err, work.polyTxHash)
						continue
					}
					hash := signedtx.Hash()
					isSuccess := waitTransactionConfirm(client, work.polyTxHash, hash)
					if isSuccess {
						log.Infof("successful to relay tx to ethereum: (eth_hash: %s, account: %s, nonce: %d, poly_hash: %s, gasPrice: %d, idx: %d)",
							hash.String(), account.Address.Hex(), nonce, work.polyTxHash, gasPrice.Int64(), idx)
					} else {
						log.Errorf("failed to relay tx to ethereum: (eth_hash: %s, account: %s, nonce: %d,  poly_hash: %s, gasPrice: %d, idx: %d)",
							hash.String(), account.Address.Hex(), nonce, work.polyTxHash, gasPrice.Int64(), idx)
					}
					return
				}

				log.Errorf("failed to relay tx to ethereum in time: (poly_hash: %s)", work.polyTxHash)
			}()
		case <-ctx.Done():
			log.Infof("startTxWorker quit for ctx")
			return
		}
	}
}

func (p *PolyToArb) getNonce(addr ethcommon.Address) uint64 {
	for {
		nonce, err := p.clients[randIdx(len(p.clients))].NonceAt(context.Background(), addr, nil)
		if err != nil {
			log.Errorf("NonceAt failed:%v", err)
			sleep()
			continue
		}
		return nonce
	}

}

func (p *PolyToArb) makeTx(header *polytypes.Header, param *common2.ToMerkleValue, headerProof string, anchorHeader *polytypes.Header, rawAuditPath []byte) []byte {
	var (
		sigs       []byte
		headerData []byte
	)

	if anchorHeader != nil && headerProof != "" {
		for _, sig := range anchorHeader.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	} else {
		for _, sig := range header.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	}

	eccd := p.ccdContracts[p.idx]
	fromTx := [32]byte{}
	copy(fromTx[:], param.TxHash[:32])

	res, err := eccd.CheckIfFromChainTxExist(nil, param.FromChainID, fromTx)
	if err != nil {
		log.Fatalf("eccd.CheckIfFromChainTxExist failed:%v", err)
	}

	if res {
		log.Infof("already relayed to sidechain: ( from_chain_id: %d, to_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
			param.FromChainID, param.MakeTxParam.ToChainID, param.TxHash, param.MakeTxParam.TxHash)
		return nil
	}

	rawProof, _ := hex.DecodeString(headerProof)
	var rawAnchor []byte
	if anchorHeader != nil {
		rawAnchor = anchorHeader.GetMessage()
	}

	headerData = header.GetMessage()

	txData, err := p.ccmAbi.Pack("verifyHeaderAndExecuteTx", rawAuditPath, headerData, rawProof, rawAnchor, sigs)
	if err != nil {
		log.Fatalf("contractAbi.Pack failed:%v", err)
	}

	return txData
}

func (p *PolyToArb) commitHeader(header *polytypes.Header, pubkList []byte) (err error) {
	return
}

func (p *PolyToArb) isPaid(param *common2.ToMerkleValue) bool {
	if p.conf.Free {
		return true
	}
	for {
		txHash := hex.EncodeToString(param.MakeTxParam.TxHash)
		req := &poly_bridge_sdk.CheckFeeReq{Hash: txHash, ChainId: param.FromChainID}
		resp, err := p.bridgeSdk.CheckFee([]*poly_bridge_sdk.CheckFeeReq{req})
		if err != nil {
			log.Errorf("CheckFee failed:%v, TxHash:%s FromChainID:%d", err, txHash, param.FromChainID)
			time.Sleep(time.Second)
			continue
		}
		if len(resp) != 1 {
			log.Errorf("CheckFee resp invalid, length %d, TxHash:%s FromChainID:%d", len(resp), txHash, param.FromChainID)
			time.Sleep(time.Second)
			continue
		}

		switch resp[0].PayState {
		case poly_bridge_sdk.STATE_HASPAY:
			return true
		case poly_bridge_sdk.STATE_NOTPAY:
			return false
		case poly_bridge_sdk.STATE_NOTCHECK:
			log.Errorf("CheckFee STATE_NOTCHECK, TxHash:%s FromChainID:%d Poly Hash:%s, wait...", txHash, param.FromChainID, hex.EncodeToString(param.TxHash))
			time.Sleep(time.Second)
			continue
		}

	}
}

func (p *PolyToArb) IsEpoch(hdr *polytypes.Header) (bool, []byte, error) {
	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(hdr.ConsensusPayload, blkInfo); err != nil {
		return false, nil, fmt.Errorf("commitHeader - unmarshal blockInfo error: %s", err)
	}
	if hdr.NextBookkeeper == common.ADDRESS_EMPTY || blkInfo.NewChainConfig == nil {
		return false, nil, nil
	}

	eccd := p.ccdContracts[p.idx]
	rawKeepers, err := eccd.GetCurEpochConPubKeyBytes(nil)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get current epoch keepers: %v", err)
	}

	var bookkeepers []keypair.PublicKey
	for _, peer := range blkInfo.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)
	publickeys := make([]byte, 0)
	sink := common.NewZeroCopySink(nil)
	sink.WriteUint64(uint64(len(bookkeepers)))
	for _, key := range bookkeepers {
		raw := GetNoCompresskey(key)
		publickeys = append(publickeys, raw...)
		sink.WriteVarBytes(crypto.Keccak256(GetEthNoCompressKey(key)[1:])[12:])
	}
	if bytes.Equal(rawKeepers, sink.Bytes()) {
		return false, nil, nil
	}
	return true, publickeys, nil
}

func (p *PolyToArb) findLatestHeight() (height uint32, err error) {

	ccdContract := p.ccdContracts[p.idx]

	height64, err := ccdContract.GetCurEpochStartHeight(nil)
	if err != nil {
		log.Errorf("findLatestHeight - GetCurEpochStartHeight failed: %v", err)
		return
	}
	height = uint32(height64)
	return
}

func sleep() {
	time.Sleep(time.Second)
}
func randIdx(size int) int {
	return int(rand.Uint32()) % size
}
