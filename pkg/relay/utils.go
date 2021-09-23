package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/sm2"
	"github.com/polynetwork/arb-relayer/pkg/log"
	"github.com/polynetwork/poly/common"
)

func ParseAuditpath(path []byte) ([]byte, []byte, [][32]byte, error) {
	source := common.NewZeroCopySource(path)
	/*
		l, eof := source.NextUint64()
		if eof {
			return nil, nil, nil, nil
		}
	*/
	value, eof := source.NextVarBytes()
	if eof {
		return nil, nil, nil, nil
	}
	size := int((source.Size() - source.Pos()) / common.UINT256_SIZE)
	pos := make([]byte, 0)
	hashs := make([][32]byte, 0)
	for i := 0; i < size; i++ {
		f, eof := source.NextByte()
		if eof {
			return nil, nil, nil, nil
		}
		pos = append(pos, f)

		v, eof := source.NextHash()
		if eof {
			return nil, nil, nil, nil
		}
		var onehash [32]byte
		copy(onehash[:], (v.ToArray())[0:32])
		hashs = append(hashs, onehash)
	}

	return value, pos, hashs, nil
}

// GetCurveLabel
func GetCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(elliptic.P224().Params().Name):
		return 1, nil
	case strings.ToUpper(elliptic.P256().Params().Name):
		return 2, nil
	case strings.ToUpper(elliptic.P384().Params().Name):
		return 3, nil
	case strings.ToUpper(elliptic.P521().Params().Name):
		return 4, nil
	case strings.ToUpper(sm2.SM2P256V1().Params().Name):
		return 20, nil
	case strings.ToUpper(btcec.S256().Name):
		return 5, nil
	default:
		panic("err")
	}
}

func GetNoCompresskey(key keypair.PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == elliptic.P256().Params().Name {
				return ec.EncodePublicKey(t.PublicKey, false)
			}
			buf.WriteByte(byte(0x12))
		case ec.SM2:
			buf.WriteByte(byte(0x13))
		}
		label, err := GetCurveLabel(t.Curve.Params().Name)
		if err != nil {
			panic(err)
		}
		buf.WriteByte(label)
		buf.Write(ec.EncodePublicKey(t.PublicKey, false))
	case ed25519.PublicKey:
		panic("err")
	default:
		panic("err")
	}
	return buf.Bytes()
}

func GetEthNoCompressKey(key keypair.PublicKey) []byte {

	switch t := key.(type) {
	case *ec.PublicKey:
		return crypto.FromECDSAPub(t.PublicKey)
	case ed25519.PublicKey:
		panic("err")
	default:
		panic("err")
	}
}

func waitTransactionConfirm(client *ethclient.Client, polyTxHash string, hash ethcommon.Hash) bool {
	start := time.Now()
	for {
		if time.Now().After(start.Add(time.Minute * 1)) {
			return false
		}
		time.Sleep(time.Second * 1)
		_, ispending, err := client.TransactionByHash(context.Background(), hash)
		if err != nil {
			continue
		}
		log.Debugf("( eth_transaction %s, poly_tx %s ) is pending: %v", hash.String(), polyTxHash, ispending)
		if ispending == true {
			continue
		} else {
			receipt, err := client.TransactionReceipt(context.Background(), hash)
			if err != nil {
				continue
			}
			return receipt.Status == types.ReceiptStatusSuccessful
		}
	}
}
