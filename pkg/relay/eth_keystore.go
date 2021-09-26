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
	"fmt"
	"math/big"
	"strings"

	"log"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
)

// EthKeyStore ...
type EthKeyStore struct {
	ks      *keystore.KeyStore
	chainID *big.Int
}

// NewEthKeyStore ...
func NewEthKeyStore(path string, pwdset map[string]string, chainID *big.Int) *EthKeyStore {
	service := &EthKeyStore{}
	capitalKeyStore := keystore.NewKeyStore(path, keystore.StandardScryptN,
		keystore.StandardScryptP)
	accArr := capitalKeyStore.Accounts()
	if len(accArr) == 0 {
		panic("no account found")
	}
	str := ""
	for i, v := range accArr {
		str += fmt.Sprintf("(no.%d acc: %s), ", i+1, v.Address.String())
	}
	log.Printf("using accounts: [ %s ]", str)
	service.ks = capitalKeyStore
	service.chainID = chainID

	err := service.unlockKeys(pwdset)
	if err != nil {
		panic(fmt.Errorf("unlockKeys failed:%v", err))
	}
	return service
}

func (store *EthKeyStore) unlockKeys(pwdset map[string]string) error {
	for _, v := range store.GetAccounts() {
		err := store.ks.Unlock(v, pwdset[strings.ToLower(v.Address.String())])
		if err != nil {
			return fmt.Errorf("failed to unlock acc %s: %v", v.Address.String(), err)
		}
	}
	return nil
}

// SignTransaction ...
func (store *EthKeyStore) SignTransaction(tx *types.Transaction, acc accounts.Account) (*types.Transaction, error) {
	tx, err := store.ks.SignTx(acc, tx, store.chainID)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// GetAccounts ...
func (store *EthKeyStore) GetAccounts() []accounts.Account {
	return store.ks.Accounts()
}

// GetChainID ...
func (store *EthKeyStore) GetChainID() uint64 {
	return store.chainID.Uint64()
}
