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

package main

import (
	"context"
	"flag"
	"os"
	"syscall"

	"github.com/polynetwork/arb-relayer/config"
	"github.com/polynetwork/arb-relayer/pkg/log"
	"github.com/polynetwork/arb-relayer/pkg/relay"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/zhiqiangxu/util/signal"
)

var confFile string
var polyHeight uint64

func init() {
	flag.StringVar(&confFile, "conf", "./config.json", "configuration file path")
	flag.Uint64Var(&polyHeight, "poly", 0, "specify poly start height")
	flag.Parse()
}

func setUpPoly(polySdk *sdk.PolySdk, rpcAddr string) error {
	polySdk.NewRpcClient().SetAddress(rpcAddr)
	hdr, err := polySdk.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	polySdk.SetChainId(hdr.ChainID)
	return nil
}

func main() {
	log.InitLog(log.InfoLog, "./Log/", log.Stdout)

	conf, err := config.LoadConfig(confFile)
	if err != nil {
		log.Fatalf("LoadConfig failed: %v", err)
	}

	if polyHeight > 0 {
		conf.ForceConfig.PolyHeight = uint32(polyHeight)
	}

	polySdk := sdk.NewPolySdk()
	err = setUpPoly(polySdk, conf.PolyConfig.RestURL)
	if err != nil {
		log.Fatalf("setUpPoly failed: %v", err)
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	signal.SetupHandler(func(sig os.Signal) {
		cancelFunc()
	}, syscall.SIGINT, syscall.SIGTERM)

	relayer := relay.NewPolyToArb(polySdk, conf)
	relayer.Start(ctx)
}
