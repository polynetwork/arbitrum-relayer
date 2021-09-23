package config

import (
	"encoding/json"
	"io/ioutil"
	"sync"
)

type Config struct {
	sync.Once
	PolyConfig       PolyConfig
	ArbConfig        ArbConfig
	BridgeConfig     BridgeConfig
	ForceConfig      ForceConfig
	WhitelistMethods []string
	whitelistMethods map[string]bool
	BoltDbPath       string
	Free             bool
}

func (c *Config) IsWhitelistMethod(method string) bool {
	c.Do(func() {
		c.whitelistMethods = map[string]bool{}
		for _, m := range c.WhitelistMethods {
			c.whitelistMethods[m] = true
		}
	})

	return c.whitelistMethods[method]
}

type PolyConfig struct {
	RestURL                 string
	EntranceContractAddress string
}

type ForceConfig struct {
	PolyHeight uint32
}

type ArbConfig struct {
	SideChainId         uint64
	RestURL             []string
	ECCMContractAddress string
	ECCDContractAddress string
	KeyStorePath        string
	KeyStorePwdSet      map[string]string
}

type BridgeConfig struct {
	RestURL [][]string
}

func LoadConfig(confFile string) (config *Config, err error) {
	jsonBytes, err := ioutil.ReadFile(confFile)
	if err != nil {
		return
	}

	config = &Config{}
	err = json.Unmarshal(jsonBytes, config)
	return
}
