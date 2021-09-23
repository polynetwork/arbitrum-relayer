module github.com/polynetwork/arb-relayer

go 1.15

require (
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/ethereum/go-ethereum v1.9.15
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/eth-contracts v0.0.0-20210816091154-2b1cbe073e40
	github.com/polynetwork/poly v0.0.0-20210112063446-24e3d053e9d6
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114120411-3dcba035134f
	github.com/zhiqiangxu/util v0.0.0-20210608123940-8b5a9fec779f
	poly_bridge_sdk v0.0.0-00010101000000-000000000000
)

replace poly_bridge_sdk => github.com/blockchain-develop/poly_bridge_sdk v0.0.0-20210327080022-0e6eb4b31700
