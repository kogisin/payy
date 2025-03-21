# Ethereum Smart Contracts

Rollup smart contracts to verify the rollup state on Ethereum.

## Run locally

Run the local Ethereum hardhat node (resets on each restart):

```bash
yarn eth-node
```

Deploy the contract:

```bash
yarn deploy:local
```

Run server:

```bash
cargo run --release --bin node
```

### Mock aggregate proof

You can deploy a mock aggregate proof verifier using the `DEV_USE_NOOP_VERIFIER=1` environment variable.

You can then run a node with `--mode mock-prover` to skip generating aggregate proofs.

## Deploy to live network

Deploy to a live network. `SECRET_KEY` must have native token on the account. Select network by providing
the network URL

* MAINNET_URL
* SEPOLIA_URL
* MUMBAI_URL
etc

For example:

```bash
SEPOLIA_URL=<alchemy_url> SECRET_KEY=<secret key with eth on network> yarn deploy -- --network sepolia
```

Run server:

```bash
export ETHEREUM_RPC='<same as SEPOLIA_URL>' # maybe I should have just used the same env var names for hardhat deploy
export PROVER_SECRET_KEY=<same as SEPOLIA_SECRET_KEY>
export ROLLUP_CONTRACT_ADDR=...

cargo run --release server
```


### Prenet

#### Deploy

```bash
OWNER=0x6B96F1A8D65eDe8AD688716078B3DD79f9BD7323 PROVER_ADDRESS=0x6B96F1A8D65eDe8AD688716078B3DD79f9BD7323 VALIDATORS=0x6B96F1A8D65eDe8AD688716078B3DD79f9BD7323 AMOY_URL=https://polygon-amoy.g.alchemy.com/v2/9e_9NcJQ4rvg9RCsW2l7dqdbHw0VHBCf SECRET_KEY=<SECRET_KEY> GAS_PRICE_GWEI=2 yarn deploy -- --network amoy
```

#### Upgrade

```bash
ROLLUP_PROXY_ADMIN_ADDR=0x3a7122f0711822e63aa6218f4db3a6e40f97bdcf ROLLUP_CONTRACT_ADDR=0x1e44fa332fc0060164061cfedf4d3a1346a9dc38 AMOY_URL=https://polygon-amoy.g.alchemy.com/v2/9e_9NcJQ4rvg9RCsW2l7dqdbHw0VHBCf SECRET_KEY=<SECRET_KEY> yarn upgrade-rollup -- --network amoy
```

Add `UPGRADE_DEPLOY=true` to deploy the contract (not just print the calldata).

#### Addresses:

```
USDC_CONTRACT_ADDR=0x206fcb3bea972c5cd6b044160b8b0691fb4aff57
AGGREGATE_BIN_ADDR=0x58f2e5031af2d6c1996334b10880973c494e3b06
AGGREGATE_VERIFIER_ADDR=0xa98e2c3a375b5aedf31b1276594a11ff41d72a36
MINT_BIN_ADDR=0x3945f7f99460c86dfe73de6a757b1b6ed1a52604
MINT_VERIFIER_ADDR=0xfeda1cec4b2b9f958e6c0823cf14b0e687fa4a59
BURN_BIN_ADDR=0xaa331ab85fa49137cbfbb614bc20eb55e0e1ae46
BURN_VERIFIER_ADDR=0xe952927e6ff3c66933fa23f228dc74f7eff95fe3
ROLLUP_V1_CONTRACT_ADDR=0x618975654efb35f6674fe9d1afb9f95fa78a31a7
ROLLUP_PROXY_ADMIN_ADDR=0x3a7122f0711822e63aa6218f4db3a6e40f97bdcf
ROLLUP_V2_CONTRACT_ADDR=0x6c5da7ccab84eb7abadbcbe87b3913ccbad0fb9a
ROLLUP_V3_CONTRACT_ADDR=0x9b89bb7a804639bfde8c8d5b5826007988142a38
ROLLUP_V4_CONTRACT_ADDR=0x68427f3169ed36b7b5933446305964f2b3445067
BURN_TO_ADDRESS_ROUTER_CONTRACT_ADDR=0x3471dadabe5a8491e14a9192b1960a55108aea8d
BURN_V2_BIN_ADDR=0x8ef4a7d9d791c4798eff556ea9bbdbdc981678f7
BURN_VERIFIER_V2_ADDR=0xbe5aee548b3b738dfb58cc3ea1c5d2c2b5d468fc
ROLLUP_V5_CONTRACT_ADDR=0xba3c280ddfca291f815cd61dc295009aae002795
ROLLUP_CONTRACT_ADDR=0x1e44fa332fc0060164061cfedf4d3a1346a9dc38
ROLLUP_V6_CONTRACT_ADDR=0x9165dbc43077c107f899a37b3c693d251a4bdb78
```

### Testnet

#### Deploy

```bash
OWNER=0x06BB7004273ac82309a7b1dF90B8cb76d6BA299F PROVER_ADDRESS=0x6B96F1A8D65eDe8AD688716078B3DD79f9BD7323 VALIDATORS=0x6B96F1A8D65eDe8AD688716078B3DD79f9BD7323 POLYGON_URL=https://polygon-mainnet.g.alchemy.com/v2/UrFsshbLOrSG1_cPayD3OHHi0s066Shx SECRET_KEY=<SECRET_KEY> yarn deploy -- --network polygon
```

#### Upgrade

```bash
SECRET_KEY=... ROLLUP_CONTRACT_ADDR=0x24baf24128af44f03d61a3e657b1cec298ef6cdc ROLLUP_PROXY_ADMIN_ADDR=0xbb923b4c1cc57c4d929adfbc4160bfc26ad750ab  POLYGON_URL=https://polygon-mainnet.g.alchemy.com/v2/UrFsshbLOrSG1_cPayD3OHHi0s066Shx yarn upgrade-rollup -- --network polygon
```

Addresses:

```
AGGREGATE_BIN_ADDR=0xebcde42fc628f06a2d395a972cb81b267a105577
AGGREGATE_VERIFIER_ADDR=0xd8ce1f59185707503bffe45e34b29e3617049c27
MINT_BIN_ADDR=0x30edc6ccf96dbda5d62e5e270d0731dac7298f81
MINT_VERIFIER_ADDR=0xd9d38308653b83501a5feee170c6030890f9e43b
BURN_BIN_ADDR=0xf009a7a0a89f7514322edc1ae5c15ce0e1db4070
BURN_VERIFIER_ADDR=0x4ac88e4a18f8f99a49bf7ccfc05b49cf8ef41cd9
ROLLUP_V1_CONTRACT_ADDR=0x4514b09f62834d9d5807f4f24d200b4ff98046ed
ROLLUP_PROXY_ADMIN_ADDR=0xbb923b4c1cc57c4d929adfbc4160bfc26ad750ab
ROLLUP_V2_CONTRACT_ADDR=0xc4d8c671fbe3834e9d476bc146d348907d235614
ROLLUP_V3_CONTRACT_ADDR=0x2cc9818c40c54de413b783aad42e407ade1d3093
ROLLUP_V4_CONTRACT_ADDR=0xc546293e7c89a425eaf093eb01d104ef8aba7c14
BURN_V2_BIN_ADDR=0x3160976dfe28b90cc0c60f9f372ee5c44a4746b5
BURN_VERIFIER_V2_ADDR=0x9ffda5bdd6a8c63ad431ca0249c5e16d19c3d708
ROLLUP_V5_CONTRACT_ADDR=0x61d67ac8d472a91c8f9bb0c8f92ed12cc362c196
ROLLUP_CONTRACT_ADDR=0x24baf24128af44f03d61a3e657b1cec298ef6cdc
BURN_TO_ADDRESS_ROUTER_CONTRACT_ADDR=0x947502b6c4363e5ba5d7b65748478fb2ebc7319b
ROLLUP_V6_CONTRACT_ADDR=0x2f0b843869de91eef34441b639b41218ae67f4ee
ACROSS_WITH_AUTHORIZATION_CONTRACT_ADDR=0xf5bf1a6a83029503157bb3761488bb75d64002e7
```

### Mainnet

```bash
OWNER=0x230Dfb03F078B0d5E705F4624fCC915f3126B40f PROVER_ADDRESS=0x5343b904bf837befb2f5a256b0cd5fbf30503d38 VALIDATORS=0x41582701cb3117680687df80bd5a2ca971bda964,0x75eadc4a85ee07e3b60610dc383eab1b27b1c4c1,0x53b385c35d7238d44dfd591eee94fee83f6711de,0x05dc3d71e2a163e6926956bc0769c5cb8a6b9d1a,0x581c5d92e35e51191a982ebd803f92742e3c9fe3,0xbb82aef611b513965371b3d33c4d3b6c8b926f24,0xeacb0b7e37709bafb4204c0c31a2919212049975,0xf9d65db5f8952bee5ea990df79a0032eda0752b7,0x662b7930b201fbe11bcef3cdef6e8f2c8ed4983a,0x68a78d978497b0a87ff8dbeaffae8e68ad4c39dc POLYGON_URL=https://polygon-mainnet.g.alchemy.com/v2/UrFsshbLOrSG1_cPayD3OHHi0s066Shx SECRET_KEY=<SECRET_KEY> yarn deploy -- --network polygon
```

Addresses:

```
USDC_CONTRACT_ADDR=0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359
AGGREGATE_BIN_ADDR=0x31063c00ad62f9090abb9308f4549a1dee4a6362
AGGREGATE_VERIFIER_ADDR=0x9d9fe636a329a07d26b5c5e8411b278462f5f325
MINT_BIN_ADDR=0xe025bb7ce28a4565a890a8d708faf9dd48ea1678
MINT_VERIFIER_ADDR=0xe938b6c17a39e80c7630040df0d2dbe794d42534
BURN_BIN_ADDR=0x4449d93873f7523d1b6cdfaa5a792e0867ca3a17
BURN_VERIFIER_ADDR=0x36e4a9f800e07a4aa6647c83e97f7e47b8028895
ROLLUP_V1_CONTRACT_ADDR=0x470e6986d9a54b498f4fa39ee118d25d52cc0a19
ROLLUP_CONTRACT_ADDR=0x4cbb5041df8d815d752239960fba5e155ba2687e
ROLLUP_PROXY_ADMIN_ADDR=0xe022130f28c4e6ddf1da5be853a185fbeb84d795
BURN_TO_ADDRESS_ROUTER_CONTRACT_ADDR=0x8e93495fb707785af8c1345858e4898c2d005f7b
BURN_V2_BIN_ADDR=0x2c103552a8f311cd6e35c2ca69e2f42e812c12d0
BURN_VERIFIER_V2_ADDR=0x51c77c8b99aab9d6c83a4deb1247c528325e5c0b
ROLLUP_V5_CONTRACT_ADDR=0x451a98322400d2a9018303cc66a68b3d903a3329
ROLLUP_V6_CONTRACT_ADDR=0x3a58033501778babcd785cd89c054f16fa9b1f2b
ACROSS_WITH_AUTHORIZATION_CONTRACT_ADDR=0xf5bf1a6a83029503157bb3761488bb75d64002e7
```

#### Upgrade

```bash
SECRET_KEY=... ROLLUP_CONTRACT_ADDR=0x4cbb5041df8d815d752239960fba5e155ba2687e ROLLUP_PROXY_ADMIN_ADDR=0xe022130f28c4e6ddf1da5be853a185fbeb84d795  POLYGON_URL=https://polygon-mainnet.g.alchemy.com/v2/UrFsshbLOrSG1_cPayD3OHHi0s066Shx yarn upgrade-rollup -- --network polygon
```

### Upgrade Rollup contract

Using `yarn upgrade-rollup`, you can upgrade a previously deployed rollup contract to a new version.

Example without a specified network:

```bash
SECRET_KEY=... ROLLUP_CONTRACT_ADDR=<proxy_contract_addr> ROLLUP_PROXY_ADMIN_ADDR=<proxy_admin_contract_addr> yarn upgrade-rollup
```

## Regenerating EVM aggregate proof verifier

To re-generate EVM proof verifier, see [pkg/contracts](/pkg/prover).
