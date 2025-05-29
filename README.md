<a href="https://discord.gg/WhZmm46APN"><img alt="Discord" src="https://img.shields.io/discord/852538978946383893?style=for-the-badge&logo=discord&label=Discord&labelColor=%231940ED&color=%233FCB9B"></a>
<a href="https://www.npmjs.com/package/cardano-wasm-libs"><img alt="NPM" src="https://img.shields.io/npm/v/cardano-wasm-libs/latest?style=for-the-badge&logo=npm&labelColor=%231940ED&color=%233FCB9B"></a>

  
# Cardano WASM Libs

A set of rust libraries that are compiled into WASM for further use in Cardano infrastructure. Used as wasm-pack export to various targets (nodejs, browser, web+serverless). Made for [CardanoWeb3js](https://github.com/xray-network/cardano-web3-js).

* [Cardano Multiplatform Lib](https://github.com/dcSpark/cardano-multiplatform-lib) (by dcSpark)
* [Message Signing Lib](https://github.com/Emurgo/message-signing) (by Emurgo)
* [Untyped Plutus Core Lib](https://github.com/xray-network/cardano-wasm-libs/tree/main/rust/untyped-plutus-core) (by XRAY/Network)

# Usage
```ts
import { CML, MSL, UPLC } from "cardano-wasm-libs/nodejs" // nodejs
import { CML, MSL, UPLC } from "cardano-wasm-libs/browser" // browser
import { CML, MSL, UPLC } from "cardano-wasm-libs/web" // browser, serverless environments (Cloudflare Workers, etc)
```

# Build & Submodules Update

Build
```
yarn cml-build
yarn msl-build
yarn uplc-build
```

Submodules Update
```
yarn cml-update
yarn msl-update
```
