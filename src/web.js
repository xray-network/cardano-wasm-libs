import * as CML from "./libs/cardano-multiplatform-lib/web/cardano_multiplatform_lib"
import wasm from "./libs/cardano-multiplatform-lib/web/cardano_multiplatform_lib_bg.wasm"

CML.initSync(wasm)
export * as CML from "./libs/cardano-multiplatform-lib/web/cardano_multiplatform_lib"
