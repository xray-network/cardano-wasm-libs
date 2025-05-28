import * as CML from "./libs/cardano-multiplatform-lib/web/cardano_multiplatform_lib"
import CMLWasm from "./libs/cardano-multiplatform-lib/web/cardano_multiplatform_lib_bg.wasm"
CML.initSync(CMLWasm)
export * as CML from "./libs/cardano-multiplatform-lib/web/cardano_multiplatform_lib"

import * as MSL from "./libs/message-signing-lib/web/cardano_message_signing"
import MSLWasm from "./libs/message-signing-lib/web/cardano_message_signing_bg.wasm"
MSL.initSync(MSLWasm)
export * as MSL from "./libs/message-signing-lib/web/cardano_message_signing"