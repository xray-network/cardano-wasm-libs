#!/bin/bash

# Config
WORKING_DIR="$(pwd)"

# Cardano Multiplatform Lib
CML_DIR="$WORKING_DIR/rust/cardano-multiplatform-lib"
CML_BUILD_DIR="$WORKING_DIR/src/libs/cardano-multiplatform-lib"
rm -rf "$CML_BUILD_DIR"
cd "$CML_DIR/cml/wasm"
wasm-pack build --target browser --out-dir "$CML_BUILD_DIR/browser"
wasm-pack build --target nodejs --out-dir "$CML_BUILD_DIR/nodejs"
wasm-pack build --target web --out-dir "$CML_BUILD_DIR/web"

# UPLC_DIR="$WORKING_DIR/rust/untyped-plutus-core"
# UPLC_BUILD_DIR="$BUILD_DIR/uplc"
# cd "$UPLC_DIR"
# wasm-pack build --target web --out-dir "$UPLC_BUILD_DIR/workers"
# wasm-pack build --target nodejs --out-dir "$UPLC_BUILD_DIR/nodejs"
# wasm-pack build --target browser --out-dir "$UPLC_BUILD_DIR/browser"

# Clean up
find "$WORKING_DIR/src" -type f -name '.gitignore' -exec rm -f {} +