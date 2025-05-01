#!/bin/bash

# This script builds local cktap Swift language bindings and corresponding cktapFFI.xcframework.

TARGETDIR="../target"
OUTDIR="."
RELDIR="release-smaller"
NAME="cktapFFI"
STATIC_LIB_NAME="lib${NAME}.a"
NEW_HEADER_DIR="../target/include"

# set required rust version and install component and targets
rustup default 1.85.0
rustup component add rust-src
rustup target add aarch64-apple-ios # iOS arm64
rustup target add x86_64-apple-ios # iOS x86_64
rustup target add aarch64-apple-ios-sim # simulator mac M1
rustup target add aarch64-apple-darwin # mac M1
rustup target add x86_64-apple-darwin # mac x86_64

# Create all required directories first
mkdir -p Sources/CKTap
mkdir -p ../target/include
mkdir -p ../target/lipo-macos/release-smaller
mkdir -p ../target/lipo-ios-sim/release-smaller

cd ../ || exit

# Target architectures
# macOS Intel
cargo build --package rust-cktap --profile release-smaller --target x86_64-apple-darwin --features uniffi
# macOS Apple Silicon
cargo build --package rust-cktap --profile release-smaller --target aarch64-apple-darwin --features uniffi
# Simulator on Intel Macs
cargo build --package rust-cktap --profile release-smaller --target x86_64-apple-ios --features uniffi
# Simulator on Apple Silicon Mac
cargo build --package rust-cktap --profile release-smaller --target aarch64-apple-ios-sim --features uniffi
# iPhone devices
cargo build --package rust-cktap --profile release-smaller --target aarch64-apple-ios --features uniffi

# Then run uniffi-bindgen
cargo run --bin uniffi-bindgen generate \
    --features uniffi \
    --manifest-path ../lib/Cargo.toml \
    --language swift \
    --out-dir cktap-swift/Sources/CKTap \
    --no-format

# Create universal library for simulator targets
lipo target/aarch64-apple-ios-sim/release-smaller/librust_cktap.a target/x86_64-apple-ios/release-smaller/librust_cktap.a -create -output target/lipo-ios-sim/release-smaller/librust_cktap.a

# Create universal library for mac targets
lipo target/aarch64-apple-darwin/release-smaller/librust_cktap.a target/x86_64-apple-darwin/release-smaller/librust_cktap.a -create -output target/lipo-macos/release-smaller/librust_cktap.a

cd cktap-swift || exit

# remove old xcframework directory
rm -rf "${OUTDIR}/${NAME}.xcframework"

# create new xcframework directory from cktap-ffi static libs and headers
xcodebuild -create-xcframework \
    -library "${TARGETDIR}/lipo-macos/${RELDIR}/librust_cktap.a" \
    -headers "${NEW_HEADER_DIR}" \
    -library "${TARGETDIR}/aarch64-apple-ios/${RELDIR}/librust_cktap.a" \
    -headers "${NEW_HEADER_DIR}" \
    -library "${TARGETDIR}/lipo-ios-sim/${RELDIR}/librust_cktap.a" \
    -headers "${NEW_HEADER_DIR}" \
    -output "${OUTDIR}/${NAME}.xcframework"

