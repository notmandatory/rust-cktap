set quiet := true
emulator_dir := 'coinkite/coinkite-tap-proto/emulator'

# list of recipes
default:
  just --list

# format the project code
fmt:
    cargo +nightly fmt --all

# lint the project
clippy: fmt
    cargo clippy --all-features --tests

# build the project
build: fmt
    cargo build --all-features --tests

# test the rust-cktap lib with the coinkite cktap card emulator
test: fmt
    (test -d emulator_env || python3 -m venv emulator_env) && source emulator_env/bin/activate && pip install -r {{emulator_dir}}/requirements.txt
    source emulator_env/bin/activate && cargo test -p rust-cktap --features emulator

# clean the project target directory
clean:
    cargo clean

# run the cli locally with a usb pcsc card reader (HID OMNIKEY 5022 CL Rev:C)
run *CMD:
    cargo run -p cktap-cli {{CMD}}