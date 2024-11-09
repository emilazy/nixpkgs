{ rustPlatform, rustc, wasmtime }:

rustPlatform.buildRustPackage {
  pname = "rust-wasm-test";
  version = "0.1.0";

  src = ./rust-wasm-test;

  nativeBuildInputs = [
    rustc.llvmPackages.lld
    wasmtime
  ];

  cargoLock.lockFile = ./rust-wasm-test/Cargo.lock;

  doCheck = false;
  doInstallCheck = true;

  buildPhase = ''
    runHook preBuild

    cargo build --offline --release --target wasm32-unknown-unknown

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib
    cp target/wasm32-unknown-unknown/release/rust_wasm_test.wasm $out/lib

    runHook postInstall
  '';

  installCheckPhase = ''
    runHook preInstallCheck

    HOME=$(mktemp -d) wasmtime run \
      --invoke rust_wasm_test \
      $out/lib/rust_wasm_test.wasm \
      | grep 1

    runHook postInstallCheck
  '';
}
