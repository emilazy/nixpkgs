{
  lib,
  stdenv,
  meson,
  ninja,
  apple-sdk_15,
  darwinMinVersionHook,
}:

stdenv.mkDerivation {
  name = "apple-sdk_15-test";

  src = ./src;

  nativeBuildInputs = [
    meson
    ninja
  ];

  buildInputs = [
    apple-sdk_15
    (darwinMinVersionHook "15.0")
  ];

  meta.mainProgram = "apple-sdk_15-test";
}
