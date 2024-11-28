{
  gccStdenv,
  llvmPackages,
  lib,
  fetchFromGitHub,
  fetchpatch,

  cmake,
  ninja,
  python3,
  openjdk8,
  mono,
  openssl,
  boost,
  pkg-config,
  msgpack-cxx,
  toml11,
}@args:

let
  cmakeBuild = import ./cmake.nix args;
in
{
  foundationdb71 = cmakeBuild {
    version = "7.1.64";
    hash = "sha256-sh6mal4innbhUIH7ymuVjaHgd7Pu8ZVWAf4h5dbUNP8=";
    inherit boost;
    ssl = openssl;

    patches = [
      ./patches/disable-flowbench.patch
      ./patches/don-t-run-tests-requiring-doctest.patch
      ./patches/don-t-use-static-boost-libs.patch
      ./patches/fix-open-with-O_CREAT.patch
      # GetMsgpack: add 4+ versions of upstream
      # https://github.com/apple/foundationdb/pull/10935
      (fetchpatch {
        url = "https://github.com/apple/foundationdb/commit/c35a23d3f6b65698c3b888d76de2d93a725bff9c.patch";
        hash = "sha256-bneRoZvCzJp0Hp/G0SzAyUyuDrWErSpzv+ickZQJR5w=";
      })
    ];
  };
}
