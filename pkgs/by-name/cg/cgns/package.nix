{
  lib,
  stdenv,
  fetchFromGitHub,
  cmake,
  ninja,
  hdf5,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "CGNS";
  version = "4.4.0";

  outputs = [
    "bin"
    "out"
    "dev"
  ];

  src = fetchFromGitHub {
    owner = "CGNS";
    repo = "CGNS";
    rev = "v${finalAttrs.version}";
    hash = "sha256-giDosTfeZdkSIrzZrNrHgQBqlvDSABYPPHzSa/B9Rr0=";
  };

  nativeBuildInputs = [
    cmake
    ninja
  ];

  buildInputs = [
    hdf5
  ];

  cmakeFlags = [
    (lib.cmakeBool "CMAKE_SKIP_BUILD_RPATH" false)
    (lib.cmakeBool "CGNS_BUILD_TESTING" true)
    (lib.cmakeBool "CGNS_ENABLE_TESTS" true)
  ];

  # Tests clobber each others’ files.
  enableParallelChecking = false;

  doCheck = true;

  postInstall = ''
    moveToOutput bin "''${!outputBin}"
  '';

  meta = {
    description = "Standard for recording and recovering computer data associated with the numerical solution of fluid dynamics equations";
    homepage = "https://cgns.github.io/";
    license = lib.licenses.zlib;
    platforms = lib.platforms.unix;
    maintainers = with lib.maintainers; [ jtojnar ];
  };
})
