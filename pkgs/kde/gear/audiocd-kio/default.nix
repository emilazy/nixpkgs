{
  lib,
  mkKdeDerivation,
  libcdio-paranoia,
  flac,
  libogg,
  libvorbis,
  substituteAll,
  lame,
  opusTools,
}:
mkKdeDerivation {
  pname = "audiocd-kio";

  patches = [
    (substituteAll {
      src = ./encoder-paths.patch;
      lame = lib.getExe lame;
      opusenc = "${opusTools}/bin/opusenc";
    })
  ];

  extraBuildInputs = [
    libcdio-paranoia
    flac
    libogg
    libvorbis
  ];
}
