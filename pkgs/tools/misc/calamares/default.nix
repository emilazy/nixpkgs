{ stdenv, lib, fetchurl, cmake, ninja, pkg-config, extra-cmake-modules
, kcoreaddons, kparts, kpmcore, kservice
, libatasmart, yaml-cpp, libxcrypt, libpwquality, parted, polkit-qt-1, python3
, qtbase, qttools, qtwebengine, wrapQtAppsHook, util-linux, tzdata
, ckbcomp, xkeyboard_config
, nixos-extensions ? false
# passthru.tests
, calamares-nixos
}:

stdenv.mkDerivation rec {
  pname = "calamares";
  version = "3.3.14";

  # release including submodule
  src = fetchurl {
    url = "https://github.com/calamares/calamares/releases/download/v${version}/calamares-${version}.tar.gz";
    hash = "sha256-VUf4DbBn3qkjrmk7pruI6ysu6sHaPr7EL85FPjHCkMA=";
  };

  # On major changes, or when otherwise required, you *must* :
  # 1. reformat the patches,
  # 2. `git am path/to/00*.patch` them into a calamares worktree,
  # 3. rebase to the more recent calamares version,
  # 4. and export the patches again via
  #   `git -c format.signoff=false format-patch v${version} --no-numbered --zero-commit --no-signature`.
  patches = lib.optionals nixos-extensions [
    ./0001-Modifies-the-users-module-to-only-set-passwords-of-u.patch
    ./0002-Makes-calamares-search-run-current-system-sw-share-c.patch
    ./0003-Uses-pkexec-within-modules-in-order-to-run-calamares.patch
    ./0004-Adds-unfree-qml-to-packagechooserq.patch
    ./0005-Modifies-finished-module-to-add-some-NixOS-resources.patch
    ./0006-Remove-options-for-unsupported-partition-types.patch
    ./0007-Fix-setting-the-kayboard-layout-on-GNOME-wayland.patch
    ./0008-Change-default-location-where-calamares-searches-for.patch
  ];

  nativeBuildInputs = [ cmake ninja pkg-config extra-cmake-modules wrapQtAppsHook ];
  buildInputs = [
    kcoreaddons kparts kpmcore kservice
    libatasmart yaml-cpp libxcrypt libpwquality parted polkit-qt-1 python3
    qtbase qttools qtwebengine.dev util-linux
  ];

  POLKITQT-1_POLICY_FILES_INSTALL_DIR = "$(out)/share/polkit-1/actions";

  postPatch = ''
    # Run calamares without root. Other patches make it functional as a normal user
    sed -e "s,pkexec calamares,calamares -D6," \
        -i calamares.desktop

    sed -e "s,X-AppStream-Ignore=true,&\nStartupWMClass=calamares," \
        -i calamares.desktop

    # Fix desktop reference with wayland
    mv calamares.desktop io.calamares.calamares.desktop

    sed -e "s,calamares.desktop,io.calamares.calamares.desktop," \
        -i CMakeLists.txt

    sed -e "s,/usr/bin/calamares,$out/bin/calamares," \
        -i com.github.calamares.calamares.policy

    sed -e 's,/usr/share/zoneinfo,${tzdata}/share/zoneinfo,' \
        -i src/modules/locale/SetTimezoneJob.cpp \
        -i src/libcalamares/locale/TimeZone.cpp

    sed -e 's,/usr/share/X11/xkb/rules/base.lst,${xkeyboard_config}/share/X11/xkb/rules/base.lst,' \
        -i src/modules/keyboard/keyboardwidget/keyboardglobal.cpp

    sed -e 's,"ckbcomp","${ckbcomp}/bin/ckbcomp",' \
        -i src/modules/keyboard/keyboardwidget/keyboardpreview.cpp

    sed "s,\''${POLKITQT-1_POLICY_FILES_INSTALL_DIR},''${out}/share/polkit-1/actions," \
        -i CMakeLists.txt
  '';

  passthru.tests = {
    inherit calamares-nixos;
  };

  meta = with lib; {
    description = "Distribution-independent installer framework";
    homepage = "https://calamares.io/";
    license = with licenses; [ gpl3Plus bsd2 cc0 ];
    maintainers = with maintainers; [ manveru vlinkz ];
    platforms = platforms.linux;
    mainProgram = "calamares";
  };
}
