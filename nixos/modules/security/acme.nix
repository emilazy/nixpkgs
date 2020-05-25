{ config, lib, pkgs, ... }:
let
  inherit (lib) types;

  cfg = config.security.acme;

  certSubmodule = { name, config, ... }: {
    options = {
      # TODO: Potentially split these into separate accounts options;
      # see the comment by `acceptTerms` below.

      server = lib.mkOption {
        type = types.nullOr types.str;
        default = cfg.server;
        description = ''
          ACME Directory Resource URI. Defaults to Let's Encrypt
          production endpoint,
          https://acme-v02.api.letsencrypt.org/directory, if unset.
        '';
      };

      email = lib.mkOption {
        type = types.nullOr types.str;
        default = cfg.email;
        description = "Contact email address for the CA to be able to reach you.";
      };

      domain = lib.mkOption {
        type = types.str;
        default = name;
        description = "Domain to fetch certificate for (defaults to the entry name)";
      };

      # TODO: Use acme user/group, remove options.
      #
      # It might be worth keeping around an option to specify the group
      # so that different certificates can be kept isolated from
      # each other.

      user = lib.mkOption {
        type = types.str;
        default = "root";
        description = "User running the ACME client.";
      };

      group = lib.mkOption {
        type = types.str;
        default = "root";
        description = "Group running the ACME client.";
      };

      # TODO: Make always on, remove option.
      allowKeysForGroup = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Give read permissions to the specified group
          (<option>security.acme.cert.&lt;name&gt;.group</option>) to read SSL private certificates.
        '';
      };

      postRun = lib.mkOption {
        type = types.lines;
        default = "";
        example = "systemctl reload nginx.service";
        description = ''
          Commands to run after new certificates go live. Typically
          the web server and other servers using certificates need to
          be reloaded.

          Executed in the same directory with the new certificate.
        '';
      };

      # TODO: Deprecate? This has to be in /var/lib thanks to systemd,
      # and in practice the /var/lib/acme/<cert> path is part of the
      # module's public API anyway.
      directory = lib.mkOption {
        type = types.str;
        readOnly = true;
        default = "/var/lib/acme/${name}";
        description = "Directory where certificate and other state is stored.";
      };

      # TODO: Allow or mandate using a list here, since distinct
      # webroots don't work any more anyway? Perhaps this could be
      # merged with `domain` into a single `domains` option.
      extraDomains = lib.mkOption {
        type = types.attrsOf (types.enum [ null ]);
        default = { };
        example = lib.literalExample ''
          {
            "example.org" = null;
            "mydomain.org" = null;
          }
        '';
        description = ''
          A list of extra domain names, which are included in the one certificate to be issued.
          Setting a distinct server root is deprecated and not functional in 20.03+
        '';
      };

      keyType = lib.mkOption {
        type = types.str;
        default = "ec256";
        description = ''
          Key type to use for private keys.
          For an up to date list of supported values check the --key-type option
          at https://go-acme.github.io/lego/usage/cli/#usage.
        '';
      };

      challenge.type = lib.mkOption {
        type = types.enum [ "http-01" "dns-01" ];
        # This default is for backwards compatibility.
        default =
          if config.dnsProvider != null
          then "dns-01"
          else if config.webroot != null
          then "http-01"
          else null;
        description = ''
          The ACME challenge type to use, in lowercase. Currently
          supported are <literal>http-01</literal>
          and <literal>dns-01</literal>.
        '';
      };

      # TODO: Make challenge options hierarchical and deprecate the old
      # option names.
      #
      # e.g. challenge.dns-01.provider

      # HTTP-01 challenge options

      webroot = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/var/lib/acme/acme-challenges";
        description = ''
          Where the webroot of the HTTP vhost is located.
          <filename>.well-known/acme-challenge/</filename> directory
          will be created below the webroot if it doesn't exist.
          <literal>http://example.org/.well-known/acme-challenge/</literal> must also
          be available (notice unencrypted HTTP).
        '';
      };

      # DNS-01 challenge options

      dnsProvider = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "route53";
        description = ''
          DNS Challenge provider. For a list of supported providers, see the "code"
          field of the DNS providers listed at https://go-acme.github.io/lego/dns/.
        '';
      };

      credentialsFile = lib.mkOption {
        type = types.path;
        description = ''
          Path to an EnvironmentFile for the cert's service containing any required and
          optional environment variables for your selected dnsProvider.
          To find out what values you need to set, consult the documentation at
          https://go-acme.github.io/lego/dns/ for the corresponding dnsProvider.
        '';
        example = "/var/src/secrets/example.org-route53-api-token";
      };

      dnsPropagationCheck = lib.mkOption {
        type = types.bool;
        default = true;
        description = ''
          Toggles lego DNS propagation check, which is used alongside DNS-01
          challenge to ensure the DNS entries required are available.
        '';
      };

      ocspMustStaple = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Turns on the OCSP Must-Staple TLS extension.
          Make sure you know what you're doing! See:
          <itemizedlist>
            <listitem><para><link xlink:href="https://blog.apnic.net/2019/01/15/is-the-web-ready-for-ocsp-must-staple/" /></para></listitem>
            <listitem><para><link xlink:href="https://blog.hboeck.de/archives/886-The-Problem-with-OCSP-Stapling-and-Must-Staple-and-why-Certificate-Revocation-is-still-broken.html" /></para></listitem>
          </itemizedlist>
        '';
      };

      extraLegoRenewFlags = lib.mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Additional flags to pass to lego renew.
        '';
      };
    };
  };

in
{

  ###### interface
  imports = [
    (lib.mkRemovedOptionModule [ "security" "acme" "production" ] ''
      Use security.acme.server to define your staging ACME server URL instead.

      To use the let's encrypt staging server, use security.acme.server =
      "https://acme-staging-v02.api.letsencrypt.org/directory".
    ''
    )
    (lib.mkRemovedOptionModule [ "security" "acme" "directory" ] "ACME Directory is now hardcoded to /var/lib/acme and its permisisons are managed by systemd. See https://github.com/NixOS/nixpkgs/issues/53852 for more info.")
    (lib.mkRemovedOptionModule [ "security" "acme" "preDelay" ] "This option has been removed. If you want to make sure that something executes before certificates are provisioned, add a RequiredBy=acme-\${cert}.service to the service you want to execute before the cert renewal")
    (lib.mkRemovedOptionModule [ "security" "acme" "activationDelay" ] "This option has been removed. If you want to make sure that something executes before certificates are provisioned, add a RequiredBy=acme-\${cert}.service to the service you want to execute before the cert renewal")
    (lib.mkChangedOptionModule [ "security" "acme" "validMin" ] [ "security" "acme" "validMinDays" ] (config: config.security.acme.validMin / (24 * 3600)))
  ];
  options = {
    security.acme = {
      # TODO: This should be cert-specific.
      validMinDays = lib.mkOption {
        type = types.int;
        default = 30;
        description = "Minimum remaining validity before renewal in days.";
      };

      email = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Contact email address for the CA to be able to reach you.";
      };

      renewInterval = lib.mkOption {
        type = types.str;
        default = "daily";
        description = ''
          Systemd calendar expression when to check for renewal. See
          <citerefentry><refentrytitle>systemd.time</refentrytitle>
          <manvolnum>7</manvolnum></citerefentry>.
        '';
      };

      server = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          ACME Directory Resource URI. Defaults to Let's Encrypt
          production endpoint,
          <literal>https://acme-v02.api.letsencrypt.org/directory</literal>, if unset.
        '';
      };

      preliminarySelfsigned = lib.mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether a preliminary self-signed certificate should be generated before
          doing ACME requests. This can be useful when certificates are required in
          a webserver, but ACME needs the webserver to make its requests.

          With preliminary self-signed certificate the webserver can be started and
          can later reload the correct ACME certificates.
        '';
      };

      # TODO: Since `server` can be overriden per certificate, maybe
      # this should also be per-certificate?
      #
      # An overall nicer approach to keep things factored might be
      # something like:
      #
      # security.acme = {
      #   accounts = {
      #     letsencrypt-1 = { email = "..."; acceptTerms = true; };
      #     letsencrypt-2 = { email = "..."; acceptTerms = true; };
      #     buypass-go = { server = "..."; email = "..."; acceptTerms = true; };
      #   };
      #   certs = {
      #     "example.com" = { account = "letsencrypt-1"; };
      #     "other.example.com" = { account = "letsencrypt-2"; };
      #     # ...
      #   };
      # };
      #
      # Backwards compatibility could be maintained by automatically
      # initializing missing accounts (e.g. named "${server}-${email}"
      # or a sanitized variant).
      acceptTerms = lib.mkOption {
        type = types.bool;
        default = false;
        description = ''
          Accept the CA's terms of service. The default provier is Let's Encrypt,
          you can find their ToS at https://letsencrypt.org/repository/
        '';
      };

      certs = lib.mkOption {
        default = { };
        type = types.attrsOf (types.submodule certSubmodule);
        description = ''
          Attribute set of certificates to get signed and renewed. Creates
          <literal>acme-''${cert}.{service,timer}</literal> systemd units for
          each certificate defined here. Other services can add dependencies
          to those units if they rely on the certificates being present,
          or trigger restarts of the service if certificates get renewed.
        '';
        example = lib.literalExample ''
          {
            "example.com" = {
              webroot = "/var/www/challenges/";
              email = "foo@example.com";
              extraDomains = { "www.example.com" = null; "foo.example.com" = null; };
            };
            "bar.example.com" = {
              webroot = "/var/www/challenges/";
              email = "bar@example.com";
            };
          }
        '';
      };
    };
  };

  ###### implementation
  config = lib.mkIf (cfg.certs != { }) {
    assertions =
      let
        challengeOptions = {
          http-01 = "webroot";
          dns-01 = "dnsProvider";
        };

        certAssertions = cert:
          let
            certCfg = cfg.certs.${cert};
            certOptionPrefix =
              "security.acme.certs.${lib.strings.escapeNixString cert}";
            challengeAssertions = challengeType: option:
              if challengeType == certCfg.challenge.type then {
                assertion = certCfg.${option} != null;
                message = ''
                  ACME challenge type "${challengeType}" requires the
                  `${certOptionPrefix}.${option}` option to be set.
                '';
              } else {
                assertion = certCfg.${option} == null;
                message = ''
                  The option `${certOptionPrefix}.${option}` is only
                  valid for ACME challenge type "${challengeType}". The
                  currently-set challenge type for ${cert}
                  is "${certCfg.challenge.type}".
                '';
              };
          in
          [
            {
              assertion = certCfg.email != null;
              message = ''
                You must define `security.acme.email` or
                `${certOptionPrefix}.email` to register with the CA.
              '';
            }

            {
              assertion = certCfg.challenge.type != null;
              message = ''
                You must specify an ACME challenge type with
                `${certOptionPrefix}.challenge.type`.
              '';
            }
          ] ++ lib.mapAttrsToList challengeAssertions challengeOptions;
      in
      [
        {
          assertion = cfg.acceptTerms;
          message = ''
            You must accept the CA's terms of service before using
            the ACME module by setting `security.acme.acceptTerms`
            to `true`. For Let's Encrypt's ToS see https://letsencrypt.org/repository/
          '';
        }
      ] ++ lib.concatMap certAssertions (lib.attrNames cfg.certs);

    systemd.services =
      let
        services = lib.concatLists servicesLists;
        servicesLists = lib.mapAttrsToList certToServices cfg.certs;
        certToServices = cert: certCfg:
          let
            # StateDirectory must be relative, and will be created under /var/lib by systemd
            lpath = "acme/${cert}";
            apath = "/var/lib/${lpath}";
            spath = "/var/lib/acme/.lego/${cert}";
            fileMode = if certCfg.allowKeysForGroup then "640" else "600";

            globalOpts = {
              inherit (certCfg) email;

              inherit (certCfg) server;
              accept-tos = cfg.acceptTerms;

              domains = [ certCfg.domain ] ++
                lib.attrNames (certCfg.extraDomains);
              key-type = certCfg.keyType;
              path = ".";
            } // challengeOpts;

            challengeOpts = {
              dns-01 = {
                dns = certCfg.dnsProvider;
                "dns.disable-cp" = !certCfg.dnsPropagationCheck;
              };
              http-01 = {
                http = true;
                "http.webroot" = certCfg.webroot;
              };
            }.${certCfg.challenge.type};

            certOpts = {
              must-staple = certCfg.ocspMustStaple;
            };

            toArgs = arg:
              if builtins.isList arg
              then lib.concatMap toArgs arg
              else if builtins.isAttrs arg
              then lib.cli.toGNUCommandLine { } arg
              else [ (lib.generators.mkValueStringDefault { } arg) ];

            toShellArgs = args: lib.escapeShellArgs (toArgs args);

            runOpts = toShellArgs [ globalOpts "run" certOpts ];
            renewOpts = toShellArgs [
              globalOpts
              "renew"
              ({ days = cfg.validMinDays; } // certOpts)
              certCfg.extraLegoRenewFlags
            ];

            acmeDnsDeps = lib.optional
              (certCfg.dnsProvider == "acme-dns")
              "acme-dns-${cert}.service";

            commonServiceConfig = {
              Type = "oneshot";
              User = certCfg.user;
              Group = certCfg.group;
              PrivateTmp = true;
              StateDirectory = "acme/.lego/${cert} acme/.lego/accounts ${lpath}";
              StateDirectoryMode = if certCfg.allowKeysForGroup then "750" else "700";
              WorkingDirectory = spath;
              # Only try loading the credentialsFile if the dns challenge is enabled
              EnvironmentFile =
                if certCfg.challenge.type == "dns-01"
                then certCfg.credentialsFile
                else null;
            };

            acmeService = {
              description = "Renew ACME Certificate for ${cert}";

              after = [ "network.target" "network-online.target" ]
                ++ acmeDnsDeps;
              wants = [ "network-online.target" ];
              # We use `requires` to avoid lego running and falling
              # back to its own acme-dns registration logic if ours
              # fails; see acmeDnsService for rationale.
              requires = acmeDnsDeps;
              wantedBy = lib.mkIf (!config.boot.isContainer) [ "multi-user.target" ];

              # acme-dns requires CNAME support for _acme-challenge
              # records. This setting only affects the behaviour of
              # DNS-01 challenge propagation checks when a CNAME
              # record is present; see:
              #
              # * https://go-acme.github.io/lego/dns/#experimental-features
              # * https://github.com/go-acme/lego/blob/v3.5.0/challenge/dns01/dns_challenge.go#L179-L185
              environment.LEGO_EXPERIMENTAL_CNAME_SUPPORT = "true";

              serviceConfig = commonServiceConfig // {
                ExecStart = pkgs.writeScript "acme-start" ''
                  #!${pkgs.runtimeShell} -e
                  test -L ${spath}/accounts -o -d ${spath}/accounts || ln -s ../accounts ${spath}/accounts
                  ${pkgs.lego}/bin/lego ${renewOpts} || ${pkgs.lego}/bin/lego ${runOpts}
                '';
                ExecStartPost =
                  let
                    keyName = builtins.replaceStrings [ "*" ] [ "_" ] certCfg.domain;
                    script = pkgs.writeScript "acme-post-start" ''
                      #!${pkgs.runtimeShell} -e
                      cd ${apath}

                      # Test that existing cert is older than new cert
                      KEY=${spath}/certificates/${keyName}.key
                      KEY_CHANGED=no
                      if [ -e $KEY -a $KEY -nt key.pem ]; then
                        KEY_CHANGED=yes
                        cp -p ${spath}/certificates/${keyName}.key key.pem
                        cp -p ${spath}/certificates/${keyName}.crt fullchain.pem
                        cp -p ${spath}/certificates/${keyName}.issuer.crt chain.pem
                        ln -sf fullchain.pem cert.pem
                        cat key.pem fullchain.pem > full.pem
                      fi

                      chmod ${fileMode} *.pem
                      chown '${certCfg.user}:${certCfg.group}' *.pem

                      if [ "$KEY_CHANGED" = "yes" ]; then
                        : # noop in case postRun is empty
                        ${certCfg.postRun}
                      fi
                    '';
                  in
                  "+${script}";
              };
            };

            # For certificates using the acme-dns dnsProvider, we
            # handle registration and CNAME checking ourselves
            # rather than letting lego do it, as it only attempts
            # registration upon renewal, leading to unpredictable
            # timing of the manual interventions required to add
            # the CNAME records.
            acmeDnsService = {
              description = "Ensure acme-dns Credentials for ${cert}";

              wants = [ "network-online.target" ];
              after = [ "network-online.target" ];

              serviceConfig = commonServiceConfig;

              # TODO: is openssl needed here? (needs testing with HTTPS
              # acme-dns API)
              path = [ pkgs.curl pkgs.openssl pkgs.dnsutils pkgs.jq ];
              script = ''
                set -uo pipefail

                if ! [ -e "$ACME_DNS_STORAGE_PATH" ]; then
                  # We use --retry because the acme-dns server might
                  # not be up when the service starts (especially if
                  # it's local).
                  response=$(curl --fail --silent --show-error \
                    --request POST "$ACME_DNS_API_BASE/register" \
                    --max-time 30 --retry 5 --retry-connrefused \
                    | jq ${lib.escapeShellArg "{${builtins.toJSON cert}: .}"})
                  # Write the response. We do this separately to the
                  # request to ensure that $ACME_DNS_STORAGE_PATH
                  # doesn't get written to if curl or jq fail.
                  echo "$response" > "$ACME_DNS_STORAGE_PATH"
                fi

                src='_acme-challenge.${cert}.'
                if ! target=$(jq --exit-status --raw-output \
                    '.${builtins.toJSON cert}.fulldomain' \
                    "$ACME_DNS_STORAGE_PATH"); then
                  echo "$ACME_DNS_STORAGE_PATH has invalid format."
                  echo "Try removing it and then running:"
                  echo '  systemctl restart acme-${cert}.service'
                  exit 1
                fi

                if ! dig +short CNAME "$src" | grep -qF "$target"; then
                  echo "Required CNAME record for $src not found."
                  echo "Please add the following DNS record:"
                  echo "  $src CNAME $target."
                  echo "and then run:"
                  echo '  systemctl restart acme-${cert}.service'
                  exit 1
                fi
              '';
            };

            selfsignedService = {
              description = "Create preliminary self-signed certificate for ${cert}";
              path = [ pkgs.openssl ];
              script =
                ''
                  workdir="$(mktemp -d)"

                  # Create CA
                  openssl genrsa -des3 -passout pass:xxxx -out $workdir/ca.pass.key 2048
                  openssl rsa -passin pass:xxxx -in $workdir/ca.pass.key -out $workdir/ca.key
                  openssl req -new -key $workdir/ca.key -out $workdir/ca.csr \
                    -subj "/C=UK/ST=Warwickshire/L=Leamington/O=OrgName/OU=Security Department/CN=example.com"
                  openssl x509 -req -days 1 -in $workdir/ca.csr -signkey $workdir/ca.key -out $workdir/ca.crt

                  # Create key
                  openssl genrsa -des3 -passout pass:xxxx -out $workdir/server.pass.key 2048
                  openssl rsa -passin pass:xxxx -in $workdir/server.pass.key -out $workdir/server.key
                  openssl req -new -key $workdir/server.key -out $workdir/server.csr \
                    -subj "/C=UK/ST=Warwickshire/L=Leamington/O=OrgName/OU=IT Department/CN=example.com"
                  openssl x509 -req -days 1 -in $workdir/server.csr -CA $workdir/ca.crt \
                    -CAkey $workdir/ca.key -CAserial $workdir/ca.srl -CAcreateserial \
                    -out $workdir/server.crt

                  # Copy key to destination
                  cp $workdir/server.key ${apath}/key.pem

                  # Create fullchain.pem (same format as "simp_le ... -f fullchain.pem" creates)
                  cat $workdir/{server.crt,ca.crt} > "${apath}/fullchain.pem"

                  # Create full.pem for e.g. lighttpd
                  cat $workdir/{server.key,server.crt,ca.crt} > "${apath}/full.pem"

                  # Give key acme permissions
                  chown '${certCfg.user}:${certCfg.group}' "${apath}/"{key,fullchain,full}.pem
                  chmod ${fileMode} "${apath}/"{key,fullchain,full}.pem
                '';
              serviceConfig = {
                Type = "oneshot";
                PrivateTmp = true;
                StateDirectory = lpath;
                User = certCfg.user;
                Group = certCfg.group;
              };
              unitConfig = {
                # Do not create self-signed key when key already exists
                ConditionPathExists = "!${apath}/key.pem";
              };
            };
          in
          (
            [{ name = "acme-${cert}"; value = acmeService; }]
            ++
            lib.optional
              (certCfg.dnsProvider == "acme-dns") { name = "acme-dns-${cert}"; value = acmeDnsService; }
            ++ lib.optional cfg.preliminarySelfsigned { name = "acme-selfsigned-${cert}"; value = selfsignedService; }
          );
        servicesAttr = lib.listToAttrs services;
      in
      servicesAttr;

    systemd.tmpfiles.rules =
      map
        (certCfg: "d ${certCfg.webroot}/.well-known/acme-challenge - ${certCfg.user} ${certCfg.group}")
        (lib.filter (certCfg: certCfg.webroot != null) (lib.attrValues cfg.certs));

    systemd.timers =
      let
        # Allow systemd to pick a convenient time within the day
        # to run the check.
        # This allows the coalescing of multiple timer jobs.
        # We divide by the number of certificates so that if you
        # have many certificates, the renewals are distributed over
        # the course of the day to avoid rate limits.
        numCerts = lib.length (lib.attrNames cfg.certs);
        _24hSecs = 60 * 60 * 24;
        AccuracySec = "${toString (_24hSecs / numCerts)}s";
      in
      lib.flip lib.mapAttrs' cfg.certs (cert: _: lib.nameValuePair "acme-${cert}" {
        description = "Renew ACME Certificate for ${cert}";
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = cfg.renewInterval;
          Unit = "acme-${cert}.service";
          Persistent = "yes";
          inherit AccuracySec;
          # Skew randomly within the day, per https://letsencrypt.org/docs/integration-guide/.
          RandomizedDelaySec = "24h";
        };
      });

    systemd.targets.acme-selfsigned-certificates = lib.mkIf cfg.preliminarySelfsigned { };
    systemd.targets.acme-certificates = { };
  };

  meta = {
    maintainers = lib.teams.acme.members;
    doc = ./acme.xml;
  };
}
