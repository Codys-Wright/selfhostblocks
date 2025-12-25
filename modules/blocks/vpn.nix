{
  config,
  pkgs,
  lib,
  ...
}:

let
  cfg = config.shb.vpn;

  quoteEach = lib.concatMapStrings (x: ''"${x}"'');

  nordvpnConfig =
    {
      name,
      dev,
      authFile,
      remoteServerIP,
      dependentServices ? [ ],
    }:
    ''
      client
      dev ${dev}
      proto tcp
      remote ${remoteServerIP} 443
      resolv-retry infinite
      remote-random
      nobind
      tun-mtu 1500
      tun-mtu-extra 32
      mssfix 1450
      persist-key
      persist-tun
      ping 15
      ping-restart 0
      ping-timer-rem
      reneg-sec 0
      comp-lzo no

      status /tmp/openvpn/${name}.status

      remote-cert-tls server

      auth-user-pass ${authFile}
      verb 3
      pull
      fast-io
      cipher AES-256-CBC
      auth SHA512

      script-security 2
      route-noexec
      route-up ${routeUp name dependentServices}/bin/routeUp.sh
      down ${routeDown name dependentServices}/bin/routeDown.sh

      <ca>
      -----BEGIN CERTIFICATE-----
      MIIFCjCCAvKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA5MQswCQYDVQQGEwJQQTEQ
      MA4GA1UEChMHTm9yZFZQTjEYMBYGA1UEAxMPTm9yZFZQTiBSb290IENBMB4XDTE2
      MDEwMTAwMDAwMFoXDTM1MTIzMTIzNTk1OVowOTELMAkGA1UEBhMCUEExEDAOBgNV
      BAoTB05vcmRWUE4xGDAWBgNVBAMTD05vcmRWUE4gUm9vdCBDQTCCAiIwDQYJKoZI
      hvcNAQEBBQADggIPADCCAgoCggIBAMkr/BYhyo0F2upsIMXwC6QvkZps3NN2/eQF
      kfQIS1gql0aejsKsEnmY0Kaon8uZCTXPsRH1gQNgg5D2gixdd1mJUvV3dE3y9FJr
      XMoDkXdCGBodvKJyU6lcfEVF6/UxHcbBguZK9UtRHS9eJYm3rpL/5huQMCppX7kU
      eQ8dpCwd3iKITqwd1ZudDqsWaU0vqzC2H55IyaZ/5/TnCk31Q1UP6BksbbuRcwOV
      skEDsm6YoWDnn/IIzGOYnFJRzQH5jTz3j1QBvRIuQuBuvUkfhx1FEwhwZigrcxXu
      MP+QgM54kezgziJUaZcOM2zF3lvrwMvXDMfNeIoJABv9ljw969xQ8czQCU5lMVmA
      37ltv5Ec9U5hZuwk/9QO1Z+d/r6Jx0mlurS8gnCAKJgwa3kyZw6e4FZ8mYL4vpRR
      hPdvRTWCMJkeB4yBHyhxUmTRgJHm6YR3D6hcFAc9cQcTEl/I60tMdz33G6m0O42s
      Qt/+AR3YCY/RusWVBJB/qNS94EtNtj8iaebCQW1jHAhvGmFILVR9lzD0EzWKHkvy
      WEjmUVRgCDd6Ne3eFRNS73gdv/C3l5boYySeu4exkEYVxVRn8DhCxs0MnkMHWFK6
      MyzXCCn+JnWFDYPfDKHvpff/kLDobtPBf+Lbch5wQy9quY27xaj0XwLyjOltpiST
      LWae/Q4vAgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqG
      SIb3DQEBDQUAA4ICAQC9fUL2sZPxIN2mD32VeNySTgZlCEdVmlq471o/bDMP4B8g
      nQesFRtXY2ZCjs50Jm73B2LViL9qlREmI6vE5IC8IsRBJSV4ce1WYxyXro5rmVg/
      k6a10rlsbK/eg//GHoJxDdXDOokLUSnxt7gk3QKpX6eCdh67p0PuWm/7WUJQxH2S
      DxsT9vB/iZriTIEe/ILoOQF0Aqp7AgNCcLcLAmbxXQkXYCCSB35Vp06u+eTWjG0/
      pyS5V14stGtw+fA0DJp5ZJV4eqJ5LqxMlYvEZ/qKTEdoCeaXv2QEmN6dVqjDoTAo
      k0t5u4YRXzEVCfXAC3ocplNdtCA72wjFJcSbfif4BSC8bDACTXtnPC7nD0VndZLp
      +RiNLeiENhk0oTC+UVdSc+n2nJOzkCK0vYu0Ads4JGIB7g8IB3z2t9ICmsWrgnhd
      NdcOe15BincrGA8avQ1cWXsfIKEjbrnEuEk9b5jel6NfHtPKoHc9mDpRdNPISeVa
      wDBM1mJChneHt59Nh8Gah74+TM1jBsw4fhJPvoc7Atcg740JErb904mZfkIEmojC
      VPhBHVQ9LHBAdM8qFI2kRK0IynOmAZhexlP/aT/kpEsEPyaZQlnBn3An1CRz8h0S
      PApL8PytggYKeQmRhl499+6jLxcZ2IegLfqq41dzIjwHwTMplg+1pKIOVojpWA==
      -----END CERTIFICATE-----
      </ca>
      key-direction 1
      <tls-auth>
      #
      # 2048 bit OpenVPN static key
      #
      -----BEGIN OpenVPN Static key V1-----
      e685bdaf659a25a200e2b9e39e51ff03
      0fc72cf1ce07232bd8b2be5e6c670143
      f51e937e670eee09d4f2ea5a6e4e6996
      5db852c275351b86fc4ca892d78ae002
      d6f70d029bd79c4d1c26cf14e9588033
      cf639f8a74809f29f72b9d58f9b8f5fe
      fc7938eade40e9fed6cb92184abb2cc1
      0eb1a296df243b251df0643d53724cdb
      5a92a1d6cb817804c4a9319b57d53be5
      80815bcfcb2df55018cc83fc43bc7ff8
      2d51f9b88364776ee9d12fc85cc7ea5b
      9741c4f598c485316db066d52db4540e
      212e1518a9bd4828219e24b20d88f598
      a196c9de96012090e333519ae18d3509
      9427e7b372d348d352dc4c85e18cd4b9
      3f8a56ddb2e64eb67adfc9b337157ff4
      -----END OpenVPN Static key V1-----
      </tls-auth>
    '';

  protonvpnConfig =
    {
      name,
      dev,
      authFile,
      dependentServices ? [ ],
    }:
    ''
      client
      dev ${dev}
      proto tcp
      
      # ProtonVPN servers with failover
      remote-random
      remote 149.40.62.62 8443
      remote 146.70.84.2 7770
      remote 149.40.51.233 7770
      remote 95.173.221.65 443
      remote 68.169.42.240 7770
      remote 89.222.100.66 8443
      remote 79.127.187.185 8443
      remote 138.199.35.97 8443
      remote 95.173.217.217 443
      remote 149.102.242.59 443
      remote 146.70.72.130 7770
      remote 68.169.42.240 8443
      remote 79.127.187.185 443
      remote 79.127.136.222 8443
      remote 79.127.187.185 7770
      remote 87.249.134.138 8443
      remote 79.127.160.129 443
      remote 89.187.175.129 443
      remote 87.249.134.138 443
      remote 79.127.136.222 443
      remote 79.127.185.166 443
      remote 95.173.221.65 7770
      remote 146.70.72.130 443
      remote 79.127.185.166 7770
      remote 163.5.171.83 7770
      remote 138.199.35.97 443
      remote 79.127.160.187 7770
      remote 89.187.175.132 8443
      remote 163.5.171.83 8443
      remote 89.222.100.66 7770
      remote 89.187.175.132 443
      remote 146.70.84.2 443
      remote 149.22.80.1 443
      remote 87.249.134.138 7770
      remote 149.22.80.1 7770
      remote 79.127.185.166 8443
      remote 79.127.160.187 443
      remote 149.40.51.233 8443
      remote 138.199.35.97 7770
      remote 149.40.62.62 443
      remote 95.173.221.65 8443
      remote 149.102.242.59 8443
      remote 163.5.171.83 443
      remote 149.40.51.226 7770
      remote 89.222.100.66 443
      remote 79.127.160.187 8443
      remote 89.187.175.129 8443
      remote 149.40.51.233 443
      remote 146.70.72.130 8443
      remote 79.127.160.129 8443
      remote 149.40.62.62 7770
      remote 95.173.217.217 8443
      remote 95.173.217.217 7770
      remote 149.102.242.59 7770
      remote 79.127.136.222 7770
      remote 79.127.160.129 7770
      remote 149.40.51.226 443
      remote 149.22.80.1 8443
      remote 149.40.51.226 8443
      remote 146.70.84.2 8443
      remote 89.187.175.132 7770
      remote 89.187.175.129 7770
      remote 68.169.42.240 443
      
      server-poll-timeout 20
      resolv-retry infinite
      nobind
      persist-key
      persist-tun
      
      cipher AES-256-GCM
      setenv CLIENT_CERT 0
      tun-mtu 1500
      mssfix 0
      reneg-sec 0
      
      remote-cert-tls server
      auth-user-pass ${authFile}
      
      verb 3
      
      status /tmp/openvpn/${name}.status
      
      script-security 2
      route-noexec
      route-up ${routeUp name dependentServices}/bin/routeUp.sh
      down ${routeDown name dependentServices}/bin/routeDown.sh
      
      <ca>
      -----BEGIN CERTIFICATE-----
      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
      EA==
      -----END CERTIFICATE-----
      </ca>
      
      <tls-crypt>
      -----BEGIN OpenVPN Static key V1-----
      6acef03f62675b4b1bbd03e53b187727
      423cea742242106cb2916a8a4c829756
      3d22c7e5cef430b1103c6f66eb1fc5b3
      75a672f158e2e2e936c3faa48b035a6d
      e17beaac23b5f03b10b868d53d03521d
      8ba115059da777a60cbfd7b2c9c57472
      78a15b8f6e68a3ef7fd583ec9f398c8b
      d4735dab40cbd1e3c62a822e97489186
      c30a0b48c7c38ea32ceb056d3fa5a710
      e10ccc7a0ddb363b08c3d2777a3395e1
      0c0b6080f56309192ab5aacd4b45f55d
      a61fc77af39bd81a19218a79762c3386
      2df55785075f37d8c71dc8a42097ee43
      344739a0dd48d03025b0450cf1fb5e8c
      aeb893d9a96d1f15519bb3c4dcb40ee3
      16672ea16c012664f8a9f11255518deb
      -----END OpenVPN Static key V1-----
      </tls-crypt>
    '';

  routeUp =
    name: dependentServices:
    pkgs.writeShellApplication {
      name = "routeUp.sh";

      runtimeInputs = [
        pkgs.iproute2
        pkgs.systemd
        pkgs.nettools
      ];

      text = ''
        echo "Running route-up..."

        echo "dev=''${dev:?}"
        echo "ifconfig_local=''${ifconfig_local:?}"
        echo "route_vpn_gateway=''${route_vpn_gateway:?}"

        set -x

        ip rule
        ip rule add from "''${ifconfig_local:?}/32" table ${name}
        ip rule add to "''${route_vpn_gateway:?}/32" table ${name}
        ip rule

        ip route list table ${name} || :
        retVal=$?
        if [ $retVal -eq 2 ]; then
          echo "table is empty"
        elif [ $retVal -ne 0 ]; then
          exit 1
        fi
        ip route add default via "''${route_vpn_gateway:?}" dev "''${dev:?}" table ${name}
        ip route flush cache
        ip route list table ${name} || :
        retVal=$?
        if [ $retVal -eq 2 ]; then
          echo "table is empty"
        elif [ $retVal -ne 0 ]; then
          exit 1
        fi

        echo "''${ifconfig_local:?}" > /run/openvpn/${name}/ifconfig_local

        dependencies=(${quoteEach dependentServices})
        for i in "''${dependencies[@]}"; do
            systemctl restart "$i" || :
        done

        echo "Running route-up DONE"
      '';
    };

  routeDown =
    name: dependentServices:
    pkgs.writeShellApplication {
      name = "routeDown.sh";

      runtimeInputs = [
        pkgs.iproute2
        pkgs.systemd
        pkgs.nettools
        pkgs.coreutils
      ];

      text = ''
        echo "Running route-down..."

        echo "dev=''${dev:?}"
        echo "ifconfig_local=''${ifconfig_local:?}"
        echo "route_vpn_gateway=''${route_vpn_gateway:?}"

        set -x

        ip rule
        ip rule del from "''${ifconfig_local:?}/32" table ${name}
        ip rule del to "''${route_vpn_gateway:?}/32" table ${name}
        ip rule

        # This will probably fail because the dev is already gone.
        ip route list table ${name} || :
        retVal=$?
        if [ $retVal -eq 2 ]; then
          echo "table is empty"
        elif [ $retVal -ne 0 ]; then
          exit 1
        fi
        ip route del default via "''${route_vpn_gateway:?}" dev "''${dev:?}" table ${name} || :
        ip route flush cache
        ip route list table ${name} || :
        retVal=$?
        if [ $retVal -eq 2 ]; then
          echo "table is empty"
        elif [ $retVal -ne 0 ]; then
          exit 1
        fi

        rm /run/openvpn/${name}/ifconfig_local

        dependencies=(${quoteEach dependentServices})
        for i in "''${dependencies[@]}"; do
            systemctl stop "$i" || :
        done

        echo "Running route-down DONE"
      '';
    };
in
{
  options =
    let
      instanceOption = lib.types.submodule {
        options = {
          enable = lib.mkEnableOption "OpenVPN config";

          package = lib.mkPackageOption pkgs "openvpn" { };

          provider = lib.mkOption {
            description = "VPN provider, if given uses ready-made configuration.";
            type = lib.types.nullOr (lib.types.enum [ "nordvpn" "protonvpn" ]);
            default = null;
          };

          dev = lib.mkOption {
            description = "Name of the interface.";
            type = lib.types.str;
            example = "tun0";
          };

          routingNumber = lib.mkOption {
            description = "Unique number used to route packets.";
            type = lib.types.int;
            example = 10;
          };

          remoteServerIP = lib.mkOption {
            description = "IP of the VPN server to connect to.";
            type = lib.types.str;
          };

          authFile = lib.mkOption {
            description = "Location of file holding authentication secrets for provider.";
            type = lib.types.anything;
          };

          proxyPort = lib.mkOption {
            description = "If not null, sets up a proxy that listens on the given port and sends traffic to the VPN.";
            type = lib.types.nullOr lib.types.int;
            default = null;
          };

          killswitch = lib.mkOption {
            description = "Kill switch configuration to block traffic when VPN is down.";
            default = { };
            type = lib.types.submodule {
              options = {
                enable = lib.mkEnableOption "VPN kill switch";

                allowedSubnets = lib.mkOption {
                  description = "Subnets that are allowed even when VPN is down (e.g., local network).";
                  type = lib.types.listOf lib.types.str;
                  default = [ "192.168.0.0/16" "10.0.0.0/8" ];
                  example = [ "192.168.1.0/24" "10.0.0.0/8" ];
                };

                exemptPorts = lib.mkOption {
                  description = "Ports that are exempt from kill switch (e.g., SSH).";
                  type = lib.types.listOf lib.types.int;
                  default = [ 22 ];
                  example = [ 22 80 443 ];
                };
              };
            };
          };
        };
      };
    in
    {
      shb.vpn = lib.mkOption {
        description = "OpenVPN instances.";
        default = { };
        type = lib.types.attrsOf instanceOption;
      };
    };

  config = {
    services.openvpn.servers =
      let
        instanceConfig =
          name: c:
          lib.mkIf c.enable {
            ${name} = {
              autoStart = true;

              up = "mkdir -p /run/openvpn/${name}";

              config =
                if c.provider == "protonvpn" then
                  protonvpnConfig {
                    inherit name;
                    inherit (c) dev authFile;
                    dependentServices = lib.optional (c.proxyPort != null) "tinyproxy-${name}.service";
                  }
                else
                  nordvpnConfig {
                    inherit name;
                    inherit (c) dev remoteServerIP authFile;
                    dependentServices = lib.optional (c.proxyPort != null) "tinyproxy-${name}.service";
                  };
            };
          };
      in
      lib.mkMerge (lib.mapAttrsToList instanceConfig cfg);

    systemd.tmpfiles.rules = map (name: "d /tmp/openvpn/${name}.status 0700 root root") (
      lib.attrNames cfg
    );

    networking.iproute2.enable = true;
    networking.iproute2.rttablesExtraConfig = lib.concatStringsSep "\n" (
      lib.mapAttrsToList (name: c: "${toString c.routingNumber} ${name}") cfg
    );

    shb.tinyproxy =
      let
        instanceConfig =
          name: c:
          lib.mkIf (c.enable && c.proxyPort != null) {
            ${name} = {
              enable = true;
              # package = pkgs.tinyproxy.overrideAttrs (old: {
              #   withDebug = false;
              #   patches = old.patches ++ [
              #     (pkgs.fetchpatch {
              #       name = "";
              #       url = "https://github.com/tinyproxy/tinyproxy/pull/494/commits/2532ba09896352b31f3538d7819daa1fc3f829f1.patch";
              #       sha256 = "sha256-Q0MkHnttW8tH3+hoCt9ACjHjmmZQgF6pC/menIrU0Co=";
              #     })
              #   ];
              # });
              dynamicBindFile = "/run/openvpn/${name}/ifconfig_local";
              settings = {
                Port = c.proxyPort;
                Listen = "127.0.0.1";
                Syslog = "On";
                LogLevel = "Info";
                Allow = [
                  "127.0.0.1"
                  "::1"
                ];
                ViaProxyName = ''"tinyproxy"'';
              };
            };
          };
      in
      lib.mkMerge (lib.mapAttrsToList instanceConfig cfg);

    # VPN Kill Switch implementation
    networking.firewall.extraCommands =
      let
        killswitchRules =
          name: c:
          lib.optionalString (c.enable && c.killswitch.enable) ''
            # Kill switch for ${name}: Block all OUTPUT traffic except VPN, loopback, and allowed subnets/ports
            
            # Allow loopback
            iptables -A nixos-fw -o lo -j ACCEPT
            
            # Allow VPN interface
            iptables -A nixos-fw -o ${c.dev} -j ACCEPT
            
            # Allow established connections
            iptables -A nixos-fw -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            
            # Allow traffic to allowed subnets (local network)
            ${lib.concatMapStrings (subnet: ''
              iptables -A nixos-fw -d ${subnet} -j ACCEPT
            '') c.killswitch.allowedSubnets}
            
            # Allow exempt ports (e.g., SSH)
            ${lib.concatMapStrings (port: ''
              iptables -A nixos-fw -p tcp --dport ${toString port} -j ACCEPT
              iptables -A nixos-fw -p udp --dport ${toString port} -j ACCEPT
            '') c.killswitch.exemptPorts}
            
            # Block everything else
            iptables -A nixos-fw -j DROP
          '';
      in
      lib.concatStrings (lib.mapAttrsToList killswitchRules cfg);
  };
}
