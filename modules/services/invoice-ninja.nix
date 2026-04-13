{
  config,
  lib,
  pkgs,
  shb,
  ...
}:

let
  cfg = config.shb.invoice-ninja;

  fqdn = "${cfg.subdomain}.${cfg.domain}";
in
{
  imports = [
    ../blocks/nginx.nix
  ];

  options.shb.invoice-ninja = {
    enable = lib.mkEnableOption "selfhostblocks.invoice-ninja";

    subdomain = lib.mkOption {
      type = lib.types.str;
      description = "Subdomain under which Invoice Ninja will be served.";
      example = "invoice";
    };

    domain = lib.mkOption {
      type = lib.types.str;
      description = "Domain under which Invoice Ninja will be served.";
      example = "mydomain.com";
    };

    ssl = lib.mkOption {
      description = "Path to SSL files";
      type = lib.types.nullOr shb.contracts.ssl.certs;
      default = null;
    };

    port = lib.mkOption {
      type = lib.types.int;
      description = "Port on which Invoice Ninja listens.";
      default = 12480;
    };

    dataDir = lib.mkOption {
      description = "Directory where Invoice Ninja stores data.";
      type = lib.types.str;
      default = "/var/lib/invoiceninja";
    };

    authEndpoint = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      description = "Auth endpoint for forward-auth SSO.";
      example = "https://authelia.example.com";
      default = null;
    };

    appKey = lib.mkOption {
      description = "APP_KEY secret (base64 encoded).";
      type = lib.types.submodule {
        options = shb.contracts.secret.mkRequester {
          owner = "root";
          restartUnits = [ "podman-invoiceninja.service" ];
        };
      };
    };

    dbPassword = lib.mkOption {
      description = "MariaDB password secret.";
      type = lib.types.submodule {
        options = shb.contracts.secret.mkRequester {
          owner = "root";
          restartUnits = [
            "podman-invoiceninja.service"
            "invoiceninja-db-setup.service"
          ];
        };
      };
    };

    ldap = {
      userGroup = lib.mkOption {
        type = lib.types.str;
        description = "LDAP group for Invoice Ninja users.";
        default = "invoiceninja_user";
      };
    };

    backup = lib.mkOption {
      description = "Backup configuration.";
      default = { };
      type = lib.types.submodule {
        options = shb.contracts.backup.mkRequester {
          user = "root";
          sourceDirectories = [
            cfg.dataDir
          ];
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    # MariaDB
    services.mysql = {
      enable = true;
      package = pkgs.mariadb;
      ensureDatabases = [ "invoiceninja" ];
      ensureUsers = [
        {
          name = "invoiceninja";
          ensurePermissions = {
            "invoiceninja.*" = "ALL PRIVILEGES";
          };
        }
      ];
      settings.mysqld = {
        # Listen on all interfaces so the container can reach MariaDB
        # via host.containers.internal (podman bridge gateway)
        bind-address = "0.0.0.0";
        port = 3306;
      };
    };

    # Data directories
    systemd.tmpfiles.rules = [
      "d ${cfg.dataDir} 0755 root root -"
    ];

    # Podman container — octane image serves HTTP directly via FrankenPHP
    virtualisation.podman.enable = true;
    virtualisation.oci-containers.backend = "podman";

    virtualisation.oci-containers.containers.invoiceninja = {
      image = "invoiceninja/invoiceninja-octane:5";
      autoStart = true;
      ports = [
        "127.0.0.1:${toString cfg.port}:80"
      ];
      volumes = [
        "${cfg.dataDir}:/var/www/app/storage:rw"
      ];
      environment = {
        APP_URL = "https://${fqdn}";
        APP_DEBUG = "false";
        APP_ENV = "production";
        REQUIRE_HTTPS = "true";
        APP_FORCE_HTTPS = "true";
        TRUSTED_PROXIES = "*";
        DB_HOST1 = "host.containers.internal";
        DB_PORT = "3306";
        DB_DATABASE1 = "invoiceninja";
        DB_USERNAME1 = "invoiceninja";
        DB_TYPE1 = "mysql";
        QUEUE_CONNECTION = "database";
        MAIL_MAILER = "log";
      };
      environmentFiles = [
        "/run/invoiceninja/env"
      ];
      extraOptions = [
        "--add-host=host.containers.internal:host-gateway"
      ];
    };

    # Ensure container waits for MariaDB and DB setup
    systemd.services.podman-invoiceninja = {
      after = [ "mysql.service" "invoiceninja-db-setup.service" ];
      requires = [ "mysql.service" ];
      serviceConfig.RestartSec = "10s";
    };

    # Create env file with secrets before container starts
    systemd.services.podman-invoiceninja.serviceConfig.ExecStartPre = lib.mkBefore [
      ("+${pkgs.writeShellScript "invoiceninja-create-env" ''
        mkdir -p /run/invoiceninja
        APP_KEY=$(cat ${cfg.appKey.result.path})
        DB_PASS=$(cat ${cfg.dbPassword.result.path})
        printf 'APP_KEY=base64:%s\nDB_PASSWORD1=%s\n' "$APP_KEY" "$DB_PASS" > /run/invoiceninja/env
        chmod 640 /run/invoiceninja/env
      ''}")
    ];

    # Set MariaDB password after DB is ready
    systemd.services.invoiceninja-db-setup = {
      description = "Set up Invoice Ninja database user password";
      after = [ "mysql.service" ];
      requires = [ "mysql.service" ];
      before = [ "podman-invoiceninja.service" ];
      requiredBy = [ "podman-invoiceninja.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        DB_PASS=$(cat ${cfg.dbPassword.result.path})
        ${config.services.mysql.package}/bin/mysql -e \
          "ALTER USER 'invoiceninja'@'localhost' IDENTIFIED BY '$DB_PASS';" || true
        ${config.services.mysql.package}/bin/mysql -e \
          "CREATE USER IF NOT EXISTS 'invoiceninja'@'%' IDENTIFIED BY '$DB_PASS';" || true
        ${config.services.mysql.package}/bin/mysql -e \
          "GRANT ALL PRIVILEGES ON invoiceninja.* TO 'invoiceninja'@'%';" || true
        ${config.services.mysql.package}/bin/mysql -e "FLUSH PRIVILEGES;" || true
      '';
    };

    # Scheduler for recurring invoices, reminders, etc.
    systemd.services.invoiceninja-scheduler = {
      description = "Invoice Ninja Scheduler";
      after = [ "podman-invoiceninja.service" ];
      requires = [ "podman-invoiceninja.service" ];
      serviceConfig.Type = "oneshot";
      script = ''
        ${pkgs.podman}/bin/podman exec invoiceninja php artisan schedule:run
      '';
    };

    systemd.timers.invoiceninja-scheduler = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "*-*-* *:*:00";
        Persistent = true;
      };
    };

    # Nginx reverse proxy + Authelia forward-auth via shb.nginx.vhosts
    shb.nginx.vhosts = [
      {
        inherit (cfg) subdomain domain authEndpoint ssl;
        upstream = "http://127.0.0.1:${toString cfg.port}";
        autheliaRules = [
          {
            domain = fqdn;
            policy = "two_factor";
            subject = [ "group:${cfg.ldap.userGroup}" ];
          }
        ];
      }
    ];
  };
}
