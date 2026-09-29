{
  description = "Secure, kernel-enforced sandbox for AI agents, MCP and LLM workloads";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    # Pin x86_64-darwin to a stable release branch for older macOS Intel
    # compatibility. The project requires Rust 1.95 (edition2024), which
    # nixpkgs-unstable does not reliably ship for x86_64-darwin.
    nixpkgs-darwin-legacy.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  };

  outputs = { self, nixpkgs, nixpkgs-darwin-legacy, ... }:
  let
    # Read version from Cargo.toml so it never needs manual syncing
    cargoToml = builtins.fromTOML (builtins.readFile ./crates/nono-cli/Cargo.toml);
    version = cargoToml.package.version;

    allSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    forAllSystems = f: nixpkgs.lib.genAttrs allSystems f;

    pkgsFor = system:
      if system == "x86_64-darwin"
      then nixpkgs-darwin-legacy.legacyPackages.${system}
      else nixpkgs.legacyPackages.${system};

    nonoFor = system: let pkgs = pkgsFor system; in pkgs.rustPlatform.buildRustPackage {
      pname = "nono";
      inherit version;
      src = self;

      cargoLock.lockFile = "${self}/Cargo.lock";

      nativeBuildInputs = [ pkgs.pkg-config ];
      buildInputs = [ pkgs.dbus ];

      # Tests require /bin/pwd, /usr/bin/env, git, /var/folders, network, etc.
      # and fail in the Nix sandbox. The project's own CI covers testing.
      doCheck = false;

      meta = with pkgs.lib; {
        description = "Secure, kernel-enforced sandbox for AI agents, MCP and LLM workloads";
        homepage = "https://github.com/nolabs-ai/nono";
        license = licenses.asl20;
        mainProgram = "nono";
        platforms = allSystems;
      };
    };

    # Map Nix system triples to the release tarball target strings.
    releaseTarget = system: {
      "x86_64-linux" = "x86_64-unknown-linux-gnu";
      "aarch64-linux" = "aarch64-unknown-linux-gnu";
      "x86_64-darwin" = "x86_64-apple-darwin";
      "aarch64-darwin" = "aarch64-apple-darwin";
    }.${system};

    # Per-platform SHA-256 hashes for the release tarballs.
    # Auto-updated by the `update-nix-hashes` job in release.yml
    # after each release — no manual maintenance needed.
    prebuiltHashes = {
      "x86_64-linux" = "sha256-r16DeXPVR6r208370S45UiJNG7d7cpKWLqGRgDmcONs=";
      "aarch64-linux" = "sha256-cwi0EJlA8W7A0CTrS7z6zhz+LqHoMz3RR6tPC+dwYHE=";
      "x86_64-darwin" = "sha256-uuQCyQ6djyXpTmwhtW5UpnTr//P6G9w8KY4b/C9+gtw=";
      "aarch64-darwin" = "sha256-rBYbVR4U7m9d+06VWTlk6a9F25ydAQdMvn1r9BEGgLQ=";
    };

    prebuiltFor = system: let pkgs = pkgsFor system; in pkgs.stdenv.mkDerivation {
      pname = "nono-prebuilt";
      inherit version;
      src = pkgs.fetchurl {
        url = "https://github.com/nolabs-ai/nono/releases/download/v${version}/nono-v${version}-${releaseTarget system}.tar.gz";
        sha256 = prebuiltHashes.${system};
      };

      # autoPatchelfHook patches the Linux binary's dynamic linker
      # and shared library references. Darwin binaries are already
      # self-contained and don't need patching.
      nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
        pkgs.autoPatchelfHook
      ];

      # The Linux release binary links against libgcc_s.so.1.
      buildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
        pkgs.gcc.cc.lib
      ];

      # The tarball contains a single `nono` binary at the root.
      sourceRoot = ".";

      installPhase = ''
        runHook preInstall
        install -Dm755 nono $out/bin/nono
        runHook postInstall
      '';

      meta = with pkgs.lib; {
        description = "Secure, kernel-enforced sandbox for AI agents, MCP and LLM workloads (prebuilt release binary)";
        homepage = "https://github.com/nolabs-ai/nono";
        license = licenses.asl20;
        mainProgram = "nono";
        platforms = allSystems;
      };
    };
  in {
    packages = forAllSystems (system: rec {
      nono = nonoFor system;
      prebuilt = prebuiltFor system;
      default = nono;
    });

    apps = forAllSystems (system: {
      default = {
        type = "app";
        program = "${nonoFor system}/bin/nono";
      };
    });

    checks = forAllSystems (system: {
      default = nonoFor system;
    });

    devShells = forAllSystems (system: let pkgs = pkgsFor system; in {
      default = pkgs.mkShell {
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.dbus pkgs.rustc pkgs.cargo ];
      };
    });
  };
}
