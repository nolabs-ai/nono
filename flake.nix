{
  description = "Secure, kernel-enforced sandbox for AI agents, MCP and LLM workloads";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    # Pin x86_64-darwin to a stable release branch for older macOS Intel
    # compatibility. Bumped from 24.05 to 26.05 because the project requires
    # Rust 1.95 (edition2024), which 24.05-darwin does not ship.
    # See references/flake-templates/darwin-legacy-pin.md.
    nixpkgs-darwin-legacy.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  };

  outputs = { self, nixpkgs, nixpkgs-darwin-legacy, ... }:
  let
    version = "0.75.0";

    assets = {
      "x86_64-linux" = {
        file = "nono-v${version}-x86_64-unknown-linux-gnu.tar.gz";
        sha256 = "sha256-L4gyaYJNhflqdfuHiPbDFhnmDSwIZek0AtLzR0YQVPo=";
      };
      "aarch64-linux" = {
        file = "nono-v${version}-aarch64-unknown-linux-gnu.tar.gz";
        sha256 = "sha256-xdIUIHerCbA4Kc9aA8IU6rdh4mpEC5ZIWPWJUNuTzQA=";
      };
      "x86_64-darwin" = {
        file = "nono-v${version}-x86_64-apple-darwin.tar.gz";
        sha256 = "sha256-9GDpKoIHUqib4G7/Z7iIIn5NuvmeBa27Nt0CfOtJgj4=";
      };
      "aarch64-darwin" = {
        file = "nono-v${version}-aarch64-apple-darwin.tar.gz";
        sha256 = "sha256-fzPxE7GTkAYAtUlRwwYTetfgQ0at66oUKDx1K3Zzx9A=";
      };
    };

    allSystems = builtins.attrNames assets;
    forAllSystems = f: nixpkgs.lib.genAttrs allSystems f;

    # Prebuilt binary from release tarball
    prebuiltFor = system: let
      pkgs =
        if system == "x86_64-darwin"
        then nixpkgs-darwin-legacy.legacyPackages.${system}
        else nixpkgs.legacyPackages.${system};
      asset = assets.${system};
    in pkgs.stdenv.mkDerivation {
      pname = "nono";
      inherit version;

      src = pkgs.fetchurl {
        url = "https://github.com/nolabs-ai/nono/releases/download/v${version}/${asset.file}";
        inherit (asset) sha256;
      };

      sourceRoot = ".";

      nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.autoPatchelfHook ];
      buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.stdenv.cc.cc.lib ];

      dontConfigure = true;
      dontBuild = true;

      installPhase = ''
        runHook preInstall
        mkdir -p "$out/bin"
        cp nono "$out/bin/nono"
        chmod +x "$out/bin/nono"
        runHook postInstall
      '';

      meta = with pkgs.lib; {
        description = "Secure, kernel-enforced sandbox for AI agents, MCP and LLM workloads";
        homepage = "https://github.com/nolabs-ai/nono";
        downloadPage = "https://github.com/nolabs-ai/nono/releases";
        license = licenses.asl20;
        mainProgram = "nono";
        platforms = allSystems;
        sourceProvenance = [ sourceTypes.binaryNativeCode ];
      };
    };

    # From-source build using rustPlatform.buildRustPackage
    # cargoHash and src hash are tracked from the upstream nixpkgs derivation
    # (pkgs/by-name/no/nono/package.nix) to stay in sync with the project's
    # actual build dependencies.
    sourceFor = system: let
      pkgs =
        if system == "x86_64-darwin"
        then nixpkgs-darwin-legacy.legacyPackages.${system}
        else nixpkgs.legacyPackages.${system};
    in pkgs.rustPlatform.buildRustPackage {
      pname = "nono";
      inherit version;

      src = pkgs.fetchFromGitHub {
        owner = "nolabs-ai";
        repo = "nono";
        rev = "v${version}";
        hash = "sha256-4HrWe6RamlfXJ1hDIc+E80a+lDxuHWzeXmpkuRp0r7U=";
      };

      cargoHash = "sha256-N6lyAQJeFm9Aa78hYW1vMQ+IBHUhxfqGKAb5TH3oyh4=";

      nativeBuildInputs = [ pkgs.pkg-config ];

      buildInputs = [ pkgs.dbus ];

      # Tests are run by the project's own CI, not the Nix flake. Many tests
      # fail in the Nix sandbox (require /bin/pwd, /usr/bin/env, git, /var/folders,
      # network, etc.) — the upstream nixpkgs derivation skips the same tests.
      doCheck = false;

      meta = {
        description = "Secure, kernel-enforced sandbox for AI agents, MCP and LLM workloads";
        homepage = "https://github.com/nolabs-ai/nono";
        license = pkgs.lib.licenses.asl20;
        mainProgram = "nono";
        platforms = allSystems;
      };
    };
  in {
    packages = forAllSystems (system: rec {
      nono = prebuiltFor system;
      prebuilt = nono;
      default = prebuilt;
      source = sourceFor system;
    });

    apps = forAllSystems (system: let
      nonoPkg = prebuiltFor system;
      sourcePkg = sourceFor system;
    in {
      nono = {
        type = "app";
        program = "${nonoPkg}/bin/nono";
      };
      prebuilt = {
        type = "app";
        program = "${nonoPkg}/bin/nono";
      };
      default = {
        type = "app";
        program = "${nonoPkg}/bin/nono";
      };
      source = {
        type = "app";
        program = "${sourcePkg}/bin/nono";
      };
    });

    checks = forAllSystems (system: {
      prebuilt = prebuiltFor system;
      source = sourceFor system;
    });

    devShells = forAllSystems (system: let
      pkgs =
        if system == "x86_64-darwin"
        then nixpkgs-darwin-legacy.legacyPackages.${system}
        else nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShell {
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.dbus pkgs.rustc pkgs.cargo ];
      };
    });
  };
}
