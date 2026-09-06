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

      cargoHash = "sha256-N6lyAQJeFm9Aa78hYW1vMQ+IBHUhxfqGKAb5TH3oyh4=";

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
  in {
    packages = forAllSystems (system: rec {
      nono = nonoFor system;
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
