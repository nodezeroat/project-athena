{
  description = "typst environment";
  nixConfig.bash-prompt = "\[typst\]$ ";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    typst-packages = {
      url = "github:typst/packages";
      flake = false;
    };
    typst-pkg-src = {
      url = "github:NixOS/nixpkgs/20c4598c84a671783f741e02bf05cbfaf4907cff";
      inputs = {};
    };
  };

  outputs = { self, nixpkgs, utils, typst-packages, typst-pkg-src, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        p = import nixpkgs { inherit system; };
        typstFromOldCommit = import typst-pkg-src { inherit system; };

        fonts = with p; [
          noto-fonts 
          fira-math
        ];

        fontPaths = (builtins.map (x: x + "/share/fonts/opentype") fonts)
                  ++ (builtins.map (x: x + "/share/fonts/truetype") fonts)
                  ++ [ ./athena-fonts/fonts ];
        fontParam = p.lib.concatStringsSep ":" fontPaths;

        typstPackagesCache = p.stdenv.mkDerivation {
          name = "typst-packages-cache";
          src = "${typst-packages}/packages";
          dontBuild = true;
          installPhase = ''
            mkdir -p "$out/typst/packages"
            cp -LR --reflink=auto --no-preserve=mode -t "$out/typst/packages" "$src"/*
          '';
        };

        derivation = { stdenvNoCC, ... }:
          stdenvNoCC.mkDerivation {
            name = "typst-build";
            src = ./.;
            buildInputs = [ typstFromOldCommit.typst ] ++ fonts;

            buildPhase = ''
              echo "Current directory contents:"
              ls -la
              mkdir -p out
              export XDG_CACHE_HOME=${typstPackagesCache}
              export TYPST_FONT_PATHS=${fontParam}

              find Curriculum -type f -path "*/slides/*.typ" | while read file; do
                name=$(basename "$file" .typ)
                echo "Compiling $file → $name.pdf"
                typst compile "$file" "out/$name.pdf" --root .
              done
            '';

            installPhase = ''
              mkdir -p $out
              cp out/*.pdf $out/
            '';
          };
      in {
        devShell = p.mkShell.override { stdenv = p.stdenv; } rec {
          packages = [
            typstFromOldCommit.typst
            p.tinymist
            # p.typst-live  # Remove if not in nixpkgs 25.05
          ] ++ fonts;

          shellHook = ''
            export XDG_CACHE_HOME=${typstPackagesCache}
            export TYPST_FONT_PATHS=${fontParam}
          '';

          name = "Typst build";
        };

        packages.default = p.callPackage derivation {};
      }
    );
}
