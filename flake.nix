{
  description = "retrieves.nvim dev shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs(systems) (system: f (import nixpkgs { inherit system; }));
    in {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          name = "retrieves-nvim-dev";
          packages = with pkgs; [
            neovim
            lua-language-server
            stylua
            curl
            jq
            ripgrep
            git
          ];
          shellHook = ''
            echo "[retrieves.nvim] Neovim $(nvim --version | head -n1) | Node $(node --version)";
            echo "Test: nvim -u NORC -c 'set rtp+=$PWD' -c 'lua require("retrieves").setup()'";
            echo "Remember to export INTEGRATES_API_TOKEN for live downloads.";
          '';
        };
      });
    };
}
