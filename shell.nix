{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  name = "retrieves-nvim-dev";
  packages = with pkgs; [
    neovim lua-language-server stylua curl jq ripgrep git nodejs_20 nodePackages.vsce yarn pnpm
  ];
  shellHook = ''
    echo "[retrieves.nvim] Neovim $(nvim --version | head -n1) | Node $(node --version)";
    echo "Test: nvim -u NORC -c 'set rtp+=$PWD' -c 'lua require(\"retrieves\").setup()'";
  '';
}
