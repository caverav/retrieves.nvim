# retrieves.nvim

Neovim plugin to highlight reported/pending vulnerability lines in files under `groups/<group>/<nickname>/...` and fetch locations asynchronously from the Platform.

Quick start
- Ensure `curl` is on PATH and set your token:
  - `export INTEGRATES_API_TOKEN=...` or `vim.g.retrieves_token = "..."`
- Add this plugin folder to Neovim's runtimepath or your plugin manager, e.g.:
  - `:set rtp+=/path/to/retrieves.nvim`
  - Or copy to your plugin manager’s path.
- Open a file under `groups/<group>/<nickname>/...`.
  - If a snapshot exists (`<repo>/retrieves-vulns-<group>.json`), highlights appear immediately.
  - Otherwise, a background download starts; you'll get notifications for start and completion; highlights apply when ready.

Commands
- `:RetrievesDownload` - background-fetch locations for the detected group and apply.
- `:RetrievesRefresh` - re-apply highlights in the current buffer.
- `:RetrievesHover` - show a small floating window with finding name(s) and link(s) for the current line.
- `:RetrievesOpenLink` - open the first finding link on the current line in the system browser.

Indicators
- Default: thin colored sign bar in the gutter (no background fill).
- Optional: full-line background fill - set `vim.g.retrieves_indicator = 'background'`.
  - Note: terminals do not support alpha; use soft tints instead.

Color overrides
- Gutter bar colors: `vim.g.retrieves_reported_fg = "#ff3435"`, `vim.g.retrieves_pending_fg = "#fff333"`.
- Background tints (if using `background`):
  - `vim.g.retrieves_reported_bg = "#FFE5E6"`
  - `vim.g.retrieves_pending_bg  = "#FFF9C4"`
- Or define highlights directly: `:hi RetrievesReported guibg=#HEX`, `:hi RetrievesPending guibg=#HEX`.

UI options
- `vim.g.retrieves_show_eol = true` - show compact end-of-line summary (title or count).
- `vim.g.retrieves_hover = true` - enable CursorHold hover with details and links.

