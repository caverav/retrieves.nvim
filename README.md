# Retrieves.nvim

Minimal Neovim plugin that highlights reported/pending vulnerable lines, mirroring the VS Code "retrieves" extension behavior (highlighting only).

How it works:
- Detects files under a `.../groups/<group>/<nickname>/<path>` tree (same layout used by the VS Code extension).
- Looks for a JSON snapshot exported by the VS Code extension at `<repo>/retrieves-vulns-<group>.json`.
- Applies full-line highlights for reported (red) and pending (yellow) locations in the current buffer.

Usage
- Place this folder on your `runtimepath` (e.g., with any plugin manager) or `:luafile` the `retrieves.lua` file directly.
- Optional: set `vim.g.retrieves_json_override` to point to a custom JSON snapshot path if you do not use the VS Code exporter.

Live Download (GraphQL)
- Set environment variable `INTEGRATES_API_TOKEN` (or `vim.g.retrieves_token`) with your token.
- Run `:RetrievesDownload` inside a file under `groups/<group>/<nickname>/...`.
- The plugin shows notifications when downloading starts and when it completes.
- Results are cached in-memory and also exported to `<repo>/retrieves-vulns-<group>.json` for reuse.

Commands
- `:RetrievesRefresh` — re-scan and re-apply highlights for the current buffer.
- `:RetrievesDownload` — fetch locations from the Platform for the detected group and apply highlights.

Autoload
- The plugin automatically re-applies highlights on `BufEnter` and `BufWritePost` for files detected under a `groups/<group>/<nickname>/...` path.

Notes
- Colors are light tints for readability in Neovim (no transparency). Override the highlight groups `RetrievesReported` and `RetrievesPending` to tweak styling.
- If you do not use the VS Code extension, you can generate a compatible JSON with keys `reported` and `drafts`, keyed by `<nickname>/<relative_path>`, each containing an object of finding titles -> `{ id, locs: [line_numbers] }`.
- Requires `curl` available in your PATH for live downloads.
