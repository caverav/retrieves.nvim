-- Retrieves.nvim (embedded alongside the VS Code extension)
-- Highlights reported/pending lines and fetches locations asynchronously.

local M = {}

local ns = vim.api.nvim_create_namespace("retrieves")
local reported_hl = "RetrievesReported"
local pending_hl  = "RetrievesPending"
local endpoint = "https://app.fluidattacks.com/api"
local sign_group  = "retrieves_signs"

-- In-memory cache keyed by group name
local cache_by_group = {}
local inflight_by_group = {}
local download_progress = {}

local function define_default_hls()
  -- Allow override via globals; fall back to readable tints similar to VS Code rgba fills.
  local rep = vim.g.retrieves_reported_bg or "#FFE5E6" -- soft red tint
  local pen = vim.g.retrieves_pending_bg or "#FFF9C4" -- soft yellow tint
  vim.api.nvim_set_hl(0, reported_hl, { bg = rep })
  vim.api.nvim_set_hl(0, pending_hl,  { bg = pen })

  -- Sign colors (thin bar in the sign column)
  local rep_fg = vim.g.retrieves_reported_fg or "#ff3435"
  local pen_fg = vim.g.retrieves_pending_fg or "#fff333"
  vim.api.nvim_set_hl(0, "RetrievesReportedSign", { fg = rep_fg })
  vim.api.nvim_set_hl(0, "RetrievesPendingSign", { fg = pen_fg })
end

local function detect_group(filepath)
  -- Matches: (root)/groups/(group)/(nickname)/(rest)
  local root, org, group, nickname, rest = filepath:match("(.+)/groups/([^/]+)/([^/]+)/([^/]+)/(.+)$")
  if not group then
    return nil
  end
  return {
    name = group,
    nickname = nickname,
    filename = rest,
    current_file = nickname .. "/" .. rest,
    repo_path = string.format("%s/groups/%s/%s", root, group, nickname),
  }
end

local function clean_location(where)
  if type(where) ~= "string" then return where end
  -- Remove trailing bracketed metadata like " (commit)" or " [..]"
  where = where:gsub("%s*[%(%[].*[%]%)]", "")
  return where
end

local function notify_progress(group_name, done, total)
  if total <= 0 then
    done, total = 1, 1
  end
  local percent = math.floor((done / total) * 100)
  local step = tonumber(vim.g.retrieves_progress_step or 10) or 10
  local state = download_progress[group_name]
  if not state then
    state = { last_percent = -step }
    download_progress[group_name] = state
  end
  if done == total then
    download_progress[group_name] = nil
  end

  if done == total or (percent - state.last_percent) >= step then
    state.last_percent = percent
    local msg = string.format(
      "Retrieves: downloading %s (%d/%d findings)",
      group_name,
      math.min(done, total),
      total
    )
    if vim.notify then
      vim.notify(msg, vim.log.levels.INFO, { title = "Retrieves" })
    else
      vim.api.nvim_echo({ { msg, "Normal" } }, false, {})
    end
  end
end

-- Async HTTP helpers (curl-based)
local function curl_post_json_async(url, headers, body_tbl, cb)
  local payload = vim.json.encode(body_tbl)
  local cmd = { "curl", "-sS", "-X", "POST", url, "-H", "content-type: application/json" }
  for _, h in ipairs(headers or {}) do
    table.insert(cmd, "-H")
    table.insert(cmd, h)
  end
  table.insert(cmd, "--data-binary")
  table.insert(cmd, payload)

  if type(vim.system) == "function" then
    vim.system(cmd, { text = true }, function(obj)
      local ok = obj.code == 0
      local out = (obj.stdout and obj.stdout ~= '') and obj.stdout or (obj.stderr or '')
      vim.schedule(function() cb(ok, out) end)
    end)
  else
    local stdout, stderr = {}, {}
    vim.fn.jobstart(cmd, {
      stdout_buffered = true,
      stderr_buffered = true,
      on_stdout = function(_, data)
        if data and #data > 0 then table.insert(stdout, table.concat(data, "\n")) end
      end,
      on_stderr = function(_, data)
        if data and #data > 0 then table.insert(stderr, table.concat(data, "\n")) end
      end,
      on_exit = function(_, code)
        local ok = code == 0
        local out = table.concat(ok and stdout or stderr, "")
        vim.schedule(function() cb(ok, out) end)
      end,
    })
  end
end

local function make_request_async(query, variables, cb)
  local token = vim.g.retrieves_token or vim.env.INTEGRATES_API_TOKEN
  if not token or token == "" then
    cb(nil, "INTEGRATES_API_TOKEN not set")
    return
  end
  curl_post_json_async(endpoint, { "authorization: Bearer " .. token }, {
    query = query,
    variables = variables,
  }, function(ok, out)
    if not ok then
      cb(nil, out or "request failed")
      return
    end
    local ok2, json = pcall(vim.json.decode, out)
    if not ok2 then
      cb(nil, "invalid json response")
      return
    end
    if json.errors then
      cb(nil, vim.inspect(json.errors))
      return
    end
    cb(json.data, nil)
  end)
end

local GET_FINDING_ID = [[
query GetFindingsIDS($group: String!){
  group(groupName: $group) {
    organization,
    findings { title, status, id }
    roots { ... on GitRoot { id nickname state } }
  }
}
]]

local GET_LOCATION_FROM_UUID = [[
query GetDraftsFromUUID($uuid: String!, $draftToken: String!, $vulnToken: String!){
  finding(identifier: $uuid) {
    draftsConnection(after: $draftToken, first: 5000) {
      edges { node { where specific state vulnerabilityType } }
      pageInfo { endCursor hasNextPage }
    }
    vulnerabilitiesConnection(after: $vulnToken, first: 5000) {
      edges { node { where specific state vulnerabilityType } }
      pageInfo { endCursor hasNextPage }
    }
  }
}
]]

local UPDATE_ATTACKED_TOE = [[
mutation ($group: String!, $file: String!, $root: String!, $loc: Int!) {
  updateToeLinesAttackedLines(
    groupName: $group,
    filename: $file,
    rootId: $root,
    attackedLines: $loc,
    comments: ""
  ) {
    success
  }
}
]]

local function download_group_async(group_name, on_done)
  if inflight_by_group[group_name] then return end
  inflight_by_group[group_name] = true
  download_progress[group_name] = nil
  vim.notify("Retrieves: downloading locations for " .. group_name .. "...", vim.log.levels.INFO)

  make_request_async(GET_FINDING_ID, { group = group_name }, function(root_data, err)
    if not root_data then
      inflight_by_group[group_name] = nil
      vim.notify("Retrieves: failed to list findings: " .. tostring(err), vim.log.levels.ERROR)
      download_progress[group_name] = nil
      if on_done then on_done(nil, err) end
      return
    end

    local reported, pending, roots = {}, {}, {}
    local organization = ""

    if root_data.group then
      organization = root_data.group.organization or ""
      for _, r in ipairs(root_data.group.roots or {}) do
        if r.state == "ACTIVE" then
          roots[r.nickname] = r.id
        end
      end

      local findings = root_data.group.findings or {}
      local total_findings = #findings
      local i = 1

      if total_findings > 0 then
        notify_progress(group_name, 0, total_findings)
      end

      local function process_next_finding()
        if i > #findings then
          local out = { reported = reported, drafts = pending, roots = roots, org = organization }
          cache_by_group[group_name] = out
          inflight_by_group[group_name] = nil
          if total_findings > 0 then
            notify_progress(group_name, total_findings, total_findings)
          end
          vim.notify("Retrieves: download complete for " .. group_name, vim.log.levels.INFO)
          if on_done then on_done(out, nil) end
          return
        end
        local f = findings[i]
        i = i + 1

        local vulnToken, draftToken = "", ""

        local function page_once()
          make_request_async(GET_LOCATION_FROM_UUID, {
            uuid = f.id, draftToken = draftToken, vulnToken = vulnToken
          }, function(d2, err2)
            if not d2 then
              process_next_finding()
              return
            end
            local vulns = d2.finding and d2.finding.vulnerabilitiesConnection
            local drafts = d2.finding and d2.finding.draftsConnection

            if vulns and vulns.edges then
              for _, e in ipairs(vulns.edges) do
                local node = e.node
                if node and node.state == "VULNERABLE" and node.vulnerabilityType == "lines" then
                  local where = clean_location(node.where or "")
                  local loc = node.specific
                  reported[where] = reported[where] or {}
                  local t = reported[where][f.title]
                  if not t then
                    reported[where][f.title] = { id = f.id, locs = { loc } }
                  else
                    local exists = false
                    for _, x in ipairs(t.locs) do if x == loc then exists = true break end end
                    if not exists then table.insert(t.locs, loc) end
                  end
                end
              end
            end

            if drafts and drafts.edges then
              for _, e in ipairs(drafts.edges) do
                local node = e.node
                if node and node.vulnerabilityType == "lines" then
                  local where = clean_location(node.where or "")
                  local loc = node.specific
                  local title = string.format("%s - %s", f.title, node.state)
                  pending[where] = pending[where] or {}
                  local t = pending[where][title]
                  if not t then
                    pending[where][title] = { id = f.id, locs = { loc } }
                  else
                    local exists = false
                    for _, x in ipairs(t.locs) do if x == loc then exists = true break end end
                    if not exists then table.insert(t.locs, loc) end
                  end
                end
              end
            end

            vulnToken = (vulns and vulns.pageInfo and vulns.pageInfo.endCursor ~= "bnVsbA==") and vulns.pageInfo.endCursor or ""
            draftToken = (drafts and drafts.pageInfo and drafts.pageInfo.endCursor ~= "bnVsbA==") and drafts.pageInfo.endCursor or ""
            local vulnHasNext = vulns and vulns.pageInfo and vulns.pageInfo.hasNextPage or false
            local draftHasNext = drafts and drafts.pageInfo and drafts.pageInfo.hasNextPage or false

            if vulnHasNext or draftHasNext then
              page_once()
            else
              if total_findings > 0 then
                notify_progress(group_name, i - 1, total_findings)
              end
              process_next_finding()
            end
          end)
        end

        page_once()
      end

      process_next_finding()
    else
      inflight_by_group[group_name] = nil
      vim.notify("Retrieves: group not found", vim.log.levels.ERROR)
      download_progress[group_name] = nil
      if on_done then on_done(nil, "group not found") end
    end
  end)
end

-- Per-buffer line metadata
local line_meta = {}

local function add_line_meta(buf, ln, entry)
  line_meta[buf] = line_meta[buf] or {}
  line_meta[buf][ln] = line_meta[buf][ln] or {}
  table.insert(line_meta[buf][ln], entry)
end

local function clear_line_meta(buf)
  if line_meta[buf] then line_meta[buf] = nil end
end

local function load_snapshot(path)
  local ok, stat = pcall(vim.uv.fs_stat or vim.loop.fs_stat, path)
  if not ok or not stat then
    return nil, string.format("snapshot not found: %s", path)
  end
  local ok2, data = pcall(vim.fn.readfile, path)
  if not ok2 then
    return nil, string.format("failed to read snapshot: %s", path)
  end
  local ok3, json = pcall(vim.fn.json_decode, table.concat(data, "\n"))
  if not ok3 then
    return nil, string.format("invalid json snapshot: %s", path)
  end
  return json, nil
end

local function snapshot_path_for(group)
  return vim.g.retrieves_json_override
    or (group.repo_path .. "/retrieves-vulns-" .. group.name .. ".json")
end

local function ensure_group_entry(group)
  if not group then
    return nil, "group not detected"
  end
  local entry = cache_by_group[group.name]
  if entry and entry.roots and entry.roots[group.nickname] then
    return entry, nil
  end

  local snapshot, err = load_snapshot(snapshot_path_for(group))
  if snapshot then
    entry = entry or {}
    entry.reported = entry.reported or snapshot.reported or {}
    entry.drafts = entry.drafts or snapshot.drafts or {}
    entry.roots = snapshot.roots or entry.roots or {}
    entry.org = snapshot.org or entry.org or ""
    cache_by_group[group.name] = entry
    if entry.roots and entry.roots[group.nickname] then
      return entry, nil
    end
  end

  return cache_by_group[group.name], err or "root id unavailable"
end

local function clear(buf)
  if vim.api.nvim_buf_is_valid(buf) then
    vim.api.nvim_buf_clear_namespace(buf, ns, 0, -1)
  end
end

local function apply(buf)
  if not vim.api.nvim_buf_is_loaded(buf) then return end
  local name = vim.api.nvim_buf_get_name(buf)
  if name == "" then return end

  local group = detect_group(name)
  if not group then
    clear(buf)
    return
  end

  local snapshot_path = snapshot_path_for(group)

  local snapshot, err = load_snapshot(snapshot_path)
  local entry = cache_by_group[group.name]
  if snapshot then
    entry = entry or {}
    entry.reported = snapshot.reported or entry.reported or {}
    entry.drafts = snapshot.drafts or entry.drafts or {}
    entry.roots = snapshot.roots or entry.roots or {}
    entry.org = snapshot.org or entry.org or ""
    cache_by_group[group.name] = entry
  elseif entry then
    -- nothing more to do; we'll rely on cached data
  end

  entry = cache_by_group[group.name]
  if not entry then
    -- Kick off async download (non-blocking) if token present
    local token = vim.g.retrieves_token or vim.env.INTEGRATES_API_TOKEN
    if token and token ~= "" then
      download_group_async(group.name, function(res, derr)
        if res then
          pcall(function()
            local fd = assert(io.open(snapshot_path, "w"))
            fd:write(vim.json.encode({
              reported = res.reported,
              drafts = res.drafts,
              org = res.org,
              roots = res.roots,
              group = group.name,
              exportedAt = os.date("!%Y-%m-%dT%H:%M:%SZ")
            }))
            fd:close()
          end)
          if vim.api.nvim_buf_is_valid(buf) then apply(buf) end
        end
      end)
    end
    clear(buf)
    return
  end

  local key = group.current_file
  local reported = ((entry.reported or {}))[key]
  local drafts   = ((entry.drafts   or {}))[key]

  clear(buf)
  clear_line_meta(buf)

  local org = entry.org or ""
  local show_eol = (vim.g.retrieves_show_eol ~= false)
  local indicator = vim.g.retrieves_indicator or 'sign' -- 'sign' (default) or 'background'
  local linecount = vim.api.nvim_buf_line_count(buf)
  -- Clear previous signs if using sign indicators
  if indicator ~= 'background' then
    pcall(vim.fn.sign_unplace, sign_group, { buffer = buf })
  end

  local function place_for(state, title, id, locs)
    local hl_group = state == 'reported' and reported_hl or pending_hl
    for _, l in ipairs(locs or {}) do
      local ln = tonumber(l) or 1
      if ln <= 0 then ln = 1 end
      if ln <= linecount then
        if indicator == 'background' then
          -- highlight whole line
          pcall(vim.api.nvim_buf_add_highlight, buf, ns, hl_group, ln - 1, 0, -1)
        else
          -- place thin bar sign
          local sign_name = (state == 'reported') and 'retrieves_reported' or 'retrieves_pending'
          pcall(vim.fn.sign_place, 0, sign_group, sign_name, buf, { lnum = ln, priority = 9 })
        end
        -- store metadata for hover/open
        local url = string.format("https://app.fluidattacks.com/orgs/%s/groups/%s/vulns/%s/locations/", org, group.name, id)
        add_line_meta(buf, ln, { state = state, title = title, id = id, url = url })
      end
    end
  end

  if reported then
    for title, entry in pairs(reported) do
      place_for('reported', title, entry.id, entry.locs)
    end
  end
  if drafts then
    for title, entry in pairs(drafts) do
      place_for('pending', title, entry.id, entry.locs)
    end
  end

  if show_eol and line_meta[buf] then
    for ln, entries in pairs(line_meta[buf]) do
      local summary
      if #entries == 1 then
        summary = string.format(" %s", entries[1].title)
      else
        summary = string.format(" %d findings", #entries)
      end
      -- small, dimmed eol text
      local vt = { { "  " .. summary, "Comment" } }
      pcall(vim.api.nvim_buf_set_extmark, buf, ns, ln - 1, 0, {
        virt_text = vt,
        virt_text_pos = "eol",
        priority = 60,
      })
    end
  end
end

function M.refresh()
  define_default_hls()
  apply(vim.api.nvim_get_current_buf())
end

function M.setup()
  define_default_hls()
  -- Define signs (thin bar). Do once; harmless if redefined.
  pcall(vim.fn.sign_define, 'retrieves_reported', { text = '▎', texthl = 'RetrievesReportedSign', numhl = '' })
  pcall(vim.fn.sign_define, 'retrieves_pending',  { text = '▎', texthl = 'RetrievesPendingSign',  numhl = '' })
  vim.api.nvim_create_user_command("RetrievesRefresh", function()
    M.refresh()
  end, {})

  vim.api.nvim_create_user_command("RetrievesDownload", function(opts)
    local buf = vim.api.nvim_get_current_buf()
    local name = vim.api.nvim_buf_get_name(buf)
    local group = detect_group(name)
    if not group then
      vim.notify("Retrieves: not a group file", vim.log.levels.WARN)
      return
    end
    download_group_async(group.name, function(res, err)
      if not res then return end
      -- Write snapshot
      local snapshot_path = snapshot_path_for(group)
      pcall(function()
        local fd = assert(io.open(snapshot_path, "w"))
        fd:write(vim.json.encode({
          reported = res.reported, drafts = res.drafts, org = res.org, roots = res.roots,
          group = group.name, exportedAt = os.date("!%Y-%m-%dT%H:%M:%SZ")
        }))
        fd:close()
      end)
      -- Apply to current buffer
      if vim.api.nvim_buf_is_valid(buf) then M.refresh() end
    end)
  end, {})

  vim.api.nvim_create_user_command("RetrievesAttack", function()
    local buf = vim.api.nvim_get_current_buf()
    local name = vim.api.nvim_buf_get_name(buf)
    if name == "" then
      vim.notify("Retrieves: current buffer has no filename", vim.log.levels.WARN)
      return
    end
    local group = detect_group(name)
    if not group then
      vim.notify("Retrieves: not a group file", vim.log.levels.WARN)
      return
    end

    local function submit_request(root_id)
      if not vim.api.nvim_buf_is_valid(buf) then
        return
      end
      local attacked = math.max(vim.api.nvim_buf_line_count(buf) - 1, 0)
      make_request_async(UPDATE_ATTACKED_TOE, {
        group = group.name,
        file = group.filename,
        root = root_id,
        loc = attacked,
      }, function(data, req_err)
        if not data then
          vim.notify("Retrieves: failed to mark attacked: " .. tostring(req_err), vim.log.levels.ERROR)
          return
        end
        local ok = data.updateToeLinesAttackedLines and data.updateToeLinesAttackedLines.success
        if ok then
          vim.notify("Retrieves: file marked as attacked", vim.log.levels.INFO)
        else
          vim.notify("Retrieves: failed to mark attacked", vim.log.levels.ERROR)
        end
      end)
    end

    local entry, err = ensure_group_entry(group)
    if not entry then
      vim.notify("Retrieves: " .. (err or "root data unavailable"), vim.log.levels.ERROR)
      return
    end
    local root_id = entry.roots and entry.roots[group.nickname]
    if root_id then
      submit_request(root_id)
      return
    end

    if inflight_by_group[group.name] then
      vim.notify("Retrieves: download in progress, try again shortly", vim.log.levels.INFO)
      return
    end

    download_group_async(group.name, function(res, err)
      if not res then
        vim.notify("Retrieves: failed to refresh group data" .. (err and (": " .. tostring(err)) or ""), vim.log.levels.ERROR)
        return
      end
      local rid = res.roots and res.roots[group.nickname]
      if not rid then
        vim.notify("Retrieves: root id not found for " .. group.current_file, vim.log.levels.ERROR)
        return
      end
      submit_request(rid)
    end)
  end, {})

  vim.api.nvim_create_autocmd({ "BufEnter", "BufWritePost" }, {
    group = vim.api.nvim_create_augroup("retrieves_nvim", { clear = true }),
    callback = function(args)
      -- Only act on normal listed buffers
      if vim.api.nvim_buf_get_option(args.buf, "buftype") == "" then
        apply(args.buf)
      end
    end,
  })

  -- Optional hover on CursorHold
  local function show_hover()
    local buf = vim.api.nvim_get_current_buf()
    local pos = vim.api.nvim_win_get_cursor(0)
    local ln = pos[1]
    local entries = line_meta[buf] and line_meta[buf][ln]
    if not entries or #entries == 0 then return end
    local lines = { "Retrieves" }
    for _, e in ipairs(entries) do
      table.insert(lines, string.format("- %s: %s", e.state == 'reported' and 'reported' or 'pending', e.title))
      table.insert(lines, string.format("  %s", e.url))
    end
    local bufnr, winnr = vim.lsp.util.open_floating_preview(lines, 'markdown', { border = 'rounded', focusable = false })
    -- Auto-close after short delay
    vim.defer_fn(function()
      if vim.api.nvim_win_is_valid(winnr) then pcall(vim.api.nvim_win_close, winnr, true) end
      if vim.api.nvim_buf_is_valid(bufnr) then pcall(vim.api.nvim_buf_delete, bufnr, { force = true }) end
    end, 2500)
  end

  if vim.g.retrieves_hover ~= false then
    vim.api.nvim_create_autocmd("CursorHold", {
      group = vim.api.nvim_create_augroup("retrieves_nvim_hover", { clear = true }),
      callback = function()
        show_hover()
      end,
    })
  end

  vim.api.nvim_create_user_command("RetrievesHover", function()
    local ok, _ = pcall(show_hover)
    if not ok then return end
  end, {})

  vim.api.nvim_create_user_command("RetrievesOpenLink", function()
    local buf = vim.api.nvim_get_current_buf()
    local pos = vim.api.nvim_win_get_cursor(0)
    local ln = pos[1]
    local entry = line_meta[buf] and line_meta[buf][ln] and line_meta[buf][ln][1]
    if not entry then
      vim.notify("Retrieves: no link on this line", vim.log.levels.INFO)
      return
    end
    if type(vim.ui.open) == 'function' then
      vim.ui.open(entry.url)
    else
      local opener = vim.fn.has('mac') == 1 and 'open' or (vim.fn.executable('xdg-open') == 1 and 'xdg-open' or 'start')
      vim.fn.jobstart({ opener, entry.url }, { detach = true })
    end
  end, {})
end

-- Auto-setup if sourced directly
if vim.g.retrieves_autosetup ~= false then
  pcall(M.setup)
end

return M
