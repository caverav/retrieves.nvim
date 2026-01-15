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
local auto_attack_done = {}

local function new_progress_state()
  local step = tonumber(vim.g.retrieves_progress_step or 10) or 10
  return { last_percent = -step, done = 0, total = 0 }
end

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
  local root, group, nickname, rest = filepath:match("(.+)/groups/([^/]+)/([^/]+)/(.+)$")
  if not group then
    return nil
  end
  return {
    name = group,
    nickname = nickname,
    filename = rest,
    current_file = nickname .. "/" .. rest,
    repo_path = string.format("%s/groups/%s/%s", root, group, nickname),
    group_path = string.format("%s/groups/%s", root, group),
  }
end

local function clean_location(where)
  if type(where) ~= "string" then return where end
  -- Remove trailing bracketed metadata like " (commit)" or " [..]"
  where = where:gsub("%s*[%(%[].*[%]%)]", "")
  return where
end

local function build_scope_urls(group_data)
  local scope = {}
  local scope_set = {}

  local function add(url)
    if not url or url == "" or scope_set[url] then return end
    scope_set[url] = true
    table.insert(scope, url)
  end

  if group_data and group_data.gitEnvironmentUrls then
    for _, env in ipairs(group_data.gitEnvironmentUrls or {}) do
      add(env.url)
    end
  end

  if group_data and group_data.roots then
    for _, root in ipairs(group_data.roots or {}) do
      if root.state == "ACTIVE" and root.host then
        local built = string.format("%s://%s", root.protocol or "https", root.host)
        if root.port and root.port ~= 80 and root.port ~= 443 then
          built = built .. ":" .. tostring(root.port)
        end
        if root.path and root.path ~= "" then
          built = built .. "/" .. root.path
        end
        built = built:gsub("([^:])//+", "%1/")
        add(built)
      end
    end
  end

  return scope
end

local function notify_progress(group_name, done, total)
  if total <= 0 then
    done, total = 1, 1
  end
  local percent = math.floor((done / total) * 100)
  local step = tonumber(vim.g.retrieves_progress_step or 10) or 10
  local state = download_progress[group_name]
  if not state then
    state = new_progress_state()
    download_progress[group_name] = state
  end
  state.done = math.min(done, total)
  state.total = total
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

local function make_upload_request_async(query, variables, file_content, file_name, cb)
  local token = vim.g.retrieves_token or vim.env.INTEGRATES_API_TOKEN
  if not token or token == "" then
    cb(nil, "INTEGRATES_API_TOKEN not set")
    return
  end

  local tmpfile = vim.fn.tempname()
  local lines = vim.split(file_content or "", "\n", { plain = true })
  pcall(vim.fn.writefile, lines, tmpfile)

  local operations = vim.json.encode({ query = query, variables = vim.tbl_extend("force", variables or {}, { file = nil }) })
  local map = vim.json.encode({ ["0"] = { "variables.file" } })

  local cmd = { "curl", "-sS", "-X", "POST", endpoint, "-H", "authorization: Bearer " .. token }
  vim.list_extend(cmd, { "-F", "operations=" .. operations })
  vim.list_extend(cmd, { "-F", "map=" .. map })
  vim.list_extend(cmd, { "-F", string.format("0=@%s;type=application/x-yaml;filename=%s", tmpfile, file_name or "report_nvim.yaml") })

  local function finish(ok, out)
    pcall(function() vim.fn.delete(tmpfile) end)
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
  end

  if type(vim.system) == "function" then
    vim.system(cmd, { text = true }, function(obj)
      local ok = obj.code == 0
      local out = (obj.stdout and obj.stdout ~= '') and obj.stdout or (obj.stderr or '')
      vim.schedule(function() finish(ok, out) end)
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
        vim.schedule(function() finish(ok, out) end)
      end,
    })
  end
end

local GET_FINDING_ID = [[
query GetFindingsIDS($group: String!){
  group(groupName: $group) {
    organization,
    findings { title, status, id, hacker }
    gitEnvironmentUrls { url }
    roots {
      ... on GitRoot { id nickname state }
      ... on URLRoot { protocol host port path state }
    }
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

local GET_ME = [[
query {
  me { userEmail }
}
]]

local UPLOAD_VULNERABILITIES = [[
mutation ($file: Upload!, $findingId: String!) {
  uploadFile(findingId: $findingId, file: $file) {
    message
    success
  }
}
]]

local function download_group_async(group_name, on_done)
  if inflight_by_group[group_name] then return end
  inflight_by_group[group_name] = true
  download_progress[group_name] = new_progress_state()
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
    local scope = {}
    local organization = ""

    if root_data.group then
      organization = root_data.group.organization or ""
      scope = build_scope_urls(root_data.group)
      for _, r in ipairs(root_data.group.roots or {}) do
        if r.state == "ACTIVE" then
          if r.nickname and r.id then
            roots[r.nickname] = r.id
          end
        end
      end

      local findings = root_data.group.findings or {}
      local total_findings = #findings
      local i = 1

      local state = download_progress[group_name] or new_progress_state()
      state.total = total_findings
      state.done = 0
      download_progress[group_name] = state

      if total_findings > 0 then
        notify_progress(group_name, 0, total_findings)
      end

      local function process_next_finding()
        if i > #findings then
          local out = { reported = reported, drafts = pending, roots = roots, org = organization, scope = scope }
          cache_by_group[group_name] = out
          inflight_by_group[group_name] = nil
          download_progress[group_name] = nil
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
    or (group.group_path .. "/retrieves-vulns-" .. group.name .. ".json")
end

local function write_snapshot_for_group(group, res)
  if not group or not res then return end
  local snapshot_path = snapshot_path_for(group)
  pcall(function()
    local fd = assert(io.open(snapshot_path, "w"))
    fd:write(vim.json.encode({
      reported = res.reported,
      drafts = res.drafts,
      org = res.org,
      roots = res.roots,
      scope = res.scope,
      group = group.name,
      exportedAt = os.date("!%Y-%m-%dT%H:%M:%SZ")
    }))
    fd:close()
  end)
end

local function merge_snapshot_into_entry(entry, snapshot)
  if not snapshot then return entry end
  entry = entry or {}
  entry.reported = snapshot.reported or entry.reported or {}
  entry.drafts = snapshot.drafts or entry.drafts or {}
  entry.roots = snapshot.roots or entry.roots or {}
  entry.scope = snapshot.scope or entry.scope or {}
  entry.org = snapshot.org or entry.org or ""
  return entry
end

local function cached_entry_for_group(group)
  if not group then return nil end
  local entry = cache_by_group[group.name]
  if entry then return entry end

  local snapshot, _ = load_snapshot(snapshot_path_for(group))
  if snapshot then
    entry = merge_snapshot_into_entry(entry, snapshot)
    cache_by_group[group.name] = entry
    return entry
  end
  return nil
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
    entry = merge_snapshot_into_entry(entry, snapshot)
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

local maybe_auto_attack

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
    entry = merge_snapshot_into_entry(entry, snapshot)
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
          write_snapshot_for_group(group, res)
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

  if maybe_auto_attack then
    maybe_auto_attack(buf, group, entry)
  end
end

local function count_locations_for_file(entries)
  local total = 0
  if not entries then return 0 end
  for _, entry in pairs(entries) do
    if type(entry) == "table" and type(entry.locs) == "table" then
      total = total + #entry.locs
    else
      total = total + 1
    end
  end
  return total
end

local function submit_attack(buf, group, root_id, silent)
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
      if not silent then
        vim.notify("Retrieves: file marked as attacked", vim.log.levels.INFO)
      end
    else
      vim.notify("Retrieves: failed to mark attacked", vim.log.levels.ERROR)
    end
  end)
end

maybe_auto_attack = function(buf, group, entry)
  if vim.g.retrieves_auto_attack ~= true then
    return
  end
  if not group or not entry or not entry.roots then
    return
  end
  if auto_attack_done[group.current_file] then
    return
  end
  local root_id = entry.roots[group.nickname]
  if not root_id then
    return
  end
  auto_attack_done[group.current_file] = true
  submit_attack(buf, group, root_id, true)
end

local function get_last_commit(path)
  if not path or path == "" then
    return ""
  end
  if type(vim.system) == "function" then
    local res = vim.system(
      { "git", "log", "-n", "1", "--pretty=format:%H", "--" },
      { text = true, cwd = path }
    ):wait()
    if res and res.code == 0 then
      return (res.stdout or ""):gsub("%s+$", "")
    end
  end
  local out = vim.fn.system({ "git", "-C", path, "log", "-n", "1", "--pretty=format:%H", "--" })
  if vim.v.shell_error == 0 then
    return (out or ""):gsub("%s+$", "")
  end
  return ""
end

local function parse_yaml_entries(content)
  local entries = {}
  local current = nil
  local lines = vim.split(content or "", "\n", { plain = true })
  for _, line in ipairs(lines) do
    if line:match("^%s*lines:%s*$") then
      current = nil
    elseif line:match("^%s*%-") then
      current = {}
      table.insert(entries, current)
      local inline = line:gsub("^%s*%-", ""):gsub("^%s*", "")
      local key, value = inline:match("^([%w_]+)%s*:%s*(.*)$")
      if key then
        value = value:gsub("^['\"]", ""):gsub("['\"]$", "")
        current[key] = value
      end
    elseif current then
      local key, value = line:match("^%s*([%w_]+)%s*:%s*(.*)$")
      if key then
        value = value:gsub("^['\"]", ""):gsub("['\"]$", "")
        current[key] = value
      end
    end
  end
  return entries
end

local function dump_yaml_entries(entries)
  local out = { "lines:" }
  for _, entry in ipairs(entries) do
    table.insert(out, string.format("- commit_hash: %s", entry.commit_hash or ""))
    table.insert(out, string.format("  line: '%s'", entry.line or ""))
    table.insert(out, string.format("  path: %s", entry.path or ""))
    table.insert(out, string.format("  repo_nickname: %s", entry.repo_nickname or ""))
    table.insert(out, string.format("  source: %s", entry.source or "analyst"))
    table.insert(out, "  state: submitted")
    table.insert(out, "  tool:")
    table.insert(out, "    impact: direct")
    table.insert(out, "    name: none")
  end
  return table.concat(out, "\n") .. "\n"
end

local function add_line_to_yaml(yaml_path, nickname, filepath, commit, line, source)
  local ok, data = pcall(vim.fn.readfile, yaml_path)
  local content = ok and table.concat(data, "\n") or ""
  local entries = parse_yaml_entries(content)
  local line_str = tostring(line)
  local max_per_entry = tonumber(vim.g.retrieves_max_yaml_lines_per_entry or 100) or 100
  local pushed = false

  for _, entry in ipairs(entries) do
    if entry.path == filepath and entry.repo_nickname == nickname then
      local existing = entry.line or ""
      local parts = vim.split(existing, ",", { plain = true, trimempty = true })
      if #parts <= max_per_entry then
        table.insert(parts, line_str)
        entry.line = table.concat(parts, ",")
        pushed = true
        break
      end
    end
  end

  if not pushed then
    table.insert(entries, {
      commit_hash = commit,
      line = line_str,
      path = filepath,
      repo_nickname = nickname,
      source = source or "analyst",
      state = "submitted",
      tool = { impact = "direct", name = "none" },
    })
  end

  local dumped = dump_yaml_entries(entries)
  local out_lines = vim.split(dumped, "\n", { plain = true })
  local ok2, err = pcall(vim.fn.writefile, out_lines, yaml_path)
  if not ok2 then
    vim.notify("Retrieves: failed to write yaml: " .. tostring(err), vim.log.levels.ERROR)
  end
end

local function absolute_path_for(group, file_path)
  if not file_path or file_path == "" then return nil end
  if vim.fn.fnamemodify(file_path, ":p") == file_path then
    return file_path
  end
  local parent = group.repo_path and group.repo_path:match("(.+)/[^/]+$") or nil
  if parent then
    return vim.fs.normalize(parent .. "/" .. file_path)
  end
  return vim.fs.normalize(file_path)
end

local function open_location(group, file_path, line)
  local path = absolute_path_for(group, file_path)
  if not path then return end
  vim.cmd("edit " .. vim.fn.fnameescape(path))
  local ln = tonumber(line) or 1
  if ln < 1 then ln = 1 end
  vim.api.nvim_win_set_cursor(0, { ln, 0 })
end

local function telescope_available()
  return pcall(require, "telescope.pickers")
end

local function use_telescope_picker()
  return vim.g.retrieves_picker ~= "buffer" and telescope_available()
end

local function buffer_select(items, opts, on_select)
  vim.cmd("vsplit")
  local win = vim.api.nvim_get_current_win()
  local buf = vim.api.nvim_create_buf(false, true)
  vim.api.nvim_win_set_buf(win, buf)
  vim.api.nvim_win_set_width(win, math.max(40, math.floor(vim.o.columns * 0.3)))

  vim.api.nvim_buf_set_option(buf, "buftype", "nofile")
  vim.api.nvim_buf_set_option(buf, "bufhidden", "wipe")
  vim.api.nvim_buf_set_option(buf, "swapfile", false)
  vim.api.nvim_buf_set_option(buf, "modifiable", true)
  vim.api.nvim_buf_set_option(buf, "filetype", "retrieves-picker")

  local title = opts and opts.prompt or "Select"
  local lines = { " " .. title, string.rep("─", #title + 2) }
  for i, item in ipairs(items) do
    local label = item.display or item.label or tostring(i)
    table.insert(lines, string.format("%2d. %s", i, label))
  end
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.api.nvim_buf_set_option(buf, "modifiable", false)
  vim.api.nvim_win_set_cursor(win, { 3, 0 })

  vim.keymap.set("n", "q", function()
    if vim.api.nvim_win_is_valid(win) then
      vim.api.nvim_win_close(win, true)
    end
  end, { buffer = buf, silent = true })

  vim.keymap.set("n", "<CR>", function()
    local cursor = vim.api.nvim_win_get_cursor(win)[1]
    local index = cursor - 2
    if index >= 1 and index <= #items then
      local choice = items[index]
      if vim.api.nvim_win_is_valid(win) then
        vim.api.nvim_win_close(win, true)
      end
      on_select(choice)
    end
  end, { buffer = buf, silent = true })
end

local function open_tree_view(nodes, title, group, main_win)
  vim.cmd("vsplit")
  local win = vim.api.nvim_get_current_win()
  local buf = vim.api.nvim_create_buf(false, true)
  vim.api.nvim_win_set_buf(win, buf)
  vim.api.nvim_win_set_width(win, math.max(40, math.floor(vim.o.columns * 0.35)))

  vim.api.nvim_buf_set_option(buf, "buftype", "nofile")
  vim.api.nvim_buf_set_option(buf, "bufhidden", "wipe")
  vim.api.nvim_buf_set_option(buf, "swapfile", false)
  vim.api.nvim_buf_set_option(buf, "modifiable", true)
  vim.api.nvim_buf_set_option(buf, "filetype", "retrieves-tree")

  local line_to_node = {}

  local function render(keep_node)
    local prev_line = 3
    if vim.api.nvim_win_is_valid(win) then
      prev_line = vim.api.nvim_win_get_cursor(win)[1]
    end
    local prev_node = keep_node
    if not prev_node then
      prev_node = line_to_node[prev_line]
    end

    local lines = { " " .. title, string.rep("─", #title + 2) }
    line_to_node = {}

    local function add_node(node)
      local indent = string.rep("  ", node.depth or 0)
      local prefix = "  "
      if node.children and #node.children > 0 then
        prefix = node.expanded and "▾ " or "▸ "
      end
      table.insert(lines, indent .. prefix .. (node.label or ""))
      line_to_node[#lines] = node
      if node.expanded and node.children then
        for _, child in ipairs(node.children) do
          add_node(child)
        end
      end
    end

    for _, node in ipairs(nodes) do
      add_node(node)
    end

    vim.api.nvim_buf_set_option(buf, "modifiable", true)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    vim.api.nvim_buf_set_option(buf, "modifiable", false)

    local target_line = math.min(prev_line, #lines)
    if prev_node then
      for idx, node in pairs(line_to_node) do
        if node == prev_node then
          target_line = idx
          break
        end
      end
    end
    vim.api.nvim_win_set_cursor(win, { target_line, 0 })
  end

  render()

  local function preview_node(node, focus)
    if not node or not node.file or not node.line then
      return
    end
    if not main_win or not vim.api.nvim_win_is_valid(main_win) then
      return
    end
    local path = absolute_path_for(group, node.file)
    if not path then return end
    vim.api.nvim_win_call(main_win, function()
      vim.cmd("edit " .. vim.fn.fnameescape(path))
      local ln = tonumber(node.line) or 1
      if ln < 1 then ln = 1 end
      vim.api.nvim_win_set_cursor(0, { ln, 0 })
    end)
    if focus then
      vim.api.nvim_set_current_win(main_win)
    end
  end

  vim.api.nvim_create_autocmd("CursorMoved", {
    buffer = buf,
    callback = function()
      local cursor = vim.api.nvim_win_get_cursor(win)[1]
      local node = line_to_node[cursor]
      preview_node(node, false)
    end,
  })

  vim.keymap.set("n", "q", function()
    if vim.api.nvim_win_is_valid(win) then
      vim.api.nvim_win_close(win, true)
    end
  end, { buffer = buf, silent = true })

  vim.keymap.set("n", "<CR>", function()
    local cursor = vim.api.nvim_win_get_cursor(win)[1]
    local node = line_to_node[cursor]
    if not node then
      return
    end
    if node.children and #node.children > 0 then
      node.expanded = not node.expanded
      render()
      return
    end
    preview_node(node, true)
  end, { buffer = buf, silent = true })

  vim.keymap.set("n", "l", function()
    local cursor = vim.api.nvim_win_get_cursor(win)[1]
    local node = line_to_node[cursor]
    if not node then
      return
    end
    if node.children and #node.children > 0 then
      if not node.expanded then
        node.expanded = true
        render()
      end
      return
    end
    preview_node(node, true)
  end, { buffer = buf, silent = true })

  vim.keymap.set("n", "h", function()
    local cursor = vim.api.nvim_win_get_cursor(win)[1]
    local node = line_to_node[cursor]
    if not node then
      return
    end
    if node.children and #node.children > 0 and node.expanded then
      node.expanded = false
      render()
    end
  end, { buffer = buf, silent = true })
end

local function select_from_list(items, opts, on_select, picker)
  if not items or #items == 0 then
    vim.notify("Retrieves: no entries available", vim.log.levels.INFO)
    return
  end
  opts = opts or {}
  if picker == "telescope" or (not picker and use_telescope_picker()) then
    local pickers = require("telescope.pickers")
    local finders = require("telescope.finders")
    local conf = require("telescope.config").values
    local actions = require("telescope.actions")
    local action_state = require("telescope.actions.state")
    pickers.new({}, {
      prompt_title = opts.prompt or "Select",
      finder = finders.new_table({
        results = items,
        entry_maker = function(item)
          return {
            value = item,
            display = item.display or item.label,
            ordinal = item.ordinal or item.label,
          }
        end,
      }),
      sorter = conf.generic_sorter({}),
      attach_mappings = function(prompt_bufnr)
        actions.select_default:replace(function()
          local selection = action_state.get_selected_entry()
          actions.close(prompt_bufnr)
          if selection and selection.value then
            on_select(selection.value)
          end
        end)
        return true
      end,
    }):find()
  elseif picker == "buffer" or vim.g.retrieves_picker == "buffer" then
    buffer_select(items, opts, on_select)
  else
    vim.ui.select(items, {
      prompt = opts.prompt or "Select",
      format_item = function(item)
        return item.display or item.label
      end,
    }, function(choice)
      if choice then
        on_select(choice)
      end
    end)
  end
end

local function pick_yaml_file(cwd, on_select)
  if use_telescope_picker() then
    local ok, builtin = pcall(require, "telescope.builtin")
    if ok then
      local find_command = nil
      if vim.fn.executable("rg") == 1 then
        find_command = { "rg", "--files", "-g", "*.yml", "-g", "*.yaml" }
      end
      builtin.find_files({
        cwd = cwd,
        prompt_title = "Select YAML report",
        find_command = find_command,
        attach_mappings = function(prompt_bufnr)
          local actions = require("telescope.actions")
          local action_state = require("telescope.actions.state")
          actions.select_default:replace(function()
            local selection = action_state.get_selected_entry()
            actions.close(prompt_bufnr)
            if selection and selection.path then
              on_select(selection.path)
            end
          end)
          return true
        end,
      })
      return
    end
  end

  vim.ui.input({ prompt = "YAML path", default = cwd and (cwd .. "/") or "" }, function(input)
    if input and input ~= "" then
      on_select(input)
    end
  end)
end

function M.lualine_component()
  local buf = vim.api.nvim_get_current_buf()
  local name = vim.api.nvim_buf_get_name(buf)
  if name == "" then return "" end

  local group = detect_group(name)
  if not group then
    return ""
  end

  if inflight_by_group[group.name] then
    local state = download_progress[group.name]
    local total = (state and state.total) or 0
    local done = (state and state.done) or 0
    if total > 0 then
      done = math.min(done, total)
      local percent = math.floor((done / total) * 100)
      return string.format("Retrieves %s %d%% (%d/%d)", group.name, percent, done, total)
    end
    return string.format("Retrieves %s downloading", group.name)
  end

  local entry = cached_entry_for_group(group)
  if not entry then
    return ""
  end

  local key = group.current_file
  local reported = count_locations_for_file((entry.reported or {})[key])
  local drafts = count_locations_for_file((entry.drafts or {})[key])

  if reported + drafts == 0 then
    return ""
  end

  return string.format("Vulns R:%d P:%d", reported, drafts)
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
  if vim.g.retrieves_verify_token ~= false then
    local token = vim.g.retrieves_token or vim.env.INTEGRATES_API_TOKEN
    if token and token ~= "" then
      make_request_async(GET_ME, {}, function(data, err)
        if data and data.me and data.me.userEmail then
          vim.notify("Retrieves active. Logged in as: " .. data.me.userEmail, vim.log.levels.INFO)
        else
          vim.notify("Retrieves Error: Invalid INTEGRATES_API_TOKEN or API connection failed.", vim.log.levels.ERROR)
        end
      end)
    else
      vim.notify("Retrieves Error: INTEGRATES_API_TOKEN not found in environment.", vim.log.levels.ERROR)
    end
  end

  local reporting_dir = vim.loop.os_homedir()
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
      write_snapshot_for_group(group, res)
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

    local entry, err = ensure_group_entry(group)
    if not entry then
      vim.notify("Retrieves: " .. (err or "root data unavailable"), vim.log.levels.ERROR)
      return
    end
    local root_id = entry.roots and entry.roots[group.nickname]
    if root_id then
      submit_attack(buf, group, root_id, false)
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
      submit_attack(buf, group, rid, false)
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

  local function current_group_entry()
    local buf = vim.api.nvim_get_current_buf()
    local name = vim.api.nvim_buf_get_name(buf)
    if name == "" then
      return nil, nil, buf
    end
    local group = detect_group(name)
    if not group then
      return nil, nil, buf
    end
    local entry = cached_entry_for_group(group)
    return group, entry, buf
  end

  local function ensure_entry_or_notify(group, entry)
    if entry then
      return true
    end
    local token = vim.g.retrieves_token or vim.env.INTEGRATES_API_TOKEN
    if token and token ~= "" then
      vim.notify("Retrieves: data not loaded yet, run :RetrievesDownload", vim.log.levels.INFO)
    else
      vim.notify("Retrieves: INTEGRATES_API_TOKEN not set", vim.log.levels.ERROR)
    end
    return false
  end

  local function build_file_items(reported)
    local items = {}
    for file, vulns in pairs(reported or {}) do
      local count = count_locations_for_file(vulns)
      table.insert(items, {
        label = file,
        display = string.format("%s (%d)", file, count),
        file = file,
        vulns = vulns,
      })
    end
    table.sort(items, function(a, b) return a.label < b.label end)
    return items
  end

local function build_tree_by_file(group, reported)
  local file_cache = {}
  local function line_text(file, line)
    if not file_cache[file] then
      local path = absolute_path_for(group, file)
      if not path then
        file_cache[file] = false
      else
        local ok, data = pcall(vim.fn.readfile, path)
        file_cache[file] = ok and data or false
      end
    end
    local lines = file_cache[file]
    if not lines or not lines[line] then
      return ""
    end
    return lines[line]
  end

  local nodes = {}
  local files = {}
  for file, vulns in pairs(reported or {}) do
    table.insert(files, { file = file, vulns = vulns })
  end
  table.sort(files, function(a, b)
    if a.file == group.current_file then
      return true
    end
    if b.file == group.current_file then
      return false
    end
    return a.file < b.file
  end)
  for _, f in ipairs(files) do
    local file_node = { kind = "file", depth = 0, label = f.file, expanded = false, children = {} }
    local titles = {}
    for title, data in pairs(f.vulns or {}) do
      table.insert(titles, { title = title, data = data })
    end
    table.sort(titles, function(a, b) return a.title < b.title end)
    for _, t in ipairs(titles) do
      local count = t.data.locs and #t.data.locs or 0
      local vuln_node = {
        kind = "vuln",
        depth = 1,
        label = string.format("%s (%d)", t.title, count),
        expanded = false,
        children = {},
      }
      local locs = t.data.locs or {}
      table.sort(locs, function(a, b) return tonumber(a) < tonumber(b) end)
      for _, line in ipairs(locs) do
        local text = line_text(f.file, tonumber(line) or line) or ""
        local label = string.format("%s: %s", tostring(line), text)
        table.insert(vuln_node.children, {
          kind = "line",
          depth = 2,
          label = label,
          file = f.file,
          line = line,
        })
      end
      table.insert(file_node.children, vuln_node)
    end
    table.insert(nodes, file_node)
  end
  return nodes
end

local function build_tree_by_type(group, reported)
  local file_cache = {}
  local function line_text(file, line)
    if not file_cache[file] then
      local path = absolute_path_for(group, file)
      if not path then
        file_cache[file] = false
      else
        local ok, data = pcall(vim.fn.readfile, path)
        file_cache[file] = ok and data or false
      end
    end
    local lines = file_cache[file]
    if not lines or not lines[line] then
      return ""
    end
    return lines[line]
  end

  local grouped = {}
  for file, vulns in pairs(reported or {}) do
      for title, data in pairs(vulns or {}) do
        grouped[title] = grouped[title] or {}
        table.insert(grouped[title], { file = file, data = data })
      end
    end
  local nodes = {}
  local titles = {}
  for title, entries in pairs(grouped) do
    table.insert(titles, { title = title, entries = entries })
  end
  table.sort(titles, function(a, b) return a.title < b.title end)
  for _, t in ipairs(titles) do
    local type_node = {
      kind = "type",
      depth = 0,
      label = string.format("%s (%d files)", t.title, #t.entries),
      expanded = false,
      children = {},
    }
    table.sort(t.entries, function(a, b) return a.file < b.file end)
    for _, entry in ipairs(t.entries) do
      local count = entry.data.locs and #entry.data.locs or 0
      local file_node = {
        kind = "file",
        depth = 1,
        label = string.format("%s (%d)", entry.file, count),
        expanded = false,
        children = {},
      }
      local locs = entry.data.locs or {}
      table.sort(locs, function(a, b) return tonumber(a) < tonumber(b) end)
      for _, line in ipairs(locs) do
        local text = line_text(entry.file, tonumber(line) or line) or ""
        local label = string.format("%s: %s", tostring(line), text)
        table.insert(file_node.children, {
          kind = "line",
          depth = 2,
          label = label,
          file = entry.file,
          line = line,
        })
      end
      table.insert(type_node.children, file_node)
    end
    table.insert(nodes, type_node)
  end
  return nodes
end

  local function build_vuln_items(vulns)
    local items = {}
    for title, data in pairs(vulns or {}) do
      local count = data.locs and #data.locs or 0
      table.insert(items, {
        label = title,
        display = string.format("%s (%d)", title, count),
        vuln = data,
      })
    end
    table.sort(items, function(a, b) return a.label < b.label end)
    return items
  end

  local function build_line_items(locs)
    local items = {}
    table.sort(locs or {}, function(a, b) return tonumber(a) < tonumber(b) end)
    for _, line in ipairs(locs or {}) do
      table.insert(items, {
        label = tostring(line),
        display = "Line " .. tostring(line),
        line = line,
      })
    end
    return items
  end

  local function build_type_groups(reported)
    local grouped = {}
    for file, vulns in pairs(reported or {}) do
      for title, data in pairs(vulns) do
        grouped[title] = grouped[title] or {}
        table.insert(grouped[title], { file = file, vuln = data })
      end
    end
    local items = {}
    for title, entries in pairs(grouped) do
      table.insert(items, {
        label = title,
        display = string.format("%s (%d files)", title, #entries),
        title = title,
        entries = entries,
      })
    end
    table.sort(items, function(a, b) return a.label < b.label end)
    return items
  end

  vim.api.nvim_create_user_command("RetrievesForce", function()
    local buf = vim.api.nvim_get_current_buf()
    local name = vim.api.nvim_buf_get_name(buf)
    local group = detect_group(name)
    if not group then
      vim.notify("Retrieves: not a group file", vim.log.levels.WARN)
      return
    end
    download_group_async(group.name, function(res, err)
      if not res then return end
      write_snapshot_for_group(group, res)
      if vim.api.nvim_buf_is_valid(buf) then M.refresh() end
    end)
  end, {})

  local function findings_by_file(picker)
    local group, entry = current_group_entry()
    if not group or not ensure_entry_or_notify(group, entry) then
      return
    end
    if picker == "buffer" then
      local nodes = build_tree_by_file(group, entry.reported or {})
      local main_win = vim.api.nvim_get_current_win()
      open_tree_view(nodes, "Findings by file", group, main_win)
      return
    end
    local files = build_file_items(entry.reported or {})
    select_from_list(files, { prompt = "Findings by file" }, function(file_item)
      local vulns = build_vuln_items(file_item.vulns)
      select_from_list(vulns, { prompt = file_item.label }, function(vuln_item)
        local lines = build_line_items(vuln_item.vuln.locs or {})
        select_from_list(lines, { prompt = vuln_item.label }, function(line_item)
          open_location(group, file_item.file, line_item.line)
        end, picker)
      end, picker)
    end, picker)
  end

  vim.api.nvim_create_user_command("RetrievesFindingsByFile", function()
    findings_by_file("buffer")
  end, {})

  vim.api.nvim_create_user_command("RetrievesFindingsByFileBuffer", function()
    findings_by_file("buffer")
  end, {})

  vim.api.nvim_create_user_command("RetrievesFindingsByFileTelescope", function()
    findings_by_file("telescope")
  end, {})

  local function findings_by_type(picker)
    local group, entry = current_group_entry()
    if not group or not ensure_entry_or_notify(group, entry) then
      return
    end
    if picker == "buffer" then
      local nodes = build_tree_by_type(group, entry.reported or {})
      local main_win = vim.api.nvim_get_current_win()
      open_tree_view(nodes, "Findings by typology", group, main_win)
      return
    end
    local types = build_type_groups(entry.reported or {})
    select_from_list(types, { prompt = "Findings by typology" }, function(type_item)
      local file_items = {}
      for _, t in ipairs(type_item.entries or {}) do
        local count = t.vuln.locs and #t.vuln.locs or 0
        table.insert(file_items, {
          label = t.file,
          display = string.format("%s (%d)", t.file, count),
          file = t.file,
          vuln = t.vuln,
        })
      end
      table.sort(file_items, function(a, b) return a.label < b.label end)
      select_from_list(file_items, { prompt = type_item.label }, function(file_item)
        local lines = build_line_items(file_item.vuln.locs or {})
        select_from_list(lines, { prompt = file_item.label }, function(line_item)
          open_location(group, file_item.file, line_item.line)
        end, picker)
      end, picker)
    end, picker)
  end

  vim.api.nvim_create_user_command("RetrievesFindingsByType", function()
    findings_by_type("buffer")
  end, {})

  vim.api.nvim_create_user_command("RetrievesFindingsByTypeBuffer", function()
    findings_by_type("buffer")
  end, {})

  vim.api.nvim_create_user_command("RetrievesFindingsByTypeTelescope", function()
    findings_by_type("telescope")
  end, {})

  vim.api.nvim_create_user_command("RetrievesScope", function()
    local group, entry = current_group_entry()
    if not group or not ensure_entry_or_notify(group, entry) then
      return
    end
    local items = {}
    for _, url in ipairs(entry.scope or {}) do
      table.insert(items, { label = url, display = url, url = url })
    end
    select_from_list(items, { prompt = "Scope URLs" }, function(item)
      if type(vim.ui.open) == "function" then
        vim.ui.open(item.url)
      else
        local opener = vim.fn.has('mac') == 1 and 'open' or (vim.fn.executable('xdg-open') == 1 and 'xdg-open' or 'start')
        vim.fn.jobstart({ opener, item.url }, { detach = true })
      end
    end)
  end, {})

  vim.api.nvim_create_user_command("RetrievesYaml", function(opts)
    local buf = vim.api.nvim_get_current_buf()
    local name = vim.api.nvim_buf_get_name(buf)
    local group = detect_group(name)
    if not group then
      vim.notify("Retrieves: not a group file", vim.log.levels.WARN)
      return
    end
    local commit = get_last_commit(group.repo_path)
    if commit == "" then
      vim.notify("Retrieves: unable to get git commit", vim.log.levels.ERROR)
      return
    end
    local source = vim.g.retrieves_default_source or vim.g.retrieves_role or "analyst"
    pick_yaml_file(reporting_dir, function(path)
      reporting_dir = vim.fn.fnamemodify(path, ":h")
      local start_line = opts.line1
      local end_line = opts.line2
      for line = start_line, end_line do
        add_line_to_yaml(path, group.nickname, group.filename, commit, line, source)
      end
      vim.notify("Retrieves: YAML updated", vim.log.levels.INFO)
    end)
  end, { range = true })

  vim.api.nvim_create_user_command("RetrievesReportDirect", function(opts)
    local origin_buf = vim.api.nvim_get_current_buf()
    local name = vim.api.nvim_buf_get_name(origin_buf)
    local group = detect_group(name)
    if not group then
      vim.notify("Retrieves: not a group file", vim.log.levels.WARN)
      return
    end
    local start_line = opts.line1
    local end_line = opts.line2
    make_request_async(GET_FINDING_ID, { group = group.name }, function(data, err)
      if not data or not data.group then
        vim.notify("Retrieves: error fetching findings: " .. tostring(err), vim.log.levels.ERROR)
        return
      end
      local finding_items = {}
      for _, f in ipairs(data.group.findings or {}) do
        table.insert(finding_items, {
          label = f.title,
          display = string.format("%s (ID: %s | Hacker: %s | Status: %s)", f.title, f.id or "-", f.hacker or "-", f.status or "-"),
          finding = f,
        })
      end
      select_from_list(finding_items, { prompt = "Select a finding" }, function(selection)
        local default_source = vim.g.retrieves_default_source or "analyst"
        local max_lines = tonumber(vim.g.retrieves_max_report_lines or 100) or 100
        local sources = { "analyst", "customer", "escape" }
        local sorted_sources = { default_source }
        for _, s in ipairs(sources) do
          if s ~= default_source then
            table.insert(sorted_sources, s)
          end
        end
        vim.ui.select(sorted_sources, { prompt = "Select source" }, function(selected_source)
          if not selected_source then return end
          local commit = get_last_commit(group.repo_path)
          if commit == "" then
            vim.notify("Retrieves: unable to get git commit", vim.log.levels.ERROR)
            return
          end
          local yaml_lines = { "lines:" }
          local count = 0
          for line = start_line, end_line do
            count = count + 1
            if count > max_lines then
              vim.notify("Retrieves: selection exceeds max lines, truncating", vim.log.levels.WARN)
              break
            end
            table.insert(yaml_lines, string.format("  - commit_hash: %s", commit))
            table.insert(yaml_lines, string.format("    line: '%d'", line))
            table.insert(yaml_lines, string.format("    path: %s", group.filename))
            table.insert(yaml_lines, string.format("    repo_nickname: %s", group.nickname))
            table.insert(yaml_lines, string.format("    source: %s", selected_source))
            table.insert(yaml_lines, "    state: submitted")
            table.insert(yaml_lines, "    tool:")
            table.insert(yaml_lines, "      impact: direct")
            table.insert(yaml_lines, "      name: none")
          end
          if count == 0 then
            vim.notify("Retrieves: no lines selected", vim.log.levels.WARN)
            return
          end

          vim.cmd("new")
          local report_buf = vim.api.nvim_get_current_buf()
          vim.bo[report_buf].filetype = "yaml"
          vim.api.nvim_buf_set_lines(report_buf, 0, -1, false, yaml_lines)

          vim.ui.select({ "Upload", "Cancel" }, {
            prompt = string.format('Report to "%s"?', selection.label),
          }, function(choice)
            if choice ~= "Upload" then return end
            local final_content = table.concat(vim.api.nvim_buf_get_lines(report_buf, 0, -1, false), "\n")
            make_upload_request_async(
              UPLOAD_VULNERABILITIES,
              { findingId = selection.finding.id },
              final_content,
              "report_nvim.yaml",
              function(res, upload_err)
                if not res then
                  vim.notify("Retrieves: upload failed - " .. tostring(upload_err), vim.log.levels.ERROR)
                  return
                end
                local upload = res.uploadFile
                if upload and upload.success then
                  vim.notify("Retrieves: successfully uploaded", vim.log.levels.INFO)
                  download_group_async(group.name, function(out, derr)
                    if out then
                      write_snapshot_for_group(group, out)
                      if vim.api.nvim_buf_is_valid(origin_buf) then
                        apply(origin_buf)
                      end
                    end
                  end)
                else
                  vim.notify("Retrieves: upload failed - " .. tostring(upload and upload.message or "unknown error"), vim.log.levels.ERROR)
                end
              end
            )
          end)
        end)
      end)
    end)
  end, { range = true })
end

-- Auto-setup if sourced directly
if vim.g.retrieves_autosetup ~= false then
  pcall(M.setup)
end

return M
