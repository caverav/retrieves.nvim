-- Retrieves.nvim
-- Highlights lines reported by the VS Code "retrieves" extension snapshot.

local M = {}

local ns = vim.api.nvim_create_namespace("retrieves")
local reported_hl = "RetrievesReported"
local pending_hl  = "RetrievesPending"
local endpoint = "https://app.fluidattacks.com/api"

-- In-memory cache keyed by group name
local cache_by_group = {}
local inflight_by_group = {}

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

local function define_default_hls()
  -- Light tints. Users can override in their config.
  vim.api.nvim_set_hl(0, reported_hl, { default = true, bg = "#FFCDD2" }) -- light red
  vim.api.nvim_set_hl(0, pending_hl,  { default = true, bg = "#FFF9C4" }) -- light yellow
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
  }
end

local function clean_location(where)
  if type(where) ~= "string" then return where end
  -- Remove trailing bracketed metadata like " (commit)" or " [..]"
  where = where:gsub("%s*[%(%[].*[%]%)]", "")
  return where
end

local function use_vim_system()
  return type(vim.system) == "function"
end

local function curl_post_json(url, headers, body_tbl)
  local payload = vim.json.encode(body_tbl)
  local cmd = { "curl", "-sS", "-X", "POST", url, "-H", "content-type: application/json" }
  for _, h in ipairs(headers or {}) do
    table.insert(cmd, "-H")
    table.insert(cmd, h)
  end
  table.insert(cmd, "--data-binary")
  table.insert(cmd, payload)

  if use_vim_system() then
    local obj = vim.system(cmd, { text = true }):wait()
    return obj and obj.code == 0, obj and obj.stdout or obj.stderr
  else
    local out = vim.fn.system(cmd)
    local ok = (vim.v.shell_error == 0)
    return ok, out
  end
end

local function make_request(query, variables)
  local token = vim.g.retrieves_token or vim.env.INTEGRATES_API_TOKEN
  if not token or token == "" then
    return nil, "INTEGRATES_API_TOKEN not set"
  end
  local ok, out = curl_post_json(endpoint, { "authorization: Bearer " .. token }, {
    query = query,
    variables = variables,
  })
  if not ok then
    return nil, out or "request failed"
  end
  local ok2, json = pcall(vim.json.decode, out)
  if not ok2 then
    return nil, "invalid json response"
  end
  if json.errors then
    return nil, vim.inspect(json.errors)
  end
  return json.data, nil
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

local function download_group_async(group_name, on_done)
  if inflight_by_group[group_name] then return end
  inflight_by_group[group_name] = true
  vim.notify("Retrieves: downloading locations for " .. group_name .. "...", vim.log.levels.INFO)

  make_request_async(GET_FINDING_ID, { group = group_name }, function(root_data, err)
    if not root_data then
      inflight_by_group[group_name] = nil
      vim.notify("Retrieves: failed to list findings: " .. tostring(err), vim.log.levels.ERROR)
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
      local i = 1

      local function process_next_finding()
        if i > #findings then
          local out = { reported = reported, drafts = pending, roots = roots, org = organization }
          cache_by_group[group_name] = out
          inflight_by_group[group_name] = nil
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
      if on_done then on_done(nil, "group not found") end
    end
  end)
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

local function clear(buf)
  if vim.api.nvim_buf_is_valid(buf) then
    vim.api.nvim_buf_clear_namespace(buf, ns, 0, -1)
  end
end

local function hl_lines(buf, lines, hl_group)
  if not lines or type(lines) ~= "table" then return end
  local linecount = vim.api.nvim_buf_line_count(buf)
  for _, l in ipairs(lines) do
    local ln = tonumber(l) or 0
    if ln <= 0 then ln = 1 end
    if ln <= linecount then
      pcall(vim.api.nvim_buf_add_highlight, buf, ns, hl_group, ln - 1, 0, -1)
    end
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

  local snapshot_path = vim.g.retrieves_json_override
    or (group.repo_path .. "/retrieves-vulns-" .. group.name .. ".json")

  local snapshot, err = load_snapshot(snapshot_path)
  if not snapshot and cache_by_group[group.name] then
    snapshot = { reported = cache_by_group[group.name].reported, drafts = cache_by_group[group.name].drafts }
  end
  if not snapshot then
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
  local reported = (snapshot.reported or {})[key]
  local drafts   = (snapshot.drafts   or {})[key]

  clear(buf)

  -- reported: red, drafts: yellow
  if reported then
    for _, entry in pairs(reported) do
      hl_lines(buf, entry.locs, reported_hl)
    end
  end
  if drafts then
    for _, entry in pairs(drafts) do
      hl_lines(buf, entry.locs, pending_hl)
    end
  end
end

function M.refresh()
  define_default_hls()
  apply(vim.api.nvim_get_current_buf())
end

function M.setup()
  define_default_hls()
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
      local snapshot_path = (group.repo_path .. "/retrieves-vulns-" .. group.name .. ".json")
      pcall(function()
        local fd = assert(io.open(snapshot_path, "w"))
        fd:write(vim.json.encode({
          reported = res.reported, drafts = res.drafts, org = res.org, roots = res.roots,
          group = group.name, exportedAt = os.date("!%Y-%m-%dT%H:%M:%SZ")
        }))
        fd:close()
      end)
      -- Apply to current buffer
      if vim.api.nvim_buf_is_valid(buf) then apply(buf) end
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
end

-- Auto-setup if sourced directly
if vim.g.retrieves_autosetup ~= false then
  pcall(M.setup)
end

return M
