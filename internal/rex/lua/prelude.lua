-- Shared by every script; the bridge puts it in front of each one.
local T = "com.superlogical.terminal"

local function must(r, err)
  if r == nil then error(err, 0) end
  return r
end

-- agent_session returns the ID of the session labeled label, creating it
-- when missing, and attaches the script to it so session calls act on it.
local function agent_session(label)
  local sid
  for _, s in ipairs(must(rex.call("session.list")).sessions or {}) do
    if s.label == label then sid = s.session_id end
  end
  if sid == nil then
    sid = must(rex.call("session.create", { label = label })).session_id
  end
  must(rex.session.attach{ session_id = sid })
  return sid
end

-- new_terminal opens a window running argv, or an interactive shell when
-- argv is nil, and returns the block ID.
local function new_terminal(sid, label, argv, cwd)
  local w = must(rex.session.new_window{
    session_id   = sid,
    focus        = false,
    window_label = label,
    layout       = rex.layout.block{
      flavor  = "com.superlogical.terminal.shell",
      options = { command = argv, cwd = cwd, exit = { on_completion = false } },
    },
  })
  return w.block_ids[1]
end

local function process(sid, block)
  return must(rex.block.call(T, "process", { session_id = sid, block_id = block }))
end

local function screen(sid, block)
  return must(rex.block.call(T, "format",
    { session_id = sid, block_id = block, format = "text", trim = true, unwrap = true })).content
end

local shells = { sh = true, bash = true, zsh = true, dash = true, ksh = true, mksh = true, fish = true }

-- each_block calls fn(session, window, block) for every block in every
-- session, attaching to each session to read its layout. fn returns true to
-- stop. The script is left attached to the session where it stopped.
local function each_block(fn)
  for _, s in ipairs(must(rex.call("session.list")).sessions or {}) do
    if rex.session.attach{ session_id = s.session_id } then
      local v = rex.session.view{ session_id = s.session_id }
      for _, w in ipairs(v and v.windows or {}) do
        for _, l in ipairs(w.layers or {}) do
          for _, b in ipairs(l.blocks or {}) do
            if fn(s, w, b) then return end
          end
        end
      end
    end
  end
end
