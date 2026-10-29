-- Types a command into a shell that is waiting at its prompt, waits for it
-- to finish, and returns its output and exit status. The shell keeps its
-- state, such as the working directory and variables, between commands.
--
-- The command is wrapped in two markers the shell prints, so its output can
-- be cut from the screen and its exit status read. Each marker is printed
-- from separate pieces, so the command line the shell echoes never contains
-- it whole. Arguments (rex.args):
--   block          block ID of the shell
--   command        command line to run
--   id             unique marker ID
--   timeout        seconds to wait; 0 returns once the command is typed
--   agent_session  label of the agents' session
--   allow_any      true to allow shells outside the agents' session
local a = rex.args

-- Find the block and the session it is in.
local sid, in_agents
each_block(function(s, _, b)
  if b.block_id == a.block then
    sid, in_agents = s.session_id, s.label == a.agent_session
    return true
  end
end)
if sid == nil then error("no pane " .. a.block .. " on this host; call list_panes", 0) end
if not in_agents and not a.allow_any then
  error("pane " .. a.block .. " is not in the \"" .. a.agent_session ..
    "\" session; typing into other panes needs interactive access", 0)
end

local p = process(sid, a.block)
if p.last_exit then error("the program in pane " .. a.block .. " has exited", 0) end
local fg = p.foreground
if fg == nil or not shells[fg.name] then
  error("pane " .. a.block .. " is busy running " .. (fg and fg.name or "something") ..
    "; wait for it, or use capture to see what it is doing", 0)
end
local shell_pid = fg.pid

-- A builtin such as read keeps the shell in the foreground, so also check
-- that the last command this bridge typed has printed its end marker.
local before = screen(sid, a.block)
local last
for id in before:gmatch("__rmb_s(%x+)") do last = id end
if last and not before:find("__rmb_e" .. last .. ":", 1, true) then
  error("pane " .. a.block .. " is busy: the last command run there has not finished; " ..
    "use capture to see what it is doing", 0)
end

local s1, s2 = "__rmb_s", "__rmb_e"
local start_mark = s1 .. a.id
local end_mark = s2 .. a.id .. ":"
-- The command goes inside a group that ends on its own line, so the shell
-- reads the whole input before running any of it: the end marker is never
-- left waiting as input for the command, and a trailing comment cannot hide
-- it. A leading space keeps the line out of history in shells set up for it.
local open, close, status = "{", "}", "\"$?\""
if fg.name == "fish" then open, close, status = "begin;", "end", "$status" end
local line = string.format(" printf '%%s%%s\\n' %s %s; %s %s\n%s; printf '%%s%%s:%%s\\n' %s %s %s\n",
  s1, a.id, open, a.command, close, s2, a.id, status)
must(rex.block.call(T, "write", { session_id = sid, block_id = a.block, data = line:gsub("\n", "\r") }))

-- Wait for the shell to come back to the foreground, then look for the end
-- marker on the screen.
local deadline = os.time() + (a.timeout or 0)
local text, code
rex.sleep(0.1)
while true do
  local q = process(sid, a.block)
  if q.foreground and q.foreground.pid == shell_pid then
    text = screen(sid, a.block)
    local i = text:find(end_mark, 1, true)
    if i then
      code = tonumber(text:match("^(%d+)", i + #end_mark))
      break
    end
  end
  if os.time() >= deadline then break end
  rex.sleep(0.2)
end
text = text or screen(sid, a.block)

-- Cut the output between the last start marker and the end marker.
local from = 1
local s = 1
while true do
  local i = text:find(start_mark .. "\n", s, true)
  if not i then break end
  from, s = i + #start_mark + 1, i + 1
end
local to = text:find(end_mark, from, true)
local output = text:sub(from, to and to - 1 or #text)
return { block = a.block, exited = code ~= nil, exit_code = code, output = output }
