-- Presses Ctrl-C in a terminal to stop the program in the foreground, waits
-- a moment for it to stop, and returns the screen. Arguments (rex.args):
--   block          block ID
--   agent_session  label of the agents' session
--   allow_any      true to allow panes outside the agents' session
local a = rex.args
local sid = find_pane(a.block, a.agent_session, a.allow_any,
  "interrupting other panes needs interactive access")

local function write(data)
  must(rex.block.call(T, "write", { session_id = sid, block_id = a.block, data = data }))
end

local p = process(sid, a.block)
if p.last_exit then error("the program in pane " .. a.block .. " has already exited", 0) end
local before = p.foreground and p.foreground.pid
write("\3")

-- Wait for the program to exit or another process to take the foreground,
-- such as the shell that started it.
local deadline = os.time() + 2
repeat
  rex.sleep(0.2)
  p = process(sid, a.block)
until p.last_exit or (p.foreground and p.foreground.pid) ~= before or os.time() >= deadline

-- Ctrl-C also stops the shell from running the rest of a command the
-- bridge typed, so the end marker that run waits for is never printed, and
-- run would find the shell busy forever. Print it for the command, with the
-- status a shell gives a command stopped by Ctrl-C. The marker is printed
-- from two pieces, as in shell.lua.
local fg = p.foreground
if not p.last_exit and fg and shells[fg.name] then
  rex.sleep(0.3)
  local id = unfinished(screen(sid, a.block))
  if id then
    write(string.format(" printf '%%s%%s:%%s\\n' __rmb_e %s 130\r", id))
    rex.sleep(0.3)
    p = process(sid, a.block)
    fg = p.foreground
  end
end

local code = p.last_exit and p.last_exit.exit_code
return {
  block = a.block,
  exited = p.last_exit ~= nil,
  exit_code = code,
  foreground = fg and fg.name,
  output = screen(sid, a.block),
}
