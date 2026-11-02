-- Runs a command in a new window of the agents' session and returns its
-- exit status and screen. A command that finishes in time has its window
-- closed once its screen is read, unless keep_open; a command still running
-- keeps its window. Arguments (rex.args):
--   session  label of the agents' session
--   label    window label
--   argv     command and arguments
--   cwd      working directory, or nil
--   timeout    seconds to wait for the command to exit; 0 returns at once
--   keep_open  true to keep the window after the command finishes
local a = rex.args
local sid = agent_session(a.session)
-- Rex must not close the window itself, or the screen could be gone before
-- it is read; the script closes it below.
local block = new_terminal(sid, a.label, a.argv, a.cwd, true)

-- Poll how the program exited. Waiting on terminal.child_exited could miss
-- a command that exits before the wait begins.
local code
local deadline = os.time() + (a.timeout or 0)
while true do
  local p = process(sid, block)
  if p.last_exit then
    code = p.last_exit.exit_code
    break
  end
  if os.time() >= deadline then break end
  rex.sleep(0.2)
end
local output = screen(sid, block)
local closed = false
if code ~= nil and not a.keep_open then
  must(rex.call("block.close", { session_id = sid, block_id = block }))
  closed = true
end
return { block = block, exited = code ~= nil, exit_code = code, output = output, closed = closed }
