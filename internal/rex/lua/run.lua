-- Runs a command in a new window of the agents' session and returns its
-- exit status and screen. Arguments (rex.args):
--   session  label of the agents' session
--   label    window label
--   argv     command and arguments
--   cwd      working directory, or nil
--   timeout  seconds to wait for the command to exit; 0 returns at once
local a = rex.args
local sid = agent_session(a.session)
local block = new_terminal(sid, a.label, a.argv, a.cwd)

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
return { block = block, exited = code ~= nil, exit_code = code, output = screen(sid, block) }
