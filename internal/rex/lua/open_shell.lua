-- Opens an interactive shell in a new window of the agents' session and
-- waits for it to reach its prompt. Arguments (rex.args):
--   session  label of the agents' session
--   label    window label
--   cwd      working directory, or nil
local a = rex.args
local sid = agent_session(a.session)
local block = new_terminal(sid, a.label, nil, a.cwd)
local deadline = os.time() + 10
while os.time() < deadline do
  local p = process(sid, block)
  if p.foreground and shells[p.foreground.name] then
    return { block = block, shell = p.foreground.name, ready = true }
  end
  rex.sleep(0.2)
end
return { block = block, ready = false }
