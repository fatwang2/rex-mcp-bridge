-- Closes a pane in the agents' session and ends the program running in it.
-- A window closes with its last pane. Arguments (rex.args):
--   block          block ID
--   agent_session  label of the agents' session
local a = rex.args
local sid = find_pane(a.block, a.agent_session, false,
  "the bridge closes only the panes in its own session")
must(rex.call("block.close", { session_id = sid, block_id = a.block }))
return { block = a.block }
