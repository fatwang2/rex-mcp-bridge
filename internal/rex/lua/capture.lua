-- Returns a terminal's screen and scrollback. Arguments (rex.args):
--   block  block ID
local a = rex.args
local sid
each_block(function(s, _, b)
  if b.block_id == a.block then
    sid = s.session_id
    return true
  end
end)
if sid == nil then error("no pane " .. a.block .. " on this host; call list_panes", 0) end
return { text = screen(sid, a.block) }
