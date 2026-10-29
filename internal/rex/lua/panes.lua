-- Lists every terminal block in every session, with where it sits.
local panes = {}
each_block(function(s, w, b)
  table.insert(panes, {
    session_id    = s.session_id,
    session_label = s.label,
    window_id     = w.window_id,
    window_label  = w.label,
    block_id      = b.block_id,
    block_label   = b.label,
    flavor        = b.flavor,
    focused       = b.block_id == w.focused_block_id,
  })
end)
return { panes = panes }
