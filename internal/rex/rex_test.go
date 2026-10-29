package rex

import (
	"encoding/json"
	"testing"
)

func TestListAcceptsEmptyObject(t *testing.T) {
	// Lua encodes an empty table as {}.
	for _, in := range []string{`{"panes":{}}`, `{"panes":[]}`, `{"panes":[{"block_id":"block:1"}]}`} {
		var out struct {
			Panes list[Pane] `json:"panes"`
		}
		if err := json.Unmarshal([]byte(in), &out); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
}
