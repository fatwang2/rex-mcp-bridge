package oauth

import (
	"html/template"
	"net/http"
	"net/url"
	"slices"

	"github.com/fatwang2/rex-mcp-bridge/internal/config"
)

type pageHost struct {
	Name    string
	This    bool
	Checked bool
	Modes   []pageMode
}

type pageMode struct {
	Mode     config.Mode
	Selected bool
}

type approveData struct {
	Request      string
	ClientName   string
	ClientDomain string
	RedirectHost string
	RedirectURI  string
	Hosts        []pageHost
	// Identity is set when the owner is recognized and needs no code.
	Identity *Identity
	Error    string
}

// renderApprove shows the approval page. form, when set, holds the choices
// from a submission that failed, so the page keeps them.
func (s *Server) renderApprove(w http.ResponseWriter, r *http.Request, id string, p *pendingAuth, form url.Values, errMsg string) {
	d := approveData{
		Request:      id,
		ClientName:   p.client.Name,
		ClientDomain: p.client.Domain,
		RedirectURI:  p.redirectURI,
		Identity:     s.identify(r),
		Error:        errMsg,
	}
	if u, err := url.Parse(p.redirectURI); err == nil {
		d.RedirectHost = u.Host
	}
	for _, c := range s.Candidates(r.Context()) {
		h := pageHost{Name: c.Name, This: c.This, Checked: slices.Contains(form["host"], c.Name)}
		chosen := config.Mode(form.Get("mode." + c.Name))
		if chosen == "" {
			chosen = config.ModeRead
		}
		for _, m := range config.Modes(c.Max) {
			h.Modes = append(h.Modes, pageMode{Mode: m, Selected: m == chosen})
		}
		d.Hosts = append(d.Hosts, h)
	}
	render(w, http.StatusOK, "approve", d)
}

func (s *Server) renderError(w http.ResponseWriter, status int, msg string) {
	render(w, status, "error", msg)
}

func render(w http.ResponseWriter, status int, name string, data any) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	// Not no-referrer: with it, Chrome sends "Origin: null" when the form
	// is submitted, which sameBrowser would refuse.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.WriteHeader(status)
	pages.ExecuteTemplate(w, name, data)
}

var pages = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rex MCP Bridge</title>
<style>
:root { color-scheme: light dark; --fg: #1d1d1f; --muted: #6e6e73; --bg: #f5f5f7; --card: #fff; --line: #d2d2d7; --warn: #b42318; --accent: #0a66d8; }
@media (prefers-color-scheme: dark) { :root { --fg: #f5f5f7; --muted: #a1a1a6; --bg: #111; --card: #1c1c1e; --line: #3a3a3c; --warn: #ff8a80; --accent: #4c9aff; } }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 -apple-system, system-ui, sans-serif; color: var(--fg); background: var(--bg); }
main { max-width: 520px; margin: 40px auto; padding: 0 16px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 24px; }
h1 { font-size: 20px; margin: 0 0 16px; }
.dest { font-size: 17px; font-weight: 600; word-break: break-all; }
.warn { color: var(--warn); }
.ok { padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px; }
.muted { color: var(--muted); font-size: 13px; }
fieldset { border: 0; padding: 0; margin: 16px 0; }
.host { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--line); }
select { font: inherit; padding: 4px 8px; border: 1px solid var(--line); border-radius: 6px; background: transparent; color: var(--fg); }
input[type=text] { width: 100%; font: 18px ui-monospace, monospace; letter-spacing: 2px; padding: 10px; border: 1px solid var(--line); border-radius: 8px; background: transparent; color: var(--fg); text-transform: uppercase; }
.buttons { display: flex; flex-direction: row-reverse; gap: 12px; margin-top: 20px; }
button { flex: 1; font: inherit; padding: 10px; border-radius: 8px; border: 1px solid var(--line); background: transparent; color: var(--fg); cursor: pointer; }
button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
code { font: 13px ui-monospace, monospace; }
</style></head><body><main><div class="card">{{end}}

{{define "foot"}}</div></main></body></html>{{end}}

{{/* Approve comes first so Enter in the code field approves. */}}
{{define "approve"}}{{template "head"}}
<h1>Allow {{.ClientName}} to use your terminals?</h1>
{{if .ClientDomain}}<p class="muted">Client verified by its metadata at <b>{{.ClientDomain}}</b></p>{{else}}<p class="muted">The client chose this name itself; it is not verified.</p>{{end}}
<p>Approving sends access to</p>
<p class="dest">{{.RedirectHost}}</p>
<p class="muted">{{.RedirectURI}}</p>
<p class="warn">Anyone who runs that service gets this access. Only approve a sign-in you started just now.</p>
<form method="post">
<input type="hidden" name="request" value="{{.Request}}">
<fieldset><legend>Machines it may use</legend>
{{range .Hosts}}<div class="host"><label><input type="checkbox" name="host" value="{{.Name}}"{{if .Checked}} checked{{end}}> <code>{{.Name}}</code>{{if .This}} <span class="muted">this machine</span>{{end}}</label>
<select name="mode.{{.Name}}" aria-label="Access on {{.Name}}">{{range .Modes}}<option value="{{.Mode}}"{{if .Selected}} selected{{end}}>{{.Mode}}</option>{{end}}</select></div>
{{else}}<p class="warn">No machines are available. Add one with: rex-mcp-bridge hosts set NAME MODE</p>{{end}}
<p class="muted"><b>read</b>: list terminals and read their output. <b>run</b>: also open shells and run commands in its own windows. <b>interactive</b>: also run commands in any terminal, including yours.</p>
</fieldset>
{{if .Identity}}<p class="ok">You are <b>{{.Identity.Login}}</b> on <b>{{.Identity.Device}}</b>, recognized through Tailscale, so no pairing code is needed.</p>
{{else}}<label for="code">Pairing code</label>
<p class="muted">Run <code>rex-mcp-bridge pair</code> on the host to get one. Open this page from one of your Tailscale devices to approve without a code.</p>
<input id="code" type="text" name="code" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="ABCD-EFGH">{{end}}
{{if .Error}}<p class="warn">{{.Error}}</p>{{end}}
<div class="buttons">
<button type="submit" name="action" value="approve" class="primary">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</div>
</form>
{{template "foot"}}{{end}}

{{define "error"}}{{template "head"}}
<h1>Sign-in stopped</h1>
<p>{{.}}</p>
{{template "foot"}}{{end}}
`))
