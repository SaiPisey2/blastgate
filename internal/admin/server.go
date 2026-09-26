package admin

// This file is the admin listener's whole handler: the /api surface and
// the built UI behind one set of response headers.

import (
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// ContentSecurityPolicy lets the UI load only its own bundle. No inline
// script or style is allowed: an object name or command line that
// somehow reached the page as markup still could not run.
// frame-ancestors keeps the approve button out of another site's frame.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// NewServer is the admin listener's handler: /api/* is the JSON API and
// the live stream; everything else is the UI from uiFS.
//
// The headers are set on the ResponseWriter before any handler runs, so
// every response carries them -- Require's 401 and 403, a 404, a static
// file -- without wrapping the writer. A wrapper would hide the
// connection's Flush and SetWriteDeadline from /api/stream (unless it
// unwrapped), and the stream would then buffer events or lose its
// defence against a client that stops reading.
func NewServer(a *Auth, d Deps, uiFS fs.FS) http.Handler {
	mux := http.NewServeMux()
	Routes(mux, a, d)
	mux.Handle("/", static(uiFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		// On every /api answer whatever its status, not only the ones
		// reply writes: a cached 401 or error page is as stale as a
		// cached queue. /api itself redirects to /api/.
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		// No Access-Control-* header is ever set: the UI is same-origin,
		// and another origin's script must not read a response.
		mux.ServeHTTP(w, r)
	})
}

// static serves the built UI. A path naming a file serves it; a path with
// no dot in its last segment is a client-side route (/approvals/<id>) and
// gets index.html so a reload or a pasted link lands in the app; any
// other miss is a 404, so a stale bundle name does not come back as HTML
// the browser then refuses as a script. Directories are never listed.
func static(uiFS fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if serveFile(w, r, uiFS, name) {
			return
		}
		if strings.Contains(path.Base(name), ".") {
			http.NotFound(w, r)
			return
		}
		if !serveFile(w, r, uiFS, "index.html") {
			http.NotFound(w, r)
		}
	})
}

// serveFile serves name from fsys if it is a regular file, and reports
// whether it did. ServeContent picks the type from the extension and
// answers Range and HEAD itself.
func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) bool {
	if !fs.ValidPath(name) {
		return false
	}
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		// embed.FS files seek; a filesystem whose files do not is a
		// wiring mistake, reported rather than served half-way.
		http.Error(w, "ui file does not seek", http.StatusInternalServerError)
		return true
	}
	if name == "index.html" {
		// index.html names the hashed bundle; a cached copy after an
		// upgrade would point at files this binary no longer has.
		w.Header().Set("Cache-Control", "no-cache")
	}
	// The modification time is left zero: embedded files have none, and a
	// fake one would make Last-Modified lie.
	http.ServeContent(w, r, name, time.Time{}, rs)
	return true
}
