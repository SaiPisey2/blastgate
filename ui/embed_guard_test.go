package ui

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The server sends style-src 'self' with no nonce and no font-src
// exception. A bundle that injects a <style> element, writes inline style
// strings, or inlines a font as data: still builds and still passes every
// jsdom test, then fails silently in a real browser: the animation jumps,
// the font falls back. These tests read what actually ships.

// distForbidden are strings that only appear in a bundle doing something
// the CSP blocks. Motion's own bundle is checked too: it is not trusted
// to stay clean across upgrades.
var distForbidden = []string{
	`.cssText=`,
	`.cssText =`,
	`setAttribute("style"`,
	`setAttribute('style'`,
	// The minifier rewrites string literals to template literals, so the
	// built form of setAttribute("style", ...) uses backticks.
	"setAttribute(`style`",
	`data:font`,
	`data:application/font`,
	`data:application/x-font`,
}

// sourceForbidden are checked in our own sources instead of dist/,
// because the bundle keeps two of them even when nothing calls them.
// Measured with Vite 8 and Motion 13.4.4: once AnimatePresence is used,
// Motion's PopChild (reached only by mode="popLayout") ships both
// createElement(`style`) and the string "popLayout"; and React DOM's
// <style precedence> support ships createElement(`style`) in every build,
// including the one before Motion was added. Searching dist/ for them
// would fail on code our views can never reach; searching src/ fails the
// moment one of our files asks for it. motion.ts also rejects
// mode="popLayout" and nonce at compile time.
var sourceForbidden = []string{
	`popLayout`,
	`AnimateView`,
	`nonce=`,
	`.cssText`,
	`createElement('style')`,
	`createElement("style")`,
	"createElement(`style`)",
	`setAttribute('style'`,
	`setAttribute("style"`,
	`dangerouslySetInnerHTML`,
	`innerHTML`,
}

func TestBuiltUIHasNothingTheCSPBlocks(t *testing.T) {
	root := FS()
	var hits []string
	cssText := map[string]string{}
	err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := path.Ext(p)
		if ext != ".js" && ext != ".css" && ext != ".html" {
			return nil
		}
		b, err := fs.ReadFile(root, p)
		if err != nil {
			return err
		}
		s := string(b)
		for _, bad := range distForbidden {
			if strings.Contains(s, bad) {
				hits = append(hits, p+": "+bad)
			}
		}
		if ext == ".html" && strings.Contains(s, `style="`) {
			hits = append(hits, p+`: style="`)
		}
		if ext == ".css" {
			cssText[p] = s
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		t.Errorf("CSP would block: %s", h)
	}

	// A url() to a font that is not embedded is a 404 the page never
	// reports; the text just renders in a fallback face.
	fontURL := regexp.MustCompile(`url\(\s*['"]?([^'")]+\.woff2)['"]?\s*\)`)
	fonts := 0
	for p, s := range cssText {
		for _, m := range fontURL.FindAllStringSubmatch(s, -1) {
			fonts++
			ref := m[1]
			var target string
			if strings.HasPrefix(ref, "/") {
				target = strings.TrimPrefix(ref, "/")
			} else {
				target = path.Join(path.Dir(p), ref)
			}
			if _, err := fs.Stat(root, target); err != nil {
				t.Errorf("%s references %s, which is not embedded: %v", p, ref, err)
			}
		}
	}
	// Five faces: Plex Sans 400/500/600 and Plex Mono 400/500. Fewer means
	// a face was inlined or dropped; the check above would then pass on
	// nothing.
	if fonts < 5 {
		t.Errorf("found %d woff2 references in the built CSS, want at least 5", fonts)
	}
}

// The fonts ship as files, so the OFL licence ships beside them as a file
// (vite.config.ts emits assets/OFL.txt); pinned here so a config change
// cannot drop it unnoticed.
func TestBuiltUIShipsTheFontLicence(t *testing.T) {
	b, err := fs.ReadFile(FS(), "assets/OFL.txt")
	if err != nil {
		t.Fatalf("font licence not embedded: %v", err)
	}
	if !strings.Contains(string(b), "SIL Open Font License") {
		t.Fatalf("assets/OFL.txt is not the OFL:\n%.200s", b)
	}
}

func TestSourcesAskForNothingTheCSPBlocks(t *testing.T) {
	err := filepath.WalkDir("src", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := filepath.Ext(p)
		if ext != ".ts" && ext != ".tsx" {
			return nil
		}
		// Tests may name a forbidden string to assert it never renders.
		if strings.HasSuffix(p, ".test.ts") || strings.HasSuffix(p, ".test.tsx") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			// Comment lines may name a banned API to explain the ban
			// (motion.ts does); only code is checked.
			if l := strings.TrimSpace(line); strings.HasPrefix(l, "//") || strings.HasPrefix(l, "/*") || strings.HasPrefix(l, "*") {
				continue
			}
			for _, bad := range sourceForbidden {
				if strings.Contains(line, bad) {
					t.Errorf("%s:%d: %s", p, i+1, bad)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
