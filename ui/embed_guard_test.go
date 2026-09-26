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
	`.cssText+=`,
	`["cssText"]`,
	`['cssText']`,
	"[`cssText`]",
	`setAttribute("style"`,
	`setAttribute('style'`,
	// The minifier rewrites string literals to template literals, so the
	// built form of setAttribute("style", ...) uses backticks.
	"setAttribute(`style`",
	`data:font`,
	`data:application/font`,
	`data:application/x-font`,
}

// distCSSTextRe and distHTMLStyleRe catch spacing and operator variants a literal list
// misses: cssText += s, and an inline style attribute in the HTML with
// either quote.
var (
	distCSSTextRe   = regexp.MustCompile(`cssText\s*\+?=`)
	distHTMLStyleRe = regexp.MustCompile(`\bstyle\s*=\s*['"]`)
)

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
	`startViewTransition`,
	`ViewTransition`,
	`.cssText`,
	`createElement('style')`,
	`createElement("style")`,
	"createElement(`style`)",
	// React 19 hoists a JSX <style> into a real style element.
	`<style`,
	`setAttribute('style'`,
	`setAttribute("style"`,
	"setAttribute(`style`",
	`dangerouslySetInnerHTML`,
	`innerHTML`,
	`outerHTML`,
	`insertAdjacentHTML`,
	`document.write`,
	`createContextualFragment`,
	`DOMParser`,
}

// motion.ts is the only file allowed to reach Motion directly or to name
// nonce (it does so to remove the prop from MotionConfig's type). A view
// importing motion/react would bypass the allow-list, and a nonce passed
// through a JSX spread would bypass the narrowed type.
var (
	motionImportRe = regexp.MustCompile(`from\s*['"]motion|import\(\s*['"]motion|framer-motion`)
	nonceRe        = regexp.MustCompile(`\bnonce\b`)
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

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
		if ext != ".css" {
			for _, m := range distCSSTextRe.FindAllString(s, -1) {
				hits = append(hits, p+": "+m)
			}
		}
		if ext == ".html" {
			for _, m := range distHTMLStyleRe.FindAllString(s, -1) {
				hits = append(hits, p+": "+m)
			}
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

// The demo fixtures (src/demo/fixtures.ts) stand in for the whole admin
// API, sign-in included, and are loaded only on the dev server. Shipped,
// they would answer /api/* from inside the page with made-up approvals. A
// build drops them because import.meta.env.DEV is false there; this test
// fails if their marker, or a file named for them, ever reaches dist/.
const demoMarker = "blastgate-demo-fixture"

// demoQuery are the minified forms of reading the ?demo parameter.
var demoQuery = []string{`get("demo")`, `get('demo')`, "get(`demo`)", `has("demo")`, `has('demo')`, "has(`demo`)"}

func TestBuiltUIHasNoDemoFixtures(t *testing.T) {
	src, err := os.ReadFile("src/demo/fixtures.ts")
	if err != nil {
		t.Fatalf("read the fixtures: %v", err)
	}
	// Pinned both ways: renaming the marker in the fixtures without here
	// would leave this test searching for a string nothing contains.
	if !strings.Contains(string(src), `"`+demoMarker+`"`) && !strings.Contains(string(src), `'`+demoMarker+`'`) {
		t.Fatalf("src/demo/fixtures.ts no longer defines the marker %q", demoMarker)
	}
	err = fs.WalkDir(FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(path.Base(p)), "demo") {
			t.Errorf("dist has a demo file: %s", p)
		}
		if d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(FS(), p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), demoMarker) {
			t.Errorf("%s: demo fixtures shipped in the build", p)
		}
		// The ?demo switch itself: a build that still reads it has kept
		// the DEV-only branch, even if the fixtures chunk was dropped.
		for _, q := range demoQuery {
			if strings.Contains(string(b), q) {
				t.Errorf("%s: the ?demo switch shipped in the build (%s)", p, q)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
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
		switch filepath.Ext(p) {
		case ".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs":
		default:
			return nil
		}
		// Tests may name a forbidden string to assert it never renders;
		// they are still held to the Motion allow-list below.
		isTest := strings.Contains(filepath.Base(p), ".test.")
		isMotion := filepath.ToSlash(p) == "src/motion.ts"
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		// Comments may name a banned API to explain the ban (motion.ts
		// does). Block comments are blanked, keeping their newlines so
		// line numbers hold, and whole // lines are skipped; code before
		// or after a comment on the same line is still checked, so
		// "/* x */ el.innerHTML = s" fails.
		src := blockCommentRe.ReplaceAllStringFunc(string(b), func(c string) string {
			return strings.Repeat("\n", strings.Count(c, "\n"))
		})
		for i, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if !isTest {
				for _, bad := range sourceForbidden {
					if strings.Contains(line, bad) {
						t.Errorf("%s:%d: %s", p, i+1, bad)
					}
				}
			}
			if !isMotion {
				if m := motionImportRe.FindString(line); m != "" {
					t.Errorf("%s:%d: %s (import Motion from ./motion only)", p, i+1, m)
				}
				if nonceRe.MatchString(line) {
					t.Errorf("%s:%d: nonce (the CSP has none; only motion.ts may name it)", p, i+1)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
