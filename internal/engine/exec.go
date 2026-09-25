package engine

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/SaiPisey2/blastgate/internal/normalize"
)

// assessExec stays Unmeasured whatever the command: what a shell in a
// container does cannot be measured from outside it. SQLDetected is a
// flag on top, so a policy can single out a database client or statement
// without that flag ever reading as "measured, therefore known".
func assessExec(a normalize.Action) Impact {
	i := Unmeasured("an arbitrary command in a container cannot be measured")
	i.SQLDetected = detectSQL(a.Query["command"])
	return i
}

// assessEphemeral is assessExec for an ephemeral container: Unmeasured,
// with the SQL check run over every command and args list in the body.
func assessEphemeral(a normalize.Action, body []byte) Impact {
	i := Unmeasured("a command in an ephemeral container cannot be measured")
	i.SQLDetected = detectSQL(commandLines(a.PatchType, body))
	return i
}

// commandLines collects every "command" and "args" string list anywhere in
// a JSON or YAML body. Walking the whole body, not one path, covers every
// shape the request can take -- a strategic merge patch, a JSON patch's
// "value", a whole Pod on update, apply YAML -- and a list that is not a
// container's is only more words to check, which errs toward holding. A
// body that cannot be decoded yields nothing: the request is unmeasured
// and held either way.
func commandLines(patchType string, body []byte) []string {
	js := bytes.TrimSpace(body)
	if strings.Contains(patchType, "yaml") || (len(js) > 0 && js[0] != '{' && js[0] != '[') {
		y, err := yaml.YAMLToJSON(js)
		if err != nil {
			return nil
		}
		js = y
	}
	var v any
	if err := json.Unmarshal(js, &v); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			// command before args, and children in key order: the result
			// feeds SQLDetected, which is part of the impact digest, so the
			// same body must always give the same words in the same order.
			for _, k := range []string{"command", "args"} {
				l, _ := t[k].([]any)
				for _, s := range l {
					if s, ok := s.(string); ok {
						out = append(out, s)
					}
				}
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(v)
	return out
}

var (
	sqlClients = map[string]bool{
		"psql": true, "mysql": true, "mysqlsh": true, "mariadb": true, "sqlite3": true,
		"mongo": true, "mongosh": true, "redis-cli": true, "valkey-cli": true, "cqlsh": true,
		"clickhouse": true, "clickhouse-client": true, "sqlcmd": true, "dropdb": true,
	}
	sqlWords = regexp.MustCompile(`(?i)\b(select|insert|update|delete|drop|truncate|alter|create|grant|flushall|flushdb)\b`)
)

// shellSeparators split a shell string into words the way it matters here:
// "echo x|psql" or "$(mysql -e ...)" hide a client behind a pipe or a
// substitution that whitespace splitting alone would leave glued to it.
func shellSeparators(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\'', '"', ';', '|', '&', '(', ')', '`', '$', '<', '>', '=':
		return true
	}
	return false
}

// detectSQL looks for a database client or SQL in an exec's argv, including
// inside `sh -c "..."`. It sees argv only: SQL piped on stdin is invisible
// to it, which the README states. A word like "selected" must not match,
// hence the word boundaries; a client name appearing anywhere as a word
// ("ls mysql") does, which errs toward holding.
func detectSQL(argv []string) bool {
	for _, arg := range argv {
		for _, tok := range strings.FieldsFunc(arg, shellSeparators) {
			// A client called by path (/usr/bin/psql) is still the client.
			// Case-insensitive: a wrapper or alias named PSQL or MySQL is
			// still a database client, and a miss here is a missed hold.
			if sqlClients[strings.ToLower(tok[strings.LastIndex(tok, "/")+1:])] {
				return true
			}
		}
	}
	// A keyword alone is too common in ordinary shell ("create", "update"):
	// it counts only beside a word that makes it a statement. A client
	// other than those listed, running SQL, is caught here.
	joined := strings.ToLower(strings.Join(argv, " "))
	if !sqlWords.MatchString(joined) {
		return false
	}
	for _, w := range []string{" from ", "table", " into ", "database", "()"} {
		if strings.Contains(joined, w) {
			return true
		}
	}
	return false
}
