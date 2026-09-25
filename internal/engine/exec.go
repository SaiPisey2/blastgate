package engine

import (
	"regexp"
	"strings"

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
