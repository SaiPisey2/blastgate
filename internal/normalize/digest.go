package normalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"sigs.k8s.io/yaml"
)

// RequestDigest identifies what a request would do: target (including the
// full path, so a different proxy sub-path is never mistaken for the same
// request), verb, the semantic query (plus the full query for a proxy
// subresource, whose backend the query itself can select) and the body --
// not who sent it, and not the body's formatting. An approval is bound to
// it, so an agent's identical retry must produce the same digest even when
// kubectl re-serialises the body with keys in a different order, and a
// request that changes anything that matters must not.
func RequestDigest(a Action, body []byte) string {
	id := struct {
		Verb, Group, Version, Resource, Subresource, Namespace, Name, Path, RawQuery, PatchType string
		Query                                                                                   map[string][]string
		Body                                                                                    json.RawMessage
		RawBody                                                                                 string `json:",omitempty"`
		// omitempty keeps every non-upgrade digest what it was before
		// this field existed.
		Upgrade bool `json:",omitempty"`
	}{a.Verb, a.Group, a.Version, a.Resource, a.Subresource, a.Namespace, a.Name, a.Path, a.RawQuery, a.PatchType, a.Query, nil, "", a.Upgrade}
	if canon, ok := canonicalBody(a.PatchType, body); ok {
		id.Body = canon
	} else if len(body) > 0 {
		// Not JSON or YAML we can read: digest the bytes as they are.
		sum := sha256.Sum256(body)
		id.RawBody = hex.EncodeToString(sum[:])
	}
	b, _ := json.Marshal(id)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// canonicalBody re-encodes a JSON or YAML body through a generic value, so
// map keys come out sorted and whitespace is gone. encoding/json sorts map
// keys when marshalling a map[string]any.
func canonicalBody(patchType string, body []byte) (json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false
	}
	js := trimmed
	if strings.Contains(patchType, "yaml") || (trimmed[0] != '{' && trimmed[0] != '[') {
		y, err := yaml.YAMLToJSON(trimmed)
		if err != nil {
			return nil, false
		}
		js = y
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(js))
	dec.UseNumber() // 1 and 1.0 must not collapse; numbers keep their text
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	return out, true
}
