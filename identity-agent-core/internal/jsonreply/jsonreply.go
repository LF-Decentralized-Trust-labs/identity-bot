// Package jsonreply is the one place an HTTP handler in this module writes a
// JSON answer. The server, login and asset packages all call it, so the
// Content-Type, the encoding and the trailing newline cannot drift apart.
package jsonreply

import (
	"encoding/json"
	"net/http"
)

// Write sends v as JSON with the given status.
//
// The body is exactly what json.Encoder produces with its defaults: HTML
// characters (<, >, &) are escaped as <, >, &, and the value is
// followed by one newline. Clients and signed-body checks have seen these bytes
// since the first handler, so they must not change.
func Write(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
