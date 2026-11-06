// Package jsonreply writes a JSON answer the one way the server, login and asset
// packages' shared helpers do, so their Content-Type, encoding and trailing
// newline cannot drift apart. Many handlers still encode their answers inline;
// they are to move here.
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
	// A plain 200 is left to the first write, as the helpers this replaced did,
	// so a handler that set its own status first is not overwritten or warned about.
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(v)
}
