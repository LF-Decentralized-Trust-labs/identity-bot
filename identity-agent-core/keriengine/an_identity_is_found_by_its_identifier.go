package keriengine

import "fmt"

// What a caller that extends a log it knows only by identifier needs.
//
// An identity is held under the name it was made with, and an identity
// reloaded after a restart is held under its identifier, so a caller that
// kept only the identifier cannot say which. It asks here, and then prepares
// and commits under the name it is given.

// heldByAID is the one identity held with this identifier, whatever name it
// is held under, or nil where none is. An identifier held under two names is
// an error: the two copies would be extended apart.
func (e *Engine) heldByAID(aid string) (*identity, error) {
	e.state.mu.RLock()
	defer e.state.mu.RUnlock()
	var found *identity
	for _, id := range e.state.identities {
		if id.AID != aid {
			continue
		}
		if found != nil && found != id {
			return nil, fmt.Errorf("%s is held twice, under %q and %q", aid, found.Name, id.Name)
		}
		found = id
	}
	return found, nil
}

// NameHolding is the name the identity with this identifier is held under,
// and whether it is held at all.
func (e *Engine) NameHolding(aid string) (name string, held bool, err error) {
	id, err := e.heldByAID(aid)
	if err != nil || id == nil {
		return "", false, err
	}
	e.state.mu.RLock()
	defer e.state.mu.RUnlock()
	return id.Name, true, nil
}
