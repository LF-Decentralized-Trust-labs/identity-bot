// Package githubrepo is how a grant names the GitHub repositories an AI agent
// may use, and how: the capabilities that grant them, the arguments that
// limit each one to its repositories, and how a repository is named. The
// Identity Agent grants with these and a verifier checks a grant against
// them, so they stand apart from the client that asks GitHub for tokens.
package githubrepo

import (
	"fmt"
	"regexp"
	"strings"
)

// Access is what an AI agent may do in a repository.
type Access string

const (
	// Read is cloning and reading.
	Read Access = "read"
	// Write is also committing, pushing and opening pull requests.
	Write Access = "write"
)

// The capabilities that grant repositories, each limited to the repositories
// its grant names: by owner/name under RepositoryArgument and by GitHub's
// number under RepositoryIDArgument, in the same place in each list. The one
// definition the Identity Agent grants with and a verifier checks against.
const (
	CapabilityRead       = "code.repository.read"
	CapabilityWrite      = "code.repository.write"
	RepositoryArgument   = "repository"
	RepositoryIDArgument = "repository_id"
)

// Capability is the capability that grants an access.
func (a Access) Capability() string {
	if a == Write {
		return CapabilityWrite
	}
	return CapabilityRead
}

// Permissions are what a token for an access asks GitHub for. A GitHub App
// must have been given at least these when it was made, or GitHub refuses the
// token.
func (a Access) Permissions() map[string]string {
	if a == Write {
		return map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}
	}
	return map[string]string{"contents": "read", "metadata": "read"}
}

// ParseAccess is an access as a person or a screen named it.
func ParseAccess(s string) (Access, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "read", "read only", "read-only":
		return Read, nil
	case "write", "read and write", "read-write":
		return Write, nil
	}
	return "", fmt.Errorf("access must be read or write, not %q", s)
}

// ownerName is what GitHub allows in an account's name: letters, digits and
// hyphens, not starting with a hyphen — and, for an enterprise's managed
// users, an underscore before its short code.
var ownerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)

// repoName is what GitHub allows in a repository's name: letters, digits, '.',
// '_' and '-', in any place, so ".github" and "_site" are names.
var repoName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// NormaliseRepository is a repository as "owner/name", lower-cased, since
// GitHub's names are not case-sensitive. A name that is not one is refused.
func NormaliseRepository(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.TrimPrefix(s, "https://github.com/"), ".git")
	owner, name, ok := strings.Cut(s, "/")
	if !ok || !ownerName.MatchString(owner) || !repoName.MatchString(name) || name == "." || name == ".." {
		return "", fmt.Errorf("%q is not a GitHub repository; name it as owner/name", s)
	}
	return strings.ToLower(owner + "/" + name), nil
}
