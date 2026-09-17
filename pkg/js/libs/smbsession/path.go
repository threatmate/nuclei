package smbsession

import (
	"fmt"
	"path"
	"strings"
)

// ParseIdentity splits DOMAIN\user, domain/user, or user@domain into domain and username.
func ParseIdentity(user string) (domain, username string) {
	user = strings.TrimSpace(user)
	if user == "" {
		return "", ""
	}
	if i := strings.IndexByte(user, '\\'); i >= 0 {
		return user[:i], user[i+1:]
	}
	if i := strings.IndexByte(user, '/'); i >= 0 {
		return user[:i], user[i+1:]
	}
	if i := strings.LastIndexByte(user, '@'); i > 0 {
		return user[i+1:], user[:i]
	}
	return "", user
}

// GuestUser is the username Dial sends when the caller offers none.
//
// An SMB null (anonymous) session is not something this client can open:
// goimpacket refuses an empty NTLM username before a packet leaves the host,
// with "Anonymous account is not supported yet. Use guest account instead".
// That refusal is unconditional and client-side, so an empty username is a
// guaranteed failure against every server rather than a check that sometimes
// works.
//
// A template that means "no credential" therefore has to spell it as
// something, and upstream's smb-anonymous-access spells it " " -- a single
// space, which ParseIdentity trims away to nothing. Taking the library's own
// advice and dialing guest is what lets that check run at all.
//
// Guest is not a second-best stand-in for anonymous here, it is the same
// claim: the finding is that an unauthenticated party reaches the share, and a
// guest session is how servers grant exactly that. What a guest session does
// NOT establish is that any credential was validated -- so the caller still
// owes evidence beyond "the session opened", which is what the share policy in
// pkg/js/libs/smb requires before a finding stands.
const GuestUser = "guest"

// resolveIdentity turns Creds into the domain and username to put on the wire.
//
// A username that parses to nothing becomes GuestUser. That covers the empty
// string, whitespace, and a bare domain with no account after it ("CORP\\"),
// all of which previously reached goimpacket as either an empty username it
// refuses outright or a separator-laden string no server has an account for.
func resolveIdentity(creds Creds) (domain, user string) {
	domain, user = ParseIdentity(creds.User)
	if creds.Domain != "" {
		domain = creds.Domain
	}
	if user == "" {
		user = GuestUser
	}
	return domain, user
}

// NormalizeSharePath converts an SMB share-relative path to a clean form
// (forward slashes, no leading slash, "." for share root). Rejects ".." escapes.
func NormalizeSharePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, `\`, `/`)
	p = strings.Trim(p, `/`)
	if p == "" || p == "." {
		return ".", nil
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("share path contains NUL")
	}
	clean := path.Clean(p)
	clean = strings.TrimPrefix(clean, "/")
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("share path escapes share root: %q", p)
	}
	if clean == "." {
		return ".", nil
	}
	return clean, nil
}

// RequireShareName validates a share name (no path separators).
func RequireShareName(share string) error {
	share = strings.TrimSpace(share)
	if share == "" {
		return fmt.Errorf("share name cannot be empty")
	}
	if strings.ContainsAny(share, `/\`) {
		return fmt.Errorf("share name must not contain path separators: %q", share)
	}
	if strings.ContainsRune(share, 0) {
		return fmt.Errorf("share name contains NUL")
	}
	return nil
}
