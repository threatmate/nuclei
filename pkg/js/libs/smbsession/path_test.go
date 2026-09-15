package smbsession

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIdentity(t *testing.T) {
	d, u := ParseIdentity(`CORP\alice`)
	require.Equal(t, "CORP", d)
	require.Equal(t, "alice", u)

	d, u = ParseIdentity("alice@corp.local")
	require.Equal(t, "corp.local", d)
	require.Equal(t, "alice", u)

	d, u = ParseIdentity("alice")
	require.Equal(t, "", d)
	require.Equal(t, "alice", u)
}

func TestNormalizeSharePath(t *testing.T) {
	got, err := NormalizeSharePath(`docs\a.txt`)
	require.NoError(t, err)
	require.Equal(t, "docs/a.txt", got)

	_, err = NormalizeSharePath("../etc")
	require.Error(t, err)

	got, err = NormalizeSharePath("")
	require.NoError(t, err)
	require.Equal(t, ".", got)
}

func TestRequireShareName(t *testing.T) {
	require.Error(t, RequireShareName(""))
	require.Error(t, RequireShareName("a/b"))
	require.NoError(t, RequireShareName("C$"))
}

func TestResolveIdentityKeepsARealUsername(t *testing.T) {
	d, u := resolveIdentity(Creds{User: `CORP\alice`, Password: "p"})
	require.Equal(t, "CORP", d)
	require.Equal(t, "alice", u)

	d, u = resolveIdentity(Creds{User: "alice", Password: "p"})
	require.Equal(t, "", d)
	require.Equal(t, "alice", u)

	// An explicit Domain still wins over the one parsed out of User.
	d, u = resolveIdentity(Creds{User: `CORP\alice`, Domain: "OTHER"})
	require.Equal(t, "OTHER", d)
	require.Equal(t, "alice", u)
}

// The regression this file exists for: upstream's smb-anonymous-access passes
// a single space as the username, which ParseIdentity trims to nothing. Before
// this, that reached goimpacket as an empty NTLM username and was refused
// client-side on every server, so the template could never fire.
func TestResolveIdentityDialsGuestWhenNoUsernameIsOffered(t *testing.T) {
	for _, offered := range []string{" ", "", "\t", "   ", `CORP\`, "corp/"} {
		_, u := resolveIdentity(Creds{User: offered, Password: " "})
		require.Equalf(t, GuestUser, u, "username %q should fall back to guest", offered)
	}

	// The domain the caller did give survives the fallback.
	d, u := resolveIdentity(Creds{User: `CORP\`})
	require.Equal(t, "CORP", d)
	require.Equal(t, GuestUser, u)
}

// Guest is a substitution for a missing username only. A caller that asks for
// the guest account by name is unchanged, and the password is never rewritten:
// Dial passes creds.Password through untouched.
func TestResolveIdentityLeavesAnExplicitGuestAlone(t *testing.T) {
	d, u := resolveIdentity(Creds{User: "guest"})
	require.Equal(t, "", d)
	require.Equal(t, GuestUser, u)
}
