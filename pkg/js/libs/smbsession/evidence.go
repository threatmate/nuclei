package smbsession

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"strings"
)

const (
	// DefaultMaxReachabilityProbes caps how many shares a reachability check
	// will try to mount before giving up. One reachable share is all the
	// evidence any caller needs, so the cap only matters on an appliance
	// exporting a long share list to a session that can open none of them.
	DefaultMaxReachabilityProbes = 16

	// canaryCredentialLength is the length of the random username and password
	// used by AcceptsAnyCredential. Long enough that no real account, and no
	// entry in any default-credential list, can collide with it.
	canaryCredentialLength = 20
)

const canaryAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// IsAdministrativeShare reports whether name is a share every Windows or Samba
// server publishes regardless of configuration.
//
// These prove nothing about access. IPC$ in particular is returned by every
// successful srvsvc.NetShareEnumAll -- it is the pipe the enumeration itself
// travelled over -- so a check that treats the enumeration's own transport as
// evidence of exposed data can never be cleared: deleting the last real share
// on the server leaves IPC$ behind and the finding stands.
//
// Recognised: IPC$, ADMIN$, the per-volume admin shares C$ through Z$, print$
// and FAX$. NETLOGON and SYSVOL are deliberately NOT here -- they are domain
// controller content shares, and reaching them anonymously is a real finding.
func IsAdministrativeShare(name string) bool {
	trimmed := strings.ToUpper(strings.TrimSpace(name))
	switch trimmed {
	case "IPC$", "ADMIN$", "PRINT$", "FAX$":
		return true
	}
	// Per-volume admin shares: a single drive letter followed by "$".
	if len(trimmed) == 2 && trimmed[1] == '$' && trimmed[0] >= 'A' && trimmed[0] <= 'Z' {
		return true
	}
	return false
}

// NonAdministrativeShares returns the entries of shares that are not
// administrative, preserving order. The result is what a caller may treat as
// candidate evidence; whether any of it is actually reachable is a separate
// question answered by ReachableShares.
func NonAdministrativeShares(shares []string) []string {
	out := make([]string, 0, len(shares))
	for _, share := range shares {
		if strings.TrimSpace(share) == "" || IsAdministrativeShare(share) {
			continue
		}
		out = append(out, share)
	}
	return out
}

// ReachableShares returns the entries of shares this session can actually open:
// a TREE_CONNECT followed by a listing of the share root. It stops at the first
// success, because one reachable share settles every question a caller asks of
// it, and gives up after maxProbe attempts.
//
// A share that mounts but denies the root listing does not count. That is the
// conservative direction on purpose: the point of the check is to stop claiming
// access we have not demonstrated.
//
// Only directory entries are read, and they are used solely as proof that the
// listing succeeded -- no entry name is returned to the caller and no file
// content is opened.
func (s *Session) ReachableShares(shares []string, maxProbe int) []string {
	ops := s.ops()
	if ops == nil {
		return nil
	}
	if maxProbe <= 0 {
		maxProbe = DefaultMaxReachabilityProbes
	}

	var reachable []string
	probes := 0
	for _, share := range shares {
		if probes >= maxProbe {
			break
		}
		probes++
		if _, err := listDir(ops, share, "."); err != nil {
			continue
		}
		reachable = append(reachable, share)
		break
	}
	return reachable
}

// AcceptsAnyCredential reports whether host:port authenticates a credential
// that cannot exist -- a random 20-character username and password.
//
// This is the reachable test for a server that maps unknown users to guest
// (Samba's `map to guest = Bad User`, the default on many NAS and backup
// appliances). Such a server completes SESSION_SETUP for any credential at all,
// so a successful login proves nothing about the credential that was offered.
// The protocol carries the answer directly in SMB2_SESSION_FLAG_IS_GUEST, but
// goimpacket parses that flag into a private field of a private struct with no
// accessor, so reading it would mean forking goimpacket. Offering a credential
// that is guaranteed to be wrong gets the same answer over the public API.
//
// The bar is deliberately the whole operation, not just the login: the canary
// must both authenticate AND enumerate. A server that admits the canary as
// guest but then denies it the share enumeration gave the real credential
// something the canary did not have, which means the real credential was
// validated after all.
//
// Returns (false, err) when the canary could not be evaluated -- a transport
// failure rather than a rejection. Callers should treat that as unknown and NOT
// suppress on canary grounds, so a flaky probe drops findings nowhere.
func AcceptsAnyCredential(ctx context.Context, executionID, host string, port int) (bool, error) {
	user, err := randomCanaryString(canaryCredentialLength)
	if err != nil {
		return false, err
	}
	password, err := randomCanaryString(canaryCredentialLength)
	if err != nil {
		return false, err
	}

	session, err := Dial(ctx, executionID, host, port, Creds{User: user, Password: password})
	if err != nil {
		if isTransportError(err) {
			return false, err
		}
		// The server rejected a credential, which is what a server that
		// validates credentials does.
		return false, nil
	}
	defer session.Close()

	if _, err := session.ListShares(); err != nil {
		// Authenticated but not authorised: the canary got less than the real
		// credential did, so the real credential bought something.
		return false, nil
	}
	return true, nil
}

// isTransportError reports whether err is a connectivity or cancellation
// failure rather than the server refusing an authentication attempt.
func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

// randomCanaryString returns a cryptographically random alphanumeric string.
func randomCanaryString(length int) (string, error) {
	limit := big.NewInt(int64(len(canaryAlphabet)))
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		out[i] = canaryAlphabet[n.Int64()]
	}
	return string(out), nil
}
