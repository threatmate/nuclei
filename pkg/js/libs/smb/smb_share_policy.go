package smb

import (
	"context"
	"errors"
	"strconv"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/smbsession"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// errCachedResultType mirrors the generated memo helpers' handling of a cache
// entry of the wrong type.
var errCachedResultType = errors.New("could not convert cached result")

// Template ids whose claim needs more than a share enumeration to stand up.
const (
	templateSMBDefaultLogin    = "smb-default-login"
	templateSMBAnonymousAccess = "smb-anonymous-access"
)

// shareEvidence is what a template's claim has to be backed by before
// ListShares will hand it a share list to match on.
//
// Every one of these templates matches on the same call -- ListShares, which is
// SESSION_SETUP then TREE_CONNECT IPC$ then srvsvc.NetShareEnumAll -- but they
// do not all claim the same thing, and the enumeration alone does not support
// the stronger claims:
//
//   - "these default credentials work" (smb-default-login, high) is false on
//     any server that maps unknown users to guest, because the login it is
//     reporting was never checked against anything.
//   - "an unauthenticated party can reach SMB shares" (smb-anonymous-access,
//     high) is false when the only thing enumerable is IPC$ and the real shares
//     refuse to mount.
//   - "these share names are enumerable" (smb-shares, low) is exactly what the
//     enumeration shows, so it needs nothing extra and is absent from this
//     table.
//
// A template with no entry here keeps the unfiltered enumeration. That is the
// deliberate default: narrowing a check we have not reasoned about would delete
// findings silently, which is worse than the false positive being fixed.
type shareEvidence struct {
	// requireValidatedCredential drops the finding when the server also
	// authenticates a credential that cannot exist, because then the offered
	// credential was never validated.
	requireValidatedCredential bool
	// requireReachableShare drops the finding unless some non-administrative
	// share can actually be mounted and listed with the offered credential.
	requireReachableShare bool
}

func sharePolicyFor(templateID string) (shareEvidence, bool) {
	switch templateID {
	case templateSMBDefaultLogin:
		return shareEvidence{requireValidatedCredential: true, requireReachableShare: true}, true
	case templateSMBAnonymousAccess:
		return shareEvidence{requireReachableShare: true}, true
	default:
		return shareEvidence{}, false
	}
}

// templateIDFromContext reads the calling template's id, "" when absent.
// Unlike executionId this is best-effort: direct Go callers and tests do not
// set it, and they get the unfiltered enumeration.
func templateIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value("templateId").(string)
	return id
}

// shareProbes are the two measurements a policy can demand. They are closures
// so an unneeded probe is never dialed, and so the decision logic can be tested
// without a server.
type shareProbes struct {
	// acceptsAnyCredential reports whether the host authenticates a credential
	// that cannot exist. The error means "could not measure", not "no".
	acceptsAnyCredential func() (bool, error)
	// reachableShares returns which of candidates could be mounted and listed.
	reachableShares func(candidates []string) []string
}

// applySharePolicy returns the share list the calling template is entitled to
// match on.
func applySharePolicy(ctx context.Context, executionId string, host string, port int, user, password string, shares []string) []string {
	policy, ok := sharePolicyFor(templateIDFromContext(ctx))
	if !ok {
		return shares
	}
	return evaluateSharePolicy(policy, shares, shareProbes{
		acceptsAnyCredential: func() (bool, error) {
			return memoizedAcceptsAnyCredential(ctx, executionId, host, port)
		},
		reachableShares: func(candidates []string) []string {
			return memoizedReachableShares(ctx, executionId, host, port, user, password, candidates)
		},
	})
}

// evaluateSharePolicy decides how much of shares survives policy.
//
// An unentitled caller gets an EMPTY, NON-NIL slice. The templates match with
// `response != "[]"` and `contains(response, "IPC$")`, so a suppressed result
// has to stringify as "[]"; a nil slice reaches the DSL as "null", which is not
// "[]" and would fire the very finding being suppressed.
func evaluateSharePolicy(policy shareEvidence, shares []string, probes shareProbes) []string {
	// IPC$, ADMIN$, C$..Z$ and print$ are published by every server, and the
	// print queues beside them by every MFP. Neither proves anything, so
	// without a share that could hold data there is nothing to probe.
	candidates := smbsession.CandidateDataShares(shares)
	if len(candidates) == 0 {
		return []string{}
	}

	if policy.requireValidatedCredential {
		// A canary error means the probe could not be evaluated, not that the
		// server validates credentials; leave the finding alone rather than
		// dropping it on a failed measurement.
		acceptsAnything, err := probes.acceptsAnyCredential()
		if err == nil && acceptsAnything {
			return []string{}
		}
	}

	if policy.requireReachableShare && len(probes.reachableShares(candidates)) == 0 {
		return []string{}
	}

	return shares
}

// memoizedAcceptsAnyCredential runs one canary login per host per execution.
// smb-default-login is a nine-way clusterbomb, so without this every credential
// pair would dial its own canary.
func memoizedAcceptsAnyCredential(ctx context.Context, executionId string, host string, port int) (bool, error) {
	key := smbMemoKey("acceptsAnyCredential", executionId, host, strconv.Itoa(port))
	v, err, _ := protocolstate.Memoizer.Do(key, func() (interface{}, error) {
		return smbsession.AcceptsAnyCredential(ctx, executionId, host, port)
	})
	if err != nil {
		return false, err
	}
	value, ok := v.(bool)
	if !ok {
		return false, errCachedResultType
	}
	return value, nil
}

// memoizedReachableShares mounts and lists candidate shares with the offered
// credential, memoized per credential because the answer is a property of the
// credential, not of the host.
func memoizedReachableShares(ctx context.Context, executionId string, host string, port int, user, password string, candidates []string) []string {
	key := smbMemoKey("reachableShares", executionId, host, strconv.Itoa(port), user, password)
	v, err, _ := protocolstate.Memoizer.Do(key, func() (interface{}, error) {
		session, err := smbsession.Dial(ctx, executionId, host, port, smbsession.Creds{User: user, Password: password})
		if err != nil {
			return []string{}, err
		}
		defer session.Close()
		reachable := session.ReachableShares(candidates, smbsession.DefaultMaxReachabilityProbes)
		if reachable == nil {
			reachable = []string{}
		}
		return reachable, nil
	})
	if err != nil {
		return nil
	}
	value, ok := v.([]string)
	if !ok {
		return nil
	}
	return value
}
