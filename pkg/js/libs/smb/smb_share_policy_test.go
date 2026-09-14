package smb

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// The share list a Datto-style appliance returns to a guest-mapped session:
// IPC$ plus the real backup shares, whose names enumerate freely even though
// the guest cannot open any of them.
var applianceShares = []string{"ADMIN$", "Backups", "IPC$", "Media"}

// guestServer is the false positive this file exists for: `map to guest = Bad
// User` authenticates anything, and nothing real is reachable.
func guestServer() shareProbes {
	return shareProbes{
		acceptsAnyCredential: func() (bool, error) { return true, nil },
		reachableShares:      func([]string) []string { return nil },
	}
}

// realFinding is a server that validates credentials and then hands the caller
// a share it can actually open.
func realFinding() shareProbes {
	return shareProbes{
		acceptsAnyCredential: func() (bool, error) { return false, nil },
		reachableShares:      func(candidates []string) []string { return candidates[:1] },
	}
}

func TestSharePolicyForCoversTheThreeTemplates(t *testing.T) {
	credentialClaim, ok := sharePolicyFor(templateSMBDefaultLogin)
	require.True(t, ok)
	require.True(t, credentialClaim.requireValidatedCredential)
	require.True(t, credentialClaim.requireReachableShare)

	// "Anonymous access" says nothing about a credential being validated -- the
	// credential it offers is blank -- so only reachability is demanded.
	anonymousClaim, ok := sharePolicyFor(templateSMBAnonymousAccess)
	require.True(t, ok)
	require.False(t, anonymousClaim.requireValidatedCredential)
	require.True(t, anonymousClaim.requireReachableShare)

	// smb-shares claims exactly what the enumeration shows, at low severity,
	// and keeps reporting the names it can read.
	_, ok = sharePolicyFor("smb-shares")
	require.False(t, ok, "smb-shares must keep the unfiltered enumeration")

	_, ok = sharePolicyFor("some-unrelated-template")
	require.False(t, ok, "a template we have not reasoned about must be left alone")
}

// The customer's appliance: a high default-credentials finding where no
// credential was ever checked.
func TestDefaultLoginSuppressedOnGuestMappingServer(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBDefaultLogin)
	require.ErrorIs(t, evaluateSharePolicy(policy, applianceShares, guestServer()), ErrNoShareEvidence)
}

func TestAnonymousAccessSuppressedWhenNothingIsReachable(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBAnonymousAccess)
	require.ErrorIs(t, evaluateSharePolicy(policy, applianceShares, guestServer()), ErrNoShareEvidence)
}

// A genuinely default-credentialed NAS is still a finding.
func TestDefaultLoginStillFiresOnARealFinding(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBDefaultLogin)
	require.NoError(t, evaluateSharePolicy(policy, applianceShares, realFinding()))
}

func TestAnonymousAccessStillFiresWhenAShareIsReachable(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBAnonymousAccess)
	require.NoError(t, evaluateSharePolicy(policy, applianceShares, realFinding()))
}

// Even when the credential is validated, share NAMES are not access. A server
// exporting only its administrative shares has nothing to report, and neither
// probe should be dialed to find that out.
func TestAdministrativeOnlyEnumerationIsNotEvidence(t *testing.T) {
	for _, id := range []string{templateSMBDefaultLogin, templateSMBAnonymousAccess} {
		t.Run(id, func(t *testing.T) {
			policy, _ := sharePolicyFor(id)
			probes := shareProbes{
				acceptsAnyCredential: func() (bool, error) {
					t.Fatal("canary dialed with no candidate share to justify it")
					return false, nil
				},
				reachableShares: func([]string) []string {
					t.Fatal("reachability probed with no candidate share")
					return nil
				},
			}
			require.ErrorIs(t, evaluateSharePolicy(policy, []string{"IPC$", "ADMIN$", "C$"}, probes), ErrNoShareEvidence)
		})
	}
}

// A canary that could not be measured must not drop a finding. Reachability
// still has to hold, so this is not a way around the policy.
func TestUnmeasurableCanaryDoesNotSuppress(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBDefaultLogin)
	probes := realFinding()
	probes.acceptsAnyCredential = func() (bool, error) {
		return false, errors.New("dial tcp: i/o timeout")
	}
	require.NoError(t, evaluateSharePolicy(policy, applianceShares, probes))

	probes.reachableShares = func([]string) []string { return nil }
	require.ErrorIs(t, evaluateSharePolicy(policy, applianceShares, probes), ErrNoShareEvidence)
}

// smb-anonymous-access never asks the canary: the credential it offers is
// blank, so "the server accepts anything" and "the server accepts anonymous"
// are the same sentence.
func TestAnonymousAccessNeverDialsTheCanary(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBAnonymousAccess)
	probes := realFinding()
	probes.acceptsAnyCredential = func() (bool, error) {
		t.Fatal("canary dialed for a claim that does not rest on a credential")
		return false, nil
	}
	require.NoError(t, evaluateSharePolicy(policy, applianceShares, probes))
}

func TestApplySharePolicyLeavesUnpolicedTemplatesAlone(t *testing.T) {
	// No templateId at all (direct Go callers, dcerpc, tests).
	require.NoError(t, applySharePolicy(context.Background(), "exec", "10.0.0.5", 445, "u", "p", applianceShares))

	// smb-shares, and an arbitrary other template, keep the raw enumeration
	// even where nothing is reachable -- reaching a probe would dial, and these
	// assertions would hang or fail if the policy tried.
	for _, id := range []string{"smb-shares", "smb-enum-domains"} {
		ctx := context.WithValue(context.Background(), "templateId", id) //nolint:staticcheck // SA1029: matches the existing executionId key
		require.NoError(t, applySharePolicy(ctx, "exec", "10.0.0.5", 445, "u", "p", applianceShares))
	}
}

func TestTemplateIDFromContext(t *testing.T) {
	require.Equal(t, "", templateIDFromContext(nil))
	require.Equal(t, "", templateIDFromContext(context.Background()))

	ctx := context.WithValue(context.Background(), "templateId", "smb-default-login") //nolint:staticcheck
	require.Equal(t, "smb-default-login", templateIDFromContext(ctx))

	// A non-string value must not panic the library.
	ctx = context.WithValue(context.Background(), "templateId", 42) //nolint:staticcheck
	require.Equal(t, "", templateIDFromContext(ctx))
}

// This is the test that an earlier version of this file got wrong, and it cost
// a whole end-to-end run to find out. Suppression was expressed as an empty,
// non-nil slice on the theory that it would reach the dsl as "[]" and fail
// `response != "[]"`. It does not. The javascript protocol sets `response` to
// results.Export() -- a Go []string, compared against a STRING literal, which
// is unequal for every slice -- and `success` to results.ToBoolean(), which is
// true for any JS array including an empty one. A verified run against a
// guest-mapping Samba server produced response='[]' and matched anyway, nine
// times.
//
// So the contract is: suppression is an ERROR, never a value. Anything that
// turns it back into a returned slice silently restores the false positive.
func TestSuppressionIsAnErrorNotAnEmptyList(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBDefaultLogin)
	err := evaluateSharePolicy(policy, applianceShares, guestServer())
	require.Error(t, err, "suppression must be an error; a returned slice cannot fail `success == true`")
	require.ErrorIs(t, err, ErrNoShareEvidence)
}
