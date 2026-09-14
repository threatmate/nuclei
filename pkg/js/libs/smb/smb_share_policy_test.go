package smb

import (
	"context"
	"encoding/json"
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
	got := evaluateSharePolicy(policy, applianceShares, guestServer())
	requireSuppressed(t, got)
}

func TestAnonymousAccessSuppressedWhenNothingIsReachable(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBAnonymousAccess)
	got := evaluateSharePolicy(policy, applianceShares, guestServer())
	requireSuppressed(t, got)
}

// A genuinely default-credentialed NAS is still a finding, and the response it
// matches on is the unmodified enumeration -- IPC$ included, because the
// templates' own extractors report that list.
func TestDefaultLoginStillFiresOnARealFinding(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBDefaultLogin)
	got := evaluateSharePolicy(policy, applianceShares, realFinding())
	require.Equal(t, applianceShares, got)
}

func TestAnonymousAccessStillFiresWhenAShareIsReachable(t *testing.T) {
	policy, _ := sharePolicyFor(templateSMBAnonymousAccess)
	got := evaluateSharePolicy(policy, applianceShares, realFinding())
	require.Equal(t, applianceShares, got)
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
			requireSuppressed(t, evaluateSharePolicy(policy, []string{"IPC$", "ADMIN$", "C$"}, probes))
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
	require.Equal(t, applianceShares, evaluateSharePolicy(policy, applianceShares, probes))

	probes.reachableShares = func([]string) []string { return nil }
	requireSuppressed(t, evaluateSharePolicy(policy, applianceShares, probes))
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
	require.Equal(t, applianceShares, evaluateSharePolicy(policy, applianceShares, probes))
}

func TestApplySharePolicyLeavesUnpolicedTemplatesAlone(t *testing.T) {
	// No templateId at all (direct Go callers, dcerpc, tests).
	require.Equal(t, applianceShares,
		applySharePolicy(context.Background(), "exec", "10.0.0.5", 445, "u", "p", applianceShares))

	// smb-shares, and an arbitrary other template, keep the raw enumeration
	// even where nothing is reachable -- reaching a probe would dial, and these
	// assertions would hang or fail if the policy tried.
	for _, id := range []string{"smb-shares", "smb-enum-domains"} {
		ctx := context.WithValue(context.Background(), "templateId", id) //nolint:staticcheck // SA1029: matches the existing executionId key
		require.Equal(t, applianceShares,
			applySharePolicy(ctx, "exec", "10.0.0.5", 445, "u", "p", applianceShares))
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

// requireSuppressed asserts the empty-not-nil contract. The templates match on
// `response != "[]"` and `contains(response, "IPC$")`; a nil slice reaches the
// DSL as "null", which is not "[]", and would fire the finding being suppressed.
func requireSuppressed(t *testing.T, got []string) {
	t.Helper()
	require.NotNil(t, got, "suppressed result must be an empty slice, never nil")
	require.Empty(t, got)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.Equal(t, "[]", string(encoded), `suppressed result must render as "[]" for the dsl matcher`)
}
