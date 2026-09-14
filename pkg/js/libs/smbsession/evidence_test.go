package smbsession

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAdministrativeShare(t *testing.T) {
	admin := []string{"IPC$", "ipc$", " IPC$ ", "ADMIN$", "C$", "c$", "Z$", "print$", "PRINT$", "FAX$"}
	for _, name := range admin {
		require.True(t, IsAdministrativeShare(name), "%q should be administrative", name)
	}

	// NETLOGON and SYSVOL hold real content; reaching them anonymously is a
	// finding, so they must not be filtered out as noise.
	notAdmin := []string{"Backups", "NETLOGON", "SYSVOL", "C", "$", "CC$", "share$", "Agent$Data"}
	for _, name := range notAdmin {
		require.False(t, IsAdministrativeShare(name), "%q should not be administrative", name)
	}
}

func TestIsPrinterSpoolerShare(t *testing.T) {
	spooler := []string{"print", "PRINT", "direct", "hold", "sequential",
		"lp1", "LP4", "lp9", "DRIVER_INST$", "PS3_Driver", "PS3_driver", "UNIV_Driver", "XPS_DRIVER"}
	for _, name := range spooler {
		require.True(t, IsPrinterSpoolerShare(name), "%q should be printer plumbing", name)
	}

	// FILE_SHARE is the scan-to-share on these same devices and holds scanned
	// documents, which is the customer data the check exists to find. LP0 and
	// LP10 are not real line-printer ports.
	notSpooler := []string{"FILE_SHARE", "Scans", "printer-logs", "lp0", "lp10", "printing", "print$"}
	for _, name := range notSpooler {
		require.False(t, IsPrinterSpoolerShare(name), "%q should not be printer plumbing", name)
	}
}

func TestCandidateDataSharesDropsNoiseAndKeepsOrder(t *testing.T) {
	got := CandidateDataShares([]string{"IPC$", "Backups", "ADMIN$", "", "C$", "Media", "print$"})
	require.Equal(t, []string{"Backups", "Media"}, got)
}

// A Samba box that enumerates only its administrative shares is the case the
// old check could never clear: IPC$ is the pipe the enumeration travelled over,
// so deleting the last real share left the finding standing.
func TestCandidateDataSharesEmptyForAdminOnlyServer(t *testing.T) {
	require.Empty(t, CandidateDataShares([]string{"IPC$", "ADMIN$", "C$"}))
}

// Real share lists from production, verbatim. The MFP rows are the 17 findings
// the printer-plumbing rule adds; the scan-to-share row must survive it, and
// the Datto row is the appliance that started all of this -- its shares are
// real, so only the tree connect can clear it.
func TestCandidateDataSharesAgainstProductionEvidence(t *testing.T) {
	cases := []struct {
		name   string
		shares []string
		want   []string
	}{
		{"xerox mfp queues", []string{"IPC$", "direct", "hold", "print"}, nil},
		{"line printer ports", []string{"IPC$", "lp1", "lp2", "lp3", "lp4"}, nil},
		{"mfp driver shares", []string{"IPC$", "UNIV_Driver", "PS3_Driver", "DRIVER_INST$", "print"}, nil},
		{"windows admin shares only", []string{"ADMIN$", "C$", "IPC$"}, nil},
		{"scan-to-share survives", []string{"DRIVER_INST$", "FILE_SHARE", "IPC$", "PS3_Driver", "UNIV_Driver", "print"}, []string{"FILE_SHARE"}},
		{"datto appliance", []string{"samba", "baremetals", "windows_agents", "virtual_failover", "hyperv_instant_recovery", "read_only", "IPC$"},
			[]string{"samba", "baremetals", "windows_agents", "virtual_failover", "hyperv_instant_recovery", "read_only"}},
		{"windows server with a data share", []string{"ADMIN$", "C$", "IPC$", "Users"}, []string{"Users"}},
		{"qnap nas", []string{"IPC$", "Multimedia", "Public", "Web"}, []string{"Multimedia", "Public", "Web"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CandidateDataShares(tc.shares)
			if tc.want == nil {
				require.Empty(t, got)
				return
			}
			require.Equal(t, tc.want, got)
		})
	}
}

// reachabilityBackend mounts only the shares in allowed, and lists only those
// in listable -- the two ways a server refuses, at TREE_CONNECT and at the
// directory read.
type reachabilityBackend struct {
	allowed  map[string]bool
	listable map[string]bool
	mounted  string
	mounts   []string
}

func (f *reachabilityBackend) UseShare(name string) error {
	f.mounts = append(f.mounts, name)
	if !f.allowed[name] {
		return errors.New("STATUS_ACCESS_DENIED")
	}
	f.mounted = name
	return nil
}

func (f *reachabilityBackend) ListShares() ([]string, error) { return nil, nil }

func (f *reachabilityBackend) Ls(string) ([]os.FileInfo, error) {
	if !f.listable[f.mounted] {
		return nil, &os.PathError{Op: "readdir", Path: f.mounted, Err: fs.ErrPermission}
	}
	return []os.FileInfo{}, nil
}

func (f *reachabilityBackend) Cat(string) (string, error) { return "", errors.New("not used") }

func TestReachableSharesStopsAtFirstSuccess(t *testing.T) {
	fake := &reachabilityBackend{
		allowed:  map[string]bool{"Media": true, "Public": true},
		listable: map[string]bool{"Media": true, "Public": true},
	}
	sess := &Session{backend: fake}

	got := sess.ReachableShares([]string{"Backups", "Media", "Public"}, 0)
	require.Equal(t, []string{"Media"}, got)
	// Backups was tried and refused, Media succeeded, Public was never probed.
	require.Equal(t, []string{"Backups", "Media"}, fake.mounts)
}

// The guest on a backup appliance: every real share refuses the tree connect,
// which is the whole point of the probe.
func TestReachableSharesEmptyWhenEveryMountDenied(t *testing.T) {
	fake := &reachabilityBackend{allowed: map[string]bool{}, listable: map[string]bool{}}
	sess := &Session{backend: fake}
	require.Empty(t, sess.ReachableShares([]string{"Backups", "Media"}, 0))
}

// A share that mounts but denies the listing does not count. Conservative on
// purpose: the point is to stop claiming access we have not demonstrated.
func TestReachableSharesRejectsMountableButUnlistable(t *testing.T) {
	fake := &reachabilityBackend{
		allowed:  map[string]bool{"Backups": true},
		listable: map[string]bool{},
	}
	sess := &Session{backend: fake}
	require.Empty(t, sess.ReachableShares([]string{"Backups"}, 0))
}

func TestReachableSharesHonoursProbeCap(t *testing.T) {
	fake := &reachabilityBackend{allowed: map[string]bool{}, listable: map[string]bool{}}
	sess := &Session{backend: fake}
	require.Empty(t, sess.ReachableShares([]string{"a", "b", "c", "d", "e"}, 2))
	require.Equal(t, []string{"a", "b"}, fake.mounts)
}

func TestReachableSharesOnDisconnectedSession(t *testing.T) {
	var s *Session
	require.Empty(t, s.ReachableShares([]string{"Backups"}, 0))
	require.Empty(t, (&Session{}).ReachableShares([]string{"Backups"}, 0))
}

func TestIsTransportError(t *testing.T) {
	require.False(t, isTransportError(nil))
	// An NT status from the server is a rejection, not a transport failure.
	require.False(t, isTransportError(errors.New("STATUS_LOGON_FAILURE")))

	require.True(t, isTransportError(context.Canceled))
	require.True(t, isTransportError(context.DeadlineExceeded))
	require.True(t, isTransportError(&net.OpError{Op: "dial", Err: errors.New("connection refused")}))
}

func TestRandomCanaryStringIsRandomAndWellFormed(t *testing.T) {
	first, err := randomCanaryString(canaryCredentialLength)
	require.NoError(t, err)
	require.Len(t, first, canaryCredentialLength)

	second, err := randomCanaryString(canaryCredentialLength)
	require.NoError(t, err)
	require.NotEqual(t, first, second)

	for _, r := range first {
		require.Contains(t, canaryAlphabet, string(r))
	}
}
