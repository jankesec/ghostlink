package buildinfo

import "testing"

func TestString(t *testing.T) {
	originalVersion, originalCommit, originalDate := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = originalVersion, originalCommit, originalDate })

	Version, Commit, Date = "v1.1.0", "abc1234", "2026-11-06T10:00:00Z"
	want := "ghostlink v1.1.0 (abc1234, 2026-11-06T10:00:00Z)"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
