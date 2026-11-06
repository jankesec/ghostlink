package operator

import "testing"

func TestTransportCatalogCoversRegistry(t *testing.T) {
	if err := ValidateCatalog(); err != nil {
		t.Fatal(err)
	}
	if got := len(Transports()); got != 9 {
		t.Fatalf("transport count = %d, want 9", got)
	}
}

func TestDiagnoseIsExplicitlyOffline(t *testing.T) {
	report := Diagnose()
	if report.Network != "not accessed" {
		t.Fatalf("network = %q", report.Network)
	}
	if !report.Healthy() {
		t.Fatal("doctor unexpectedly unhealthy")
	}
}
