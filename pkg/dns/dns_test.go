package dns

import (
	"reflect"
	"testing"
)

func TestParseTXTCoordinatorRecords(t *testing.T) {
	dom, ok := IsDNSDiscoveryEntry("sshcast.net")
	if !ok || dom != "sshcast.net" {
		t.Fatalf("IsDNSDiscoveryEntry(sshcast.net) = (%q, %v)", dom, ok)
	}
	if _, ok := IsDNSDiscoveryEntry("https://c1.sshcast.net"); ok {
		t.Fatalf("expected https://c1.sshcast.net not to be a DNS discovery entry")
	}
	if got := TXTLookupQName("sshcast.net"); got != "_sshcast.sshcast.net" {
		t.Fatalf("TXTLookupQName = %q", got)
	}

	records := []string{
		"v=sshcast1; coordinators=c1.sshcast.net,https://c2.sshcast.net/",
		"c3.sshcast.net c1.sshcast.net",
	}
	got := ParseTXTCoordinatorRecords(records)
	want := []string{
		"https://c1.sshcast.net",
		"https://c2.sshcast.net",
		"https://c3.sshcast.net",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
