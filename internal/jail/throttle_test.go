package jail

import "testing"

func TestThrottle(t *testing.T) {
	var th Throttle
	attacker, other := Network("192.0.2.1:2121"), Network("192.0.2.2:2121")
	for range maxFailures {
		if !th.allow(attacker) {
			t.Fatal("refused before the limit")
		}
		th.fail(attacker)
	}
	if th.allow(attacker) {
		t.Error("allowed past the limit")
	}
	if !th.allow(other) {
		t.Error("another address was refused")
	}
}

func TestNetwork(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"192.0.2.1:21", "[::ffff:192.0.2.1]:21"},
		{"[2001:db8::1]:21", "[2001:db8::ffff]:4000"},
		{"[fe80::1%eth0]:21", "[fe80::2]:21"},
	} {
		if Network(tc.a) != Network(tc.b) {
			t.Errorf("Network(%q) = %v, Network(%q) = %v; want the same", tc.a, Network(tc.a), tc.b, Network(tc.b))
		}
	}
	if Network("192.0.2.1:21") == Network("192.0.2.2:21") {
		t.Error("two IPv4 addresses share a network")
	}
}
