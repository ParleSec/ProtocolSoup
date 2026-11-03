package capture

import "testing"

func TestLocalOriginsAreLocalhostPorts(t *testing.T) {
	origins, err := LocalOrigins(8181, 8282, 0)
	if err != nil {
		t.Fatalf("LocalOrigins: %v", err)
	}
	if origins != (Origins{Base: "http://localhost:8181", Wallet: "http://localhost:8282"}) {
		t.Fatalf("LocalOrigins = %+v", origins)
	}
	for _, ports := range [][3]int{{0, 0, 0}, {-1, 0, 0}, {70000, 0, 0}, {8080, 65536, 0}, {8080, 0, -5}} {
		if origins, err := LocalOrigins(ports[0], ports[1], ports[2]); err == nil {
			t.Fatalf("LocalOrigins%v = %+v; want an error", ports, origins)
		}
	}
}
