package capture

import (
	"fmt"
	"strconv"
)

// A capture run sends requests only to ProtocolSoup's production apps or to
// servers on this machine. Origins are never taken from input as text:
// production origins are constants, and a local origin is built from a port
// number, so nothing a caller supplies can point the capture at another host.

// The production apps the CI capture runs against.
const (
	ProductionBaseURL         = "https://protocolsoup.com"
	ProductionWalletURL       = "https://wallet.protocolsoup.com"
	ProductionCounterpartyURL = "https://protocolsoup-counterparty.fly.dev"
)

// Origins are the apps a run talks to. An empty Wallet or Counterparty means
// that app is not part of the run.
type Origins struct {
	Base         string
	Wallet       string
	Counterparty string
}

// ProductionOrigins are ProtocolSoup's deployed main app, hosted wallet and
// conformance counterparty.
func ProductionOrigins() Origins {
	return Origins{Base: ProductionBaseURL, Wallet: ProductionWalletURL, Counterparty: ProductionCounterpartyURL}
}

// LocalOrigins are http://localhost origins on the given ports. basePort is
// required; walletPort and counterpartyPort are 0 when that app is not
// running.
func LocalOrigins(basePort, walletPort, counterpartyPort int) (Origins, error) {
	if basePort == 0 {
		return Origins{}, fmt.Errorf("the main app port is required")
	}
	var origins Origins
	for _, port := range []struct {
		name   string
		number int
		origin *string
	}{
		{"main app", basePort, &origins.Base},
		{"wallet", walletPort, &origins.Wallet},
		{"counterparty", counterpartyPort, &origins.Counterparty},
	} {
		if port.number == 0 {
			continue
		}
		if port.number < 1 || port.number > 65535 {
			return Origins{}, fmt.Errorf("%s port %d is not a TCP port", port.name, port.number)
		}
		*port.origin = "http://localhost:" + strconv.Itoa(port.number)
	}
	return origins, nil
}
