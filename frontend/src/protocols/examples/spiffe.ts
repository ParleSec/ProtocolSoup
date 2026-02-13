import type { CodeExample } from './index'

export const SPIFFE_EXAMPLES: Record<string, CodeExample> = {
  /* ------------------------------------------------------------------ */
  'x509-svid-issuance': {
    language: 'go',
    label: 'Go (Workload)',
    code: `// X.509-SVID Acquisition via SPIRE Workload API
// SPIFFE X.509-SVID spec §3 — Workload API spec §5

package main

import (
    "context"
    "fmt"
    "log"

    "github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
    ctx := context.Background()

    // Connect to the SPIRE Agent's Workload API over Unix Domain Socket.
    // The agent performs workload attestation using kernel-level selectors
    // (PID, UID, cgroup, Docker labels, K8s pod identity, etc.)
    source, err := workloadapi.NewX509Source(ctx,
        workloadapi.WithClientOptions(
            workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock"),
        ),
    )
    if err != nil {
        log.Fatal("Failed to create X509Source:", err)
    }
    defer source.Close()

    // GetX509SVID returns the workload's current X.509-SVID.
    // The SPIFFE ID is encoded in the certificate's URI SAN field.
    svid, err := source.GetX509SVID()
    if err != nil {
        log.Fatal("Failed to get X509-SVID:", err)
    }

    cert := svid.Certificates[0]
    fmt.Printf("SPIFFE ID:     %s\\n", svid.ID)            // spiffe://trust-domain/workload/path
    fmt.Printf("Serial:        %s\\n", cert.SerialNumber)
    fmt.Printf("Not Before:    %s\\n", cert.NotBefore)
    fmt.Printf("Not After:     %s\\n", cert.NotAfter)
    fmt.Printf("URI SANs:      %v\\n", cert.URIs)          // Contains the SPIFFE ID
    fmt.Printf("Issuer:        %s\\n", cert.Issuer)
    fmt.Printf("Key Algorithm: %s\\n", cert.PublicKeyAlgorithm)

    // The X509Source implements x509.Certificate pooling and auto-rotation.
    // SPIRE rotates SVIDs at ~50% of their TTL (default 1h → rotates at ~30m).
    // New TLS connections automatically use the latest certificate.
}`,
  },

  /* ------------------------------------------------------------------ */
  'jwt-svid-issuance': {
    language: 'go',
    label: 'Go (Workload)',
    code: `// JWT-SVID Acquisition via SPIRE Workload API
// SPIFFE JWT-SVID spec §3 — Workload API spec §6

package main

import (
    "context"
    "fmt"
    "log"

    "github.com/spiffe/go-spiffe/v2/workloadapi"
    "github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

func main() {
    ctx := context.Background()

    // Create a JWT-SVID source connected to the SPIRE Agent
    source, err := workloadapi.NewJWTSource(ctx,
        workloadapi.WithClientOptions(
            workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock"),
        ),
    )
    if err != nil {
        log.Fatal("Failed to create JWTSource:", err)
    }
    defer source.Close()

    // Fetch a JWT-SVID for a specific audience.
    // The "audience" identifies the intended recipient service.
    // The SPIRE Server signs the JWT with its private key.
    svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{
        Audience: "spiffe://trust-domain/target-service",
    })
    if err != nil {
        log.Fatal("Failed to get JWT-SVID:", err)
    }

    fmt.Printf("SPIFFE ID: %s\\n", svid.ID)
    fmt.Printf("Audience:  %v\\n", svid.Audience)
    fmt.Printf("Expiry:    %s\\n", svid.Expiry)
    fmt.Printf("Token:     %s\\n", svid.Marshal())  // Compact JWT string

    // JWT-SVID Claims (JWT-SVID spec §3):
    // {
    //   "sub": "spiffe://trust-domain/workload/caller",     ← SPIFFE ID
    //   "aud": ["spiffe://trust-domain/target-service"],     ← intended recipient
    //   "exp": 1740000000,                                   ← short-lived (~5 min)
    //   "iat": 1739999700
    // }

    // Use the JWT-SVID as a Bearer token in HTTP requests
    // req.Header.Set("Authorization", "Bearer " + svid.Marshal())
    //
    // The receiving service validates using FetchJWTBundles
    // and checks: signature, sub (SPIFFE ID), aud (matches self), exp
}`,
  },

  /* ------------------------------------------------------------------ */
  'mtls-handshake': {
    language: 'go',
    label: 'Go (Server + Client)',
    code: `// mTLS with X.509-SVIDs (SPIFFE X.509-SVID spec §5)
// Both sides present SPIFFE-issued certificates and verify against the
// SPIFFE trust bundle (NOT system CA store).

package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "log"
    "net/http"

    "github.com/spiffe/go-spiffe/v2/spiffetls"
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
    "github.com/spiffe/go-spiffe/v2/workloadapi"
)

// === SERVER: Accept mTLS connections ===
func server(ctx context.Context) {
    // AuthorizeMemberOf allows any workload in the trust domain
    listener, err := spiffetls.Listen(ctx, "tcp", ":8443",
        tlsconfig.AuthorizeMemberOf("spiffe://trust-domain"),
    )
    if err != nil {
        log.Fatal("Failed to create mTLS listener:", err)
    }

    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        tlsConn := conn.(*tls.Conn)
        peerCerts := tlsConn.ConnectionState().PeerCertificates
        peerID := peerCerts[0].URIs[0] // Peer's SPIFFE ID from URI SAN

        fmt.Printf("Authenticated peer: %s\\n", peerID)
        fmt.Printf("TLS Version:        %s\\n", tlsVersionName(tlsConn))
        fmt.Printf("Cipher Suite:       %s\\n", tls.CipherSuiteName(
            tlsConn.ConnectionState().CipherSuite))

        // Perform SPIFFE-ID-based authorization here:
        // e.g. only allow spiffe://trust-domain/frontend to call this API
        conn.Close()
    }
}

// === CLIENT: Dial with mTLS ===
func client(ctx context.Context) {
    source, _ := workloadapi.NewX509Source(ctx)
    defer source.Close()

    // AuthorizeID restricts which server SPIFFE IDs are accepted
    tlsConfig := tlsconfig.MTLSClientConfig(source, source,
        tlsconfig.AuthorizeID("spiffe://trust-domain/backend"),
    )

    httpClient := &http.Client{
        Transport: &http.Transport{TLSClientConfig: tlsConfig},
    }
    resp, _ := httpClient.Get("https://backend.svc:8443/api/data")
    // Both sides verified: server presented its SVID, client presented its SVID,
    // both validated against the SPIFFE trust bundle.
}`,
  },

  /* ------------------------------------------------------------------ */
  'certificate-rotation': {
    language: 'go',
    label: 'Go (Workload)',
    code: `// Automatic Certificate Rotation via SPIRE Streaming API
// SPIFFE Workload API spec §5 — X509-SVIDs are delivered via
// server-streaming RPC and automatically rotated.

package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
    ctx := context.Background()

    // X509Source uses the FetchX509SVID streaming RPC under the hood.
    // The SPIRE Agent pushes new SVIDs automatically when rotation occurs.
    source, err := workloadapi.NewX509Source(ctx,
        workloadapi.WithClientOptions(
            workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock"),
        ),
    )
    if err != nil {
        log.Fatal("Failed to create X509Source:", err)
    }
    defer source.Close()

    // Monitor certificate rotation
    // SPIRE rotates at ~50% of TTL to ensure overlap:
    //   Default TTL: 1 hour → Rotation at ~30 minutes
    //   Short TTL:   5 min  → Rotation at ~2.5 minutes
    //
    // During rotation:
    //   1. Agent requests new SVID from Server
    //   2. Server issues new cert with new serial number
    //   3. Agent pushes update via streaming API
    //   4. X509Source swaps the certificate atomically
    //   5. New TLS connections use the new cert immediately
    //   6. Existing connections continue with old cert until closed

    var lastSerial string
    for {
        svid, err := source.GetX509SVID()
        if err != nil {
            log.Printf("Error getting SVID: %v", err)
            time.Sleep(5 * time.Second)
            continue
        }

        cert := svid.Certificates[0]
        serial := cert.SerialNumber.String()

        if serial != lastSerial {
            if lastSerial != "" {
                fmt.Printf("ROTATED: %s → %s\\n", lastSerial, serial)
            }
            fmt.Printf("SPIFFE ID:  %s\\n", svid.ID)
            fmt.Printf("Serial:     %s\\n", serial)
            fmt.Printf("Not After:  %s\\n", cert.NotAfter)
            fmt.Printf("TTL:        %s\\n", time.Until(cert.NotAfter).Round(time.Second))
            lastSerial = serial
        }

        time.Sleep(10 * time.Second)
    }
}`,
  },
}
