package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Check if SPIRE Server is healthy
		cmd := exec.Command("/opt/spire/bin/spire-server", "healthcheck",
			"-socketPath", "/run/spire/sockets/server.sock")
		output, err := cmd.CombinedOutput()
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "unhealthy: %s", string(output))
			return
		}
		if strings.Contains(string(output), "healthy") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "healthy")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "unhealthy: %s", string(output))
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "SPIRE Server - protocolsoup.com")
	})

	port := os.Getenv("HEALTH_PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Health server listening on :%s\n", port)
	http.ListenAndServe(":"+port, nil)
}

