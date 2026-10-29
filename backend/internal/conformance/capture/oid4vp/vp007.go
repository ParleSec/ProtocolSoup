package oid4vp

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.Register("VP-007", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "final-vp-formats-supported",
			Description: "The conformance client fetches a request object from the request_uri of a request created without its own client_metadata. Its client_metadata.vp_formats_supported must use the OpenID4VP 1.0 Appendix B parameter names, sd-jwt_alg_values and kb-jwt_alg_values for dc+sd-jwt and issuerauth_alg_values and deviceauth_alg_values for mso_mdoc, with integer COSE algorithm identifiers for mso_mdoc.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         finalVPFormatsSupported,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "vp_formats_supported is metadata the verifier publishes about itself, and OpenID4VP defines no wallet or client request that could make it wrong, so there is nothing for the verifier to reject.",
		},
	})
}

// finalVPFormatsSupported checks the verifier's default vp_formats_supported
// against OID4VP 1.0 Section 11.1 and Appendix B.
func finalVPFormatsSupported(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	_, requestURI, err := createRequest(ctx, env, requestOptions{responseMode: "direct_post", vct: env.BaseURL + "/credentials/university_degree"})
	if err != nil {
		return "", err
	}
	object, err := fetchRequestObject(ctx, env, requestURI)
	if err != nil {
		return "", err
	}
	metadata, _ := object.claims["client_metadata"].(map[string]any)
	formats, _ := metadata["vp_formats_supported"].(map[string]any)
	if len(formats) == 0 {
		return "", fmt.Errorf("request object client_metadata has no vp_formats_supported")
	}
	if err := checkVPFormats(formats); err != nil {
		return "", err
	}
	return conformance.OutcomeAccepted, nil
}

func checkVPFormats(formats map[string]any) error {
	names := make([]string, 0, len(formats))
	for name := range formats {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, ok := formats[name].(map[string]any)
		if !ok {
			return fmt.Errorf("vp_formats_supported.%s is not an object", name)
		}
		for parameter := range entry {
			if strings.HasSuffix(parameter, "_supported") {
				return fmt.Errorf("vp_formats_supported.%s uses %s, which OpenID4VP 1.0 Appendix B does not define", name, parameter)
			}
		}
	}
	sdJWT, _ := formats["dc+sd-jwt"].(map[string]any)
	for _, parameter := range []string{"sd-jwt_alg_values", "kb-jwt_alg_values"} {
		values, _ := sdJWT[parameter].([]any)
		if len(values) == 0 {
			return fmt.Errorf("vp_formats_supported.dc+sd-jwt has no %s", parameter)
		}
		for _, value := range values {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("vp_formats_supported.dc+sd-jwt.%s carries %v, want JOSE algorithm names", parameter, value)
			}
		}
	}
	mdoc, _ := formats["mso_mdoc"].(map[string]any)
	for _, parameter := range []string{"issuerauth_alg_values", "deviceauth_alg_values"} {
		values, _ := mdoc[parameter].([]any)
		if len(values) == 0 {
			return fmt.Errorf("vp_formats_supported.mso_mdoc has no %s", parameter)
		}
		for _, value := range values {
			number, ok := value.(float64)
			if !ok || number != math.Trunc(number) {
				return fmt.Errorf("vp_formats_supported.mso_mdoc.%s carries %v, want integer COSE algorithm identifiers", parameter, value)
			}
		}
	}
	return nil
}
