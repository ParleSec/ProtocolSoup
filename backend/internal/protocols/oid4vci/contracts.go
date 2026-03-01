package oid4vci

import (
	"fmt"
	"strings"
)

// ValidateCredentialOfferEnvelope enforces that exactly one offer transport mode is used.
func ValidateCredentialOfferEnvelope(hasOfferByValue bool, hasOfferByReference bool) error {
	switch {
	case hasOfferByValue && hasOfferByReference:
		return fmt.Errorf("credential_offer and credential_offer_uri cannot both be present")
	case !hasOfferByValue && !hasOfferByReference:
		return fmt.Errorf("either credential_offer or credential_offer_uri is required")
	default:
		return nil
	}
}

// ValidatePreAuthorizedTxCodeRequirement enforces tx_code presence when the offer requires it.
func ValidatePreAuthorizedTxCodeRequirement(txCodeObjectPresent bool, txCodeValue string) error {
	if txCodeObjectPresent && strings.TrimSpace(txCodeValue) == "" {
		return fmt.Errorf("tx_code is required when tx_code object is present in credential offer")
	}
	return nil
}

// ValidateProofRequirement enforces proof submission requirements.
func ValidateProofRequirement(proofTypesDeclared bool, proofCount int) error {
	if proofTypesDeclared && proofCount <= 0 {
		return fmt.Errorf("proofs are required when proof_types_supported is declared")
	}
	return nil
}

// ValidateNonceEndpointRequirement enforces nonce endpoint requirement when c_nonce freshness is needed.
func ValidateNonceEndpointRequirement(cNonceRequired bool, nonceEndpoint string) error {
	if cNonceRequired && strings.TrimSpace(nonceEndpoint) == "" {
		return fmt.Errorf("nonce_endpoint is required when c_nonce freshness is enforced")
	}
	return nil
}

// ValidateOID4VCIProofType enforces OID4VCI proof JWT typ header value.
func ValidateOID4VCIProofType(typ string) error {
	if strings.TrimSpace(typ) != "openid4vci-proof+jwt" {
		return fmt.Errorf("proof jwt typ must be openid4vci-proof+jwt")
	}
	return nil
}
