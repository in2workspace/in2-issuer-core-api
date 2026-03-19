package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialRequest(
        @JsonProperty(value = "credential_configuration_id", required = true) String credentialConfigurationId,
        @JsonProperty(value = "format", required = true) String format,
        @JsonProperty(value = "proof") Proof proof) {
}
