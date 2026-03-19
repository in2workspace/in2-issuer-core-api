package es.in2.issuer.backend.shared.domain.model.dto.credential;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

import java.util.List;

@Builder
public record LabelCredential(
        @JsonProperty("@context") List<String> context,
        @JsonProperty("id") String id,
        @JsonProperty("type") List<String> type,

        @JsonProperty("issuer")
        @JsonDeserialize(using = IssuerDeserializer.class)
        Issuer issuer,

        @NotNull
        @Valid
        @JsonProperty("credentialSubject")
        CredentialSubject credentialSubject,

        @JsonProperty("validFrom") String validFrom,

        @JsonProperty("validUntil") String validUntil,

        @JsonProperty("credentialStatus")
        CredentialStatus credentialStatus
) {
    @Builder
    public record CredentialSubject(
            @NotBlank
            @JsonProperty("id") String id,

            @NotBlank
            @JsonProperty("gx:labelLevel") String gxLabelLevel,

            @NotBlank
            @JsonProperty("gx:engineVersion") String gxEngineVersion,

            @NotBlank
            @JsonProperty("gx:rulesVersion") String gxRulesVersion,

            @NotEmpty
            @Valid
            @JsonProperty("gx:compliantCredentials") List<CompliantCredentials> gxCompliantCredentials,

            @NotEmpty
            @JsonProperty("gx:validatedCriteria") List<String> gxValidatedCriteria
    ) {
        @Builder
        public record CompliantCredentials(
                @NotBlank
                @JsonProperty("id") String id,

                @NotBlank
                @JsonProperty("type") String type,

                @NotBlank
                @JsonProperty("gx:digestSRI") String gxDigestSRI
        ) {
        }
    }
}
