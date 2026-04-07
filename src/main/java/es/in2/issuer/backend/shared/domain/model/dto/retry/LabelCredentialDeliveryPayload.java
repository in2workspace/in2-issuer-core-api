package es.in2.issuer.backend.shared.domain.model.dto.retry;

import lombok.Builder;

/**
 * Payload for UPLOAD_LABEL_TO_RESPONSE_URI delivery/retry action
 */
@Builder
public record LabelCredentialDeliveryPayload(
        String responseUri,
        String credentialId, 
        String companyEmail,
        String signedCredential
) {
}