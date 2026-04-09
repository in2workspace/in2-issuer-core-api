package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriDeliveryResult;
import reactor.core.publisher.Mono;

public interface CredentialDeliveryService {
    Mono<ResponseUriDeliveryResult> deliverLabelToResponseUri(String responseUri, String encodedVc, String credId, String bearerToken);
}
