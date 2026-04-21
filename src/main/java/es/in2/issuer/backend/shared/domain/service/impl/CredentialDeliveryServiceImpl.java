package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.ResponseUriDeliveryException;
import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriDeliveryResult;
import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriRequest;
import es.in2.issuer.backend.shared.domain.service.CredentialDeliveryService;
import es.in2.issuer.backend.shared.infrastructure.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
@Service
public class CredentialDeliveryServiceImpl implements CredentialDeliveryService {

    private final WebClientConfig webClient;

    @Override
    public Mono<ResponseUriDeliveryResult> deliverLabelToResponseUri(String responseUri, String encodedVc, String credId, String bearerToken) {
        ResponseUriRequest responseUriRequest = ResponseUriRequest.builder()
                .encodedVc(encodedVc)
                .build();
        log.debug("[RESPONSE-URI] Starting PATCH request to: {} for credId: {}", responseUri, credId);

        return webClient.commonWebClient()
                .patch()
                .uri(responseUri)
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken)
                .bodyValue(responseUriRequest)
                .exchangeToMono(response -> {
                    log.debug("[RESPONSE-URI] Received response: {} from {}", response.statusCode(), responseUri);
                    if (response.statusCode().is2xxSuccessful()) {
                        if (HttpStatus.ACCEPTED.equals(response.statusCode())) {
                            log.debug("[RESPONSE-URI] SUCCESS: Received 202 ACCEPTED from response_uri for credId: {}", credId);
                            return response.bodyToMono(String.class)
                                    .map(ResponseUriDeliveryResult::acceptedWithHtml)
                                    .defaultIfEmpty(ResponseUriDeliveryResult.success());
                        }
                        log.debug("[RESPONSE-URI] SUCCESS: Received {} from response_uri for credId: {}", response.statusCode(), credId);
                        return response.releaseBody().thenReturn(ResponseUriDeliveryResult.success());
                    } else {
                        int statusCode = response.statusCode().value();
                        log.debug("[RESPONSE-URI] FAILURE: Non-2xx status code received: {} from {} for credId: {}",
                                response.statusCode(), responseUri, credId);
                        return response.releaseBody().then(Mono.error(new ResponseUriDeliveryException(
                                "Failed to upload credential to response URI: " + response.statusCode(),
                                statusCode, responseUri, credId
                        )));
                    }
                });
    }
}