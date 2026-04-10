package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.ResponseUriDeliveryException;
import es.in2.issuer.backend.shared.infrastructure.config.WebClientConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.net.URI;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CredentialDeliveryServiceImplTest {

    private WebClientConfig webClientConfig;
    private ExchangeFunction exchangeFunction;
    private CredentialDeliveryServiceImpl service;

    private static final String RESPONSE_URI = "http://example.com/endpoint";
    private static final String ENC_VC = "encoded-vc";
    private static final String CRED_ID = "cred-123";
    private static final String BEARER = "token-xyz";

    @BeforeEach
    void setup() {
        webClientConfig = mock(WebClientConfig.class);
        exchangeFunction = mock(ExchangeFunction.class);

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        when(webClientConfig.commonWebClient()).thenReturn(webClient);

        service = new CredentialDeliveryServiceImpl(webClientConfig);
    }

    @Test
    void whenAccepted202_thenReturnAcceptedWithHtml() {
        ClientResponse clientResponse = mock(ClientResponse.class);
        when(clientResponse.statusCode()).thenReturn(HttpStatus.ACCEPTED);
        when(clientResponse.bodyToMono(String.class))
                .thenReturn(Mono.just("<html>missing docs</html>"));
        when(clientResponse.releaseBody()).thenReturn(Mono.empty());
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        StepVerifier.create(service.deliverLabelToResponseUri(RESPONSE_URI, ENC_VC, CRED_ID, BEARER))
                .assertNext(result -> {
                    assertTrue(result.acceptedWithHtml());
                    assertEquals("<html>missing docs</html>", result.html());
                })
                .verifyComplete();
    }

    @Test
    void whenOk200_thenReturnSuccess() {
        ClientResponse clientResponse = ClientResponse
                .create(HttpStatus.OK)
                .build();
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        StepVerifier.create(service.deliverLabelToResponseUri(RESPONSE_URI, ENC_VC, CRED_ID, BEARER))
                .assertNext(result -> {
                    assertFalse(result.acceptedWithHtml());
                    assertNull(result.html());
                })
                .verifyComplete();
    }

    @Test
    void whenErrorStatus_thenPropagateResponseUriDeliveryException() {
        ClientResponse clientResponse = mock(ClientResponse.class);
        when(clientResponse.statusCode()).thenReturn(HttpStatus.BAD_REQUEST);
        when(clientResponse.releaseBody()).thenReturn(Mono.empty());
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        StepVerifier.create(service.deliverLabelToResponseUri(RESPONSE_URI, ENC_VC, CRED_ID, BEARER))
                .expectErrorSatisfies(error -> {
                    assertInstanceOf(ResponseUriDeliveryException.class, error);
                    ResponseUriDeliveryException ex = (ResponseUriDeliveryException) error;
                    assertEquals(400, ex.getHttpStatusCode());
                    assertEquals(RESPONSE_URI, ex.getResponseUri());
                    assertEquals(CRED_ID, ex.getCredentialId());
                })
                .verify();
    }

    @Test
    void whenNetworkError_thenPropagateException() {
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.error(
                        new WebClientRequestException(
                                new IOException("network error"),
                                HttpMethod.PATCH,
                                URI.create(RESPONSE_URI),
                                new HttpHeaders()
                        )
                ));

        StepVerifier.create(service.deliverLabelToResponseUri(RESPONSE_URI, ENC_VC, CRED_ID, BEARER))
                .expectError(WebClientRequestException.class)
                .verify();
    }
}
