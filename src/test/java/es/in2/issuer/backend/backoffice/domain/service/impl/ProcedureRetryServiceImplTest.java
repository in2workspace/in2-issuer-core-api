package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.ProcedureRetryRecordNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.InvalidRetryStatusException;
import es.in2.issuer.backend.shared.domain.exception.RetryPayloadException;
import es.in2.issuer.backend.shared.domain.exception.ResponseUriDeliveryException;
import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriDeliveryResult;
import es.in2.issuer.backend.shared.domain.model.dto.VerifierOauth2AccessToken;
import es.in2.issuer.backend.shared.domain.model.dto.retry.LabelCredentialDeliveryPayload;
import es.in2.issuer.backend.shared.domain.model.entities.ProcedureRetry;
import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import es.in2.issuer.backend.shared.domain.model.enums.RetryStatus;
import es.in2.issuer.backend.shared.domain.service.CredentialDeliveryService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.M2MTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.backoffice.infrastructure.repository.ProcedureRetryRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ProcedureRetryServiceImplTest {

    @Mock
    private ProcedureRetryRepository procedureRetryRepository;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private CredentialDeliveryService credentialDeliveryService;

    @Mock
    private M2MTokenService m2mTokenService;

    @Mock
    private EmailService emailService;

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private ProcedureRetryServiceImpl service;

    // ──────────────────────────────────────────────────────────────────────
    // Test fixtures
    // ──────────────────────────────────────────────────────────────────────

    private static final UUID PROCEDURE_ID = UUID.fromString("d290f1ee-6c54-4b01-90e6-d701748f0851");
    private static final String RESPONSE_URI = "https://example.com/response";
    private static final String SIGNED_CREDENTIAL = "signed.credential.jwt";
    private static final String CREDENTIAL_ID = "cred-123";
    private static final String COMPANY_EMAIL = "company@example.com";
    private static final String GUIDE_URL = "https://guide.example.com";
    private static final VerifierOauth2AccessToken M2M_TOKEN =
            VerifierOauth2AccessToken.builder().accessToken("m2m-token").build();

    private LabelCredentialDeliveryPayload buildPayload() {
        return LabelCredentialDeliveryPayload.builder()
                .responseUri(RESPONSE_URI)
                .signedCredential(SIGNED_CREDENTIAL)
                .credentialId(CREDENTIAL_ID)
                .companyEmail(COMPANY_EMAIL)
                .build();
    }

    private ProcedureRetry buildPendingRecord(String payloadJson) {
        return ProcedureRetry.builder()
                .id(UUID.randomUUID())
                .procedureId(PROCEDURE_ID)
                .actionType(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI)
                .status(RetryStatus.PENDING)
                .attemptCount(0)
                .firstFailureAt(Instant.now())
                .payload(payloadJson)
                .build();
    }

    // ──────────────────────────────────────────────────────────────────────
    // handleInitialAction
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void handleInitialAction_deliverySucceeds_withHtmlResponse_sendsHtmlEmail() {
        ResponseUriDeliveryResult htmlResult = ResponseUriDeliveryResult.acceptedWithHtml("<html/>");
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(RESPONSE_URI, SIGNED_CREDENTIAL, CREDENTIAL_ID, "m2m-token"))
                .thenReturn(Mono.just(htmlResult));
        when(emailService.sendResponseUriAcceptedWithHtml(COMPANY_EMAIL, CREDENTIAL_ID, "<html/>"))
                .thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verify(emailService).sendResponseUriAcceptedWithHtml(COMPANY_EMAIL, CREDENTIAL_ID, "<html/>");
        verify(emailService, never()).sendCertificationUploaded(any(), any());
    }

    @Test
    void handleInitialAction_deliverySucceeds_noHtml_sendsCertificationUploadedEmail() {
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(RESPONSE_URI, SIGNED_CREDENTIAL, CREDENTIAL_ID, "m2m-token"))
                .thenReturn(Mono.just(ResponseUriDeliveryResult.success()));
        when(emailService.sendCertificationUploaded(COMPANY_EMAIL, CREDENTIAL_ID)).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verify(emailService).sendCertificationUploaded(COMPANY_EMAIL, CREDENTIAL_ID);
        verify(emailService, never()).sendResponseUriAcceptedWithHtml(any(), any(), any());
    }

    @Test
    void handleInitialAction_deliverySucceeds_nullEmail_noEmailSent() {
        LabelCredentialDeliveryPayload payload = LabelCredentialDeliveryPayload.builder()
                .responseUri(RESPONSE_URI).signedCredential(SIGNED_CREDENTIAL)
                .credentialId(CREDENTIAL_ID).companyEmail(null).build();
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.just(ResponseUriDeliveryResult.success()));

        StepVerifier.create(service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, payload))
                .verifyComplete();

        verifyNoInteractions(emailService);
    }

    @Test
    void handleInitialAction_deliverySucceeds_blankEmail_noEmailSent() {
        LabelCredentialDeliveryPayload payload = LabelCredentialDeliveryPayload.builder()
                .responseUri(RESPONSE_URI).signedCredential(SIGNED_CREDENTIAL)
                .credentialId(CREDENTIAL_ID).companyEmail("   ").build();
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.just(ResponseUriDeliveryResult.success()));

        StepVerifier.create(service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, payload))
                .verifyComplete();

        verifyNoInteractions(emailService);
    }

    @Test
    void handleInitialAction_deliverySucceeds_emailFails_errorSwallowed() {
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.just(ResponseUriDeliveryResult.success()));
        when(emailService.sendCertificationUploaded(any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unavailable")));

        StepVerifier.create(service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();
    }

    @Test
    void handleInitialAction_nonRetryableError_createsRetryRecord_sendsFailureEmail() {
        WebClientResponseException badRequest = WebClientResponseException.create(400, "Bad Request", null, null, null);
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(badRequest));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(COMPANY_EMAIL, CREDENTIAL_ID, GUIDE_URL)).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        // Delivery attempted exactly once (400 is not retryable)
        verify(credentialDeliveryService, times(1)).deliverLabelToResponseUri(any(), any(), any(), any());
        verify(procedureRetryRepository).upsert(any());
        verify(emailService).sendResponseUriFailed(COMPANY_EMAIL, CREDENTIAL_ID, GUIDE_URL);
    }

    @Test
    void handleInitialAction_nonRetryableError_nullEmail_noFailureEmail() {
        LabelCredentialDeliveryPayload payload = LabelCredentialDeliveryPayload.builder()
                .responseUri(RESPONSE_URI).signedCredential(SIGNED_CREDENTIAL)
                .credentialId(CREDENTIAL_ID).companyEmail(null).build();
        WebClientResponseException badRequest = WebClientResponseException.create(400, "Bad Request", null, null, null);
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(badRequest));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));

        StepVerifier.create(service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, payload))
                .verifyComplete();

        verifyNoInteractions(emailService);
    }

    @Test
    void handleInitialAction_invalidPayloadType_throwsRetryPayloadException() {
        // castPayload() throws synchronously (not via Mono.error) – assertThrows is the right approach
        assertThrows(RetryPayloadException.class, () ->
                service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, "not-a-valid-payload"));
    }

    @Test
    void handleInitialAction_nullPayload_throwsRetryPayloadException() {
        assertThrows(RetryPayloadException.class, () ->
                service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, null));
    }

    // ──────────────────────────────────────────────────────────────────────
    // Retryable errors - use virtual time to skip actual delays
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void handleInitialAction_retryableError_5xx_allRetriesExhausted_createsRetryRecord() {
        WebClientResponseException serverError = WebClientResponseException.create(500, "Internal Server Error", null, null, null);
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(serverError));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() ->
                        service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(2))   // delay after retry 2
                .thenAwait(Duration.ofMinutes(5))   // delay after retry 2
                .thenAwait(Duration.ofMinutes(15))  // delay after retry 3
                .verifyComplete();

        // Original call + 3 retries = 4 total attempts
        verify(credentialDeliveryService, times(4)).deliverLabelToResponseUri(any(), any(), any(), any());
        verify(procedureRetryRepository).upsert(any());
    }

    @Test
    void handleInitialAction_nonRetryableError_401_createsRetryRecordAndSendsFailureNotification() {
        WebClientResponseException unauthorized =
                WebClientResponseException.create(401, "Unauthorized", null, null, null);

        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(unauthorized));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(
                        service.handleInitialAction(
                                PROCEDURE_ID,
                                ActionType.UPLOAD_LABEL_TO_RESPONSE_URI,
                                buildPayload()
                        )
                )
                .verifyComplete();

        verify(m2mTokenService, times(1)).getM2MToken();
        verify(credentialDeliveryService, times(1)).deliverLabelToResponseUri(any(), any(), any(), any());
        verify(procedureRetryRepository, times(1)).upsert(any());
        verify(emailService, times(1)).sendResponseUriFailed(any(), any(), any());
    }

    @Test
    void handleInitialAction_nonRetryableError_403_createsRetryRecordAndSendsFailureNotification() {
        WebClientResponseException forbidden =
                WebClientResponseException.create(403, "Forbidden", null, null, null);

        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(forbidden));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(
                        service.handleInitialAction(
                                PROCEDURE_ID,
                                ActionType.UPLOAD_LABEL_TO_RESPONSE_URI,
                                buildPayload()
                        )
                )
                .verifyComplete();

        verify(m2mTokenService, times(1)).getM2MToken();
        verify(credentialDeliveryService, times(1)).deliverLabelToResponseUri(any(), any(), any(), any());
        verify(procedureRetryRepository, times(1)).upsert(any());
        verify(emailService, times(1)).sendResponseUriFailed(any(), any(), any());
    }

    @Test
    void handleInitialAction_retryableError_408_allRetriesExhausted() {
        WebClientResponseException timeout = WebClientResponseException.create(408, "Request Timeout", null, null, null);
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(timeout));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() ->
                        service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(22))
                .verifyComplete();

        verify(credentialDeliveryService, times(4)).deliverLabelToResponseUri(any(), any(), any(), any());
    }

    @Test
    void handleInitialAction_retryableError_429_allRetriesExhausted() {
        WebClientResponseException tooMany = WebClientResponseException.create(429, "Too Many Requests", null, null, null);
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(tooMany));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() ->
                        service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(22))
                .verifyComplete();

        verify(credentialDeliveryService, times(4)).deliverLabelToResponseUri(any(), any(), any(), any());
    }

    @Test
    void handleInitialAction_retryableError_connectException_allRetriesExhausted() {
        ConnectException connectException = new ConnectException("Connection refused");
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(connectException));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() ->
                        service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(22))
                .verifyComplete();

        verify(credentialDeliveryService, times(4)).deliverLabelToResponseUri(any(), any(), any(), any());
    }

    @Test
    void handleInitialAction_retryableError_timeoutException_allRetriesExhausted() {
        TimeoutException timeoutException = new TimeoutException("Timed out");
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(timeoutException));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() ->
                        service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(22))
                .verifyComplete();

        verify(credentialDeliveryService, times(4)).deliverLabelToResponseUri(any(), any(), any(), any());
    }

    @Test
    void handleInitialAction_retryableError_webClientRequestException_allRetriesExhausted() {
        WebClientRequestException requestException = new WebClientRequestException(
                new IOException("Network error"), HttpMethod.POST, URI.create(RESPONSE_URI), new HttpHeaders());
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(requestException));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() ->
                        service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(22))
                .verifyComplete();

        verify(credentialDeliveryService, times(4)).deliverLabelToResponseUri(any(), any(), any(), any());
    }

    @Test
    void handleInitialAction_retryableError_responseUriDeliveryException_5xx_allRetriesExhausted() {
        ResponseUriDeliveryException ex = new ResponseUriDeliveryException("Service unavailable", 503, RESPONSE_URI, CREDENTIAL_ID);
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(ex));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() ->
                        service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(22))
                .verifyComplete();

        verify(credentialDeliveryService, times(4)).deliverLabelToResponseUri(any(), any(), any(), any());
    }

    @Test
    void handleInitialAction_nonRetryableError_responseUriDeliveryException_400_noRetries() {
        ResponseUriDeliveryException ex = new ResponseUriDeliveryException("Bad request", 400, RESPONSE_URI, CREDENTIAL_ID);
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(ex));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verify(credentialDeliveryService, times(1)).deliverLabelToResponseUri(any(), any(), any(), any());
    }

    @Test
    void handleInitialAction_nonRetryableError_genericException_noRetries() {
        RuntimeException ex = new RuntimeException("Generic unexpected error");
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(ex));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriFailed(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verify(credentialDeliveryService, times(1)).deliverLabelToResponseUri(any(), any(), any(), any());
    }

    @Test
    void handleInitialAction_retrySucceeds_onSecondAttempt_completesWithSuccessEmail() {
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(
                        Mono.error(WebClientResponseException.create(500, "Server Error", null, null, null)),
                        Mono.just(ResponseUriDeliveryResult.success())
                );
        when(emailService.sendCertificationUploaded(COMPANY_EMAIL, CREDENTIAL_ID)).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() ->
                        service.handleInitialAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(2)) // retry 2 delay
                .verifyComplete();

        verify(credentialDeliveryService, times(2)).deliverLabelToResponseUri(any(), any(), any(), any());
        verify(emailService).sendCertificationUploaded(COMPANY_EMAIL, CREDENTIAL_ID);
        verify(procedureRetryRepository, never()).upsert(any());
    }

    // ──────────────────────────────────────────────────────────────────────
    // processPendingRetries
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void processPendingRetries_noPendingRecords_completesImmediately() {
        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING)).thenReturn(Flux.empty());

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        verifyNoInteractions(m2mTokenService, credentialDeliveryService, emailService);
    }

    @Test
    void processPendingRetries_deliverySucceeds_marksCompletedAndSendsEmail() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING)).thenReturn(Flux.just(retryRecord));
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.just(ResponseUriDeliveryResult.success()));
        when(procedureRetryRepository.markAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(emailService.sendCertificationUploaded(COMPANY_EMAIL, CREDENTIAL_ID)).thenReturn(Mono.empty());

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        verify(procedureRetryRepository).markAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
        verify(emailService).sendCertificationUploaded(COMPANY_EMAIL, CREDENTIAL_ID);
        verify(procedureRetryRepository, never()).incrementAttemptCount(any(), any(), any());
    }

    @Test
    void processPendingRetries_deliverySucceeds_withHtml_marksCompletedAndSendsHtmlEmail() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING)).thenReturn(Flux.just(retryRecord));
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.just(ResponseUriDeliveryResult.acceptedWithHtml("<html/>")));
        when(procedureRetryRepository.markAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(emailService.sendResponseUriAcceptedWithHtml(COMPANY_EMAIL, CREDENTIAL_ID, "<html/>"))
                .thenReturn(Mono.empty());

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        verify(procedureRetryRepository).markAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
        verify(emailService).sendResponseUriAcceptedWithHtml(COMPANY_EMAIL, CREDENTIAL_ID, "<html/>");
    }

    @Test
    void processPendingRetries_deliveryFails_nonRetryableError_incrementsAttemptCount() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);
        WebClientResponseException badRequest = WebClientResponseException.create(400, "Bad Request", null, null, null);

        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING)).thenReturn(Flux.just(retryRecord));
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.error(badRequest));
        when(procedureRetryRepository.incrementAttemptCount(eq(PROCEDURE_ID), eq(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any()))
                .thenReturn(Mono.just(1));

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        verify(procedureRetryRepository).incrementAttemptCount(eq(PROCEDURE_ID), eq(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any());
        verify(procedureRetryRepository, never()).markAsCompleted(any(), any());
        verifyNoInteractions(emailService);
    }

    @Test
    void processPendingRetries_deserializationFails_incrementsAttemptCount() {
        ProcedureRetry retryRecord = buildPendingRecord("NOT_VALID_JSON{{{");

        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING)).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.incrementAttemptCount(eq(PROCEDURE_ID), eq(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any()))
                .thenReturn(Mono.just(1));

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        verify(procedureRetryRepository).incrementAttemptCount(eq(PROCEDURE_ID), eq(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any());
        verifyNoInteractions(m2mTokenService, credentialDeliveryService, emailService);
    }

    @Test
    void processPendingRetries_incrementAttemptCountFails_outerErrorResumeContinues() throws Exception {
        // The outer onErrorResume in processPendingRetries swallows errors from executeRetryAction
        // (including errors propagated from updateRetryAfterScheduledFailure if incrementAttemptCount fails)
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry failingRecord = buildPendingRecord("INVALID_JSON");
        UUID otherProcedureId = UUID.randomUUID();
        ProcedureRetry successRecord = ProcedureRetry.builder()
                .id(UUID.randomUUID())
                .procedureId(otherProcedureId)
                .actionType(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI)
                .status(RetryStatus.PENDING)
                .attemptCount(0)
                .firstFailureAt(Instant.now())
                .payload(payloadJson)
                .build();

        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING))
                .thenReturn(Flux.just(failingRecord, successRecord));
        // For failingRecord: deserialization fails → incrementAttemptCount fails → outer onErrorResume
        when(procedureRetryRepository.incrementAttemptCount(eq(PROCEDURE_ID), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("DB error")));
        // For successRecord: delivery succeeds → markAsCompleted
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.just(ResponseUriDeliveryResult.success()));
        when(procedureRetryRepository.markAsCompleted(otherProcedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(emailService.sendCertificationUploaded(COMPANY_EMAIL, CREDENTIAL_ID)).thenReturn(Mono.empty());

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        // Second record was still processed despite first failing
        verify(procedureRetryRepository).markAsCompleted(otherProcedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
    }

    // ──────────────────────────────────────────────────────────────────────
    // createRetryRecord
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void createRetryRecord_success_upsertsRecord() {
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));

        StepVerifier.create(service.createRetryRecord(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verify(procedureRetryRepository).upsert(any());
    }

    @Test
    void createRetryRecord_upsertReturnsZero_logsWarningButCompletes() {
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(0));

        StepVerifier.create(service.createRetryRecord(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verify(procedureRetryRepository).upsert(any());
    }

    @Test
    void createRetryRecord_serializationFails_returnsEmptyWithoutUpserting() throws Exception {
        doThrow(new RuntimeException("JSON serialization failed"))
                .when(objectMapper).writeValueAsString(any());

        StepVerifier.create(service.createRetryRecord(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verifyNoInteractions(procedureRetryRepository);
    }

    @Test
    void createRetryRecord_upsertFails_errorSwallowed() {
        when(procedureRetryRepository.upsert(any()))
                .thenReturn(Mono.error(new RuntimeException("DB connection lost")));

        StepVerifier.create(service.createRetryRecord(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();
    }

    // ──────────────────────────────────────────────────────────────────────
    // retryAction
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void retryAction_recordNotFound_throwsProcedureRetryRecordNotFound() {
        when(procedureRetryRepository.findByProcedureIdAndActionType(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.empty());

        StepVerifier.create(service.retryAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .expectErrorMatches(e -> e instanceof ProcedureRetryRecordNotFoundException
                        && e.getMessage().contains("No retry record found"))
                .verify();
    }

    @Test
    void retryAction_recordInCompletedStatus_throwsInvalidRetryStatus() {
        ProcedureRetry completed = ProcedureRetry.builder()
                .id(UUID.randomUUID()).procedureId(PROCEDURE_ID)
                .actionType(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI)
                .status(RetryStatus.COMPLETED).build();
        when(procedureRetryRepository.findByProcedureIdAndActionType(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(completed));

        StepVerifier.create(service.retryAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .expectErrorMatches(e -> e instanceof InvalidRetryStatusException
                        && e.getMessage().contains("not in PENDING status"))
                .verify();
    }

    @Test
    void retryAction_recordExhausted_throwsInvalidRetryStatus() {
        ProcedureRetry exhausted = ProcedureRetry.builder()
                .id(UUID.randomUUID()).procedureId(PROCEDURE_ID)
                .actionType(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI)
                .status(RetryStatus.RETRY_EXHAUSTED).build();
        when(procedureRetryRepository.findByProcedureIdAndActionType(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(exhausted));

        StepVerifier.create(service.retryAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .expectErrorMatches(e -> e instanceof InvalidRetryStatusException
                        && e.getMessage().contains("not in PENDING status"))
                .verify();
    }

    @Test
    void retryAction_pendingRecord_deliverySucceeds_marksCompleted() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findByProcedureIdAndActionType(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(retryRecord));
        when(m2mTokenService.getM2MToken()).thenReturn(Mono.just(M2M_TOKEN));
        when(credentialDeliveryService.deliverLabelToResponseUri(any(), any(), any(), any()))
                .thenReturn(Mono.just(ResponseUriDeliveryResult.success()));
        when(procedureRetryRepository.markAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(emailService.sendCertificationUploaded(COMPANY_EMAIL, CREDENTIAL_ID)).thenReturn(Mono.empty());

        StepVerifier.create(service.retryAction(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .verifyComplete();

        verify(procedureRetryRepository).markAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
    }

    // ──────────────────────────────────────────────────────────────────────
    // markRetryAsCompleted
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void markRetryAsCompleted_success_rowsAffected() {
        when(procedureRetryRepository.markAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));

        StepVerifier.create(service.markRetryAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .verifyComplete();

        verify(procedureRetryRepository).markAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
    }

    @Test
    void markRetryAsCompleted_noRowsAffected_logsWarningAndCompletes() {
        when(procedureRetryRepository.markAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(0));

        StepVerifier.create(service.markRetryAsCompleted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .verifyComplete();
    }

    // ──────────────────────────────────────────────────────────────────────
    // markRetryAsExhausted
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void markRetryAsExhausted_noOldPendingRecords_completesImmediately() {
        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.empty());

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();

        verify(procedureRetryRepository, never()).markAsExhausted(any(), any());
        verifyNoInteractions(emailService);
    }

    @Test
    void markRetryAsExhausted_oldRecord_marksExhaustedAndSendsExhaustionEmail() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriExhausted(COMPANY_EMAIL, CREDENTIAL_ID, GUIDE_URL)).thenReturn(Mono.empty());

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();

        verify(procedureRetryRepository).markAsExhausted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
        verify(emailService).sendResponseUriExhausted(COMPANY_EMAIL, CREDENTIAL_ID, GUIDE_URL);
    }

    @Test
    void markRetryAsExhausted_markAsExhaustedReturnsZero_logsWarningAndContinues() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(0));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriExhausted(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();
    }

    @Test
    void markRetryAsExhausted_blankEmail_noExhaustionEmail() throws Exception {
        LabelCredentialDeliveryPayload blankEmailPayload = LabelCredentialDeliveryPayload.builder()
                .responseUri(RESPONSE_URI).signedCredential(SIGNED_CREDENTIAL)
                .credentialId(CREDENTIAL_ID).companyEmail("").build();
        String payloadJson = objectMapper.writeValueAsString(blankEmailPayload);
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();

        verifyNoInteractions(emailService);
    }

    @Test
    void markRetryAsExhausted_emailFails_errorSwallowed() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriExhausted(any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unreachable")));

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();
    }

    @Test
    void markRetryAsExhausted_deserializationFails_errorSwallowed() {
        ProcedureRetry retryRecord = buildPendingRecord("NOT_VALID_JSON");

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();

        verifyNoInteractions(emailService);
    }

    @Test
    void markRetryAsExhausted_withCustomDuration_usesProvidedThreshold() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(appConfig.getKnowledgeBaseUploadCertificationGuideUrl()).thenReturn(GUIDE_URL);
        when(emailService.sendResponseUriExhausted(any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.markRetryAsExhausted(Duration.ofDays(7)))
                .verifyComplete();

        verify(procedureRetryRepository).findPendingRecordsOlderThan(any());
        verify(procedureRetryRepository).markAsExhausted(PROCEDURE_ID, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
    }

    @Test
    void markRetryAsExhausted_nullCustomDuration_fallsBackToDefaultThreshold() {
        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.empty());

        StepVerifier.create(service.markRetryAsExhausted(null))
                .verifyComplete();

        verify(procedureRetryRepository).findPendingRecordsOlderThan(any());
    }
}
