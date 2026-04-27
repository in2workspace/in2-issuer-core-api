package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.model.dtos.RetryableProcedureAction;
import es.in2.issuer.backend.backoffice.domain.service.RetryableActionHandler;
import es.in2.issuer.backend.backoffice.domain.service.RetryableActionHandlerRegistry;
import es.in2.issuer.backend.backoffice.infrastructure.repository.ProcedureRetryRepository;
import es.in2.issuer.backend.shared.domain.exception.ResponseUriDeliveryException;
import es.in2.issuer.backend.shared.domain.exception.RetryPayloadException;
import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriDeliveryResult;
import es.in2.issuer.backend.shared.domain.model.dto.retry.LabelCredentialDeliveryPayload;
import es.in2.issuer.backend.shared.domain.model.entities.ProcedureRetry;
import es.in2.issuer.backend.shared.domain.model.enums.RetryableActionType;
import es.in2.issuer.backend.shared.domain.model.enums.RetryStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ProcedureRetryServiceImplTest {

    @Mock
    private ProcedureRetryRepository procedureRetryRepository;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private RetryableActionHandlerRegistry handlerRegistry;

    @InjectMocks
    private ProcedureRetryServiceImpl service;

    @SuppressWarnings("unchecked")
    private RetryableActionHandler<Object> mockHandler;

    private static final UUID PROCEDURE_ID = UUID.fromString("d290f1ee-6c54-4b01-90e6-d701748f0851");
    private static final String RESPONSE_URI = "https://example.com/response";
    private static final String SIGNED_CREDENTIAL = "signed.credential.jwt";
    private static final String CREDENTIAL_ID = "cred-123";
    private static final String PRODUCT_SPECIFICATION_ID = "product-spec-456";
    private static final String COMPANY_EMAIL = "company@example.com";

    @SuppressWarnings("unchecked")
    @BeforeEach
    void setUp() {
        mockHandler = mock(RetryableActionHandler.class);
        lenient().when(handlerRegistry.getHandler(RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(mockHandler);
        lenient().when(mockHandler.getPayloadType())
                .thenReturn((Class) LabelCredentialDeliveryPayload.class);
        lenient().when(mockHandler.getInitialRetryAttempts()).thenReturn(3);
        lenient().when(mockHandler.getInitialRetryDelays()).thenReturn(new Duration[]{
                Duration.ofMinutes(2),
                Duration.ofMinutes(5),
                Duration.ofMinutes(15)
        });
    }

    private LabelCredentialDeliveryPayload buildPayload() {
        return LabelCredentialDeliveryPayload.builder()
                .responseUri(RESPONSE_URI)
                .signedCredential(SIGNED_CREDENTIAL)
                .credentialId(CREDENTIAL_ID)
                .productSpecificationId(PRODUCT_SPECIFICATION_ID)
                .email(COMPANY_EMAIL)
                .build();
    }

    private RetryableProcedureAction<LabelCredentialDeliveryPayload> buildAction() {
        return new RetryableProcedureAction<>(
                RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI,
                buildPayload(),
                PROCEDURE_ID
        );
    }

    private ProcedureRetry buildPendingRecord(String payloadJson) {
        return ProcedureRetry.builder()
                .id(UUID.randomUUID())
                .procedureId(PROCEDURE_ID)
                .actionType(RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI)
                .status(RetryStatus.PENDING)
                .attemptCount(0)
                .firstFailureAt(Instant.now())
                .payload(payloadJson)
                .build();
    }

    private static Stream<WebClientResponseException> nonRetryableUnauthorizedOrForbiddenErrors() {
        return Stream.of(
                WebClientResponseException.create(401, "Unauthorized", null, null, null),
                WebClientResponseException.create(403, "Forbidden", null, null, null)
        );
    }

    private static Stream<Throwable> retryableErrorsWithVirtualTime() {
        return Stream.of(
                WebClientResponseException.create(408, "Request Timeout", null, null, null),
                WebClientResponseException.create(429, "Too Many Requests", null, null, null),
                new ConnectException("Connection refused"),
                new TimeoutException("Timed out"),
                new WebClientRequestException(
                        new IOException("Network error"),
                        HttpMethod.POST,
                        URI.create(RESPONSE_URI),
                        new HttpHeaders()
                ),
                new ResponseUriDeliveryException("Service unavailable", 503, RESPONSE_URI, CREDENTIAL_ID)
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // handleInitialAction
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void handleInitialAction_deliverySucceeds_callsOnInitialSuccess() {
        ResponseUriDeliveryResult result = ResponseUriDeliveryResult.success();
        when(mockHandler.execute(any())).thenReturn(Mono.just(result));
        when(mockHandler.onInitialSuccess(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(buildAction()))
                .verifyComplete();

        verify(mockHandler).onInitialSuccess(any(), eq(result));
        verify(mockHandler, never()).onInitialFailure(any());
        verify(procedureRetryRepository, never()).upsert(any());
    }

    @Test
    void handleInitialAction_deliverySucceeds_htmlResult_callsOnInitialSuccessWithHtmlResult() {
        ResponseUriDeliveryResult htmlResult = ResponseUriDeliveryResult.acceptedWithHtml("<html/>");
        when(mockHandler.execute(any())).thenReturn(Mono.just(htmlResult));
        when(mockHandler.onInitialSuccess(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(buildAction()))
                .verifyComplete();

        verify(mockHandler).onInitialSuccess(any(), eq(htmlResult));
    }

    @Test
    void handleInitialAction_deliverySucceeds_onInitialSuccessFails_errorSwallowed() {
        when(mockHandler.execute(any())).thenReturn(Mono.just(ResponseUriDeliveryResult.success()));
        when(mockHandler.onInitialSuccess(any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unavailable")));

        StepVerifier.create(service.handleInitialAction(buildAction()))
                .verifyComplete();
    }

    @Test
    void handleInitialAction_nonRetryableError_createsRetryRecordAndCallsOnInitialFailure() {
        WebClientResponseException badRequest = WebClientResponseException.create(400, "Bad Request", null, null, null);
        when(mockHandler.execute(any())).thenReturn(Mono.error(badRequest));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(mockHandler.onInitialFailure(any())).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(buildAction()))
                .verifyComplete();

        verify(procedureRetryRepository).upsert(any());
        verify(mockHandler).onInitialFailure(any());
        verify(mockHandler, never()).onInitialSuccess(any(), any());
    }

    @Test
    void handleInitialAction_invalidPayloadType_throwsRetryPayloadException() {
        assertThrows(RetryPayloadException.class, () ->
                service.handleInitialAction(new RetryableProcedureAction<>(
                        RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI,
                        "not-a-valid-payload",
                        PROCEDURE_ID
                )));
    }

    @Test
    void handleInitialAction_nullPayload_throwsRetryPayloadException() {
        assertThrows(RetryPayloadException.class, () ->
                service.handleInitialAction(new RetryableProcedureAction<>(
                        RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI,
                        null,
                        PROCEDURE_ID
                )));
    }

    @Test
    void handleInitialAction_retryableError_5xx_allRetriesExhausted_createsRetryRecord() {
        WebClientResponseException serverError = WebClientResponseException.create(500, "Internal Server Error", null, null, null);
        when(mockHandler.execute(any())).thenReturn(Mono.error(serverError));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(mockHandler.onInitialFailure(any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() -> service.handleInitialAction(buildAction()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(2))
                .thenAwait(Duration.ofMinutes(5))
                .thenAwait(Duration.ofMinutes(15))
                .verifyComplete();

        verify(mockHandler, times(4)).execute(any());
        verify(procedureRetryRepository).upsert(any());
    }

    @ParameterizedTest
    @MethodSource("nonRetryableUnauthorizedOrForbiddenErrors")
    void handleInitialAction_nonRetryableError_401And403_createsRetryRecordAndCallsOnInitialFailure(
            WebClientResponseException exception
    ) {
        when(mockHandler.execute(any())).thenReturn(Mono.error(exception));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(mockHandler.onInitialFailure(any())).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(buildAction()))
                .verifyComplete();

        verify(mockHandler, times(1)).execute(any());
        verify(procedureRetryRepository, times(1)).upsert(any());
        verify(mockHandler).onInitialFailure(any());
    }

    @ParameterizedTest
    @MethodSource("retryableErrorsWithVirtualTime")
    void handleInitialAction_retryableErrors_allRetriesExhausted(Throwable exception) {
        when(mockHandler.execute(any())).thenReturn(Mono.error(exception));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(mockHandler.onInitialFailure(any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() -> service.handleInitialAction(buildAction()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(22))
                .verifyComplete();

        verify(mockHandler, times(4)).execute(any());
    }

    @Test
    void handleInitialAction_nonRetryableError_responseUriDeliveryException_400_noRetries() {
        ResponseUriDeliveryException ex = new ResponseUriDeliveryException("Bad request", 400, RESPONSE_URI, CREDENTIAL_ID);
        when(mockHandler.execute(any())).thenReturn(Mono.error(ex));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(mockHandler.onInitialFailure(any())).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(buildAction()))
                .verifyComplete();

        verify(mockHandler, times(1)).execute(any());
    }

    @Test
    void handleInitialAction_nonRetryableError_genericException_noRetries() {
        RuntimeException ex = new RuntimeException("Generic unexpected error");
        when(mockHandler.execute(any())).thenReturn(Mono.error(ex));
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));
        when(mockHandler.onInitialFailure(any())).thenReturn(Mono.empty());

        StepVerifier.create(service.handleInitialAction(buildAction()))
                .verifyComplete();

        verify(mockHandler, times(1)).execute(any());
    }

    @Test
    void handleInitialAction_retrySucceeds_onSecondAttempt_callsOnInitialSuccess() {
        ResponseUriDeliveryResult success = ResponseUriDeliveryResult.success();
        when(mockHandler.execute(any()))
                .thenReturn(
                        Mono.error(WebClientResponseException.create(500, "Server Error", null, null, null)),
                        Mono.just(success)
                );
        when(mockHandler.onInitialSuccess(any(), any())).thenReturn(Mono.empty());

        StepVerifier.withVirtualTime(() -> service.handleInitialAction(buildAction()))
                .expectSubscription()
                .thenAwait(Duration.ofMinutes(2))
                .verifyComplete();

        verify(mockHandler, times(2)).execute(any());
        verify(mockHandler).onInitialSuccess(any(), eq(success));
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

        verify(mockHandler, never()).execute(any());
    }

    @Test
    void processPendingRetries_deliverySucceeds_marksCompletedAndCallsOnScheduledSuccess() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);
        ResponseUriDeliveryResult result = ResponseUriDeliveryResult.success();

        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING)).thenReturn(Flux.just(retryRecord));
        when(mockHandler.execute(any())).thenReturn(Mono.just(result));
        when(procedureRetryRepository.markAsCompleted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(mockHandler.onScheduledSuccess(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        verify(procedureRetryRepository).markAsCompleted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
        verify(mockHandler).onScheduledSuccess(any(), eq(result));
        verify(procedureRetryRepository, never()).incrementAttemptCount(any(), any(), any());
    }

    @Test
    void processPendingRetries_deliveryFails_nonRetryableError_incrementsAttemptCount() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);
        WebClientResponseException badRequest = WebClientResponseException.create(400, "Bad Request", null, null, null);

        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING)).thenReturn(Flux.just(retryRecord));
        when(mockHandler.execute(any())).thenReturn(Mono.error(badRequest));
        when(mockHandler.onSchedulerFailure(any(), any())).thenReturn(Mono.empty());
        when(procedureRetryRepository.incrementAttemptCount(eq(PROCEDURE_ID), eq(RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any()))
                .thenReturn(Mono.just(1));

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        verify(procedureRetryRepository).incrementAttemptCount(eq(PROCEDURE_ID), eq(RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any());
        verify(procedureRetryRepository, never()).markAsCompleted(any(), any());
    }

    @Test
    void processPendingRetries_deserializationFails_incrementsAttemptCount() {
        ProcedureRetry retryRecord = buildPendingRecord("NOT_VALID_JSON{{{");

        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING)).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.incrementAttemptCount(eq(PROCEDURE_ID), eq(RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any()))
                .thenReturn(Mono.just(1));

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        verify(procedureRetryRepository).incrementAttemptCount(eq(PROCEDURE_ID), eq(RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any());
        verify(mockHandler, never()).execute(any());
    }

    @Test
    void processPendingRetries_incrementAttemptCountFails_outerErrorResumeContinues() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry failingRecord = buildPendingRecord("INVALID_JSON");
        UUID otherProcedureId = UUID.randomUUID();
        ProcedureRetry successRecord = ProcedureRetry.builder()
                .id(UUID.randomUUID())
                .procedureId(otherProcedureId)
                .actionType(RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI)
                .status(RetryStatus.PENDING)
                .attemptCount(0)
                .firstFailureAt(Instant.now())
                .payload(payloadJson)
                .build();

        when(procedureRetryRepository.findByStatus(RetryStatus.PENDING))
                .thenReturn(Flux.just(failingRecord, successRecord));
        when(procedureRetryRepository.incrementAttemptCount(eq(PROCEDURE_ID), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("DB error")));
        when(mockHandler.execute(any())).thenReturn(Mono.just(ResponseUriDeliveryResult.success()));
        when(procedureRetryRepository.markAsCompleted(otherProcedureId, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(mockHandler.onScheduledSuccess(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.processPendingRetries())
                .verifyComplete();

        verify(procedureRetryRepository).markAsCompleted(otherProcedureId, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
    }

    // ──────────────────────────────────────────────────────────────────────
    // createRetryRecord
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void createRetryRecord_success_upsertsRecord() {
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(1));

        StepVerifier.create(service.createRetryRecord(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verify(procedureRetryRepository).upsert(any());
    }

    @Test
    void createRetryRecord_upsertReturnsZero_logsWarningButCompletes() {
        when(procedureRetryRepository.upsert(any())).thenReturn(Mono.just(0));

        StepVerifier.create(service.createRetryRecord(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verify(procedureRetryRepository).upsert(any());
    }

    @Test
    void createRetryRecord_serializationFails_returnsEmptyWithoutUpserting() throws Exception {
        doThrow(new RuntimeException("JSON serialization failed"))
                .when(objectMapper).writeValueAsString(any());

        StepVerifier.create(service.createRetryRecord(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();

        verifyNoInteractions(procedureRetryRepository);
    }

    @Test
    void createRetryRecord_upsertFails_errorSwallowed() {
        when(procedureRetryRepository.upsert(any()))
                .thenReturn(Mono.error(new RuntimeException("DB connection lost")));

        StepVerifier.create(service.createRetryRecord(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI, buildPayload()))
                .verifyComplete();
    }

    // ──────────────────────────────────────────────────────────────────────
    // markRetryAsCompleted
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void markRetryAsCompleted_success_rowsAffected() {
        when(procedureRetryRepository.markAsCompleted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));

        StepVerifier.create(service.markRetryAsCompleted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .verifyComplete();

        verify(procedureRetryRepository).markAsCompleted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
    }

    @Test
    void markRetryAsCompleted_noRowsAffected_logsWarningAndCompletes() {
        when(procedureRetryRepository.markAsCompleted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(0));

        StepVerifier.create(service.markRetryAsCompleted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
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
    }

    @Test
    void markRetryAsExhausted_oldRecord_marksExhaustedAndCallsOnExhausted() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(mockHandler.onExhausted(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();

        verify(procedureRetryRepository).markAsExhausted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
        verify(mockHandler).onExhausted(any(), eq(PROCEDURE_ID));
    }

    @Test
    void markRetryAsExhausted_markAsExhaustedReturnsZero_logsWarningAndContinues() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(0));
        when(mockHandler.onExhausted(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();
    }

    @Test
    void markRetryAsExhausted_onExhaustedFails_errorSwallowed() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(mockHandler.onExhausted(any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unreachable")));

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();
    }

    @Test
    void markRetryAsExhausted_deserializationFails_errorSwallowed() {
        ProcedureRetry retryRecord = buildPendingRecord("NOT_VALID_JSON");

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));

        StepVerifier.create(service.markRetryAsExhausted())
                .verifyComplete();

        verify(mockHandler, never()).onExhausted(any(), any());
    }

    @Test
    void markRetryAsExhausted_withCustomDuration_usesProvidedThreshold() throws Exception {
        String payloadJson = objectMapper.writeValueAsString(buildPayload());
        ProcedureRetry retryRecord = buildPendingRecord(payloadJson);

        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.just(retryRecord));
        when(procedureRetryRepository.markAsExhausted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI))
                .thenReturn(Mono.just(1));
        when(mockHandler.onExhausted(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.markRetryAsExhausted(Duration.ofDays(7)))
                .verifyComplete();

        verify(procedureRetryRepository).findPendingRecordsOlderThan(any());
        verify(procedureRetryRepository).markAsExhausted(PROCEDURE_ID, RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
    }

    @Test
    void markRetryAsExhausted_nullCustomDuration_fallsBackToDefaultThreshold() {
        when(procedureRetryRepository.findPendingRecordsOlderThan(any())).thenReturn(Flux.empty());

        StepVerifier.create(service.markRetryAsExhausted(null))
                .verifyComplete();

        verify(procedureRetryRepository).findPendingRecordsOlderThan(any());
    }
}
