package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.ResponseUriDeliveryException;
import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriDeliveryResult;
import es.in2.issuer.backend.shared.domain.model.dto.retry.LabelCredentialDeliveryPayload;
import es.in2.issuer.backend.shared.domain.model.entities.ProcedureRetry;
import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import es.in2.issuer.backend.shared.domain.model.enums.RetryStatus;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.ProcedureRetryRepository;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.net.ConnectException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeoutException;

@Service
@Slf4j
@RequiredArgsConstructor
public class ProcedureRetryServiceImpl implements ProcedureRetryService {

    private final ProcedureRetryRepository procedureRetryRepository;
    private final ObjectMapper objectMapper;
    private final CredentialDeliveryService credentialDeliveryService;
    private final M2MTokenService m2mTokenService;
    private final EmailService emailService;
    private final CredentialProcedureRepository credentialProcedureRepository;
    private final AppConfig appConfig;

    // Retry configuration constants
    private static final int INITIAL_RETRY_ATTEMPTS = 3;
    private static final Duration[] INITIAL_RETRY_DELAYS = {
            Duration.ofSeconds(5),
            Duration.ofSeconds(10),
            Duration.ofSeconds(15)
//          todo restore  Duration.ofMinutes(1),
//            Duration.ofMinutes(5),
//            Duration.ofMinutes(15)
    };
    private static final Duration EXHAUSTION_THRESHOLD = Duration.ofMinutes(2);

    // ──────────────────────────────────────────────────────────────────────
    // A. Initial Issuance Orchestration
    // ──────────────────────────────────────────────────────────────────────

    @Override
    public Mono<Void> handleInitialAction(UUID procedureId, ActionType actionType, Object payload) {
        return switch (actionType) {
            case UPLOAD_LABEL_TO_RESPONSE_URI ->
                    handleInitialLabelDeliveryAction(
                            procedureId,
                            castPayload(payload, LabelCredentialDeliveryPayload.class)
                    );
        };
    }

    private Mono<Void> handleInitialLabelDeliveryAction(
        UUID procedureId,
        LabelCredentialDeliveryPayload payload
    ) {
        return deliverLabelWithImmediateRetries(payload)
                .flatMap(result -> {
                    log.info("[DELIVERY] Initial delivery succeeded for credId: {}", payload.credentialId());
                    return sendSuccessNotificationSafely(payload.companyEmail(), payload.credentialId(), result);
                })
                .onErrorResume(e -> {
                    log.error("[DELIVERY] Initial delivery failed after all retries for credId: {} - {}",
                            payload.credentialId(), e.getMessage());

                    return createRetryRecord(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, payload)
                            .then(sendInitialFailureNotificationSafely(payload.companyEmail(), payload.credentialId()));
                });
    }

    // ──────────────────────────────────────────────────────────────────────
    // B. Scheduler Retry Orchestration
    // ──────────────────────────────────────────────────────────────────────

    @Override
    public Mono<Void> processPendingRetries() {
        return procedureRetryRepository.findByStatus(RetryStatus.PENDING)
                .flatMap(retryRecord ->
                        executeRetryAction(retryRecord)
                                .onErrorResume(error -> {
                                    log.warn(
                                            "[SCHEDULER] Continuing after error processing retry for procedure {}: {}",
                                            retryRecord.getProcedureId(),
                                            error.getMessage(),
                                            error
                                    );
                                    return Mono.empty();
                                })
                )
                .then()
                .doOnSuccess(unused -> log.info("[SCHEDULER] Completed processing all pending retries"));
    }

    private Mono<Void> executeRetryAction(ProcedureRetry retryRecord) {
        return switch (retryRecord.getActionType()) {
            case UPLOAD_LABEL_TO_RESPONSE_URI -> handleScheduledLabelDelivery(retryRecord);
        };
    }

    private Mono<Void> handleScheduledLabelDelivery(ProcedureRetry retryRecord) {
        log.info("[SCHEDULER] Processing retry attempt {} for procedure {} action {}",
                retryRecord.getAttemptCount() + 1, retryRecord.getProcedureId(), retryRecord.getActionType());

        return deserializePayload(retryRecord)
                .flatMap(payload ->
                        deliverLabelWithImmediateRetries(payload)
                                .flatMap(result -> {
                                    log.info("[SCHEDULER] Delivery succeeded for procedure {}", retryRecord.getProcedureId());
                                    return markRetryAsCompleted(retryRecord.getProcedureId(), retryRecord.getActionType())
                                            .then(sendSuccessNotificationSafely(
                                                    payload.companyEmail(),
                                                    payload.credentialId(),
                                                    result
                                            ));
                                })
                )
                .onErrorResume(e -> {
                    log.warn("[SCHEDULER] Delivery failed for procedure {}: {}",
                            retryRecord.getProcedureId(), e.getMessage(), e);
                    return updateRetryAfterScheduledFailure(retryRecord);
                });
    }

    // ──────────────────────────────────────────────────────────────────────
    // Pure delivery with immediate retries (no emails, no persistence)
    // ──────────────────────────────────────────────────────────────────────

    private Mono<ResponseUriDeliveryResult> deliverLabelWithImmediateRetries(LabelCredentialDeliveryPayload payload) {
        log.info("[DELIVERY] Attempting to deliver label for credId: {} with immediate retries", payload.credentialId());
        return m2mTokenService.getM2MToken()
                .flatMap(m2mToken ->
                        credentialDeliveryService.deliverLabelToResponseUri(
                                payload.responseUri(),
                                payload.signedCredential(),
                                payload.credentialId(),
                                m2mToken.accessToken()
                        )
                )
                .retryWhen(createRetrySpec("deliverLabel", INITIAL_RETRY_ATTEMPTS, INITIAL_RETRY_DELAYS));
    }

    // ──────────────────────────────────────────────────────────────────────
    // Retry record management
    // ──────────────────────────────────────────────────────────────────────

    @Override
    public Mono<Void> createRetryRecord(UUID procedureId, ActionType actionType, Object payload) {
        log.info("[RETRY] Creating retry record for procedureId={} actionType={}", procedureId, actionType);

        return Mono.fromCallable(() -> {
                    try {
                        String payloadJson = objectMapper.writeValueAsString(payload);
                        return ProcedureRetry.builder()
                                .id(UUID.randomUUID())
                                .procedureId(procedureId)
                                .actionType(actionType)
                                .status(RetryStatus.PENDING)
                                .attemptCount(0)
                                .firstFailureAt(Instant.now())
                                .payload(payloadJson)
                                .createdAt(Instant.now())
                                .updatedAt(Instant.now())
                                .build();
                    } catch (Exception e) {
                        log.error("[RETRY] Error serializing payload for procedureId={}: {}", procedureId, e.getMessage(), e);
                        throw new RuntimeException("Failed to serialize retry payload", e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(procedureRetryRepository::upsert)
                .doOnNext(rowsAffected -> {
                    if (rowsAffected == null || rowsAffected == 0) {
                        log.warn("[RETRY] No retry record inserted/updated for procedureId={} actionType={}", procedureId, actionType);
                    } else {
                        log.info("[RETRY] Upserted retry record for procedureId={} actionType={} (rows: {})", procedureId, actionType, rowsAffected);
                    }
                })
                .then()
                .onErrorResume(e -> {
                    log.error("[RETRY] Error upserting retry record for procedureId={}: {}", procedureId, e.getMessage(), e);
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> retryAction(UUID procedureId, ActionType actionType) {
        return procedureRetryRepository.findByProcedureIdAndActionType(procedureId, actionType)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("No retry record found for procedure " + procedureId + " and action " + actionType)))
                .filter(record -> record.getStatus() == RetryStatus.PENDING)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Retry record is not in PENDING status")))
                .flatMap(this::executeRetryAction);
    }

    @Override
    public Mono<Void> markRetryAsCompleted(UUID procedureId, ActionType actionType) {
        return procedureRetryRepository.markAsCompleted(procedureId, actionType)
                .doOnNext(rowsAffected -> {
                    if (rowsAffected == null || rowsAffected == 0) {
                        log.warn("[RETRY] No retry record found to mark as completed for procedure {} action {}", procedureId, actionType);
                    } else {
                        log.info("[RETRY] Marked retry as completed for procedure {} action {}", procedureId, actionType);
                    }
                })
                .then();
    }

    @Override
    public Mono<Void> markRetryAsExhausted() {
        return markRetryAsExhausted(EXHAUSTION_THRESHOLD);
    }

    @Override
    public Mono<Void> markRetryAsExhausted(Duration customExhaustionThreshold) {
        Duration threshold = customExhaustionThreshold != null ? customExhaustionThreshold : EXHAUSTION_THRESHOLD;
        Instant exhaustionThreshold = Instant.now().minus(threshold);

        return procedureRetryRepository.findPendingRecordsOlderThan(exhaustionThreshold)
                .flatMap(record -> {
                    log.info("[RETRY] Marking retry as exhausted for procedure {} action {} (first failure at: {})",
                            record.getProcedureId(), record.getActionType(), record.getFirstFailureAt());

                    return procedureRetryRepository.markAsExhausted(record.getProcedureId(), record.getActionType())
                            .doOnSuccess(rowsAffected -> {
                                if (rowsAffected > 0) {
                                    log.info("[RETRY] Successfully marked retry as exhausted for procedure {}", record.getProcedureId());
                                } else {
                                    log.warn("[RETRY] Failed to mark retry as exhausted for procedure {} (record may have been modified)", record.getProcedureId());
                                }
                            })
                            .then();
                })
                .then();
    }

    // ──────────────────────────────────────────────────────────────────────
    // Non-blocking email notifications
    // ──────────────────────────────────────────────────────────────────────

    private Mono<Void> sendSuccessNotificationSafely(String email, String credentialId, ResponseUriDeliveryResult result) {
        if (email == null || email.isBlank()) {
            log.warn("[NOTIFICATION] No email available for success notification, credId: {}", credentialId);
            return Mono.empty();
        }

        Mono<Void> emailMono;
        if (result.acceptedWithHtml() && result.html() != null) {
            emailMono = emailService.sendResponseUriAcceptedWithHtml(email, credentialId, result.html());
        } else {
            emailMono = emailService.sendCredentialSignedNotification(
                    email,
                    "Credential Delivery Successful",
                    "Your credential has been successfully delivered."
            );
        }

        return emailMono
                .doOnSuccess(unused -> log.info("[NOTIFICATION] Success email sent for credId: {}", credentialId))
                .onErrorResume(e -> {
                    log.error("[NOTIFICATION] Failed to send success email for credId: {}: {}", credentialId, e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<Void> sendInitialFailureNotificationSafely(String email, String credentialId) {
        if (email == null || email.isBlank()) {
            log.warn("[NOTIFICATION] No email available for failure notification, credId: {}", credentialId);
            return Mono.empty();
        }

        return emailService.sendResponseUriFailed(email, credentialId, appConfig.getKnowledgeBaseUploadCertificationGuideUrl())
                .doOnSuccess(unused -> log.info("[NOTIFICATION] Failure email sent for credId: {}", credentialId))
                .onErrorResume(e -> {
                    log.error("[NOTIFICATION] Failed to send failure email for credId: {}: {}", credentialId, e.getMessage());
                    return Mono.empty();
                });
    }

    // ──────────────────────────────────────────────────────────────────────
    // Scheduler failure handling
    // ──────────────────────────────────────────────────────────────────────

    private Mono<Void> updateRetryAfterScheduledFailure(ProcedureRetry retryRecord) {
        log.info("updateRetryAfterScheduledFailure: {}", retryRecord);
        return procedureRetryRepository.incrementAttemptCount(
                        retryRecord.getProcedureId(),
                        retryRecord.getActionType(),
                        Instant.now()
                )
                .doOnSuccess(rowsAffected -> log.info("[SCHEDULER] Incremented attempt count for procedure {} (rows: {})",
                        retryRecord.getProcedureId(), rowsAffected))
                .then();
    }

    // ──────────────────────────────────────────────────────────────────────
    // Retry spec and helpers
    // ──────────────────────────────────────────────────────────────────────

    private Retry createRetrySpec(String operationName, int attempts, Duration[] delays) {
        if (attempts < 1) {
            throw new IllegalArgumentException("attempts must be greater than 0");
        }
        if (delays == null || delays.length == 0) {
            throw new IllegalArgumentException("delays must contain at least one value");
        }
        for (Duration delay : delays) {
            if (delay == null || delay.isNegative()) {
                throw new IllegalArgumentException("delays must not contain null or negative values");
            }
        }

        return Retry.from(companion ->
                companion.concatMap(retrySignal -> {
                    long attempt = retrySignal.totalRetries() + 1;
                    Throwable failure = retrySignal.failure();

                    if (failure == null) {
                        return Mono.error(new IllegalStateException("Retry failure is null"));
                    }

                    if (!isRetryableError(failure)) {
                        log.warn("[RETRY] Not retrying {} - error is not retryable: {}", operationName, failure.getMessage());
                        return Mono.error(failure);
                    }

                    if (attempt > attempts) {
                        log.error("[RETRY] Retry attempts exhausted for {} after {} attempts. Final error: {}",
                                operationName, attempts, failure.getMessage());
                        return Mono.error(failure);
                    }

                    Duration nextDelay = attempt <= delays.length
                            ? delays[(int) attempt - 1]
                            : delays[delays.length - 1];

                    log.warn("[RETRY] Retrying {} - attempt {} of {}, next delay: {}, previous failure: {}",
                            operationName, attempt, attempts, nextDelay, failure.getMessage());

                    return Mono.delay(nextDelay);
                })
        );
    }

    private boolean isRetryableError(Throwable throwable) {
        if (throwable instanceof WebClientResponseException ex) {
            int statusCode = ex.getStatusCode().value();
            return ex.getStatusCode().is5xxServerError()
                    || statusCode == 408
                    || statusCode == 429
                    || statusCode == 401
                    || statusCode == 403;
        }

        if (throwable instanceof ResponseUriDeliveryException ex) {
            int statusCode = ex.getHttpStatusCode();
            return statusCode >= 500
                    || statusCode == 408
                    || statusCode == 429
                    || statusCode == 401
                    || statusCode == 403;
        }

        return throwable instanceof ConnectException
                || throwable instanceof TimeoutException
                || throwable instanceof WebClientRequestException;
    }

    private Mono<LabelCredentialDeliveryPayload> deserializePayload(ProcedureRetry retryRecord) {
        log.info("deserializePayload: {}", retryRecord);
        return Mono.fromCallable(() -> {
                    try {
                        log.info("return deserializePayload: {}", retryRecord);
                        return objectMapper.readValue(retryRecord.getPayload(), LabelCredentialDeliveryPayload.class);
                    } catch (Exception e) {
                        log.error("[RETRY] Error deserializing retry payload for procedure {}: {}", retryRecord.getProcedureId(), e.getMessage(), e);
                        throw new RuntimeException("Failed to deserialize retry payload", e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private <T> T castPayload(Object payload, Class<T> expectedType) {
        if (!expectedType.isInstance(payload)) {
            throw new IllegalArgumentException(
                    "Invalid payload type. Expected " + expectedType.getSimpleName()
                            + " but got " + (payload == null ? "null" : payload.getClass().getSimpleName())
            );
        }
        return expectedType.cast(payload);
    }
}
