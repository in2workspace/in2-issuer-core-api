package es.in2.issuer.backend.backoffice.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.service.ProcedureRetryService;
import es.in2.issuer.backend.shared.domain.exception.ProcedureRetryRecordNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.InvalidRetryStatusException;
import es.in2.issuer.backend.shared.domain.exception.RetryPayloadException;
import es.in2.issuer.backend.shared.domain.exception.RetryConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.ResponseUriDeliveryException;
import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriDeliveryResult;
import es.in2.issuer.backend.shared.domain.model.dto.retry.LabelCredentialDeliveryPayload;
import es.in2.issuer.backend.shared.domain.model.entities.ProcedureRetry;
import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import es.in2.issuer.backend.shared.domain.model.enums.RetryStatus;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.backoffice.infrastructure.repository.ProcedureRetryRepository;
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
    private final AppConfig appConfig;

    // Retry configuration constants
    private static final int INITIAL_RETRY_ATTEMPTS = 3;
    private static final Duration[] INITIAL_RETRY_DELAYS = {
            Duration.ofMinutes(2),
            Duration.ofMinutes(5),
            Duration.ofMinutes(15)
    };

    private static final Duration EXHAUSTION_THRESHOLD = Duration.ofDays(14);

    // ──────────────────────────────────────────────────────────────────────
    // A. Initial Issuance Orchestration
    // ──────────────────────────────────────────────────────────────────────

    @Override
    public Mono<Void> handleInitialAction(UUID procedureId, ActionType actionType, Object payload) {
        log.info("[RETRY] Handling initial action for procedureId={} actionType={}", procedureId, actionType);
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
                    return sendSuccessNotificationSafely(payload.email(), payload.credentialId(), result);
                })
                .onErrorResume(e -> {
                    log.error("[DELIVERY] Initial delivery failed after all retries for credId: {} - {}",
                            payload.credentialId(), e.getMessage());

                    return createRetryRecord(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, payload)
                            .then(sendInitialFailureNotificationSafely(payload.productSpecificationId(), payload.email()));
                });
    }

    // ──────────────────────────────────────────────────────────────────────
    // B. Scheduler Retry Orchestration
    // ──────────────────────────────────────────────────────────────────────

    @Override
    public Mono<Void> processPendingRetries() {
        log.info("[RETRY] Starting processing of pending retries");
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
                                            .then(sendScheduledSuccessNotifications(payload, result));
                                })
                )
                .onErrorResume(e -> {
                    log.warn("[SCHEDULER] Delivery failed for procedure {}: {}",
                            retryRecord.getProcedureId(), e.getMessage(), e);
                    return updateRetryAfterScheduledFailure(retryRecord);
                });
    }

    private Mono<Void> sendScheduledSuccessNotifications(LabelCredentialDeliveryPayload payload, ResponseUriDeliveryResult result) {
        return Mono.when(
                sendSuccessNotificationSafely(payload.email(), payload.credentialId(), result),
                sendSuccessNotificationSafely(appConfig.getLabelUploadCertifierEmail(), payload.credentialId(), result),
                sendSuccessNotificationSafely(appConfig.getLabelUploadMarketplaceEmail(), payload.credentialId(), result)
        );
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
        log.debug("[RETRY] Creating retry record for procedureId={} actionType={}", procedureId, actionType);

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
                                .build();
                    } catch (Exception e) {
                        log.error("[RETRY] Error serializing payload for procedureId={}: {}", procedureId, e.getMessage(), e);
                        throw new RetryPayloadException("Failed to serialize retry payload", e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(procedureRetryRepository::upsert)
                .doOnNext(rowsAffected -> {
                    if (rowsAffected == null || rowsAffected == 0) {
                        log.warn("[RETRY] No retry record inserted/updated for procedureId={} actionType={}", procedureId, actionType);
                    } else {
                        log.info("[debug] Upserted retry record for procedureId={} actionType={} (rows: {})", procedureId, actionType, rowsAffected);
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
                .switchIfEmpty(Mono.error(new ProcedureRetryRecordNotFoundException("No retry record found for procedure " + procedureId + " and action " + actionType)))
                .filter(retryRecord -> retryRecord.getStatus() == RetryStatus.PENDING)
                .switchIfEmpty(Mono.error(new InvalidRetryStatusException("Retry record is not in PENDING status")))
                .flatMap(this::executeRetryAction);
    }

    @Override
    public Mono<Void> markRetryAsCompleted(UUID procedureId, ActionType actionType) {
        return procedureRetryRepository.markAsCompleted(procedureId, actionType)
                .doOnNext(rowsAffected -> {
                    if (rowsAffected == null || rowsAffected == 0) {
                        log.warn("[RETRY] No retry record found to mark as completed for procedure {} action {}", procedureId, actionType);
                    } else {
                        log.debug("[RETRY] Marked retry as completed for procedure {} action {}", procedureId, actionType);
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
                .flatMap(retryRecord -> {
                    log.debug("[RETRY] Marking retry as exhausted for procedure {} action {} (first failure at: {})",
                            retryRecord.getProcedureId(), retryRecord.getActionType(), retryRecord.getFirstFailureAt());

                    return procedureRetryRepository.markAsExhausted(retryRecord.getProcedureId(), retryRecord.getActionType())
                            .doOnSuccess(rowsAffected -> {
                                if (rowsAffected > 0) {
                                    log.debug("[RETRY] Successfully marked retry as exhausted for procedure {}", retryRecord.getProcedureId());
                                } else {
                                    log.warn("[RETRY] Failed to mark retry as exhausted for procedure {} (record may have been modified)", retryRecord.getProcedureId());
                                }
                            })
                            .then(sendExhaustionNotificationSafely(retryRecord));
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
            emailMono = emailService.sendCertificationUploaded(email, credentialId);
        }

        return emailMono
                .doOnSuccess(unused -> log.info("[NOTIFICATION] Success email sent for credId: {}", credentialId))
                .onErrorResume(e -> {
                    log.error("[NOTIFICATION] Failed to send success email for credId: {}: {}", credentialId, e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<Void> sendInitialFailureNotificationSafely(String productSpecificationId, String ownerEmail) {
        return Mono.when(
                sendFailureNotificationSafely(appConfig.getLabelUploadCertifierEmail(), productSpecificationId, ownerEmail, "certifier"),
                sendFailureNotificationSafely(appConfig.getLabelUploadMarketplaceEmail(), productSpecificationId, ownerEmail, "marketplace")
        );
    }

    private Mono<Void> sendFailureNotificationSafely(String email, String productSpecificationId, String ownerEmail, String recipientType) {
        if (email == null || email.isBlank()) {
            log.warn("[NOTIFICATION] No {} email available for failure notification, productSpecId: {}", recipientType, productSpecificationId);
            return Mono.empty();
        }

        return emailService.sendResponseUriFailed(
                        email,
                        productSpecificationId,
                        ownerEmail,
                        appConfig.getKnowledgeBaseUploadCertificationGuideUrl()
                )
                .doOnSuccess(unused ->
                        log.info("[NOTIFICATION] Failure email sent to {} for productSpecId: {}", recipientType, productSpecificationId)
                )
                .onErrorResume(e -> {
                    log.error("[NOTIFICATION] Failed to send failure email to {} for productSpecId: {}: {}",
                            recipientType, productSpecificationId, e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<Void> sendExhaustionNotificationSafely(ProcedureRetry retryRecord) {
        return deserializePayload(retryRecord)
                .flatMap(payload ->
                        Mono.when(
                                sendExhaustionNotificationSafely(
                                        appConfig.getLabelUploadCertifierEmail(),
                                        payload.productSpecificationId(),
                                        payload.credentialId(),
                                        payload.email(),
                                        retryRecord.getProcedureId(),
                                        "certifier"
                                ),
                                sendExhaustionNotificationSafely(
                                        appConfig.getLabelUploadMarketplaceEmail(),
                                        payload.productSpecificationId(),
                                        payload.credentialId(),
                                        payload.email(),
                                        retryRecord.getProcedureId(),
                                        "marketplace"
                                )
                        )
                )
                .onErrorResume(e -> {
                    log.error("[NOTIFICATION] Failed to deserialize payload for exhaustion notification, procedure: {}: {}",
                            retryRecord.getProcedureId(), e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<Void> sendExhaustionNotificationSafely(
            String email,
            String productSpecificationId,
            String credentialId,
            String ownerEmail,
            UUID procedureId,
            String recipientType
    ) {
        if (email == null || email.isBlank()) {
            log.warn("[NOTIFICATION] No {} email available for exhaustion notification, procedure: {}", recipientType, procedureId);
            return Mono.empty();
        }

        return emailService.sendResponseUriExhausted(email, productSpecificationId, credentialId, ownerEmail, appConfig.getKnowledgeBaseUploadCertificationGuideUrl())
                .doOnSuccess(unused -> log.info("[NOTIFICATION] Exhaustion email sent to {} for procedure: {}, productSpecId: {}, credId: {}",
                        recipientType, procedureId, productSpecificationId, credentialId))
                .onErrorResume(e -> {
                    log.error("[NOTIFICATION] Failed to send exhaustion email to {} for procedure: {}, productSpecId: {}, credId: {}: {}",
                            recipientType, procedureId, productSpecificationId, credentialId, e.getMessage());
                    return Mono.empty();
                });
    }

    // ──────────────────────────────────────────────────────────────────────
    // Scheduler failure handling
    // ──────────────────────────────────────────────────────────────────────

    private Mono<Void> updateRetryAfterScheduledFailure(ProcedureRetry retryRecord) {
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
        validateRetryConfiguration(attempts, delays);

        return Retry.from(companion ->
                companion.concatMap(retrySignal -> handleRetrySignal(operationName, attempts, delays, retrySignal))
        );
    }

    private Mono<Long> handleRetrySignal(
            String operationName,
            int attempts,
            Duration[] delays,
            reactor.util.retry.Retry.RetrySignal retrySignal
    ) {
        long attempt = retrySignal.totalRetries() + 1;
        Throwable failure = requireFailure(retrySignal);

        if (!isRetryableError(failure)) {
            return propagateNonRetryableError(operationName, failure);
        }

        if (hasExhaustedAttempts(attempt, attempts)) {
            return propagateExhaustedRetries(operationName, attempts, failure);
        }

        Duration nextDelay = resolveNextDelay(attempt, delays);
        logRetryAttempt(operationName, attempt, attempts, nextDelay, failure);

        return Mono.delay(nextDelay);
    }

    private void validateRetryConfiguration(int attempts, Duration[] delays) {
        if (attempts < 1) {
            throw new RetryConfigurationException("attempts must be greater than 0");
        }
        if (delays == null || delays.length == 0) {
            throw new RetryConfigurationException("delays must contain at least one value");
        }
        for (Duration delay : delays) {
            if (delay == null || delay.isNegative()) {
                throw new RetryConfigurationException("delays must not contain null or negative values");
            }
        }
    }

    private Throwable requireFailure(reactor.util.retry.Retry.RetrySignal retrySignal) {
        Throwable failure = retrySignal.failure();
        if (failure == null) {
            throw new RetryConfigurationException("Retry failure is null");
        }
        return failure;
    }

    private Mono<Long> propagateNonRetryableError(String operationName, Throwable failure) {
        log.warn("[RETRY] Not retrying {} - error is not retryable: {}", operationName, failure.getMessage());
        return Mono.error(failure);
    }

    private boolean hasExhaustedAttempts(long attempt, int attempts) {
        return attempt > attempts;
    }

    private Mono<Long> propagateExhaustedRetries(String operationName, int attempts, Throwable failure) {
        log.error("[RETRY] Retry attempts exhausted for {} after {} attempts. Final error: {}",
                operationName, attempts, failure.getMessage());
        return Mono.error(failure);
    }

    private Duration resolveNextDelay(long attempt, Duration[] delays) {
        return attempt <= delays.length
                ? delays[(int) attempt - 1]
                : delays[delays.length - 1];
    }

    private void logRetryAttempt(
            String operationName,
            long attempt,
            int attempts,
            Duration nextDelay,
            Throwable failure
    ) {
        log.warn("[RETRY] Retrying {} - attempt {} of {}, next delay: {}, previous failure: {}",
                operationName, attempt, attempts, nextDelay, failure.getMessage());
    }

    private boolean isRetryableError(Throwable throwable) {
        if (throwable instanceof WebClientResponseException ex) {
            int statusCode = ex.getStatusCode().value();
            return ex.getStatusCode().is5xxServerError()
                    || statusCode == 408
                    || statusCode == 429;
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
        return Mono.fromCallable(() -> {
                    try {
                        return objectMapper.readValue(retryRecord.getPayload(), LabelCredentialDeliveryPayload.class);
                    } catch (Exception e) {
                        log.error("[RETRY] Error deserializing retry payload for procedure {}: {}", retryRecord.getProcedureId(), e.getMessage(), e);
                        throw new RetryPayloadException("Failed to deserialize retry payload", e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private <T> T castPayload(Object payload, Class<T> expectedType) {
        if (!expectedType.isInstance(payload)) {
            throw new RetryPayloadException(
                    "Invalid payload type. Expected " + expectedType.getSimpleName()
                            + " but got " + (payload == null ? "null" : payload.getClass().getSimpleName())
            );
        }
        return expectedType.cast(payload);
    }
}