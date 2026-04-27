package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.backoffice.domain.model.dtos.RetryableProcedureAction;
import es.in2.issuer.backend.shared.domain.model.enums.RetryableActionType;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;

public interface ProcedureRetryService {

    /**
     * Initial issuance orchestration: delivers label to response URI with immediate retries.
     * On success: sends success email (non-blocking).
     * On failure after retries: creates retry record, sends failure email once (non-blocking).
     */
    Mono<Void> handleInitialAction(RetryableProcedureAction<?> action);

    /**
     * Creates a retry record when initial action fails.
     */
    Mono<Void> createRetryRecord(UUID procedureId, RetryableActionType actionType, Object payload);

    /**
     * Marks a retry as successful.
     */
    Mono<Void> markRetryAsCompleted(UUID procedureId, RetryableActionType actionType);

    /**
     * Marks retries as exhausted for records older than the exhaustion threshold.
     */
    Mono<Void> markRetryAsExhausted();

    /**
     * Marks retries as exhausted for records older than a custom threshold.
     */
    Mono<Void> markRetryAsExhausted(Duration customExhaustionThreshold);

    /**
     * Processes all pending retries (called by scheduler).
     * Each pending record is handled via scheduler orchestration:
     * on success marks completed + success email, on failure updates retry metadata (no failure email).
     */
    Mono<Void> processPendingRetries();
}
