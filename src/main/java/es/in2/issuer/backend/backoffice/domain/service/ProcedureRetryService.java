package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;

public interface ProcedureRetryService {

    /**
     * Initial issuance orchestration: delivers label to response URI with immediate retries.
     * On success: sends success email (non-blocking).
     * On failure after retries: creates retry record, sends failure email once (non-blocking).
     */
    Mono<Void> handleInitialAction(UUID procedureId, ActionType actionType, Object payload);

    /**
     * Creates a retry record when initial action fails.
     */
    Mono<Void> createRetryRecord(UUID procedureId, ActionType actionType, Object payload);

    /**
     * Executes retry attempts for a specific procedure and action type.
     */
    Mono<Void> retryAction(UUID procedureId, ActionType actionType);

    /**
     * Marks a retry as successful.
     */
    Mono<Void> markRetryAsCompleted(UUID procedureId, ActionType actionType);

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
