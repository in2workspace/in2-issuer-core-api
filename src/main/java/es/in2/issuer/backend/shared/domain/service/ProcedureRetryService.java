package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.retry.LabelCredentialDeliveryPayload;
import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;

/**
 * Service to handle retry operations for external actions
 */
public interface ProcedureRetryService {

    /**
     * Creates a retry record when initial action fails
     *
     * @param procedureId the procedure ID
     * @param actionType the type of action that failed
     * @param payload the payload data needed to reconstruct the action
     * @return void Mono
     */
    Mono<Void> createRetryRecord(UUID procedureId, ActionType actionType, Object payload);

    /**
     * Executes retry attempts for a specific procedure and action type
     *
     * @param procedureId the procedure ID
     * @param actionType the action type to retry
     * @return void Mono
     */
    Mono<Void> retryAction(UUID procedureId, ActionType actionType);

    /**
     * Executes label credential upload with retry logic
     *
     * @param payload the label credential retry payload
     * @return void Mono
     */
    Mono<Void> executeUploadLabelToResponseUri(LabelCredentialDeliveryPayload payload);

    /**
     * Executes label credential upload with custom retry parameters
     *
     * @param payload the label credential retry payload
     * @param customRetryAttempts custom number of retry attempts (null for default)
     * @param customRetryDelays custom retry delays array (null for default)
     * @return void Mono
     */
    Mono<Void> executeUploadLabelToResponseUri(LabelCredentialDeliveryPayload payload, 
                                              Integer customRetryAttempts, 
                                              Duration[] customRetryDelays);

    /**
     * Marks a retry as successful and sends success notification
     *
     * @param procedureId the procedure ID
     * @param actionType the action type
     * @return void Mono
     */
    Mono<Void> markRetryAsCompleted(UUID procedureId, ActionType actionType);

    /**
     * Marks retries as exhausted for records older than the exhaustion threshold
     *
     * @return void Mono
     */
    Mono<Void> markRetryAsExhausted();

    /**
     * Marks retries as exhausted for records older than the custom exhaustion threshold
     *
     * @param customExhaustionThreshold custom exhaustion threshold (null for default)
     * @return void Mono
     */
    Mono<Void> markRetryAsExhausted(Duration customExhaustionThreshold);

    /**
     * Processes all pending retries (called by scheduler)
     *
     * @return void Mono
     */
    Mono<Void> processPendingRetries();
}