package es.in2.issuer.backend.backoffice.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.ProcedureRetry;
import es.in2.issuer.backend.shared.domain.model.enums.RetryableActionType;
import es.in2.issuer.backend.shared.domain.model.enums.RetryStatus;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface ProcedureRetryRepository extends ReactiveCrudRepository<ProcedureRetry, UUID> {

    Flux<ProcedureRetry> findByStatus(RetryStatus status);

    Mono<ProcedureRetry> findByProcedureIdAndActionType(UUID procedureId, RetryableActionType actionType);

    @Query("SELECT * FROM issuer.procedure_retry WHERE status = 'PENDING' AND first_failure_at < :exhaustionThreshold")
    Flux<ProcedureRetry> findPendingRecordsOlderThan(Instant exhaustionThreshold);

    @Modifying
    @Query("""
            INSERT INTO issuer.procedure_retry
                (id, procedure_id, action_type, status, attempt_count, first_failure_at, payload)
            VALUES
                (:#{#retry.id}, :#{#retry.procedureId}, :#{#retry.actionType}, :#{#retry.status},
                 :#{#retry.attemptCount}, :#{#retry.firstFailureAt}, :#{#retry.payload})
            ON CONFLICT (procedure_id, action_type)
            DO UPDATE SET
                status = EXCLUDED.status,
                payload = EXCLUDED.payload
            """)
    Mono<Integer> upsert(ProcedureRetry retry);

    @Modifying
    @Query("""
            UPDATE issuer.procedure_retry
            SET attempt_count = attempt_count + 1,
                last_attempt_at = :lastAttemptAt
            WHERE procedure_id = :procedureId AND action_type = :actionType
            """)
    Mono<Integer> incrementAttemptCount(UUID procedureId, RetryableActionType actionType, Instant lastAttemptAt);

    @Modifying
    @Query("""
            UPDATE issuer.procedure_retry
            SET status = 'COMPLETED'
            WHERE procedure_id = :procedureId AND action_type = :actionType
            """)
    Mono<Integer> markAsCompleted(UUID procedureId, RetryableActionType actionType);

    @Modifying
    @Query("""
            UPDATE issuer.procedure_retry
            SET status = 'RETRY_EXHAUSTED'
            WHERE procedure_id = :procedureId AND action_type = :actionType
            """)
    Mono<Integer> markAsExhausted(UUID procedureId, RetryableActionType actionType);
}
