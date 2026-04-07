package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.ProcedureRetry;
import es.in2.issuer.backend.shared.domain.model.enums.RetryStatus;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface ProcedureRetryRepository extends ReactiveCrudRepository<ProcedureRetry, UUID> {

    /**
     * Find all retry records with PENDING status
     */
    Flux<ProcedureRetry> findByStatus(RetryStatus status);

    /**
     * Find retry record by procedure ID and action type
     */
    Mono<ProcedureRetry> findByProcedureIdAndActionType(UUID procedureId, es.in2.issuer.backend.shared.domain.model.enums.ActionType actionType);

    /**
     * Find all PENDING retry records where first_failure_at is older than the given instant (for exhaustion check)
     */
    @Query("SELECT * FROM issuer.procedure_retry WHERE status = 'PENDING' AND first_failure_at < :exhaustionThreshold")
    Flux<ProcedureRetry> findPendingRecordsOlderThan(Instant exhaustionThreshold);
}