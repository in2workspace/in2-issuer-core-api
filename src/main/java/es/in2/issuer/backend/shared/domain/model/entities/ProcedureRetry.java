package es.in2.issuer.backend.shared.domain.model.entities;

import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import es.in2.issuer.backend.shared.domain.model.enums.RetryStatus;
import lombok.*;
import org.springframework.data.annotation.*;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Table("issuer.procedure_retry")
public class ProcedureRetry {

    @Id
    @Column("id")
    private UUID id;

    @Column("procedure_id")
    private UUID procedureId;

    @Column("action_type")
    private ActionType actionType;

    @Column("status")
    private RetryStatus status;

    @Column("attempt_count")
    private Integer attemptCount;

    @Column("last_attempt_at")
    private Instant lastAttemptAt;

    @Column("first_failure_at")
    private Instant firstFailureAt;

    @Column("payload")
    private String payload;

    // --- Auditing fields (R2DBC auditing will fill these) ---
    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    @LastModifiedDate
    @Column("updated_at")
    private Instant updatedAt;

    @CreatedBy
    @Column("created_by")
    private String createdBy;

    @LastModifiedBy
    @Column("updated_by")
    private String updatedBy;
    // --------------------------------------------------------
}