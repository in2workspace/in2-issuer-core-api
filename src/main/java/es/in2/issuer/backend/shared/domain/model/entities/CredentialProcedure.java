package es.in2.issuer.backend.shared.domain.model.entities;

import brave.internal.Nullable;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import lombok.*;
import org.springframework.data.annotation.*;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.sql.Timestamp;
import java.util.UUID;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Table("issuer.credential_procedure")
public class CredentialProcedure extends AuditableEntity{
    @Id
    @Column("procedure_id")
    private UUID procedureId;

    @Column("credential_format")
    private String credentialFormat;

    @Column("credential_decoded")
    private String credentialDecoded;

    @Column("credential_encoded")
    private String credentialEncoded;

    @Column("credential_status")
    private CredentialStatusEnum credentialStatus;

    @Column("organization_identifier")
    private String organizationIdentifier;

    @Column("subject")
    @Nullable
    private String subject;

    @Column("credential_type")
    private String credentialType;

    @Column("valid_until")
    private Timestamp validUntil;

    @Column("operation_mode")
    private String operationMode;

    @Column("signature_mode")
    private String signatureMode;

    @Column("email")
    private String email;

    @Column("notification_id")
    private UUID notificationId;

}
