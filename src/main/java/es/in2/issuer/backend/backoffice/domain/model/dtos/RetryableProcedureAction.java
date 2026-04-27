package es.in2.issuer.backend.backoffice.domain.model.dtos;

import es.in2.issuer.backend.shared.domain.model.enums.RetryableActionType;

import java.util.UUID;

public record RetryableProcedureAction<T>(
        RetryableActionType actionType,
        T payload,
        UUID procedureId
) {
}
