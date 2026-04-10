package es.in2.issuer.backend.shared.domain.util;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum GlobalErrorTypes {

    INVALID_TOKEN("invalid_token"),
    INVALID_JWT("invalid_jwt"),
    UNSUPPORTED_CREDENTIAL_TYPE("unsupported_credential_type"),
    INVALID_OR_MISSING_PROOF("invalid_or_missing_proof"),
    OPERATION_NOT_SUPPORTED("operation_not_supported"),
    FORMAT_IS_NOT_SUPPORTED("format_is_not_supported"),
    INSUFFICIENT_PERMISSION("insufficient_permission"),
    MISSING_HEADER("missing_header"),
    SAD_ERROR("sad_error"),
    NO_SUCH_ELEMENT("no_such_element"),
    PARSE_ERROR("parse_error"),
    PROOF_VALIDATION_ERROR("proof_validation_error"),
    CREDENTIAL_NOT_FOUND("credential_not_found"),
    PRE_AUTHORIZATION_CODE_GET("pre_authorization_code_get_error"),
    CREDENTIAL_OFFER_NOT_FOUND("credential_offer_not_found"),
    CREDENTIAL_ALREADY_ISSUED("credential_already_issued"),
    JWT_VERIFICATION("jwt_verification_error"),
    UNAUTHORIZED_ROLE("unauthorized_role"),
    EMAIL_COMMUNICATION("email_communication_error"),
    CREDENTIAL_SERIALIZATION("credential_serialization"),
    CREDENTIAL_PROCEDURE_INVALID_STATUS("credential_procedure_invalid_status"),
    CREDENTIAL_PROCEDURE_NOT_FOUND("credential_procedure_not_found"),
    INVALID_CREDENTIAL_FORMAT("invalid_credential_format"),
    PROCEDURE_RETRY_RECORD_NOT_FOUND("procedure_retry_record_not_found"),
    INVALID_RETRY_STATUS("invalid_retry_status"),
    RETRY_PAYLOAD_ERROR("retry_payload_error"),
    RETRY_CONFIGURATION_ERROR("retry_configuration_error");

    private final String code;

}
