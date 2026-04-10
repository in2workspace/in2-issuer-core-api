package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.NoSuchElementException;

//todo make recursive
@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final ErrorResponseFactory errors;

    //todo add handler for RemoteSignatureException

    @ExceptionHandler(CredentialTypeUnsupportedException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleCredentialTypeUnsupported(
            CredentialTypeUnsupportedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_TYPE.getCode(),
                "Unsupported credential type",
                HttpStatus.NOT_FOUND,
                "The given credential type is not supported"
        );
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoSuchElementException(
            NoSuchElementException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.NO_SUCH_ELEMENT.getCode(),
                "Resource not found",
                HttpStatus.NOT_FOUND,
                "The requested resource was not found"
        );
    }

    @ExceptionHandler(InvalidOrMissingProofException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleInvalidOrMissingProof(
            InvalidOrMissingProofException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_OR_MISSING_PROOF.getCode(),
                "Invalid or missing proof",
                HttpStatus.NOT_FOUND,
                "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce."
        );
    }

    @ExceptionHandler(InvalidTokenException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleInvalidToken(
            InvalidTokenException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_TOKEN.getCode(),
                "Invalid token",
                HttpStatus.NOT_FOUND,
                "Credential Request contains the wrong Access Token or the Access Token is missing"
        );
    }

    @ExceptionHandler(ParseException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleParseException(
            ParseException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Parse error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal parsing error occurred."
        );
    }

    @ExceptionHandler(Base45Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleBase45Exception(
            Base45Exception ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Base45 decoding error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal Base45 decoding error occurred."
        );
    }

    @ExceptionHandler(SignedDataParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleSignedDataParsingException(
            SignedDataParsingException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Signed data parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal signed data parsing error occurred."
        );
    }

    @ExceptionHandler(ParseCredentialJsonException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleParseCredentialJsonException(
            ParseCredentialJsonException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Credential JSON parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal credential JSON parsing error occurred."
        );
    }

    @ExceptionHandler(ProofValidationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleProofValidationException(
            ProofValidationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PROOF_VALIDATION_ERROR.getCode(),
                "Proof validation error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal proof validation error occurred."
        );
    }

    @ExceptionHandler(NoCredentialFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoCredentialFoundException(
            NoCredentialFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_NOT_FOUND.getCode(),
                "Credential not found",
                HttpStatus.NOT_FOUND,
                "No credential found."
        );
    }

    @ExceptionHandler(PreAuthorizationCodeGetException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handlePreAuthorizationCodeGetException(
            PreAuthorizationCodeGetException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PRE_AUTHORIZATION_CODE_GET.getCode(),
                "Pre-authorization code retrieval error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Failed to retrieve pre-authorization code."
        );
    }

    @ExceptionHandler(CredentialOfferNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleCredentialOfferNotFoundException(
            CredentialOfferNotFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_OFFER_NOT_FOUND.getCode(),
                "Credential offer not found",
                HttpStatus.NOT_FOUND,
                "Credential offer not found."
        );
    }

    @ExceptionHandler(CredentialAlreadyIssuedException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleCredentialAlreadyIssuedException(
            CredentialAlreadyIssuedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_ALREADY_ISSUED.getCode(),
                "Credential already issued",
                HttpStatus.CONFLICT,
                "The credential has already been issued."
        );
    }

    @ExceptionHandler(OperationNotSupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleOperationNotSupportedException(
            OperationNotSupportedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.OPERATION_NOT_SUPPORTED.getCode(),
                "Operation not supported",
                HttpStatus.BAD_REQUEST,
                "The given operation is not supported"
        );
    }

    @ExceptionHandler(JWTVerificationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<GlobalErrorMessage> handleJWTVerificationException(
            JWTVerificationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.JWT_VERIFICATION.getCode(),
                "JWT verification failed",
                HttpStatus.UNAUTHORIZED,
                "JWT verification failed."
        );
    }

    @ExceptionHandler(FormatUnsupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleFormatUnsupportedException(
            FormatUnsupportedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.FORMAT_IS_NOT_SUPPORTED.getCode(),
                "Format not supported",
                HttpStatus.BAD_REQUEST,
                "Format is not supported"
        );
    }

    @ExceptionHandler(InsufficientPermissionException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleInsufficientPermissionException(
            InsufficientPermissionException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INSUFFICIENT_PERMISSION.getCode(),
                "Insufficient permission",
                HttpStatus.FORBIDDEN,
                "The client who made the issuance request do not have the required permissions"
        );
    }

    @ExceptionHandler(UnauthorizedRoleException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<GlobalErrorMessage> handleUnauthorizedRoleException(
            UnauthorizedRoleException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNAUTHORIZED_ROLE.getCode(),
                "Unauthorized role",
                HttpStatus.UNAUTHORIZED,
                "The user role is not authorized to perform this action"
        );
    }

    @ExceptionHandler(EmailCommunicationException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public Mono<GlobalErrorMessage> handleEmailCommunicationException(
            EmailCommunicationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.EMAIL_COMMUNICATION.getCode(),
                "Email communication error",
                HttpStatus.SERVICE_UNAVAILABLE,
                "Email communication failed"
        );
    }

    @ExceptionHandler(MissingIdTokenHeaderException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleMissingIdTokenHeaderException(
            MissingIdTokenHeaderException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.MISSING_HEADER.getCode(),
                "Missing header",
                HttpStatus.BAD_REQUEST,
                "The X-ID-TOKEN header is missing, this header is needed to issue a Verifiable Certification"
        );
    }

    @ExceptionHandler(SadException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public Mono<GlobalErrorMessage> handleSadException(
            SadException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.SAD_ERROR.getCode(),
                "SAD error",
                HttpStatus.BAD_GATEWAY,
                "An upstream SAD error occurred"
        );
    }

    @ExceptionHandler(CredentialSerializationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleCredentialSerializationException(
            CredentialSerializationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_SERIALIZATION.getCode(),
                "Credential serialization error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An error occurred during credential serialization"
        );
    }

    @ExceptionHandler(JWTParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleJWTParsingException(
            JWTParsingException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_JWT.getCode(),
                "JWT parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "The provided JWT is invalid or can't be parsed."
        );
    }

    @ExceptionHandler(CredentialProcedureInvalidStatusException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleCredentialProcedureInvalidStatusException(
            CredentialProcedureInvalidStatusException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_PROCEDURE_INVALID_STATUS.getCode(),
                "Invalid credential procedure status",
                HttpStatus.CONFLICT,
                "The credential procedure is not in a status that allows signing."
        );
    }

    @ExceptionHandler(CredentialProcedureNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleCredentialProcedureNotFoundException(
            CredentialProcedureNotFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_PROCEDURE_NOT_FOUND.getCode(),
                "Credential procedure not found",
                HttpStatus.NOT_FOUND,
                "The requested credential procedure was not found"
        );
    }

    @ExceptionHandler(InvalidCredentialFormatException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidCredentialFormatException(
            InvalidCredentialFormatException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_CREDENTIAL_FORMAT.getCode(),
                "Invalid credential format",
                HttpStatus.BAD_REQUEST,
                "The credential payload is invalid"
        );
    }

    @ExceptionHandler(ProcedureRetryRecordNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleProcedureRetryRecordNotFoundException(
            ProcedureRetryRecordNotFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PROCEDURE_RETRY_RECORD_NOT_FOUND.getCode(),
                "Retry record not found",
                HttpStatus.NOT_FOUND,
                "The requested retry record was not found"
        );
    }

    @ExceptionHandler(InvalidRetryStatusException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleInvalidRetryStatusException(
            InvalidRetryStatusException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_RETRY_STATUS.getCode(),
                "Invalid retry status",
                HttpStatus.CONFLICT,
                "The retry record is not in a valid status for this operation"
        );
    }

    @ExceptionHandler(RetryPayloadException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleRetryPayloadException(
            RetryPayloadException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.RETRY_PAYLOAD_ERROR.getCode(),
                "Retry payload error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An error occurred while serializing or deserializing retry payload"
        );
    }

    @ExceptionHandler(RetryConfigurationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleRetryConfigurationException(
            RetryConfigurationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.RETRY_CONFIGURATION_ERROR.getCode(),
                "Retry configuration error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An error occurred in the retry mechanism configuration"
        );
    }

}
