package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

//todo make recursive
class GlobalExceptionHandlerTest {

    private ErrorResponseFactory errors;     // mock
    private GlobalExceptionHandler handler;  // SUT
    private ServerHttpRequest request;

    @BeforeEach
    void setUp() {
        errors = mock(ErrorResponseFactory.class);
        handler = new GlobalExceptionHandler(errors);
        request = MockServerHttpRequest.get("/any").build();
    }

    private void assertGem(GlobalErrorMessage gem,
                           String expectedType,
                           String expectedTitle,
                           HttpStatus expectedStatus,
                           String expectedDetail) {
        // accessors de record: type(), title(), status(), detail(), instance()
        assertEquals(expectedType, gem.type());
        assertEquals(expectedTitle, gem.title());
        assertEquals(expectedStatus.value(), gem.status());
        assertEquals(expectedDetail, gem.detail());
        assertDoesNotThrow(() -> UUID.fromString(gem.instance()));
    }

    // -------------------- handleCredentialTypeUnsupported --------------------

    @Test
    void handleCredentialTypeUnsupported_usesExceptionMessage_whenPresent() {
        var ex = new CredentialTypeUnsupportedException("custom msg");
        var type = GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_TYPE.getCode();
        var title = "Unsupported credential type";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "The given credential type is not supported";
        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialTypeUnsupported(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "custom msg"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleCredentialTypeUnsupported_usesFallback_whenMessageNullOrBlank() {
        var type = GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_TYPE.getCode();
        var title = "Unsupported credential type";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "The given credential type is not supported";

        var exNull = new CredentialTypeUnsupportedException((String) null);
        var exBlank = new CredentialTypeUnsupportedException("   ");
        var expectedNull = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull, request, type, title, st, fallback))
                .thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback))
                .thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleCredentialTypeUnsupported(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();
        StepVerifier.create(handler.handleCredentialTypeUnsupported(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull, request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // -------------------- handleNoSuchElementException --------------------

    @Test
    void handleNoSuchElementException_usesExceptionMessage_whenPresent() {
        var ex = new NoSuchElementException("not here");
        var type = GlobalErrorTypes.NO_SUCH_ELEMENT.getCode();
        var title = "Resource not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "The requested resource was not found";
        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleNoSuchElementException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "not here"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleNoSuchElementException_usesFallback_whenMessageNullOrBlank() {
        var type = GlobalErrorTypes.NO_SUCH_ELEMENT.getCode();
        var title = "Resource not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "The requested resource was not found";

        var exBlank = new NoSuchElementException("  ");
        var expected = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exBlank, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleNoSuchElementException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // -------------------- handleInvalidOrMissingProof --------------------

    @Test
    void handleInvalidOrMissingProof_usesExceptionMessage_whenPresent() {
        var ex = new InvalidOrMissingProofException("bad proof");
        var type = GlobalErrorTypes.INVALID_OR_MISSING_PROOF.getCode();
        var title = "Invalid or missing proof";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce.";
        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidOrMissingProof(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "bad proof"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleInvalidOrMissingProof_usesFallback_whenMessageNullOrBlank() {
        var type = GlobalErrorTypes.INVALID_OR_MISSING_PROOF.getCode();
        var title = "Invalid or missing proof";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce.";

        var exNull = new InvalidOrMissingProofException((String) null);
        var exBlank = new InvalidOrMissingProofException(" ");

        var expectedNull = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull, request, type, title, st, fallback))
                .thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback))
                .thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleInvalidOrMissingProof(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();
        StepVerifier.create(handler.handleInvalidOrMissingProof(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull, request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // -------------------- handleInvalidToken --------------------

    @Test
    void handleInvalidToken_usesExceptionMessage_whenPresent() {
        var ex = new InvalidTokenException("Message");
        var type = GlobalErrorTypes.INVALID_TOKEN.getCode();
        var title = "Invalid token";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "Credential Request contains the wrong Access Token or the Access Token is missing";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidToken(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "Message"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleInvalidToken_usesFallback_whenMessageNullOrBlank() {
        var type = GlobalErrorTypes.INVALID_TOKEN.getCode();
        var title = "Invalid token";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "Credential Request contains the wrong Access Token or the Access Token is missing";

        var exNull = new InvalidTokenException((String) null);
        var exBlank = new InvalidTokenException("   ");

        var expectedNull = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull, request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleInvalidToken(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();
        StepVerifier.create(handler.handleInvalidToken(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull, request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // -------------------- handleParseException --------------------

    @Test
    void handleParseException_usesExceptionMessage_whenPresent() {
        var ex = new ParseException("bad date", 0);
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Parse error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal parsing error occurred.";
        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleParseException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "bad date"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleParseException_usesFallback_whenMessageNullOrBlank() {
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Parse error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal parsing error occurred.";

        var exNull = new ParseException(null, 0);
        var exBlank = new ParseException("   ", 0);

        var expectedNull = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull, request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleParseException(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();
        StepVerifier.create(handler.handleParseException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull, request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // -------------------- handleBase45Exception --------------------

    @Test
    void handleBase45Exception() {
        var ex = new Base45Exception("decode failed");
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Base45 decoding error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal Base45 decoding error occurred.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "decode failed", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleBase45Exception(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "decode failed"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleSignedDataParsingException --------------------

    @Test
    void handleSignedDataParsingException() {
        var ex = new SignedDataParsingException("bad signature payload");
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Signed data parsing error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal signed data parsing error occurred.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "bad signature payload", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleSignedDataParsingException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "bad signature payload"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleParseCredentialJsonException --------------------

    @Test
    void handleParseCredentialJsonException() {
        var ex = new ParseCredentialJsonException("bad json");
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Credential JSON parsing error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal credential JSON parsing error occurred.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "bad json", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleParseCredentialJsonException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "bad json"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleProofValidationException --------------------

    @Test
    void handleProofValidationException() {
        var ex = new ProofValidationException("proof invalid");
        var type = GlobalErrorTypes.PROOF_VALIDATION_ERROR.getCode();
        var title = "Proof validation error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal proof validation error occurred.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "proof invalid", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleProofValidationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "proof invalid"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleNoCredentialFoundException --------------------

    @Test
    void handleNoCredentialFoundException() {
        var ex = new NoCredentialFoundException("nothing here");
        var type = GlobalErrorTypes.CREDENTIAL_NOT_FOUND.getCode();
        var title = "Credential not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "No credential found.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "nothing here", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleNoCredentialFoundException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "nothing here"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handlePreAuthorizationCodeGetException --------------------

    @Test
    void handlePreAuthorizationCodeGetException() {
        var ex = new PreAuthorizationCodeGetException("service down");
        var type = GlobalErrorTypes.PRE_AUTHORIZATION_CODE_GET.getCode();
        var title = "Pre-authorization code retrieval error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "Failed to retrieve pre-authorization code.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "service down", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handlePreAuthorizationCodeGetException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "service down"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleCredentialOfferNotFoundException --------------------

    @Test
    void handleCredentialOfferNotFoundException() {
        var ex = new CredentialOfferNotFoundException("offer not found");
        var type = GlobalErrorTypes.CREDENTIAL_OFFER_NOT_FOUND.getCode();
        var title = "Credential offer not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "Credential offer not found.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "offer not found", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialOfferNotFoundException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "offer not found"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleCredentialAlreadyIssuedException --------------------

    @Test
    void handleCredentialAlreadyIssuedException() {
        var ex = new CredentialAlreadyIssuedException("already issued");
        var type = GlobalErrorTypes.CREDENTIAL_ALREADY_ISSUED.getCode();
        var title = "Credential already issued";
        var st = HttpStatus.CONFLICT;
        var fallback = "The credential has already been issued.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "already issued", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialAlreadyIssuedException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "already issued"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleOperationNotSupportedException --------------------

    @Test
    void handleOperationNotSupportedException() {
        var ex = new OperationNotSupportedException("not allowed");
        var type = GlobalErrorTypes.OPERATION_NOT_SUPPORTED.getCode();
        var title = "Operation not supported";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The given operation is not supported";
        var expected = new GlobalErrorMessage(type, title, st.value(), "not allowed", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleOperationNotSupportedException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "not allowed"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleJWTVerificationException --------------------

    @Test
    void handleJWTVerificationException() {
        var ex = new JWTVerificationException("jwt invalid");
        var type = GlobalErrorTypes.JWT_VERIFICATION.getCode();
        var title = "JWT verification failed";
        var st = HttpStatus.UNAUTHORIZED;
        var fallback = "JWT verification failed.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "jwt invalid", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleJWTVerificationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "jwt invalid"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleFormatUnsupportedException --------------------

    @Test
    void handleFormatUnsupportedException() {
        var ex = new FormatUnsupportedException("format xyz not supported");
        var type = GlobalErrorTypes.FORMAT_IS_NOT_SUPPORTED.getCode();
        var title = "Format not supported";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "Format is not supported";
        var expected = new GlobalErrorMessage(type, title, st.value(), "format xyz not supported", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleFormatUnsupportedException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "format xyz not supported"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleInsufficientPermissionException --------------------

    @Test
    void handleInsufficientPermissionException() {
        var ex = new InsufficientPermissionException("no perms");
        var type = GlobalErrorTypes.INSUFFICIENT_PERMISSION.getCode();
        var title = "Insufficient permission";
        var st = HttpStatus.FORBIDDEN;
        var fallback = "The client who made the issuance request do not have the required permissions";
        var expected = new GlobalErrorMessage(type, title, st.value(), "no perms", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInsufficientPermissionException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "no perms"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleUnauthorizedRoleException --------------------

    @Test
    void handleUnauthorizedRoleException() {
        var ex = new UnauthorizedRoleException("role not allowed");
        var type = GlobalErrorTypes.UNAUTHORIZED_ROLE.getCode();
        var title = "Unauthorized role";
        var st = HttpStatus.UNAUTHORIZED;
        var fallback = "The user role is not authorized to perform this action";
        var expected = new GlobalErrorMessage(type, title, st.value(), "role not allowed", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleUnauthorizedRoleException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "role not allowed"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleEmailCommunicationException --------------------

    @Test
    void handleEmailCommunicationException() {
        var ex = new EmailCommunicationException("smtp down");
        var type = GlobalErrorTypes.EMAIL_COMMUNICATION.getCode();
        var title = "Email communication error";
        var st = HttpStatus.SERVICE_UNAVAILABLE;
        var fallback = "Email communication failed";
        var expected = new GlobalErrorMessage(type, title, st.value(), "smtp down", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleEmailCommunicationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "smtp down"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleMissingIdTokenHeaderException --------------------

    @Test
    void handleMissingIdTokenHeaderException() {
        var ex = new MissingIdTokenHeaderException("header missing");
        var type = GlobalErrorTypes.MISSING_HEADER.getCode();
        var title = "Missing header";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The X-ID-TOKEN header is missing, this header is needed to issue a Verifiable Certification";
        var expected = new GlobalErrorMessage(type, title, st.value(), "header missing", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleMissingIdTokenHeaderException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "header missing"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleSadException--------------------

    @Test
    void handleSadException() {
        var ex = new SadException("upstream SAD failed");
        var type = GlobalErrorTypes.SAD_ERROR.getCode();
        var title = "SAD error";
        var st = HttpStatus.BAD_GATEWAY;
        var fallback = "An upstream SAD error occurred";
        var expected = new GlobalErrorMessage(type, title, st.value(), "upstream SAD failed", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleSadException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "upstream SAD failed"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleCredentialSerializationException --------------------

    @Test

    void handleCredentialSerializationException() {
        var ex = new CredentialSerializationException("Credential serialization err");
        var type = GlobalErrorTypes.CREDENTIAL_SERIALIZATION.getCode();
        var title = "Credential serialization error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An error occurred during credential serialization";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "Credential serialization err",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialSerializationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "Credential serialization err"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleJWTParsingExceptionTest --------------------
  
    @Test
    void handleJWTParsingExceptionTest() {
        var ex = new JWTParsingException("jwt parsing exception");
        var type = GlobalErrorTypes.INVALID_JWT.getCode();
        var title = "JWT parsing error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "The provided JWT is invalid or can't be parsed.";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "jwt parsing exception",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleJWTParsingException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "jwt parsing exception"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleCredentialProcedureInvalidStatusException --------------------

    @Test
    void handleCredentialProcedureInvalidStatusException() {
        var ex = new CredentialProcedureInvalidStatusException("procedure status exception");
        var type = GlobalErrorTypes.CREDENTIAL_PROCEDURE_INVALID_STATUS.getCode();
        var title = "Invalid credential procedure status";
        var st = HttpStatus.CONFLICT;
        var fallback = "The credential procedure is not in a status that allows signing.";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "invalid procedure status",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialProcedureInvalidStatusException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "invalid procedure status"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

// -------------------- handleCredentialProcedureNotFoundException --------------------

    @Test
    void handleCredentialProcedureNotFoundException() {
        var ex = new CredentialProcedureNotFoundException("procedure not found");
        var type = GlobalErrorTypes.CREDENTIAL_PROCEDURE_NOT_FOUND.getCode();
        var title = "Credential procedure not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "The requested credential procedure was not found";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "procedure not found",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialProcedureNotFoundException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "procedure not found"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleInvalidCredentialFormatException() {
        var ex = new InvalidCredentialFormatException("invalid credential payload");
        var type = GlobalErrorTypes.INVALID_CREDENTIAL_FORMAT.getCode();
        var title = "Invalid credential format";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The credential payload is invalid";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "invalid credential payload",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidCredentialFormatException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "invalid credential payload"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleProcedureRetryRecordNotFoundException --------------------

    @Test
    void handleProcedureRetryRecordNotFoundException() {
        var ex = new ProcedureRetryRecordNotFoundException("retry record not found");
        var type = GlobalErrorTypes.PROCEDURE_RETRY_RECORD_NOT_FOUND.getCode();
        var title = "Retry record not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "The requested retry record was not found";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "retry record not found",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleProcedureRetryRecordNotFoundException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "retry record not found"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleInvalidRetryStatusException --------------------

    @Test
    void handleInvalidRetryStatusException() {
        var ex = new InvalidRetryStatusException("retry status is not pending");
        var type = GlobalErrorTypes.INVALID_RETRY_STATUS.getCode();
        var title = "Invalid retry status";
        var st = HttpStatus.CONFLICT;
        var fallback = "The retry record is not in a valid status for this operation";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "retry status is not pending",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidRetryStatusException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "retry status is not pending"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleRetryPayloadException --------------------

    @Test
    void handleRetryPayloadException() {
        var ex = new RetryPayloadException("failed to serialize payload");
        var type = GlobalErrorTypes.RETRY_PAYLOAD_ERROR.getCode();
        var title = "Retry payload error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An error occurred while serializing or deserializing retry payload";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "failed to serialize payload",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleRetryPayloadException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "failed to serialize payload"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleRetryConfigurationException --------------------

    @Test
    void handleRetryConfigurationException() {
        var ex = new RetryConfigurationException("invalid retry configuration");
        var type = GlobalErrorTypes.RETRY_CONFIGURATION_ERROR.getCode();
        var title = "Retry configuration error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An error occurred in the retry mechanism configuration";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "invalid retry configuration",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleRetryConfigurationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "invalid retry configuration"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

}
