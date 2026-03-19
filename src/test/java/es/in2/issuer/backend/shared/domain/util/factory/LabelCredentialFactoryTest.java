package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.CredentialSerializationException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.LabelCredentialJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.LabelCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LabelCredentialFactoryTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private IssuerFactory issuerFactory;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private Validator validator;

    @InjectMocks
    private LabelCredentialFactory labelCredentialFactory;

    @Test
    void testMapCredentialAndBindIssuerInToTheCredential() throws Exception {
        String procedureId = "procedure-123";
        String credentialJson = "{\"id\":\"urn:uuid:123\"}";
        String testEmail = "test@email.com";

        LabelCredential labelCredential = validLabelCredential();

        when(objectMapper.readValue(credentialJson, LabelCredential.class))
                .thenReturn(labelCredential);

        when(issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, testEmail))
                .thenReturn(Mono.just(SimpleIssuer.builder().id("issuer-id").build()));

        when(objectMapper.writeValueAsString(any(LabelCredential.class)))
                .thenReturn("{\"mocked\": true}");

        Mono<String> result = labelCredentialFactory.mapCredentialAndBindIssuerInToTheCredential(
                credentialJson,
                procedureId,
                testEmail
        );

        StepVerifier.create(result)
                .expectNext("{\"mocked\": true}")
                .verifyComplete();
    }

    @Test
    void testMapAndBuildLabelCredential() throws JsonProcessingException {
        String procedureId = "proc-123";
        String email = "test@in2.es";
        String operationMode = "S";
        JsonNode mockNode = mock(JsonNode.class);
        CredentialStatus credentialStatus = mock(CredentialStatus.class);

        LabelCredential labelCredential = validLabelCredential();

        when(objectMapper.convertValue(mockNode, LabelCredential.class))
                .thenReturn(labelCredential);
        when(validator.validate(labelCredential))
                .thenReturn(Collections.emptySet());
        when(accessTokenService.getOrganizationIdFromCurrentSession())
                .thenReturn(Mono.just("org-456"));
        when(objectMapper.writeValueAsString(any(LabelCredential.class)))
                .thenReturn("{\"mocked\": true}");

        Mono<CredentialProcedureCreationRequest> result =
                labelCredentialFactory.mapAndBuildLabelCredential(
                        procedureId,
                        mockNode,
                        credentialStatus,
                        operationMode,
                        email
                );

        StepVerifier.create(result)
                .assertNext(request -> {
                    assertEquals(procedureId, request.procedureId());
                    assertEquals("subject-1", request.subject());
                    assertEquals(CredentialType.LABEL_CREDENTIAL, request.credentialType());
                    assertEquals(email, request.email());
                    assertEquals(operationMode, request.operationMode());
                    assertEquals("org-456", request.organizationIdentifier());
                    assertNotNull(request.validUntil());
                    assertNotNull(request.credentialDecoded());
                })
                .verifyComplete();

        verify(accessTokenService).getOrganizationIdFromCurrentSession();
        verify(objectMapper).convertValue(mockNode, LabelCredential.class);
        verify(validator).validate(labelCredential);
        verify(objectMapper).writeValueAsString(any(LabelCredential.class));
    }

    @Test
    void testMapAndBuildLabelCredential_whenValidationFails_returnsInvalidCredentialFormatException() {
        String procedureId = "proc-123";
        String email = "test@in2.es";
        String operationMode = "S";
        JsonNode mockNode = mock(JsonNode.class);
        CredentialStatus credentialStatus = mock(CredentialStatus.class);

        LabelCredential labelCredential = validLabelCredential();

        @SuppressWarnings("unchecked")
        ConstraintViolation<LabelCredential> violation = mock(ConstraintViolation.class);

        when(objectMapper.convertValue(mockNode, LabelCredential.class))
                .thenReturn(labelCredential);
        when(validator.validate(labelCredential))
                .thenReturn(Set.of(violation));

        Mono<CredentialProcedureCreationRequest> result =
                labelCredentialFactory.mapAndBuildLabelCredential(
                        procedureId,
                        mockNode,
                        credentialStatus,
                        operationMode,
                        email
                );

        StepVerifier.create(result)
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(InvalidCredentialFormatException.class, ex);
                    assertEquals("Invalid LabelCredential payload", ex.getMessage());
                })
                .verify();
    }

    @Test
    void testMapStringToLabelCredential_validV1() throws Exception {
        String credentialJson = "{\"@context\": \"https://trust-framework.dome-marketplace.eu/credentials/labelcredential/v1\"}";
        LabelCredential labelCredential = validLabelCredential();

        when(objectMapper.readValue(credentialJson, LabelCredential.class))
                .thenReturn(labelCredential);

        LabelCredential result = labelCredentialFactory.mapStringToLabelCredential(credentialJson);

        assertEquals("label-123", result.id());
    }

    @Test
    void testMapIssuer() throws Exception {
        String procedureId = "proc-1";
        String credentialJson = "{\"id\":\"label-1\"}";

        LabelCredential labelCredential = validLabelCredential();
        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id("issuer-1").build();

        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureId))
                .thenReturn(Mono.just(credentialJson));
        when(objectMapper.readValue(credentialJson, LabelCredential.class))
                .thenReturn(labelCredential);
        when(objectMapper.writeValueAsString(any(LabelCredential.class)))
                .thenReturn("{\"mocked\":true}");

        Mono<String> result = labelCredentialFactory.mapIssuer(procedureId, simpleIssuer);

        StepVerifier.create(result)
                .expectNext("{\"mocked\":true}")
                .verifyComplete();
    }

    @Test
    void testBindIssuer() {
        LabelCredential labelCredential = validLabelCredential();
        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id("issuer-1").build();

        Mono<LabelCredential> result = labelCredentialFactory.bindIssuer(labelCredential, simpleIssuer);

        StepVerifier.create(result)
                .assertNext(lc -> {
                    assertEquals("label-123", lc.id());
                    assertEquals("issuer-1", lc.issuer().getId());
                })
                .verifyComplete();
    }

    @Test
    void testBuildLabelCredentialJwtPayload() {
        LabelCredential credential = LabelCredential.builder()
                .id("label-1")
                .issuer(SimpleIssuer.builder().id("issuer-123").build())
                .credentialSubject(validCredentialSubject())
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-01-02T00:00:00Z")
                .build();

        Mono<LabelCredentialJwtPayload> result = labelCredentialFactory.buildLabelCredentialJwtPayload(credential);

        StepVerifier.create(result)
                .assertNext(payload -> {
                    assertEquals("issuer-123", payload.issuer());
                    assertEquals("subject-1", payload.subject());
                    assertNotNull(payload.JwtId());
                    assertNotNull(payload.expirationTime());
                    assertNotNull(payload.issuedAt());
                })
                .verifyComplete();
    }

    @Test
    void testConvertLabelCredentialJwtPayloadInToString() throws Exception {
        LabelCredentialJwtPayload payload = LabelCredentialJwtPayload.builder()
                .JwtId("jwt-id")
                .issuer("issuer-1")
                .subject("sub-1")
                .expirationTime(123456789L)
                .issuedAt(123456700L)
                .notValidBefore(123456700L)
                .build();

        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"jwt\":\"mocked\"}");

        Mono<String> result = labelCredentialFactory.convertLabelCredentialJwtPayloadInToString(payload);

        StepVerifier.create(result)
                .expectNext("{\"jwt\":\"mocked\"}")
                .verifyComplete();
    }

    @Test
    void testMapStringToLabelCredential_throwsInvalidCredentialFormatException() throws Exception {
        String malformedJson = "{invalid_json}";

        when(objectMapper.readValue(malformedJson, LabelCredential.class))
                .thenThrow(new JsonProcessingException("boom") {});

        assertThrows(
                InvalidCredentialFormatException.class,
                () -> labelCredentialFactory.mapStringToLabelCredential(malformedJson)
        );
    }

    @Test
    void convertLabelCredentialInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LabelCredential credential = validLabelCredential();

        when(objectMapper.writeValueAsString(any(LabelCredential.class)))
                .thenThrow(new JsonProcessingException("error") {});

        Method method = LabelCredentialFactory.class
                .getDeclaredMethod("convertLabelCredentialInToString", LabelCredential.class);
        method.setAccessible(true);

        Object invokeResult = method.invoke(labelCredentialFactory, credential);

        assertInstanceOf(Mono.class, invokeResult);

        StepVerifier.create((Mono<?>) invokeResult)
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(CredentialSerializationException.class, ex);
                    assertEquals("Error serializing LabelCredential to string.", ex.getMessage());
                })
                .verify();
    }

    @Test
    void convertLabelCredentialJwtPayloadInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LabelCredentialJwtPayload payload = mock(LabelCredentialJwtPayload.class);

        when(objectMapper.writeValueAsString(any(LabelCredentialJwtPayload.class)))
                .thenThrow(new JsonProcessingException("error") {});

        Mono<String> result = labelCredentialFactory.convertLabelCredentialJwtPayloadInToString(payload);

        StepVerifier.create(result)
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(CredentialSerializationException.class, ex);
                    assertEquals("Error serializing LabelCredential JWT payload to string.", ex.getMessage());
                })
                .verify();
    }

    private LabelCredential validLabelCredential() {
        return LabelCredential.builder()
                .id("label-123")
                .type(List.of("gx:LabelCredential"))
                .credentialSubject(validCredentialSubject())
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-01-02T00:00:00Z")
                .build();
    }

    private LabelCredential.CredentialSubject validCredentialSubject() {
        return LabelCredential.CredentialSubject.builder()
                .id("subject-1")
                .gxLabelLevel("gold")
                .gxEngineVersion("1.0.0")
                .gxRulesVersion("2.0.0")
                .gxCompliantCredentials(List.of(validCompliantCredential()))
                .gxValidatedCriteria(List.of("criterion-1"))
                .build();
    }

    private LabelCredential.CredentialSubject.CompliantCredentials validCompliantCredential() {
        return LabelCredential.CredentialSubject.CompliantCredentials.builder()
                .id("credential-1")
                .type("VerifiableCredential")
                .gxDigestSRI("sha256-abc123")
                .build();
    }
}