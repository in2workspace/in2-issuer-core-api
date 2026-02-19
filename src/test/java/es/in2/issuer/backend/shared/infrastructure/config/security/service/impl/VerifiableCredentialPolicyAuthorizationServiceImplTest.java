package es.in2.issuer.backend.shared.infrastructure.config.security.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialMachineFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL;
import static es.in2.issuer.backend.shared.domain.util.Constants.ROLE;
import static es.in2.issuer.backend.shared.domain.util.Constants.VC;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialPolicyAuthorizationServiceImplTest {

    // Use a single source of truth for the admin org id used across tests
    private static final String ADMIN_ORG_ID = "IN2_ADMIN_ORG_ID_FOR_TEST";

    @Mock
    private JWTService jwtService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private VerifierService verifierService;

    @Mock
    private AppConfig appConfig;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    @Mock
    private LabelCredentialFactory labelCredentialFactory;
    @Mock
    private LEARCredentialMachineFactory learCredentialMachineFactory;
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @InjectMocks
    private VerifiableCredentialPolicyAuthorizationServiceImpl policyAuthorizationService;

    @BeforeEach
    void setUp() {
        // Build real CredentialFactory composed of mocked sub-factories
        CredentialFactory credentialFactory = new CredentialFactory(
                learCredentialEmployeeFactory,
                learCredentialMachineFactory,
                labelCredentialFactory,
                credentialProcedureService,
                deferredCredentialMetadataService
        );

        // AppConfig must provide the current admin organization id used by the service
        org.mockito.Mockito.lenient()
                .when(appConfig.getAdminOrganizationId())
                .thenReturn(ADMIN_ORG_ID);

        // Construct service with AppConfig first
        policyAuthorizationService = new VerifiableCredentialPolicyAuthorizationServiceImpl(
                appConfig,
                jwtService,
                objectMapper,
                credentialFactory,
                verifierService
        );
    }

    @Test
    void authorize_success_withLearCredentialEmployee() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployee();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_dueToInvalidCredentialType() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"InvalidCredentialType\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: Credential type 'LEARCredentialEmployee' or 'LEARCredentialMachine' is required."))
                .verify();
    }

    @Test
    void authorize_failure_dueToUnsupportedSchema() throws Exception {
        // Arrange
        String token = "valid-token";
        String schema = "UnsupportedSchema";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployee();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, schema, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: Unsupported schema"))
                .verify();
    }

    @Test
    void authorize_failure_dueToInvalidToken() {
        String token = "invalid-token";
        JsonNode payload = mock(JsonNode.class);

        when(jwtService.parseJWT(token)).thenThrow(new ParseErrorException("Invalid token"));

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof ParseErrorException &&
                                throwable.getMessage().contains("Invalid token"))
                .verify();
    }

    @Test
    void authorize_failure_dueToIssuancePoliciesNotMet() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "some-other-issuer");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_failure_dueToVerifiableCertificationPolicyNotMet() throws Exception {
        // Arrange
        String token = "valid-token";
        String idToken = "dummy-id-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialMachine\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "some-other-issuer");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialMachine learCredential = getLEARCredentialMachineWithInvalidPolicy();
        when(learCredentialMachineFactory.mapStringToLEARCredentialMachine(vcClaim)).thenReturn(learCredential);

        SignedJWT idTokenSignedJWT = mock(SignedJWT.class);
        Payload idTokenPayload = new Payload(new HashMap<>());
        when(idTokenSignedJWT.getPayload()).thenReturn(idTokenPayload);
        when(verifierService.verifyTokenWithoutExpiration(idToken)).thenReturn(Mono.empty());
        when(jwtService.parseJWT(idToken)).thenReturn(idTokenSignedJWT);
        when(jwtService.getClaimFromPayload(idTokenPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");

        LEARCredentialEmployee idTokenCredential = getLEARCredentialEmployeeForCertification();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vcJson")).thenReturn(idTokenCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LABEL_CREDENTIAL, payload, idToken);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: VerifiableCertification does not meet the issuance policy."))
                .verify();
    }

    @Test
    void authorize_success_withVerifiableCertification() throws Exception {
        // Arrange
        String token = "valid-token";
        String idToken = "dummy-id-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialMachine\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "external-verifier");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Emulate a machine credential that meets Certification+Attest
        LEARCredentialMachine learCredential = getLEARCredentialMachineForCertification();
        when(learCredentialMachineFactory.mapStringToLEARCredentialMachine(vcClaim)).thenReturn(learCredential);

        // --- id_token mocks ---
        SignedJWT idTokenSignedJWT = mock(SignedJWT.class);
        Payload idTokenPayload = new Payload(new HashMap<>());
        when(idTokenSignedJWT.getPayload()).thenReturn(idTokenPayload);
        when(verifierService.verifyTokenWithoutExpiration(idToken)).thenReturn(Mono.empty());
        when(jwtService.parseJWT(idToken)).thenReturn(idTokenSignedJWT);
        when(jwtService.getClaimFromPayload(idTokenPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");
        LEARCredentialEmployee idTokenCredential = getLEARCredentialEmployeeForCertification();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vcJson")).thenReturn(idTokenCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LABEL_CREDENTIAL, payload, idToken);

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_withLearCredentialEmployerRoleLear() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "external-verifier");
        String roleClaim = LEAR;
        payloadMap.put(ROLE, roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeForCertification();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_success_withMandatorIssuancePolicyValid() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();

        LEARCredentialEmployee.CredentialSubject.Mandate mandateFromPayload = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(Mandator.builder()
                        .organizationIdentifier(learCredential.credentialSubject().mandate().mandator().organizationIdentifier())
                        .serialNumber(learCredential.credentialSubject().mandate().mandator().serialNumber())
                        .country(learCredential.credentialSubject().mandate().mandator().country())
                        .commonName(learCredential.credentialSubject().mandate().mandator().commonName())
                        .email(learCredential.credentialSubject().mandate().mandator().email())
                        .build())
                .power(Collections.singletonList(
                        Power.builder()
                                .function("ProductOffering")
                                .action(List.of("Create", "Update", "Delete"))
                                .build()))
                .build();
        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class)).thenReturn(mandateFromPayload);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_dueToInvalidPayloadPowers() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();

        LEARCredentialEmployee.CredentialSubject.Mandate mandateFromPayload = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(Mandator.builder()
                        .organizationIdentifier(learCredential.credentialSubject().mandate().mandator().organizationIdentifier())
                        .serialNumber(learCredential.credentialSubject().mandate().mandator().serialNumber())
                        .country(learCredential.credentialSubject().mandate().mandator().country())
                        .commonName(learCredential.credentialSubject().mandate().mandator().commonName())
                        .email(learCredential.credentialSubject().mandate().mandator().email())
                        .build())
                .power(Collections.singletonList(
                        Power.builder()
                                .function("OtherFunction")
                                .action("SomeAction")
                                .build()))
                .build();
        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class)).thenReturn(mandateFromPayload);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_success_withLearCredentialMachine() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_withLearCredentialMachine_dueToPolicy() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, "LEAR_CREDENTIAL_MACHINE", payload, "dummy-id-token");

        StepVerifier.create(result)
                .expectErrorMatches(InsufficientPermissionException.class::isInstance)
                .verify();
    }

    @Test
    void authorize_failure_dueToUnauthorizedRoleIsBlank() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim = "\"\"";
        payloadMap.put(ROLE, roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LABEL_CREDENTIAL, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("Access denied: Role is empty"))
                .verify();
    }

    @Test
    void authorize_failure_dueToUnauthorizedRoleWithVerifiableCertification() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim = LER;
        payloadMap.put(ROLE, roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LABEL_CREDENTIAL, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("Access denied: Unauthorized Role '" + roleClaim + "'"))
                .verify();
    }

    @Test
    void authorize_failure_dueToSYS_ADMINOrLERRole() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim = SYS_ADMIN;
        payloadMap.put(ROLE, roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("The request is invalid. The roles 'SYSADMIN' and 'LER' currently have no defined permissions.")
                )
                .verify();
    }

    @Test
    void authorize_failureDueToUnknownRole() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim = "ADMIN";
        payloadMap.put(ROLE, roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("Access denied: Unauthorized Role '" + roleClaim + "'"))
                .verify();
    }

    @Test
    void authorize_failureDueToNullRole() {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        String roleClaim = null;
        payloadMap.put(ROLE, roleClaim);
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, ROLE)).thenReturn(roleClaim);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof UnauthorizedRoleException &&
                                throwable.getMessage().contains("Access denied: Role is empty"))
                .verify();
    }

    // Helpers to build credentials for tests (use ADMIN_ORG_ID instead of any constant)

    private LEARCredentialEmployee getLEARCredentialEmployee() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier(ADMIN_ORG_ID)
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .firstName("John")
                        .lastName("Doe")
                        .email("john.doe@example.com")
                        .build();
        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();
        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialEmployee getLEARCredentialEmployeeWithDifferentOrg() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("OTHER_ORGANIZATION")
                .commonName("SomeOtherOrganization")
                .country("ES")
                .email("someaddress@example.com")
                .serialNumber("123456")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .firstName("John")
                        .lastName("Doe")
                        .email("john.doe@example.com")
                        .build();
        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();
        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialMachine getLEARCredentialMachineForCertification() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                        .organization("SomeOrganization")
                        .build();
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .build();
        Power power = Power.builder()
                .function("Certification")
                .action("Attest")
                .build();
        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();
        LEARCredentialMachine.CredentialSubject credentialSubject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialEmployee getLEARCredentialEmployeeForCertification() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("SomeOrganization")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .firstName("Jane")
                        .lastName("Doe")
                        .email("jane.doe@example.com")
                        .build();
        Power power = Power.builder()
                .function("Certification")
                .action("Attest")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();
        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialMachine getLEARCredentialMachine() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                        .organization(ADMIN_ORG_ID)
                        .build();
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .build();
        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();
        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();
        LEARCredentialMachine.CredentialSubject credentialSubject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialMachine getLEARCredentialMachineWithInvalidPolicy() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                        .organization(ADMIN_ORG_ID)
                        .build();
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .build();
        // Empty list of powers to simulate failing policy
        List<Power> emptyPowers = Collections.emptyList();
        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(emptyPowers)
                        .build();
        LEARCredentialMachine.CredentialSubject credentialSubject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }

    @Test
    void authorize_machine_success_whenMandatorAllowed_and_OnboardingExecute() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        LEARCredentialEmployee signerEmployee = getLEARCredentialEmployee();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim))
                .thenReturn(signerEmployee);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_whenMandatorOrgIdMismatch() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();

        // Payload mandate with different mandator org id than token
        LEARCredentialEmployee.CredentialSubject.Mandate mandateFromPayload =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(Mandator.builder()
                                .organizationIdentifier("DIFFERENT_ORG_ID")
                                .serialNumber(learCredential.credentialSubject().mandate().mandator().serialNumber())
                                .country(learCredential.credentialSubject().mandate().mandator().country())
                                .commonName(learCredential.credentialSubject().mandate().mandator().commonName())
                                .email(learCredential.credentialSubject().mandate().mandator().email())
                                .build())
                        .power(Collections.singletonList(
                                Power.builder()
                                        .function("ProductOffering")
                                        .action(List.of("Create", "Update", "Delete"))
                                        .build()))
                        .build();

        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class))
                .thenReturn(mandateFromPayload);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_failure_whenPayloadMandateIsNull() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();

        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class))
                .thenReturn(null);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_failure_whenTokenDoesNotHaveOnboardingExecutePower() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithoutOnboardingExecutePower();

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(learCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    private LEARCredentialEmployee getLEARCredentialEmployeeWithoutOnboardingExecutePower() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("OTHER_ORGANIZATION")
                .commonName("SomeOtherOrganization")
                .country("ES")
                .email("someaddress@example.com")
                .serialNumber("123456")
                .build();

        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .firstName("John")
                        .lastName("Doe")
                        .email("john.doe@example.com")
                        .build();

        // Not Execute -> should fail new guard
        Power power = Power.builder()
                .function("Onboarding")
                .action("Read")
                .build();

        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();

        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }

    @Test
    void authorize_machine_success_withMandatorIssuancePolicyValidLearCredentialMachine() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        // Token credential: Employee with Onboarding/Execute + full Mandator fields
        LEARCredentialEmployee tokenCredential = getLEARCredentialEmployeeWithFullMandatorData();

        // Payload mandate: Machine mandate whose mandator matches token mandator
        LEARCredentialMachine.CredentialSubject.Mandate payloadMandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                                .organizationIdentifier(tokenCredential.credentialSubject().mandate().mandator().organizationIdentifier())
                                .organization(tokenCredential.credentialSubject().mandate().mandator().organization())
                                .country(tokenCredential.credentialSubject().mandate().mandator().country())
                                .commonName(tokenCredential.credentialSubject().mandate().mandator().commonName())
                                .serialNumber(tokenCredential.credentialSubject().mandate().mandator().serialNumber())
                                .build())
                        .power(Collections.singletonList(
                                Power.builder()
                                        .function("Onboarding")
                                        .action("Execute")
                                        .build()))
                        .build();

        when(objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(payloadMandate);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(tokenCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_machine_failure_whenPayloadMandatorOrganizationIsNull_equalsSafeReturnsFalse() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee tokenCredential = getLEARCredentialEmployeeWithFullMandatorData();

        // Same as token, BUT payload mandator.organization is null => equalsSafe(null, tokenOrg) is false
        LEARCredentialMachine.CredentialSubject.Mandate payloadMandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                                .organizationIdentifier(tokenCredential.credentialSubject().mandate().mandator().organizationIdentifier())
                                .organization(null)
                                .country(tokenCredential.credentialSubject().mandate().mandator().country())
                                .commonName(tokenCredential.credentialSubject().mandate().mandator().commonName())
                                .serialNumber(tokenCredential.credentialSubject().mandate().mandator().serialNumber())
                                .build())
                        .power(Collections.singletonList(
                                Power.builder()
                                        .function("Onboarding")
                                        .action("Execute")
                                        .build()))
                        .build();

        when(objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(payloadMandate);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(tokenCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized"))
                .verify();
    }

    @Test
    void authorize_machine_failure_whenTokenMandatorIsNull() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee tokenCredential = getLEARCredentialEmployeeWithOnboardingExecuteButNullMandator();

        // Payload mandate: can be valid, but it won't matter because tokenMandator becomes null
        LEARCredentialMachine.CredentialSubject.Mandate payloadMandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                                .organizationIdentifier("ANY")
                                .organization("ANY")
                                .country("ES")
                                .commonName("ANY")
                                .serialNumber("ANY")
                                .build())
                        .power(Collections.singletonList(
                                Power.builder()
                                        .function("Onboarding")
                                        .action("Execute")
                                        .build()))
                        .build();

        when(objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(payloadMandate);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(tokenCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized"))
                .verify();
    }

    @Test
    void authorize_machine_failure_whenPayloadMandateIsNull() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee tokenCredential = getLEARCredentialEmployeeWithFullMandatorData();

        when(objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(null);

        SignedJWT signedJWT = mock(SignedJWT.class);
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialEmployee\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        when(signedJWT.getPayload()).thenReturn(jwtPayload);
        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim)).thenReturn(tokenCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized"))
                .verify();
    }

    private LEARCredentialEmployee getLEARCredentialEmployeeWithFullMandatorData() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("ORG_ID_1")
                .organization("ORG_1")
                .country("ES")
                .commonName("Org Common Name")
                .serialNumber("SN-123")
                .email("contact@example.com")
                .build();

        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .firstName("John")
                        .lastName("Doe")
                        .email("john.doe@example.com")
                        .build();

        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();

        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();

        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }
    private LEARCredentialEmployee getLEARCredentialEmployeeWithOnboardingExecuteButNullMandator() {
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .firstName("John")
                        .lastName("Doe")
                        .email("john.doe@example.com")
                        .build();

        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();

        // Mandator intentionally null
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(null)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();

        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }

    @Test
    void authorize_employee_success_whenTokenContainsLearCredentialMachine_withOnboardingExecute_andAdminOrg() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        // Token vc is a Machine credential, but schema requested is Employee
        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialMachine\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Machine credential must satisfy signer policy:
        // - mandator orgIdentifier == ADMIN_ORG_ID
        // - has Onboarding + Execute
        LEARCredentialMachine machineCredential = getLEARCredentialMachineForEmployeeIssuance();
        when(learCredentialMachineFactory.mapStringToLEARCredentialMachine(vcClaim)).thenReturn(machineCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_employee_failure_whenTokenContainsLearCredentialMachine_withoutOnboardingExecute() throws Exception {
        // Arrange
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        String vcClaim = "{\"type\": [\"VerifiableCredential\", \"LEARCredentialMachine\"]}";

        Map<String, Object> payloadMap = new HashMap<>();
        payloadMap.put("iss", "internal-auth-server");
        Payload jwtPayload = new Payload(payloadMap);

        SignedJWT signedJWT = mock(SignedJWT.class);
        when(signedJWT.getPayload()).thenReturn(jwtPayload);

        when(jwtService.parseJWT(token)).thenReturn(signedJWT);
        when(jwtService.getClaimFromPayload(jwtPayload, VC)).thenReturn(vcClaim);

        ObjectMapper realObjectMapper = new ObjectMapper();
        JsonNode vcJsonNode = realObjectMapper.readTree(vcClaim);
        when(objectMapper.readTree(vcClaim)).thenReturn(vcJsonNode);

        // Machine credential does NOT have Onboarding/Execute => signer policy fails
        LEARCredentialMachine machineCredential = getLEARCredentialMachineForEmployeeIssuanceWithoutOnboardingExecute();
        when(learCredentialMachineFactory.mapStringToLEARCredentialMachine(vcClaim)).thenReturn(machineCredential);

        // Act
        Mono<Void> result = policyAuthorizationService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    private LEARCredentialMachine getLEARCredentialMachineForEmployeeIssuance() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                        .organizationIdentifier(ADMIN_ORG_ID)
                        .organization("IN2")
                        .country("ES")
                        .commonName("IN2")
                        .serialNumber("SN-IN2")
                        .build();

        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:machine-1234")
                        .build();

        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();

        LEARCredentialMachine.CredentialSubject credentialSubject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialMachine getLEARCredentialMachineForEmployeeIssuanceWithoutOnboardingExecute() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                        .organizationIdentifier(ADMIN_ORG_ID)
                        .organization("IN2")
                        .country("ES")
                        .commonName("IN2")
                        .serialNumber("SN-IN2")
                        .build();

        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:machine-1234")
                        .build();

        // Not Execute => should fail issuance policy
        Power power = Power.builder()
                .function("Onboarding")
                .action("Read")
                .build();

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();

        LEARCredentialMachine.CredentialSubject credentialSubject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }




}
