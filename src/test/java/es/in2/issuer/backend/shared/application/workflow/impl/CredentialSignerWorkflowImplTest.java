package es.in2.issuer.backend.shared.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.backoffice.domain.service.ProcedureRetryService;
import es.in2.issuer.backend.shared.application.workflow.DeferredCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureInvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialMachineFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.JWT_VC;
import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL_TYPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE_TYPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_MACHINE_TYPE;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialSignerWorkflowImplTest {

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private BackofficePdpService backofficePdpService;

    @Mock
    private RemoteSignatureService remoteSignatureService;

    @Mock
    private DeferredCredentialWorkflow deferredCredentialWorkflow;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @Mock
    private LEARCredentialMachineFactory learCredentialMachineFactory;

    @Mock
    private LabelCredentialFactory labelCredentialFactory;

    @Mock
    private IssuerFactory issuerFactory;

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @Mock
    private M2MTokenService m2mTokenService;

    @Mock
    private CredentialDeliveryService credentialDeliveryService;

    @Mock
    private ProcedureRetryService procedureRetryService;

    @Mock
    private AppConfig appConfig;

    @Mock
    private EmailService emailService;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private SimpleIssuer simpleIssuer;

    @Mock
    private VerifierOauth2AccessToken verifierOauth2AccessToken;

    @Spy
    @InjectMocks
    CredentialSignerWorkflowImpl credentialSignerWorkflow;

    private final String processId = "process-123";
    private final String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";
    private final String authorizationHeader = "Bearer some-token";
    private final String token = "some-token";
    private final String email = "alice@example.com";
    private final String bindedCredential = "bindedCredential";

    @Test
    void testRetrySignUnsignedCredential_Success_LEARCredentialEmployee() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_TYPE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC))
                .thenReturn(Mono.empty());
        doReturn(Mono.just("signedCredential"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any())).thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .verifyComplete();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdpService).validateSignCredential(processId, token, procedureId);
        verify(learCredentialEmployeeFactory)
                .mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email);
        // Helper method path verification
        verify(credentialProcedureService)
                .updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC);
        verify(credentialSignerWorkflow).signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        verify(credentialProcedureService).updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);
    }

    @Test
    void testRetrySignUnsignedCredential_ThrowsWhenProcedureNotFound() {
        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorSatisfies(throwable -> {
                    assertTrue(throwable instanceof CredentialProcedureNotFoundException);
                    assertEquals(
                            "Credential procedure with ID " + procedureId + " was not found",
                            throwable.getMessage()
                    );
                })
                .verify();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdpService).validateSignCredential(processId, token, procedureId);
        verifyNoInteractions(learCredentialEmployeeFactory);
    }

    @Test
    void testRetrySignUnsignedCredential_ErrorOnMappingCredential() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_TYPE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email))
                .thenReturn(Mono.error(new RuntimeException("Mapping failed")));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorMessage("Mapping failed")
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_DefaultCase_ThrowsIllegalArgument() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialType()).thenReturn("UNKNOWN_TYPE");
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalArgumentException &&
                                throwable.getMessage().contains("Unsupported credential type: UNKNOWN_TYPE")
                )
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_LabelCredential_NoResponseUri_ThrowsError() {
        CredentialProcedure initialProcedure = mock(CredentialProcedure.class);
        when(initialProcedure.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(initialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProcedure updatedProcedure = mock(CredentialProcedure.class);
        when(updatedProcedure.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(updatedProcedure.getEmail()).thenReturn(email);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(initialProcedure), Mono.just(updatedProcedure));

        when(issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, email))
                .thenReturn(Mono.just(simpleIssuer));
        when(labelCredentialFactory.mapIssuer(procedureId, simpleIssuer))
                .thenReturn(Mono.just("bindedVc"));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, "bindedVc", JWT_VC))
                .thenReturn(Mono.empty());

        doReturn(Mono.just("signedVc"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(updatedProcedure));

        // Mock email sending (fire-and-forget) - use lenient since async may not complete during test
        lenient().when(deferredCredentialMetadataService.getTransactionCodeByProcedureId(procedureId))
                .thenReturn(Mono.just("trans-code"));
        lenient().when(appConfig.getIssuerFrontendUrl()).thenReturn("https://issuer.example.com");
        lenient().when(appConfig.getKnowledgebaseWalletUrl()).thenReturn("https://wallet.example.com");
        lenient().when(appConfig.getSysTenant()).thenReturn("sys-tenant");
        lenient().when(emailService.sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(deferredCredentialMetadataService.getResponseUriByProcedureId(procedureId))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalStateException &&
                                throwable.getMessage().contains("Missing responseUri for procedureId")
                )
                .verify();

        // Verify LABEL flow and helper usage
        verify(issuerFactory).createSimpleIssuerAndNotifyOnError(procedureId, email);
        verify(labelCredentialFactory).mapIssuer(procedureId, simpleIssuer);
        verify(credentialProcedureService)
                .updateDecodedCredentialByProcedureId(procedureId, "bindedVc", JWT_VC);
        verify(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        verify(credentialProcedureService)
                .updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);
        verify(credentialProcedureRepository).save(any());
    }

    @Test
    void testRetrySignUnsignedCredential_NonLabelCredential_DoesNotSendVc() {
        CredentialProcedure initialProcedure = mock(CredentialProcedure.class);
        when(initialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_TYPE);
        when(initialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(initialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProcedure updatedProcedure = mock(CredentialProcedure.class);
        when(updatedProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_TYPE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(initialProcedure), Mono.just(updatedProcedure));

        when(learCredentialEmployeeFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC))
                .thenReturn(Mono.empty());

        doReturn(Mono.just("signedVc"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(updatedProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .verifyComplete();

        // Verify LEAR employee flow and helper usage
        verify(learCredentialEmployeeFactory)
                .mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email);
        verify(credentialProcedureService)
                .updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC);

        // No VC delivery should happen for non-LABEL credentials
        verifyNoInteractions(deferredCredentialMetadataService);
        verifyNoInteractions(m2mTokenService);
        verifyNoInteractions(credentialDeliveryService);
    }

    @Test
    void testRetrySignUnsignedCredential_ValidationFails() {
        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.error(new RuntimeException("Validation failed")));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorMessage("Validation failed")
                .verify();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdpService).validateSignCredential(processId, token, procedureId);
        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void testRetrySignUnsignedCredential_StatusNotPendSignature_ThrowsInvalidStatusException() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(null);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectError(CredentialProcedureInvalidStatusException.class)
                .verify();

        verify(credentialProcedureRepository).findByProcedureId(UUID.fromString(procedureId));
        verifyNoInteractions(learCredentialEmployeeFactory);
        verifyNoInteractions(issuerFactory);
    }

    @Test
    void testRetrySignUnsignedCredential_Success_LEARCredentialMachine() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_MACHINE_TYPE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialMachineFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC))
                .thenReturn(Mono.empty());

        doReturn(Mono.just("signedCredential"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);

        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .verifyComplete();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdpService).validateSignCredential(processId, token, procedureId);
        verify(accessTokenService).getMandateeEmail(authorizationHeader);
        verify(credentialProcedureRepository, atLeastOnce()).findByProcedureId(UUID.fromString(procedureId));

        verify(learCredentialMachineFactory)
                .mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email);
        // Helper call verification for machine credential
        verify(credentialProcedureService)
                .updateDecodedCredentialByProcedureId(procedureId, bindedCredential, JWT_VC);
        verify(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        verify(credentialProcedureService)
                .updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);
        verify(credentialProcedureRepository).save(any());

        verifyNoInteractions(learCredentialEmployeeFactory);
        verifyNoInteractions(labelCredentialFactory);
    }

    @Test
    void testRetrySignUnsignedCredential_ErrorOnMappingCredential_LEARCredentialMachine() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_MACHINE_TYPE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(learCredentialMachineFactory.mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email))
                .thenReturn(Mono.error(new RuntimeException("Machine mapping failed")));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorMessage("Machine mapping failed")
                .verify();

        verify(learCredentialMachineFactory)
                .mapCredentialAndBindIssuerInToTheCredential("decodedCredential", procedureId, email);

        verifyNoInteractions(learCredentialEmployeeFactory);
        verifyNoInteractions(labelCredentialFactory);
    }

    @Test
    void signAndUpdateCredentialByProcedureId_setsSub_whenCredentialSubjectIdPresent_object() throws Exception {
        String procId = UUID.randomUUID().toString();

        String unsignedCredential = """
            {"iss":"issuer","vc":{"credentialSubject":{"id":"did:key:zAlice","name":"Alice"}}}
        """;

        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_TYPE);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decoded");
        when(credentialProcedure.getUpdatedBy()).thenReturn("alice@example.com");

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procId)))
                .thenReturn(Mono.just(credentialProcedure));


        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(anyString()))
                .thenReturn(mock(es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee.class));
        when(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(any()))
                .thenReturn(Mono.just(mock(LEARCredentialEmployeeJwtPayload.class)));
        when(learCredentialEmployeeFactory.convertLEARCredentialEmployeeJwtPayloadInToString(any()))
                .thenReturn(Mono.just(unsignedCredential));

        ObjectNode root = mock(ObjectNode.class);
        ObjectNode vc = mock(ObjectNode.class);
        ObjectNode cs = mock(ObjectNode.class);
        JsonNode idNode = mock(JsonNode.class);

        when(objectMapper.readTree(unsignedCredential)).thenReturn(root);
        when(root.path("vc")).thenReturn(vc);
        when(vc.path("credentialSubject")).thenReturn(cs);
        when(cs.isObject()).thenReturn(true);
        when(cs.path("id")).thenReturn(idNode);
        when(idNode.isTextual()).thenReturn(true);
        when(idNode.asText()).thenReturn("did:key:zAlice");

        when(root.put("sub", "did:key:zAlice")).thenReturn(root);

        // stringify modified JSON
        String expectedPayloadToSign = """
            {"iss":"issuer","sub":"did:key:zAlice","vc":{"credentialSubject":{"id":"did:key:zAlice","name":"Alice"}}}
        """;
        when(objectMapper.writeValueAsString(root)).thenReturn(expectedPayloadToSign);

        when(remoteSignatureService.signIssuedCredential(any(SignatureRequest.class), eq("some-token"), eq(procId), anyString()))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES, "signed")));
        when(deferredCredentialWorkflow.updateSignedCredentials(any(), eq(procId))).thenReturn(Mono.empty());

        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId("some-token", procId, JWT_VC))
                .expectNext("signed")
                .verifyComplete();

        ArgumentCaptor<SignatureRequest> captor = ArgumentCaptor.forClass(SignatureRequest.class);
        verify(remoteSignatureService).signIssuedCredential(captor.capture(), eq("some-token"), eq(procId), anyString());

        assertEquals(expectedPayloadToSign, captor.getValue().data());
        verify(root).put("sub", "did:key:zAlice");
    }


    @Test
    void signAndUpdateCredentialByProcedureId_doesNotSetSub_whenCredentialSubjectIdMissing() throws Exception {
        String procID = UUID.randomUUID().toString();


        String unsignedCredential = """
            {"iss":"issuer","vc":{"credentialSubject":{"name":"NoId"}}}
        """;

        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_TYPE);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decoded");
        when(credentialProcedure.getUpdatedBy()).thenReturn("alice@example.com");

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procID)))
                .thenReturn(Mono.just(credentialProcedure));

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(anyString()))
                .thenReturn(mock(es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee.class));
        when(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(any()))
                .thenReturn(Mono.just(mock(LEARCredentialEmployeeJwtPayload.class)));
        when(learCredentialEmployeeFactory.convertLEARCredentialEmployeeJwtPayloadInToString(any()))
                .thenReturn(Mono.just(unsignedCredential));

        ObjectNode root = mock(ObjectNode.class);
        ObjectNode vc = mock(ObjectNode.class);
        ObjectNode cs = mock(ObjectNode.class);
        JsonNode idNode = mock(JsonNode.class);

        when(objectMapper.readTree(unsignedCredential)).thenReturn(root);
        when(root.path("vc")).thenReturn(vc);
        when(vc.path("credentialSubject")).thenReturn(cs);
        when(cs.isObject()).thenReturn(true);
        when(cs.path("id")).thenReturn(idNode);
        when(idNode.isTextual()).thenReturn(false); // no id textual

        when(remoteSignatureService.signIssuedCredential(any(SignatureRequest.class), eq(token), eq(procID), anyString()))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES, "signed")));
        when(deferredCredentialWorkflow.updateSignedCredentials(any(), eq(procID))).thenReturn(Mono.empty());

        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procID, JWT_VC))
                .expectNext("signed")
                .verifyComplete();

        ArgumentCaptor<SignatureRequest> captor = ArgumentCaptor.forClass(SignatureRequest.class);
        verify(remoteSignatureService).signIssuedCredential(captor.capture(), eq(token), eq(procID), anyString());

        // should be original payload (since setSub returns original when no id)
        assertEquals(unsignedCredential, captor.getValue().data());
        verify(root, never()).put(eq("sub"), anyString());
        verify(objectMapper, never()).writeValueAsString(any());
    }

    @Test
    void signAndUpdateCredentialByProcedureId_keepsOriginalPayload_whenInvalidJson() throws Exception {
        String procId = UUID.randomUUID().toString();


        String unsignedCredential = "{\"vc\":{\"credentialSubject\":{\"id\":\"did:key:zAlice\"}}"; // invalid json

        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_TYPE);
        when(credentialProcedure.getCredentialDecoded()).thenReturn("decoded");
        when(credentialProcedure.getUpdatedBy()).thenReturn("alice@example.com");

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procId)))
                .thenReturn(Mono.just(credentialProcedure));

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(anyString()))
                .thenReturn(mock(es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee.class));
        when(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(any()))
                .thenReturn(Mono.just(mock(LEARCredentialEmployeeJwtPayload.class)));
        when(learCredentialEmployeeFactory.convertLEARCredentialEmployeeJwtPayloadInToString(any()))
                .thenReturn(Mono.just(unsignedCredential));

        doThrow(new RuntimeException("boom"))
                .when(objectMapper)
                .readTree(unsignedCredential);


        when(remoteSignatureService.signIssuedCredential(any(SignatureRequest.class), eq(token), eq(procId), anyString()))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES, "signed")));
        when(deferredCredentialWorkflow.updateSignedCredentials(any(), eq(procId))).thenReturn(Mono.empty());

        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procId, JWT_VC))
                .expectNext("signed")
                .verifyComplete();

        ArgumentCaptor<SignatureRequest> captor = ArgumentCaptor.forClass(SignatureRequest.class);
        verify(remoteSignatureService).signIssuedCredential(captor.capture(), eq(token), eq(procId), anyString());

        // unchanged payload
        assertEquals(unsignedCredential, captor.getValue().data());
        verify(objectMapper, never()).writeValueAsString(any());
    }
    @Test
    void signAndUpdateCredentialByProcedureId_setsSub_whenCredentialSubjectIsArray_firstNonBlankId() {
        // Arrange
        String procId = UUID.randomUUID().toString();


        String unsignedCredential =
                """
                {
                  "iss":"issuer",
                  "vc":{
                    "credentialSubject":[
                      {"id":""},
                      {"id":"did:key:zBob"},
                      {"id":"did:key:zCharlie"}
                    ]
                  }
                }
                """;

        CredentialProcedure cp = mock(CredentialProcedure.class);
        when(cp.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_TYPE);
        when(cp.getCredentialDecoded()).thenReturn("decoded");
        when(cp.getUpdatedBy()).thenReturn("alice@example.com");

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procId)))
                .thenReturn(Mono.just(cp));

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(anyString()))
                .thenReturn(mock(es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee.class));
        when(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(any()))
                .thenReturn(Mono.just(mock(es.in2.issuer.backend.shared.domain.model.dto.LEARCredentialEmployeeJwtPayload.class)));
        when(learCredentialEmployeeFactory.convertLEARCredentialEmployeeJwtPayloadInToString(any()))
                .thenReturn(Mono.just(unsignedCredential));

        when(remoteSignatureService.signIssuedCredential(any(SignatureRequest.class), eq(token), eq(procId), anyString()))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES, "signed")));

        doReturn(Mono.empty())
                .when(deferredCredentialWorkflow)
                .updateSignedCredentials(any(SignedCredentials.class), eq(procId));

        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procId, JWT_VC))
                .expectNext("signed")
                .verifyComplete();

        ArgumentCaptor<SignatureRequest> captor = ArgumentCaptor.forClass(SignatureRequest.class);
        verify(remoteSignatureService).signIssuedCredential(captor.capture(), eq(token), eq(procId), anyString());

        String payloadToSign = captor.getValue().data();

        assertTrue(payloadToSign.contains("\"sub\":\"did:key:zBob\""));
        assertFalse(payloadToSign.contains("\"sub\":\"did:key:zCharlie\""));

        verify(deferredCredentialWorkflow).updateSignedCredentials(any(SignedCredentials.class), eq(procId));
    }

    @Test
    void signAndUpdateCredentialByProcedureId_doesNotSetSub_whenCredentialSubjectArray_hasNoValidId() {
        String procId = UUID.randomUUID().toString();

        String unsignedCredential =
                """
                {
                  "iss":"issuer",
                  "vc":{
                    "credentialSubject":[
                      {"id":""},
                      {"id":"   "},
                      {"id":null},
                      {"name":"NoIdHere"}
                    ]
                  }
                }
                """;
        when(deferredCredentialWorkflow.updateSignedCredentials(any(), anyString()))
                .thenReturn(Mono.empty());


        CredentialProcedure cp = mock(CredentialProcedure.class);
        when(cp.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE_TYPE);
        when(cp.getCredentialDecoded()).thenReturn("decoded");
        when(cp.getUpdatedBy()).thenReturn("alice@example.com");


        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procId)))
                .thenReturn(Mono.just(cp));

        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(anyString()))
                .thenReturn(mock(es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee.class));
        when(learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(any()))
                .thenReturn(Mono.just(mock(es.in2.issuer.backend.shared.domain.model.dto.LEARCredentialEmployeeJwtPayload.class)));
        when(learCredentialEmployeeFactory.convertLEARCredentialEmployeeJwtPayloadInToString(any()))
                .thenReturn(Mono.just(unsignedCredential));

        when(remoteSignatureService.signIssuedCredential(any(SignatureRequest.class), eq(token), eq(procId), anyString()))
                .thenReturn(Mono.just(new SignedData(SignatureType.JADES, "signed")));

        StepVerifier.create(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procId, JWT_VC))
                .expectNext("signed")
                .verifyComplete();

        ArgumentCaptor<SignatureRequest> captor = ArgumentCaptor.forClass(SignatureRequest.class);
        verify(remoteSignatureService).signIssuedCredential(captor.capture(), eq(token), eq(procId), anyString());

        String payloadToSign = captor.getValue().data();

        assertFalse(payloadToSign.contains("\"sub\""),
                "No debe añadir sub si no encuentra ningún credentialSubject.id válido en el array");
    }

    @Test
    void retrySignUnsignedCredential_LabelCredential_withResponseUri_triggersFireAndForgetDelivery() {
        CredentialProcedure initialProcedure = mock(CredentialProcedure.class);
        when(initialProcedure.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(initialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProcedure updatedProcedure = mock(CredentialProcedure.class);
        when(updatedProcedure.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(updatedProcedure.getEmail()).thenReturn("company@example.com");

        when(accessTokenService.getCleanBearerToken(authorizationHeader)).thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId)).thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader)).thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(initialProcedure), Mono.just(updatedProcedure));

        when(issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, email)).thenReturn(Mono.just(simpleIssuer));
        when(labelCredentialFactory.mapIssuer(procedureId, simpleIssuer)).thenReturn(Mono.just("bindedVc"));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, "bindedVc", JWT_VC))
                .thenReturn(Mono.empty());

        doReturn(Mono.just("signedVc")).when(credentialSignerWorkflow).signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any())).thenReturn(Mono.just(updatedProcedure));

        // Mock email sending (fire-and-forget) - use lenient since async may not complete during test
        lenient().when(deferredCredentialMetadataService.getTransactionCodeByProcedureId(procedureId))
                .thenReturn(Mono.just("trans-code"));
        lenient().when(appConfig.getIssuerFrontendUrl()).thenReturn("https://issuer.example.com");
        lenient().when(appConfig.getKnowledgebaseWalletUrl()).thenReturn("https://wallet.example.com");
        lenient().when(appConfig.getSysTenant()).thenReturn("sys-tenant");
        lenient().when(emailService.sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(deferredCredentialMetadataService.getResponseUriByProcedureId(procedureId))
                .thenReturn(Mono.just("https://response.example.com/callback"));
        when(credentialProcedureService.getCredentialId(updatedProcedure)).thenReturn(Mono.just("cred-id-123"));
        when(procedureRetryService.handleInitialAction(any(UUID.class), eq(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId))
                .verifyComplete();

        verify(deferredCredentialMetadataService).getResponseUriByProcedureId(procedureId);
        verify(credentialProcedureService).getCredentialId(updatedProcedure);
        // handleInitialAction is called synchronously (before .subscribe()) so it is recorded by Mockito
        verify(procedureRetryService).handleInitialAction(any(UUID.class), eq(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any());
    }
}