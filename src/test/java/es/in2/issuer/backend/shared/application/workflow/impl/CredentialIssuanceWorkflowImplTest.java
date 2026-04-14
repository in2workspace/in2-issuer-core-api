package es.in2.issuer.backend.shared.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.service.ProcedureRetryService;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.JwtUtils;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.VerifiableCredentialPolicyAuthorizationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.OperationNotSupportedException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialIssuanceWorkflowImplTest {

    @Mock private VerifiableCredentialService verifiableCredentialService;
    @Mock private AppConfig appConfig;
    @Mock private ProofValidationService proofValidationService;
    @Mock private EmailService emailService;
    @Mock private CredentialProcedureService credentialProcedureService;
    @Mock private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock private VerifiableCredentialPolicyAuthorizationService verifiableCredentialPolicyAuthorizationService;
    @Mock private TrustFrameworkService trustFrameworkService;
    @Mock private LEARCredentialEmployeeFactory credentialEmployeeFactory;
    @Mock private CredentialIssuerMetadataService credentialIssuerMetadataService;
    @Mock private ProcedureRetryService procedureRetryService;
    @Mock private JwtUtils jwtUtils;
    @Mock private CredentialSignerWorkflow credentialSignerWorkflow;
    @Mock private IssuerFactory issuerFactory;
    @Mock private LabelCredentialFactory labelCredentialFactory;

    @InjectMocks
    private CredentialIssuanceWorkflowImpl workflow;

    private static final String PROCESS_ID = "proc-123";
    private static final String PROCEDURE_ID = "d290f1ee-6c54-4b01-90e6-d701748f0851";
    private static final String RESPONSE_URI = "https://response.example.com/callback";
    private static final String ENCODED_CREDENTIAL = "encoded.jwt.credential";
    private static final String COMPANY_EMAIL = "company@example.com";

    // ──────────────────────────────────────────────────────────────────────
    // execute()
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void execute_unsupportedFormat_throwsFormatUnsupportedException() {
        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .schema(LEAR_CREDENTIAL_EMPLOYEE).format("unsupported_format").operationMode(SYNC)
                .payload(null).build();

        StepVerifier.create(workflow.execute(PROCESS_ID, request, "token", null))
                .expectError(FormatUnsupportedException.class)
                .verify();
    }

    @Test
    void execute_unsupportedOperationMode_throwsOperationNotSupportedException() {
        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .schema(LEAR_CREDENTIAL_EMPLOYEE).format(JWT_VC_JSON).operationMode("UNSUPPORTED")
                .payload(null).build();

        StepVerifier.create(workflow.execute(PROCESS_ID, request, "token", null))
                .expectError(OperationNotSupportedException.class)
                .verify();
    }

    @Test
    void execute_labelCredential_missingIdToken_throwsMissingIdTokenHeaderException() {
        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .schema(LABEL_CREDENTIAL).format(JWT_VC_JSON).operationMode(SYNC)
                .email("owner@example.com").payload(null).build();

        StepVerifier.create(workflow.execute(PROCESS_ID, request, "token", null))
                .expectErrorMatches(e -> e.getMessage().contains("Missing required ID Token header"))
                .verify();
    }

    @Test
    void execute_learCredentialEmployee_success_sendsCredentialOfferEmail() throws Exception {
        String email = "employee@example.com";
        String org = "ACME Corp";
        String transactionCode = "tx-abc";
        String issuerUrl = "https://issuer.example.com";
        String walletUrl = "https://wallet.example.com";

        ObjectMapper mapper = new ObjectMapper();
        JsonNode payload = mapper.readTree("""
            {"mandatee":{"email":"%s"},"mandator":{"organization":"%s"}}
            """.formatted(email, org));

        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .schema(LEAR_CREDENTIAL_EMPLOYEE).format(JWT_VC_JSON).operationMode(SYNC)
                .payload(payload).build();

        when(verifiableCredentialPolicyAuthorizationService.authorize(eq("token"), eq(LEAR_CREDENTIAL_EMPLOYEE), any(), isNull()))
                .thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(PROCESS_ID, request, email, "token"))
                .thenReturn(Mono.just(transactionCode));
        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUrl);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(walletUrl);
        when(emailService.sendCredentialActivationEmail(
                eq(email), eq(CREDENTIAL_ACTIVATION_EMAIL_SUBJECT),
                contains(transactionCode), eq(walletUrl), eq(org)))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.execute(PROCESS_ID, request, "token", null))
                .verifyComplete();

        verify(emailService).sendCredentialActivationEmail(
                eq(email), eq(CREDENTIAL_ACTIVATION_EMAIL_SUBJECT), contains(transactionCode), eq(walletUrl), eq(org));
    }

    @Test
    void execute_learCredentialEmployee_emailFails_throwsEmailCommunicationException() throws Exception {
        String email = "employee@example.com";
        String org = "ACME Corp";
        String transactionCode = "tx-abc";

        ObjectMapper mapper = new ObjectMapper();
        JsonNode payload = mapper.readTree("""
            {"mandatee":{"email":"%s"},"mandator":{"organization":"%s"}}
            """.formatted(email, org));

        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .schema(LEAR_CREDENTIAL_EMPLOYEE).format(JWT_VC_JSON).operationMode(SYNC)
                .payload(payload).build();

        when(verifiableCredentialPolicyAuthorizationService.authorize(any(), any(), any(), any()))
                .thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(any(), any(), any(), any()))
                .thenReturn(Mono.just(transactionCode));
        when(appConfig.getIssuerFrontendUrl()).thenReturn("https://issuer.example.com");
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn("https://wallet.example.com");
        when(emailService.sendCredentialActivationEmail(any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP error")));

        StepVerifier.create(workflow.execute(PROCESS_ID, request, "token", null))
                .expectErrorMatches(e -> e instanceof EmailCommunicationException
                        && e.getMessage().contains(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                .verify();
    }

    // ──────────────────────────────────────────────────────────────────────
    // generateVerifiableCredentialResponse() – retry delivery paths
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Builds a CredentialIssuerMetadata with a LABEL_CREDENTIAL configuration that requires
     * no cryptographic binding (null cryptographicBindingMethodsSupported).
     * This causes validateAndDetermineBindingInfo to return Mono.empty() so that
     * buildCredentialResponse is called with a null subjectId.
     */
    private CredentialIssuerMetadata buildMetadataForLabelCredential() {
        return CredentialIssuerMetadata.builder()
                .credentialIssuer("https://issuer.example.com")
                .credentialEndpoint("https://issuer.example.com/credentials")
                .credentialConfigurationsSupported(Map.of(
                        "label_credential", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format(JWT_VC_JSON)
                                .credentialDefinition(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.builder()
                                        .type(Set.of(VERIFIABLE_CREDENTIAL, LABEL_CREDENTIAL)) // "gx:LabelCredential"
                                        .build())
                                .cryptographicBindingMethodsSupported(null) // no proof required
                                .build()
                ))
                .build();
    }

    /**
     * Builds a minimal CredentialProcedure mock for LABEL_CREDENTIAL in SYNC mode.
     * getCredentialEncoded() is NOT stubbed here because it is only called on the
     * responseUri path — each test that needs it adds the stub explicitly.
     */
    private CredentialProcedure buildLabelCredentialProcedure() {
        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getProcedureId()).thenReturn(UUID.fromString(PROCEDURE_ID));
        when(proc.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(proc.getOperationMode()).thenReturn(SYNC);
        when(proc.getEmail()).thenReturn(COMPANY_EMAIL);
        return proc;
    }

    @Test
    void generateVerifiableCredentialResponse_syncMode_labelCredential_withResponseUri_triggersFireAndForgetDelivery() {
        AccessTokenContext ctx = AccessTokenContext.builder()
                .jti("nonce-abc").procedureId(PROCEDURE_ID)
                .responseUri(RESPONSE_URI).rawToken("raw-token").build();
        CredentialRequest credentialRequest = CredentialRequest.builder().build();

        CredentialProcedure proc = buildLabelCredentialProcedure();
        when(proc.getCredentialEncoded()).thenReturn(ENCODED_CREDENTIAL);
        CredentialIssuerMetadata metadata = buildMetadataForLabelCredential();
        CredentialResponse credentialResponse = mock(CredentialResponse.class);

        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(proc));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PROCESS_ID)).thenReturn(Mono.just(metadata));
        // No binding needed (empty) → buildCredentialResponse called with null subjectId
        when(verifiableCredentialService.buildCredentialResponse(
                eq(PROCESS_ID), isNull(), eq("nonce-abc"), eq("raw-token"), eq(COMPANY_EMAIL), eq(PROCEDURE_ID)))
                .thenReturn(Mono.just(credentialResponse));
        // SYNC branch: status check and update
        when(credentialProcedureService.getCredentialStatusByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.just("VALID"));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getDecodedCredentialByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.just("decoded-credential"));
        // getCredentialProcedureById is called twice (outer + zipWith); one stub covers both
        when(credentialProcedureService.getCredentialId(proc)).thenReturn(Mono.just("cred-id-123"));
        // Fire-and-forget delivery
        when(procedureRetryService.handleInitialAction(any(UUID.class), eq(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any()))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.generateVerifiableCredentialResponse(PROCESS_ID, credentialRequest, ctx))
                .expectNext(credentialResponse)
                .verifyComplete();

        verify(credentialProcedureService).getCredentialId(proc);
        // handleInitialAction is called synchronously before .subscribe(), so it's recorded by Mockito
        verify(procedureRetryService).handleInitialAction(eq(UUID.fromString(PROCEDURE_ID)), eq(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any());
    }

    @Test
    void generateVerifiableCredentialResponse_syncMode_labelCredential_noResponseUri_noDeliveryTriggered() {
        AccessTokenContext ctx = AccessTokenContext.builder()
                .jti("nonce-abc").procedureId(PROCEDURE_ID)
                .responseUri(null).rawToken("raw-token").build(); // no responseUri
        CredentialRequest credentialRequest = CredentialRequest.builder().build();

        CredentialProcedure proc = buildLabelCredentialProcedure();
        CredentialIssuerMetadata metadata = buildMetadataForLabelCredential();
        CredentialResponse credentialResponse = mock(CredentialResponse.class);

        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(proc));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PROCESS_ID)).thenReturn(Mono.just(metadata));
        when(verifiableCredentialService.buildCredentialResponse(any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(credentialResponse));
        when(credentialProcedureService.getCredentialStatusByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("VALID"));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getDecodedCredentialByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("decoded"));
        // getCredentialProcedureById called twice; single stub covers both
        // getCredentialEncoded not stubbed: the no-responseUri path never reaches that branch

        StepVerifier.create(workflow.generateVerifiableCredentialResponse(PROCESS_ID, credentialRequest, ctx))
                .expectNext(credentialResponse)
                .verifyComplete();

        verifyNoInteractions(procedureRetryService);
    }

    @Test
    void generateVerifiableCredentialResponse_syncMode_labelCredential_blankResponseUri_noDeliveryTriggered() {
        AccessTokenContext ctx = AccessTokenContext.builder()
                .jti("nonce-abc").procedureId(PROCEDURE_ID)
                .responseUri("   ").rawToken("raw-token").build(); // blank responseUri
        CredentialRequest credentialRequest = CredentialRequest.builder().build();

        CredentialProcedure proc = buildLabelCredentialProcedure();
        CredentialIssuerMetadata metadata = buildMetadataForLabelCredential();
        CredentialResponse credentialResponse = mock(CredentialResponse.class);

        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(proc));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PROCESS_ID)).thenReturn(Mono.just(metadata));
        when(verifiableCredentialService.buildCredentialResponse(any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(credentialResponse));
        when(credentialProcedureService.getCredentialStatusByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("VALID"));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getDecodedCredentialByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("decoded"));
        // getCredentialProcedureById called twice; single stub covers both
        // getCredentialEncoded not stubbed: blank responseUri never reaches that branch

        StepVerifier.create(workflow.generateVerifiableCredentialResponse(PROCESS_ID, credentialRequest, ctx))
                .expectNext(credentialResponse)
                .verifyComplete();

        verifyNoInteractions(procedureRetryService);
    }

    @Test
    void generateVerifiableCredentialResponse_syncMode_labelCredential_encodedCredentialNull_throwsIllegalState() {
        AccessTokenContext ctx = AccessTokenContext.builder()
                .jti("nonce-abc").procedureId(PROCEDURE_ID)
                .responseUri(RESPONSE_URI).rawToken("raw-token").build();
        CredentialRequest credentialRequest = CredentialRequest.builder().build();

        // getCredentialEncoded() not stubbed → Mockito returns null by default, triggering the error
        CredentialProcedure proc = buildLabelCredentialProcedure();
        CredentialIssuerMetadata metadata = buildMetadataForLabelCredential();
        CredentialResponse credentialResponse = mock(CredentialResponse.class);

        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(proc));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PROCESS_ID)).thenReturn(Mono.just(metadata));
        when(verifiableCredentialService.buildCredentialResponse(any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(credentialResponse));
        when(credentialProcedureService.getCredentialStatusByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("VALID"));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getDecodedCredentialByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("decoded"));
        // getCredentialProcedureById called twice; single stub covers both

        StepVerifier.create(workflow.generateVerifiableCredentialResponse(PROCESS_ID, credentialRequest, ctx))
                .expectErrorMatches(e -> e instanceof IllegalStateException
                        && e.getMessage().contains("Encoded credential not found"))
                .verify();

        verifyNoInteractions(procedureRetryService);
    }

    // ──────────────────────────────────────────────────────────────────────
    // execute() – label credential issuance paths
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void execute_labelCredential_success_triggersParallelDelivery() {
        String email = "company@example.com";
        String transactionCode = "tx-label-123";
        String signedCredential = "signed.jwt.credential";
        String credentialId = "cred-id-456";
        String responseUri = "https://response.example.com/callback";
        String issuerUrl = "https://issuer.example.com";
        String walletUrl = "https://wallet.example.com";
        String sysTenant = "SysTenant";

        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .schema(LABEL_CREDENTIAL).format(JWT_VC_JSON).operationMode(SYNC)
                .email(email).payload(null).build();

        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getEmail()).thenReturn(email);

        SimpleIssuer simpleIssuer = mock(SimpleIssuer.class);

        when(verifiableCredentialPolicyAuthorizationService.authorize(eq("token"), eq(LABEL_CREDENTIAL), any(), eq("idToken")))
                .thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(PROCESS_ID, request, email, "token"))
                .thenReturn(Mono.just(transactionCode));
        when(appConfig.getSysTenant()).thenReturn(sysTenant);
        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUrl);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(walletUrl);
        
        // handleLabelCredentialIssuance mocks
        when(deferredCredentialMetadataService.getProcedureIdByTransactionCode(transactionCode))
                .thenReturn(Mono.just(PROCEDURE_ID));
        when(issuerFactory.createSimpleIssuerAndNotifyOnError(PROCEDURE_ID, email))
                .thenReturn(Mono.just(simpleIssuer));
        when(labelCredentialFactory.mapIssuer(eq(PROCEDURE_ID), any(SimpleIssuer.class)))
                .thenReturn(Mono.just("boundCredentialJson"));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(PROCEDURE_ID, "boundCredentialJson"))
                .thenReturn(Mono.empty());
        when(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId("token", PROCEDURE_ID, JWT_VC))
                .thenReturn(Mono.just(signedCredential));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID))
                .thenReturn(Mono.just(proc));
        
        // triggerLabelCredentialParallelDelivery mocks
        when(emailService.sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());
        when(deferredCredentialMetadataService.getResponseUriByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.just(responseUri));
        when(credentialProcedureService.getCredentialId(proc))
                .thenReturn(Mono.just(credentialId));
        when(procedureRetryService.handleInitialAction(any(UUID.class), eq(ActionType.UPLOAD_LABEL_TO_RESPONSE_URI), any()))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.execute(PROCESS_ID, request, "token", "idToken"))
                .verifyComplete();

        verify(credentialSignerWorkflow).signAndUpdateCredentialByProcedureId("token", PROCEDURE_ID, JWT_VC);
        verify(credentialProcedureService).updateCredentialProcedureCredentialStatusToValidByProcedureId(PROCEDURE_ID);
    }

    @Test
    void execute_labelCredential_noResponseUri_stillCompletes() {
        String email = "company@example.com";
        String transactionCode = "tx-label-123";
        String signedCredential = "signed.jwt.credential";
        String issuerUrl = "https://issuer.example.com";
        String walletUrl = "https://wallet.example.com";
        String sysTenant = "SysTenant";

        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .schema(LABEL_CREDENTIAL).format(JWT_VC_JSON).operationMode(SYNC)
                .email(email).payload(null).build();

        CredentialProcedure proc = mock(CredentialProcedure.class);
        lenient().when(proc.getEmail()).thenReturn(email);

        SimpleIssuer simpleIssuer = mock(SimpleIssuer.class);

        when(verifiableCredentialPolicyAuthorizationService.authorize(eq("token"), eq(LABEL_CREDENTIAL), any(), eq("idToken")))
                .thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(PROCESS_ID, request, email, "token"))
                .thenReturn(Mono.just(transactionCode));
        when(appConfig.getSysTenant()).thenReturn(sysTenant);
        lenient().when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUrl);
        lenient().when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(walletUrl);
        
        when(deferredCredentialMetadataService.getProcedureIdByTransactionCode(transactionCode))
                .thenReturn(Mono.just(PROCEDURE_ID));
        when(issuerFactory.createSimpleIssuerAndNotifyOnError(PROCEDURE_ID, email))
                .thenReturn(Mono.just(simpleIssuer));
        when(labelCredentialFactory.mapIssuer(eq(PROCEDURE_ID), any(SimpleIssuer.class)))
                .thenReturn(Mono.just("boundCredentialJson"));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(PROCEDURE_ID, "boundCredentialJson"))
                .thenReturn(Mono.empty());
        when(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId("token", PROCEDURE_ID, JWT_VC))
                .thenReturn(Mono.just(signedCredential));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID))
                .thenReturn(Mono.just(proc));
        
        lenient().when(emailService.sendCredentialActivationEmail(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());
        // No response URI available
        when(deferredCredentialMetadataService.getResponseUriByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.execute(PROCESS_ID, request, "token", "idToken"))
                .verifyComplete();

        verifyNoInteractions(procedureRetryService);
    }

    @Test
    void execute_labelCredential_signingFails_throwsRemoteSignatureException() {
        String email = "company@example.com";
        String transactionCode = "tx-label-123";
        String sysTenant = "SysTenant";

        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .schema(LABEL_CREDENTIAL).format(JWT_VC_JSON).operationMode(SYNC)
                .email(email).payload(null).build();

        SimpleIssuer simpleIssuer = mock(SimpleIssuer.class);

        when(verifiableCredentialPolicyAuthorizationService.authorize(eq("token"), eq(LABEL_CREDENTIAL), any(), eq("idToken")))
                .thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(PROCESS_ID, request, email, "token"))
                .thenReturn(Mono.just(transactionCode));
        when(appConfig.getSysTenant()).thenReturn(sysTenant);
        
        when(deferredCredentialMetadataService.getProcedureIdByTransactionCode(transactionCode))
                .thenReturn(Mono.just(PROCEDURE_ID));
        when(issuerFactory.createSimpleIssuerAndNotifyOnError(PROCEDURE_ID, email))
                .thenReturn(Mono.just(simpleIssuer));
        when(labelCredentialFactory.mapIssuer(eq(PROCEDURE_ID), any(SimpleIssuer.class)))
                .thenReturn(Mono.just("boundCredentialJson"));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(PROCEDURE_ID, "boundCredentialJson"))
                .thenReturn(Mono.empty());
        // Signing fails
        when(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId("token", PROCEDURE_ID, JWT_VC))
                .thenReturn(Mono.error(new RuntimeException("Remote signer unavailable")));
        when(credentialProcedureService.updateCredentialStatusToPendSignature(PROCEDURE_ID))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.execute(PROCESS_ID, request, "token", "idToken"))
                .expectErrorMatches(e -> e instanceof RemoteSignatureException
                        && e.getMessage().contains("Label credential signing failed"))
                .verify();

        verify(credentialProcedureService).updateCredentialStatusToPendSignature(PROCEDURE_ID);
    }

    // ──────────────────────────────────────────────────────────────────────
    // generateVerifiableCredentialResponse() – label credential already signed
    // ──────────────────────────────────────────────────────────────────────

    @Test
    void generateVerifiableCredentialResponse_labelCredential_alreadySigned_returnsStoredCredential() {
        String notificationId = "notification-id-123";
        String encodedCredential = "already.signed.jwt";

        AccessTokenContext ctx = AccessTokenContext.builder()
                .jti("nonce-abc").procedureId(PROCEDURE_ID)
                .responseUri(null).rawToken("raw-token").build();
        CredentialRequest credentialRequest = CredentialRequest.builder().build();

        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(proc.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);
        when(proc.getCredentialEncoded()).thenReturn(encodedCredential);

        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(proc));
        when(credentialProcedureService.getNotificationIdByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just(notificationId));

        StepVerifier.create(workflow.generateVerifiableCredentialResponse(PROCESS_ID, credentialRequest, ctx))
                .expectNextMatches(response ->
                        response.notificationId().equals(notificationId)
                                && response.credentials().size() == 1
                                && response.credentials().get(0).credential().equals(encodedCredential)
                )
                .verifyComplete();

        // Should NOT call buildCredentialResponse since credential is pre-signed
        verifyNoInteractions(verifiableCredentialService);
        verifyNoInteractions(credentialIssuerMetadataService);
    }

    @Test
    void generateVerifiableCredentialResponse_labelCredential_notYetSigned_proceedsWithNormalFlow() {
        AccessTokenContext ctx = AccessTokenContext.builder()
                .jti("nonce-abc").procedureId(PROCEDURE_ID)
                .responseUri(null).rawToken("raw-token").build();
        CredentialRequest credentialRequest = CredentialRequest.builder().build();

        // Label credential but NOT VALID status (e.g., DRAFT)
        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(proc.getCredentialStatus()).thenReturn(CredentialStatusEnum.DRAFT);
        when(proc.getOperationMode()).thenReturn(SYNC);
        when(proc.getEmail()).thenReturn(COMPANY_EMAIL);
        when(proc.getProcedureId()).thenReturn(UUID.fromString(PROCEDURE_ID));

        CredentialIssuerMetadata metadata = buildMetadataForLabelCredential();
        CredentialResponse credentialResponse = mock(CredentialResponse.class);

        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(proc));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PROCESS_ID)).thenReturn(Mono.just(metadata));
        when(verifiableCredentialService.buildCredentialResponse(any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(credentialResponse));
        when(credentialProcedureService.getCredentialStatusByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("DRAFT"));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getDecodedCredentialByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("decoded"));

        StepVerifier.create(workflow.generateVerifiableCredentialResponse(PROCESS_ID, credentialRequest, ctx))
                .expectNext(credentialResponse)
                .verifyComplete();

        // Should call buildCredentialResponse since credential is not yet signed
        verify(verifiableCredentialService).buildCredentialResponse(any(), any(), any(), any(), any(), any());
    }

    @Test
    void generateVerifiableCredentialResponse_labelCredential_validButBlankEncoded_proceedsWithNormalFlow() {
        AccessTokenContext ctx = AccessTokenContext.builder()
                .jti("nonce-abc").procedureId(PROCEDURE_ID)
                .responseUri(null).rawToken("raw-token").build();
        CredentialRequest credentialRequest = CredentialRequest.builder().build();

        // Label credential with VALID status but blank encoded credential
        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getCredentialType()).thenReturn(LABEL_CREDENTIAL_TYPE);
        when(proc.getCredentialStatus()).thenReturn(CredentialStatusEnum.VALID);
        when(proc.getCredentialEncoded()).thenReturn("   "); // blank
        when(proc.getOperationMode()).thenReturn(SYNC);
        when(proc.getEmail()).thenReturn(COMPANY_EMAIL);
        when(proc.getProcedureId()).thenReturn(UUID.fromString(PROCEDURE_ID));

        CredentialIssuerMetadata metadata = buildMetadataForLabelCredential();
        CredentialResponse credentialResponse = mock(CredentialResponse.class);

        when(credentialProcedureService.getCredentialProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(proc));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PROCESS_ID)).thenReturn(Mono.just(metadata));
        when(verifiableCredentialService.buildCredentialResponse(any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(credentialResponse));
        when(credentialProcedureService.getCredentialStatusByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("VALID"));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(PROCEDURE_ID))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getDecodedCredentialByProcedureId(PROCEDURE_ID)).thenReturn(Mono.just("decoded"));

        StepVerifier.create(workflow.generateVerifiableCredentialResponse(PROCESS_ID, credentialRequest, ctx))
                .expectNext(credentialResponse)
                .verifyComplete();

        // Should call buildCredentialResponse since encoded credential is blank
        verify(verifiableCredentialService).buildCredentialResponse(any(), any(), any(), any(), any(), any());
    }
}
