package es.in2.issuer.backend.shared.application.workflow.impl;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.InvalidOrMissingProofException;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.WebClientConfig;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.VerifiableCredentialPolicyAuthorizationService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.OperationNotSupportedException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.DID_ELSI;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;
import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;
import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialIssuanceWorkflowImplTest {

    @Mock
    private CredentialDeliveryService credentialDeliveryService;

    @Mock
    private VerifiableCredentialService verifiableCredentialService;

    @Mock
    private ProofValidationService proofValidationService;

    @Mock
    private AppConfig appConfig;

    @Mock
    private EmailService emailService;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock
    private IssuerApiClientTokenService issuerApiClientTokenService;

    @Mock
    private CredentialSignerWorkflow credentialSignerWorkflow;

    @Mock
    private WebClientConfig webClientConfig;

    @Mock
    private VerifiableCredentialPolicyAuthorizationService verifiableCredentialPolicyAuthorizationService;

    @Mock
    private TrustFrameworkService trustFrameworkService;

    @Mock
    private LEARCredentialEmployeeFactory credentialEmployeeFactory;

    @Mock
    private M2MTokenService m2MTokenService;

    @Mock
    private CredentialIssuerMetadataService credentialIssuerMetadataService;

    @Mock
    private ProcedureRetryService procedureRetryService;

    @Mock
    private es.in2.issuer.backend.shared.domain.util.JwtUtils jwtUtils;

    @InjectMocks
    private CredentialIssuanceWorkflowImpl verifiableCredentialIssuanceWorkflow;

    @Test
    void unsupportedFormatErrorExceptionTest() {
        String processId = "1234";
        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder().payload(null).schema("LEARCredentialEmployee").format("json_ldp").operationMode("S").build();
        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, "token", null))
                .expectError(FormatUnsupportedException.class)
                .verify();
    }

    @Test
    void unsupportedOperationModeExceptionTest() {
        String processId = "1234";
        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest =
                PreSubmittedCredentialDataRequest.builder()
                        .payload(null)
                        .schema("LEARCredentialEmployee")
                        .format(JWT_VC_JSON)
                        .operationMode("F")
                        .build();

        StepVerifier.create(
                        verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, "token", null)
                )
                .expectError(OperationNotSupportedException.class)
                .verify();
    }

    @Test
    void completeWithdrawLEARProcessSyncSuccess() throws JsonProcessingException {
        String processId = "1234";
        String type = "LEARCredentialEmployee";
        String knowledgebaseWalletUrl = "https://knowledgebase.com";
        String issuerUiExternalDomain = "https://example.com";
        String token = "token";
        String idToken = "idToken";
        String expectedEmail = "example@in2.es";
        String json = """
                {
                    "life_span": {
                        "end_date_time": "2025-04-02 09:23:22.637345122 +0000 UTC",
                        "start_date_time": "2024-04-02 09:23:22.637345122 +0000 UTC"
                    },
                    "mandatee": {
                        "email": "example@in2.es",
                        "firstName": "Jhon",
                        "lastName": "Doe",
                        "mobile_phone": "+34666336699"
                    },
                    "mandator": {
                        "commonName": "IN2",
                        "country": "ES",
                        "email": "rrhh@in2.es",
                        "organization": "IN2, Ingeniería de la Información, S.L.",
                        "organizationIdentifier": "VATES-B26246436",
                        "serialNumber": "3424320"
                    },
                    "power": [
                        {
                            "id": "6b8f3137-a57a-46a5-97e7-1117a20142fv",
                            "tmf_domain": "DOME",
                            "tmf_function": "DomePlatform",
                            "tmf_type": "Domain",
                            "tmf_action": [
                                "Operator",
                                "Customer",
                                "Provider"
                            ]
                        },
                        {
                            "id": "6b8f3137-a57a-46a5-97e7-1117a20142fb",
                            "tmf_action": "Execute",
                            "tmf_domain": "DOME",
                            "tmf_function": "Onboarding",
                            "tmf_type": "Domain"
                        },
                        {
                            "id": "ad9b1509-60ea-47d4-9878-18b581d8e19b",
                            "tmf_action": [
                                "Create",
                                "Update"
                            ],
                            "tmf_domain": "DOME",
                            "tmf_function": "ProductOffering",
                            "tmf_type": "Domain"
                        }
                    ]
                }
                """;
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(json);
        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder().payload(jsonNode).schema("LEARCredentialEmployee").format(JWT_VC_JSON).operationMode("S").build();
        String transactionCode = "4321";

        when(verifiableCredentialPolicyAuthorizationService.authorize(token, type, jsonNode, idToken)).thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(processId, preSubmittedCredentialDataRequest, expectedEmail, token))
                .thenReturn(Mono.just(transactionCode));
        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);
        when(emailService.sendCredentialActivationEmail("example@in2.es", "email.activation.subject", issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode, knowledgebaseWalletUrl, "IN2, Ingeniería de la Información, S.L.")).thenReturn(Mono.empty());
        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, token, idToken))
                .verifyComplete();
    }

    @Test
    void completeWithdrawLEARProcessSyncFailureOnEmailSending() throws JsonProcessingException {
        String processId = "1234";
        String type = "LEARCredentialEmployee";
        String knowledgebaseWalletUrl = "https://knowledgebase.com";
        String issuerUiExternalDomain = "https://example.com";
        String token = "token";
        String expectedEmail = "example@in2.es";
        String json = """
                {
                    "life_span": {
                        "end_date_time": "2025-04-02 09:23:22.637345122 +0000 UTC",
                        "start_date_time": "2024-04-02 09:23:22.637345122 +0000 UTC"
                    },
                    "mandatee": {
                        "email": "example@in2.es",
                        "firstName": "Jhon",
                        "lastName": "Doe",
                        "mobile_phone": "+34666336699"
                    },
                    "mandator": {
                        "commonName": "IN2",
                        "country": "ES",
                        "email": "rrhh@in2.es",
                        "organization": "IN2, Ingeniería de la Información, S.L.",
                        "organizationIdentifier": "VATES-B26246436",
                        "serialNumber": "3424320"
                    },
                    "power": [
                        {
                            "id": "6b8f3137-a57a-46a5-97e7-1117a20142fv",
                            "tmf_domain": "DOME",
                            "tmf_function": "DomePlatform",
                            "tmf_type": "Domain",
                            "tmf_action": [
                                "Operator",
                                "Customer",
                                "Provider"
                            ]
                        },
                        {
                            "id": "6b8f3137-a57a-46a5-97e7-1117a20142fb",
                            "tmf_action": "Execute",
                            "tmf_domain": "DOME",
                            "tmf_function": "Onboarding",
                            "tmf_type": "Domain"
                        },
                        {
                            "id": "ad9b1509-60ea-47d4-9878-18b581d8e19b",
                            "tmf_action": [
                                "Create",
                                "Update"
                            ],
                            "tmf_domain": "DOME",
                            "tmf_function": "ProductOffering",
                            "tmf_type": "Domain"
                        }
                    ]
                }
                """;
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(json);
        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder()
                .payload(jsonNode)
                .schema("LEARCredentialEmployee")
                .format(JWT_VC_JSON)
                .operationMode("S")
                .build();
        String transactionCode = "4321";

        when(verifiableCredentialPolicyAuthorizationService.authorize(token, type, jsonNode, null)).thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(processId, preSubmittedCredentialDataRequest, expectedEmail, token))
                .thenReturn(Mono.just(transactionCode));
        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);

        // Simulated failure when sending the email
        when(emailService.sendCredentialActivationEmail(
                "example@in2.es",
                "email.activation.subject",
                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,
                knowledgebaseWalletUrl,
                "IN2, Ingeniería de la Información, S.L."))
                .thenReturn(Mono.error(new RuntimeException("Email sending failed")));

        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, token, null))
                .expectErrorMatches(throwable ->
                        throwable instanceof EmailCommunicationException &&
                                throwable.getMessage().contains(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                .verify();
    }

    // TODO
    //    @Test
    //    void completeWithdrawVerifiableCertificationProcessSuccess() throws JsonProcessingException {
    //        String processId = "1234";
    //        String type = "VerifiableCertification";
    //        String procedureId = "procedureId";
    //        String token = "token";
    //        String idToken = "idToken";
    //        String json = """
    //                {
    //                    "type": [
    //                        "ProductOfferingCredential"
    //                    ],
    //                    "issuer": {
    //                        "commonName": "IssuerCommonName",
    //                        "country": "ES",
    //                        "id": "did:web:issuer-test.com",
    //                        "organization": "Issuer Test"
    //                    },
    //                    "credentialSubject": {
    //                        "company": {
    //                            "address": "address",
    //                            "commonName": "commonName",
    //                            "country": "ES",
    //                            "email": "email@email.com",
    //                            "id": "did:web:commonname.com",
    //                            "organization": "Organization Name"
    //                        },
    //                        "compliance": [
    //                            {
    //                                "scope": "Scope Name",
    //                                "standard": "standard"
    //                            }
    //                        ],
    //                        "product": {
    //                            "productId": "productId",
    //                            "productName": "Product Name",
    //                            "productVersion": "0.1"
    //                        }
    //                    },
    //                    "issuanceDate": "2024-08-22T00:00:00Z",
    //                    "validFrom": "2024-08-22T00:00:00Z",
    //                    "expirationDate": "2025-08-22T00:00:00Z"
    //                }
    //                """;
    //        ObjectMapper objectMapper = new ObjectMapper();
    //        JsonNode jsonNode = objectMapper.readTree(json);
    //        PreSubmittedCredentialRequest preSubmittedCredentialRequest = PreSubmittedCredentialRequest.builder().payload(jsonNode).schema("VerifiableCertification").format(JWT_VC_JSON).responseUri("https://example.com/1234").operationMode("S").build();
    //
    //
    //        when(verifiableCredentialPolicyAuthorizationService.authorize(token, type, jsonNode, idToken)).thenReturn(Mono.empty());
    //        when(verifiableCredentialService.generateVc(processId, preSubmittedCredentialRequest.schema(),preSubmittedCredentialRequest)).thenReturn(Mono.just(procedureId));
    //        when(issuerApiClientTokenService.getClientToken()).thenReturn(Mono.just("internalToken"));
    //        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId)).thenReturn(Mono.empty());
    //        when(m2MTokenService.getM2MToken()).thenReturn(Mono.just(new VerifierOauth2AccessToken("", "", "")));
    //        when(credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(BEARER_PREFIX + "internalToken", procedureId, JWT_VC_JSON)).thenReturn(Mono.just("signedCredential"));
    //        when(credentialDeliveryService.sendVcToResponseUri(
    //                anyString(),
    //                anyString(),
    //                anyString(),
    //                anyString(),
    //                anyString()
    //        )).thenReturn(Mono.empty());
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialRequest, token, idToken))
    //                .verifyComplete();
    //    }

    //    @Test
    //    void generateVerifiableCredentialResponseSyncSuccess() {
    //        String processId = "1234";
    //        CredentialRequest credentialRequest = CredentialRequest.builder()
    //                .credentialConfigurationId(JWT_VC)
    //                .proofs(Proofs.builder()
    //                        .jwt(List.of("eyJraWQiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MjekRuYWVuMjN3TTc2Z3BpU0xIa3U0YkZEYnNzVlM5c3R5OXgzSzd5VnFqYlNkVFBXQyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwNzEiLCJleHAiOjE3MTI5MTcwNDAsImlhdCI6MTcxMjA1MzA0MCwibm9uY2UiOiI4OVh4bXdMMlJtR2wyUlp1LU1UU3lRPT0ifQ.DdaaNm4vTn60njLtAQ7Q5oGsQILfA-5h9-sv4MBcVyNBAfSrUUajZqlUukT-5Bx8EqocSvf0RIFRHLcvO9_LMg"))
    //                        .build())
    //                .build();
    //        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";
    //        String jti = "fcca7591-6742-4c30-949c-ee9707196756";
    //        String did = "did:key:zDnaen23wM76gpiSLHku4bFDbssVS9sty9x3K7yVqjbSdTPWC";
    //        CredentialResponse credentialResponse = CredentialResponse.builder()
    //                .credentials(List.of(
    //                        CredentialResponse.Credential.builder()
    //                                .credential("credential")
    //                                .build()))
    //                .transactionId("4321")
    //                .build();
    //        String procedureId = "123456";
    //        String decodedCredential = "decodedCredential";
    //
    //        when(proofValidationService.isProofValid(credentialRequest.proofs().jwt().get(0), token)).thenReturn(Mono.just(true));
    //        when(verifiableCredentialService.buildCredentialResponse(processId, did, jti, token)).thenReturn(Mono.just(credentialResponse));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just(procedureId));
    //        when(deferredCredentialMetadataService.getOperationModeByAuthServerNonce(jti)).thenReturn(Mono.just("S"));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just("procedureId"));
    //        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId("procedureId")).thenReturn(Mono.empty());
    //        when(credentialProcedureService.getCredentialStatusByProcedureId("procedureId")).thenReturn(Mono.just(CredentialStatus.DRAFT.toString()));
    //        when(credentialProcedureService.getDecodedCredentialByProcedureId("procedureId")).thenReturn(Mono.just(decodedCredential));
    //
    //        LEARCredentialEmployee learCredentialEmployee = mock(LEARCredentialEmployee.class);
    //        LEARCredentialEmployee.CredentialSubject credentialSubject = mock(LEARCredentialEmployee.CredentialSubject.class);
    //        LEARCredentialEmployee.CredentialSubject.Mandate mandate = mock(LEARCredentialEmployee.CredentialSubject.Mandate.class);
    //        Mandator mandator = mock(Mandator.class);
    //
    //        when(learCredentialEmployee.credentialSubject()).thenReturn(credentialSubject);
    //        when(credentialSubject.mandate()).thenReturn(mandate);
    //        when(mandate.mandator()).thenReturn(mandator);
    //
    //        String organizationIdentifier = "organizationIdentifier";
    //        when(mandator.organizationIdentifier()).thenReturn(organizationIdentifier);
    //
    //        String organizationIdentifierDid = DID_ELSI + organizationIdentifier;
    //
    //        when(credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential)).thenReturn(learCredentialEmployee);
    //        when(trustFrameworkService.validateDidFormat(processId, organizationIdentifierDid)).thenReturn(Mono.just(true));
    //        when(trustFrameworkService.registerDid(processId, organizationIdentifierDid)).thenReturn(Mono.empty());
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId, credentialRequest, token))
    //                .expectNext(credentialResponse)
    //                .verifyComplete();
    //    }
    //
    //    @Test
    //    void generateVerifiableCredentialResponseFailedProofException() {
    //        String processId = "1234";
    //        CredentialRequest credentialRequest = CredentialRequest.builder()
    //                .credentialConfigurationId(JWT_VC)
    //                .proofs(Proofs.builder()
    //                        .jwt(List.of("eyJraWQiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MjekRuYWVuMjN3TTc2Z3BpU0xIa3U0YkZEYnNzVlM5c3R5OXgzSzd5VnFqYlNkVFBXQyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwNzEiLCJleHAiOjE3MTI5MTcwNDAsImlhdCI6MTcxMjA1MzA0MCwibm9uY2UiOiI4OVh4bXdMMlJtR2wyUlp1LU1UU3lRPT0ifQ.DdaaNm4vTn60njLtAQ7Q5oGsQILfA-5h9-sv4MBcVyNBAfSrUUajZqlUukT-5Bx8EqocSvf0RIFRHLcvO9_LMg"))
    //                        .build())
    //                .build();
    //        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";
    //
    //        when(proofValidationService.isProofValid(credentialRequest.proofs().jwt().get(0), token)).thenReturn(Mono.just(false));
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId, credentialRequest, token))
    //                .expectError(InvalidOrMissingProofException.class)
    //                .verify();
    //    }
    //
    //    @Test
    //    void generateVerifiableCredentialResponseInvalidSignerOrgIdentifier() {
    //        String processId = "1234";
    //        CredentialRequest credentialRequest = CredentialRequest.builder()
    //                .credentialConfigurationId(JWT_VC)
    //                .proofs(Proofs.builder()
    //                        .jwt(List.of("eyJraWQiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MjekRuYWVuMjN3TTc2Z3BpU0xIa3U0YkZEYnNzVlM5c3R5OXgzSzd5VnFqYlNkVFBXQyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwNzEiLCJleHAiOjE3MTI5MTcwNDAsImlhdCI6MTcxMjA1MzA0MCwibm9uY2UiOiI4OVh4bXdMMlJtR2wyUlp1LU1UU3lRPT0ifQ.DdaaNm4vTn60njLtAQ7Q5oGsQILfA-5h9-sv4MBcVyNBAfSrUUajZqlUukT-5Bx8EqocSvf0RIFRHLcvO9_LMg"))
    //                        .build())
    //                .build();
    //        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";
    //        String jti = "fcca7591-6742-4c30-949c-ee9707196756";
    //        String did = "did:key:zDnaen23wM76gpiSLHku4bFDbssVS9sty9x3K7yVqjbSdTPWC";
    //        CredentialResponse credentialResponse = CredentialResponse.builder()
    //                .credentials(List.of(
    //                        CredentialResponse.Credential.builder()
    //                                .credential("credential")
    //                                .build()))
    //                .transactionId("4321")
    //                .build();
    //        String procedureId = "123456";
    //        String decodedCredential = "decodedCredential";
    //
    //        when(proofValidationService.isProofValid(credentialRequest.proofs().jwt().get(0), token)).thenReturn(Mono.just(true));
    //        when(verifiableCredentialService.buildCredentialResponse(processId, did, jti, token)).thenReturn(Mono.just(credentialResponse));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just(procedureId));
    //        when(deferredCredentialMetadataService.getOperationModeByAuthServerNonce(jti)).thenReturn(Mono.just("S"));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just("procedureId"));
    //        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId("procedureId")).thenReturn(Mono.empty());
    //        when(credentialProcedureService.getCredentialStatusByProcedureId("procedureId")).thenReturn(Mono.just(CredentialStatus.DRAFT.toString()));
    //        when(credentialProcedureService.getDecodedCredentialByProcedureId("procedureId")).thenReturn(Mono.just(decodedCredential));
    //
    //        LEARCredentialEmployee learCredentialEmployee = LEARCredentialEmployee.builder()
    //                .credentialSubject(
    //                        LEARCredentialEmployee.CredentialSubject.builder()
    //                                .mandate(LEARCredentialEmployee.CredentialSubject.Mandate.builder()
    //                                        .mandator(Mandator.builder()
    //                                                .organizationIdentifier("")
    //                                                .build())
    //                                        .build()
    //                                )
    //                                .build()
    //                )
    //                .build();
    //
    //        when(credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential)).thenReturn(learCredentialEmployee);
    //
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId, credentialRequest, token))
    //                .expectError(IllegalArgumentException.class)
    //                .verify();
    //    }
    //
    //    @Test
    //    void generateVerifiableCredentialResponseInvalidMandatorOrgIdentifier() {
    //        String processId = "1234";
    //        CredentialRequest credentialRequest = CredentialRequest.builder()
    //                .credentialConfigurationId(JWT_VC)
    //                .proofs(Proofs.builder()
    //                        .jwt(List.of("eyJraWQiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MjekRuYWVuMjN3TTc2Z3BpU0xIa3U0YkZEYnNzVlM5c3R5OXgzSzd5VnFqYlNkVFBXQyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlbjIzd003NmdwaVNMSGt1NGJGRGJzc1ZTOXN0eTl4M0s3eVZxamJTZFRQV0MiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwNzEiLCJleHAiOjE3MTI5MTcwNDAsImlhdCI6MTcxMjA1MzA0MCwibm9uY2UiOiI4OVh4bXdMMlJtR2wyUlp1LU1UU3lRPT0ifQ.DdaaNm4vTn60njLtAQ7Q5oGsQILfA-5h9-sv4MBcVyNBAfSrUUajZqlUukT-5Bx8EqocSvf0RIFRHLcvO9_LMg"))
    //                        .build())
    //                .build();
    //        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";
    //        String jti = "fcca7591-6742-4c30-949c-ee9707196756";
    //        String did = "did:key:zDnaen23wM76gpiSLHku4bFDbssVS9sty9x3K7yVqjbSdTPWC";
    //        CredentialResponse credentialResponse = CredentialResponse.builder()
    //                .credentials(List.of(
    //                        CredentialResponse.Credential.builder()
    //                                .credential("credential")
    //                                .build()))
    //                .transactionId("4321")
    //                .build();
    //        String procedureId = "123456";
    //        String decodedCredential = "decodedCredential";
    //
    //        when(proofValidationService.isProofValid(credentialRequest.proofs().jwt().get(0), token)).thenReturn(Mono.just(true));
    //        when(verifiableCredentialService.buildCredentialResponse(processId, did, jti, token)).thenReturn(Mono.just(credentialResponse));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just(procedureId));
    //        when(deferredCredentialMetadataService.getOperationModeByAuthServerNonce(jti)).thenReturn(Mono.just("S"));
    //        when(deferredCredentialMetadataService.getProcedureIdByAuthServerNonce(jti)).thenReturn(Mono.just("procedureId"));
    //        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId("procedureId")).thenReturn(Mono.empty());
    //        when(credentialProcedureService.getCredentialStatusByProcedureId("procedureId")).thenReturn(Mono.just(CredentialStatus.DRAFT.toString()));
    //        when(credentialProcedureService.getDecodedCredentialByProcedureId("procedureId")).thenReturn(Mono.just(decodedCredential));
    //
    //        LEARCredentialEmployee learCredentialEmployee = LEARCredentialEmployee.builder()
    //                .credentialSubject(
    //                        LEARCredentialEmployee.CredentialSubject.builder()
    //                                .mandate(LEARCredentialEmployee.CredentialSubject.Mandate.builder()
    //                                        .signer(Signer.builder()
    //                                                .organizationIdentifier("some-identifier")
    //                                                .build())
    //                                        .mandator(Mandator.builder()
    //                                                .organizationIdentifier("")
    //                                                .build())
    //                                        .build()
    //                                )
    //                                .build()
    //                )
    //                .build();
    //
    //        when(credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential)).thenReturn(learCredentialEmployee);
    //
    //        StepVerifier.create(verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(processId, credentialRequest, token))
    //                .expectError(IllegalArgumentException.class)
    //                .verify();
    //    }

    @Test
    void completeWithdrawLEARMachineProcessUsesEmailWhenProvided() throws Exception {
        // given
        String processId = "1234";
        String schema = "LEARCredentialMachine";
        String token = "token";
        String idToken = null;

        // owner email comes from the request and must take precedence over mandator.email
        String email = "owner.override@in2.es";
        String mandatorEmail = "mandator@in2.es";
        String name = "Robot 3000";
        String org  = "IN2 Machines";
        String knowledgebaseWalletUrl = "https://knowledgebase.com";
        String issuerUiExternalDomain = "https://issuer.example.com";
        String transactionCode = "tx-ABCD";

        String json = """
    {
      "mandator": {
        "email": "%s",
        "commonName": "%s",
        "organization": "%s"
      }
    }
    """.formatted(mandatorEmail, name, org);

        ObjectMapper om = new ObjectMapper();
        JsonNode payload = om.readTree(json);

        PreSubmittedCredentialDataRequest req =
                PreSubmittedCredentialDataRequest.builder()
                        .payload(payload)
                        .schema(schema)
                        .format(JWT_VC_JSON)
                        .operationMode("S")
                        .email(email) // <- important for the test
                        .build();

        when(verifiableCredentialPolicyAuthorizationService.authorize(token, schema, payload, idToken))
                .thenReturn(Mono.empty());

        when(verifiableCredentialService.generateVc(processId, req, email, token))
                .thenReturn(Mono.just(transactionCode));

        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);

        when(emailService.sendCredentialActivationEmail(
                email,
                "email.activation.subject",
                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,
                knowledgebaseWalletUrl,
                org
        )).thenReturn(Mono.empty());

        // when / then
        StepVerifier.create(verifiableCredentialIssuanceWorkflow.execute(processId, req, token, idToken))
                .verifyComplete();

        // and we explicitly verify that email was used
        verify(emailService).sendCredentialActivationEmail(
                eq(email),
                anyString(),
                contains(transactionCode),
                eq(knowledgebaseWalletUrl),
                eq(org)
        );
    }

    @Test
    void generateVerifiableCredentialResponse_PersistsEncodedAndFormat_AfterBuild() {
        String processId = "proc-1";
        String nonce = "nonce-save-001";

        String procedureId = UUID.randomUUID().toString(); // <-- IMPORTANT: UUID
        AccessTokenContext accessTokenContext = new AccessTokenContext(
                "raw-token",
                nonce,
                procedureId,
                null
        );

        // metadata no proof
        CredentialIssuerMetadata metadata = mock(CredentialIssuerMetadata.class);
        CredentialIssuerMetadata.CredentialConfiguration cfg = mock(CredentialIssuerMetadata.CredentialConfiguration.class);
        CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition def = mock(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.class);

        String typeId = CredentialType.LEAR_CREDENTIAL_MACHINE.getTypeId();
        when(cfg.credentialDefinition()).thenReturn(def);
        when(def.type()).thenReturn(Set.of(typeId));
        when(cfg.cryptographicBindingMethodsSupported()).thenReturn(Collections.emptySet());

        Map<String, CredentialIssuerMetadata.CredentialConfiguration> map = new HashMap<>();
        map.put("cfg1", cfg);
        when(metadata.credentialConfigurationsSupported()).thenReturn(map);

        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getOperationMode()).thenReturn("S");
        when(proc.getCredentialType()).thenReturn(CredentialType.LEAR_CREDENTIAL_MACHINE.name());
        when(proc.getEmail()).thenReturn(null);
        when(proc.getProcedureId()).thenReturn(UUID.fromString(procedureId));

        when(credentialProcedureService.getCredentialProcedureById(procedureId)).thenReturn(Mono.just(proc));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(processId)).thenReturn(Mono.just(metadata));

        // CR
        String encodedJwt = "eyJhbGciOiJ...encoded.jwt...";
        CredentialResponse cr = CredentialResponse.builder()
                .credentials(List.of(CredentialResponse.Credential.builder().credential(encodedJwt).build()))
                .transactionId("t-encoded")
                .build();

        when(verifiableCredentialService.buildCredentialResponse(
                eq(processId),
                isNull(),
                eq(nonce),
                eq(accessTokenContext.rawToken()),
                isNull(String.class),
                eq(procedureId)
        )).thenReturn(Mono.just(cr));

        // SYNC path mocks
        when(credentialProcedureService.getCredentialStatusByProcedureId(procedureId))
                .thenReturn(Mono.just(CredentialStatusEnum.DRAFT.toString()));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureId))
                .thenReturn(Mono.just("{\"vc\":\"decoded\"}"));

        StepVerifier.create(
                verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(
                        processId,
                        CredentialRequest.builder().credentialConfigurationId(JWT_VC_JSON).build(),
                        accessTokenContext
                )
        ).expectNext(cr).verifyComplete();

        verifyNoInteractions(credentialDeliveryService);
    }

    @Test
    void generateVerifiableCredentialResponse_UsesEncodedCredentialOnDelivery() {
        String processId = "p-1";
        String nonce = "nonce123";
        String responseUri = "https://wallet.example.com/callback";

        String procedureId = UUID.randomUUID().toString(); // ✅ UUID
        AccessTokenContext accessTokenContext = new AccessTokenContext(
                "raw-token",
                nonce,
                procedureId,
                responseUri
        );

        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getOperationMode()).thenReturn("S");
        when(proc.getCredentialType()).thenReturn(CredentialType.LEAR_CREDENTIAL_MACHINE.name());
        when(proc.getEmail()).thenReturn("owner@in2.es");
        when(proc.getCredentialEncoded()).thenReturn("ENCODED_JWT_VALUE");
        when(proc.getProcedureId()).thenReturn(UUID.fromString(procedureId));

        // metadata no proof
        CredentialIssuerMetadata metadata = mock(CredentialIssuerMetadata.class);
        CredentialIssuerMetadata.CredentialConfiguration cfg = mock(CredentialIssuerMetadata.CredentialConfiguration.class);
        CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition def = mock(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.class);

        String typeId = CredentialType.LEAR_CREDENTIAL_MACHINE.getTypeId();
        when(cfg.credentialDefinition()).thenReturn(def);
        when(def.type()).thenReturn(Set.of(typeId));
        when(cfg.cryptographicBindingMethodsSupported()).thenReturn(Collections.emptySet());

        Map<String, CredentialIssuerMetadata.CredentialConfiguration> map = new HashMap<>();
        map.put("cfg1", cfg);
        when(metadata.credentialConfigurationsSupported()).thenReturn(map);

        when(credentialProcedureService.getCredentialProcedureById(procedureId)).thenReturn(Mono.just(proc));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(processId)).thenReturn(Mono.just(metadata));

        CredentialResponse cr = CredentialResponse.builder()
                .credentials(List.of(CredentialResponse.Credential.builder().credential("whatever").build()))
                .transactionId("t-1")
                .build();

        when(verifiableCredentialService.buildCredentialResponse(
                eq(processId),
                isNull(),
                eq(nonce),
                eq(accessTokenContext.rawToken()),
                eq("owner@in2.es"),
                eq(procedureId)
        )).thenReturn(Mono.just(cr));

        when(credentialProcedureService.getCredentialStatusByProcedureId(procedureId))
                .thenReturn(Mono.just(CredentialStatusEnum.DRAFT.toString()));
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureService.getDecodedCredentialByProcedureId(procedureId))
                .thenReturn(Mono.just("DECODED_SHOULD_NOT_BE_USED"));

        when(credentialProcedureService.getCredentialId(proc)).thenReturn(Mono.just("cred-777"));

        when(procedureRetryService.handleInitialLabelDelivery(any(), any()))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                verifiableCredentialIssuanceWorkflow.generateVerifiableCredentialResponse(
                        processId,
                        CredentialRequest.builder().credentialConfigurationId(JWT_VC_JSON).build(),
                        accessTokenContext
                )
        ).expectNext(cr).verifyComplete();

        verify(procedureRetryService).handleInitialLabelDelivery(any(), eq(UUID.fromString(procedureId)));
    }

    @Test
    void bindAccessTokenByPreAuthorizedCodeSuccess() {
        String processId = "1234";
        AuthServerNonceRequest authServerNonceRequest = AuthServerNonceRequest.builder()
                .accessToken("ey1234")
                .preAuthorizedCode("4321")
                .build();

        when(verifiableCredentialService.bindAccessTokenByPreAuthorizedCode(processId, authServerNonceRequest.accessToken(), authServerNonceRequest.preAuthorizedCode()))
                .thenReturn(Mono.empty());
        StepVerifier.create(verifiableCredentialIssuanceWorkflow.bindAccessTokenByPreAuthorizedCode(processId, authServerNonceRequest))
                .verifyComplete();
    }

    @Test
    void completeWithdrawLEARMachineProcessSyncSuccess() throws Exception {
        String processId = "1234";
        String type = "LEARCredentialMachine";
        String knowledgebaseWalletUrl = "https://knowledgebase.com";
        String issuerUiExternalDomain = "https://example.com";
        String token = "token";
        String idToken = null;
        String expectedEmail = "machine.owner@in2.es";
        String expectedOrg   = "IN2 Machines";

        String json = """
        {
          "mandator": {
            "email": "machine.owner@in2.es",
            "commonName": "Robot 3000",
            "organization": "IN2 Machines"
          }
        }
        """;

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(json);

        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest =
                PreSubmittedCredentialDataRequest.builder()
                        .payload(jsonNode)
                        .schema("LEARCredentialMachine")
                        .format(JWT_VC_JSON)
                        .operationMode("S")
                        .build();

        String transactionCode = "tx-9876";

        // arrange
        when(verifiableCredentialPolicyAuthorizationService.authorize(token, type, jsonNode, idToken))
                .thenReturn(Mono.empty());

        when(verifiableCredentialService.generateVc(processId, preSubmittedCredentialDataRequest, expectedEmail, token))
                .thenReturn(Mono.just(transactionCode));

        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);


        when(emailService.sendCredentialActivationEmail(
                expectedEmail,
                "email.activation.subject",
                issuerUiExternalDomain + "/credential-offer?transaction_code=" + transactionCode,
                knowledgebaseWalletUrl,
                expectedOrg
        )).thenReturn(Mono.empty());

        StepVerifier.create(
                verifiableCredentialIssuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, token, idToken)
        ).verifyComplete();
    }

    @Test
    void labelCredential_usesSysTenantAsOrganizationInEmail() throws Exception {
        // given
        String processId = "1234";
        String token = "token";
        String idToken = "idToken"; // required by execute() when schema is LABEL_CREDENTIAL
        String ownerEmail = "label.owner@in2.es";
        String issuerUiExternalDomain = "https://issuer.example.com";
        String knowledgebaseWalletUrl = "https://knowledgebase.com";
        String sysTenant = "my-sys-tenant";
        String tx = "tx-label-001";

        // Minimal payload for label credential (email comes from request, not payload)
        ObjectMapper om = new ObjectMapper();
        JsonNode payload = om.readTree("{}");

        PreSubmittedCredentialDataRequest req = PreSubmittedCredentialDataRequest.builder()
                .payload(payload)
                .schema(LABEL_CREDENTIAL)
                .format(JWT_VC_JSON)
                .operationMode("S")
                .email(ownerEmail)
                .build();

        // when
        when(verifiableCredentialPolicyAuthorizationService.authorize(token, LABEL_CREDENTIAL, payload, idToken))
                .thenReturn(Mono.empty());
        when(verifiableCredentialService.generateVc(processId, req, ownerEmail, token))
                .thenReturn(Mono.just(tx));
        when(appConfig.getIssuerFrontendUrl()).thenReturn(issuerUiExternalDomain);
        when(appConfig.getKnowledgebaseWalletUrl()).thenReturn(knowledgebaseWalletUrl);
        when(appConfig.getSysTenant()).thenReturn(sysTenant);

        when(emailService.sendCredentialActivationEmail(
                ownerEmail,
                "email.activation.subject",
                issuerUiExternalDomain + "/credential-offer?transaction_code=" + tx,
                knowledgebaseWalletUrl,
                sysTenant
        )).thenReturn(Mono.empty());

        // then
        StepVerifier.create(
                verifiableCredentialIssuanceWorkflow.execute(processId, req, token, idToken)
        ).verifyComplete();

        // verify
        verify(emailService).sendCredentialActivationEmail(
                eq(ownerEmail),
                eq("email.activation.subject"),
                contains(tx),
                eq(knowledgebaseWalletUrl),
                eq(sysTenant)
        );
    }

    @Test
    void extractBindingInfoFromJwtProof_kid_ok_extractsSubjectIdAndCnf() throws Exception {
        String kid = "did:key:zDnaeiLt1XYBTBZk123";
        String jwt = buildDummyJwtWithHeaderJson(
                "{\"alg\":\"HS256\",\"kid\":\"" + kid + "\"}",
                "{\"nonce\":\"n\"}"
        );

        Mono<Object> mono = invokePrivateMono(
                verifiableCredentialIssuanceWorkflow,
                "extractBindingInfoFromJwtProof",
                new Class<?>[]{String.class},
                jwt
        );

        StepVerifier.create(mono)
                .assertNext(obj -> {
                    // record BindingInfo(String subjectId, Object cnf)
                    Assertions.assertEquals("BindingInfo", obj.getClass().getSimpleName());

                    // getters de record -> subjectId() cnf()
                    try {
                        Method subjectIdM = obj.getClass().getMethod("subjectId");
                        Method cnfM = obj.getClass().getMethod("cnf");
                        String subjectId = (String) subjectIdM.invoke(obj);
                        Object cnf = cnfM.invoke(obj);

                        Assertions.assertEquals(kid, subjectId);
                        Assertions.assertTrue(cnf.toString().contains("kid"));
                        Assertions.assertTrue(cnf.toString().contains(kid));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .verifyComplete();
    }

    @Test
    void extractBindingInfoFromJwtProof_kid_withFragment_stripsFragment() throws Exception {
        String kid = "did:key:zDnaeiLt1XYBTBZk123#key-1";
        String jwt = buildDummyJwtWithHeaderJson(
                "{\"alg\":\"HS256\",\"kid\":\"" + kid + "\"}",
                "{\"nonce\":\"n\"}"
        );

        Mono<Object> mono = invokePrivateMono(
                verifiableCredentialIssuanceWorkflow,
                "extractBindingInfoFromJwtProof",
                new Class<?>[]{String.class},
                jwt
        );

        StepVerifier.create(mono)
                .assertNext(obj -> {
                    try {
                        Method subjectIdM = obj.getClass().getMethod("subjectId");
                        String subjectId = (String) subjectIdM.invoke(obj);
                        Assertions.assertEquals("did:key:zDnaeiLt1XYBTBZk123", subjectId);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .verifyComplete();
    }

    @Test
    void extractBindingInfoFromJwtProof_error_when_no_kid_jwk_x5c() throws Exception {
        String jwt = buildDummyJwtWithHeaderJson(
                "{\"alg\":\"HS256\"}",
                "{\"nonce\":\"n\"}"
        );

        Mono<Object> mono = invokePrivateMono(
                verifiableCredentialIssuanceWorkflow,
                "extractBindingInfoFromJwtProof",
                new Class<?>[]{String.class},
                jwt
        );

        StepVerifier.create(mono)
                .expectErrorSatisfies(ex -> {
                    Assertions.assertInstanceOf(ProofValidationException.class, ex);
                    Assertions.assertEquals("Expected exactly one of kid/jwk/x5c in proof header", ex.getMessage());
                })
                .verify();
    }

    @Test
    void extractBindingInfoFromJwtProof_error_when_x5c_only_present() throws Exception {
        String jwt = buildDummyJwtWithHeaderJson(
                "{\"alg\":\"HS256\",\"x5c\":[\"MIIB...\"]}",
                "{\"nonce\":\"n\"}"
        );

        Mono<Object> mono = invokePrivateMono(
                verifiableCredentialIssuanceWorkflow,
                "extractBindingInfoFromJwtProof",
                new Class<?>[]{String.class},
                jwt
        );

        StepVerifier.create(mono)
                .expectErrorSatisfies(ex -> {
                    Assertions.assertInstanceOf(ProofValidationException.class, ex);
                    Assertions.assertEquals("x5c not supported yet", ex.getMessage());
                })
                .verify();
    }

    @Test
    void getMandatorOrganizationIdentifier_whenOrgIdValid_andDidValid_registersDid() throws Exception {
        String processId = "p-1";
        String decodedCredential = "{\"vc\":\"decoded\"}";
        String orgId = "VATES-B26246436";
        String did = DID_ELSI + orgId;

        // mock LEARCredentialEmployee -> mandate -> mandator -> organizationIdentifier
        var mandator = Mandator.builder().organizationIdentifier(orgId).build();
        var mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder().mandator(mandator).build();
        var subject = LEARCredentialEmployee.CredentialSubject.builder().mandate(mandate).build();
        var employee = LEARCredentialEmployee.builder().credentialSubject(subject).build();

        when(credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential))
                .thenReturn(employee);

        when(trustFrameworkService.validateDidFormat(processId, did))
                .thenReturn(Mono.just(true));

        when(trustFrameworkService.registerDid(processId, did))
                .thenReturn(Mono.empty());

        Mono<Object> mono = invokePrivateMono(
                verifiableCredentialIssuanceWorkflow,
                "getMandatorOrganizationIdentifier",
                new Class<?>[]{String.class, String.class},
                processId,
                decodedCredential
        );

        StepVerifier.create(mono)
                .verifyComplete();

        verify(trustFrameworkService).validateDidFormat(processId, did);
        verify(trustFrameworkService).registerDid(processId, did);
    }

    @Test
    void getMandatorOrganizationIdentifier_whenDidInvalid_doesNotRegister() throws Exception {
        String processId = "p-2";
        String decodedCredential = "{\"vc\":\"decoded\"}";
        String orgId = "VATES-B26246436";
        String did = DID_ELSI + orgId;

        var mandator = Mandator.builder().organizationIdentifier(orgId).build();
        var mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder().mandator(mandator).build();
        var subject = LEARCredentialEmployee.CredentialSubject.builder().mandate(mandate).build();
        var employee = LEARCredentialEmployee.builder().credentialSubject(subject).build();

        when(credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential))
                .thenReturn(employee);

        when(trustFrameworkService.validateDidFormat(processId, did))
                .thenReturn(Mono.just(false));

        Mono<Object> mono = invokePrivateMono(
                verifiableCredentialIssuanceWorkflow,
                "getMandatorOrganizationIdentifier",
                new Class<?>[]{String.class, String.class},
                processId,
                decodedCredential
        );

        StepVerifier.create(mono)
                .verifyComplete();

        verify(trustFrameworkService).validateDidFormat(processId, did);
        verify(trustFrameworkService, never()).registerDid(anyString(), anyString());
    }

    @Test
    void getMandatorOrganizationIdentifier_whenOrgIdBlank_emitsIllegalArgumentException() throws Exception {
        String processId = "p-3";
        String decodedCredential = "{\"vc\":\"decoded\"}";

        var mandator = Mandator.builder().organizationIdentifier("   ").build();
        var mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder().mandator(mandator).build();
        var subject = LEARCredentialEmployee.CredentialSubject.builder().mandate(mandate).build();
        var employee = LEARCredentialEmployee.builder().credentialSubject(subject).build();

        when(credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential))
                .thenReturn(employee);

        Mono<Object> mono = invokePrivateMono(
                verifiableCredentialIssuanceWorkflow,
                "getMandatorOrganizationIdentifier",
                new Class<?>[]{String.class, String.class},
                processId,
                decodedCredential
        );

        StepVerifier.create(mono)
                .expectErrorSatisfies(ex -> {
                    Assertions.assertInstanceOf(IllegalArgumentException.class, ex);
                    Assertions.assertEquals("Organization Identifier not valid", ex.getMessage());
                })
                .verify();

        verifyNoInteractions(trustFrameworkService);
    }

    @Test
    void validateAndDetermineBindingInfo_whenProofSigningAlgsMissing_throwsConfigurationException() {
        // given
        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getCredentialType()).thenReturn(CredentialType.LEAR_CREDENTIAL_MACHINE.name());

        CredentialIssuerMetadata md = mock(CredentialIssuerMetadata.class);

        var cfg = mock(CredentialIssuerMetadata.CredentialConfiguration.class);
        var def = mock(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.class);

        when(def.type()).thenReturn(Set.of(CredentialType.LEAR_CREDENTIAL_MACHINE.getTypeId()));
        when(cfg.credentialDefinition()).thenReturn(def);

        // needsProof = true
        when(cfg.cryptographicBindingMethodsSupported()).thenReturn(Set.of("did"));

        // proofTypesSupported jwt present but NO algs
        when(cfg.proofTypesSupported()).thenReturn(Map.of("jwt", jwtProofCfg(Collections.emptySet())));

        when(md.credentialConfigurationsSupported()).thenReturn(Map.of("cfg1", cfg));

        CredentialRequest req = CredentialRequest.builder()
                .proof(Proof.builder().jwt(buildDummyJwtProofWithKid("did:key:z123#k1")).build())
                .build();

        // when
        Mono<CredentialIssuanceWorkflowImpl.BindingInfo> mono =
                callValidateAndDetermineBindingInfo(proc, md, req);

        // then
        StepVerifier.create(mono)
                .expectErrorSatisfies(ex ->
                        org.junit.jupiter.api.Assertions.assertInstanceOf(javax.naming.ConfigurationException.class, ex)
                )
                .verify();

        verifyNoInteractions(proofValidationService);
    }

    @Test
    void validateAndDetermineBindingInfo_whenProofsNull_throwsInvalidOrMissingProofException() {
        // given
        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getCredentialType()).thenReturn(CredentialType.LEAR_CREDENTIAL_MACHINE.name());

        CredentialIssuerMetadata md = mock(CredentialIssuerMetadata.class);

        var cfg = mock(CredentialIssuerMetadata.CredentialConfiguration.class);
        var def = mock(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.class);

        when(def.type()).thenReturn(Set.of(CredentialType.LEAR_CREDENTIAL_MACHINE.getTypeId()));
        when(cfg.credentialDefinition()).thenReturn(def);

        // needsProof = true
        when(cfg.cryptographicBindingMethodsSupported()).thenReturn(Set.of("did"));

        when(cfg.proofTypesSupported()).thenReturn(
                Map.of("jwt", jwtProofCfg(Set.of("ES256")))
        );

        when(md.credentialConfigurationsSupported()).thenReturn(Map.of("cfg1", cfg));

        CredentialRequest req = CredentialRequest.builder()
                .proof(null)
                .build();

        // when
        Mono<CredentialIssuanceWorkflowImpl.BindingInfo> mono =
                callValidateAndDetermineBindingInfo(proc, md, req);

        // then
        StepVerifier.create(mono)
                .expectErrorSatisfies(ex -> {
                    org.junit.jupiter.api.Assertions.assertInstanceOf(InvalidOrMissingProofException.class, ex);
                    org.junit.jupiter.api.Assertions.assertEquals(
                            "Missing proof for type " + CredentialType.LEAR_CREDENTIAL_MACHINE.name(),
                            ex.getMessage()
                    );
                })
                .verify();

        verifyNoInteractions(proofValidationService);
    }



    @Test
    void validateAndDetermineBindingInfo_whenProofInvalid_throwsInvalidOrMissingProofException() {
        // given
        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getCredentialType()).thenReturn(CredentialType.LEAR_CREDENTIAL_MACHINE.name());

        CredentialIssuerMetadata md = mock(CredentialIssuerMetadata.class);
        when(md.credentialIssuer()).thenReturn("https://issuer.example");

        CredentialIssuerMetadata.CredentialConfiguration cfg =
                mock(CredentialIssuerMetadata.CredentialConfiguration.class);
        CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition def =
                mock(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.class);

        when(def.type()).thenReturn(Set.of(CredentialType.LEAR_CREDENTIAL_MACHINE.getTypeId()));
        when(cfg.credentialDefinition()).thenReturn(def);

        when(cfg.cryptographicBindingMethodsSupported()).thenReturn(Set.of("did"));
        when(cfg.proofTypesSupported()).thenReturn(Map.of("jwt", jwtProofCfg(Set.of("ES256"))));

        when(md.credentialConfigurationsSupported()).thenReturn(Map.of("cfg1", cfg));

        String jwtProof = buildDummyJwtProofWithKid("did:key:z123#k1");
        CredentialRequest req = CredentialRequest.builder()
                .proof(Proof.builder().jwt(jwtProof).build())
                .build();

        when(proofValidationService.isProofValid(jwtProof, Set.of("ES256"), "https://issuer.example"))
                .thenReturn(Mono.just(false));

        // when
        Mono<CredentialIssuanceWorkflowImpl.BindingInfo> mono =
                callValidateAndDetermineBindingInfo(proc, md, req);

        // then
        StepVerifier.create(mono)
                .expectErrorSatisfies(ex -> {
                    Assertions.assertInstanceOf(InvalidOrMissingProofException.class, ex);
                    Assertions.assertEquals("Invalid proof", ex.getMessage());
                })
                .verify();
    }


    @Test
    void validateAndDetermineBindingInfo_whenProofValid_returnsBindingInfoWithKidSubjectId() {
        // given
        CredentialProcedure proc = mock(CredentialProcedure.class);
        when(proc.getCredentialType()).thenReturn(CredentialType.LEAR_CREDENTIAL_MACHINE.name());

        CredentialIssuerMetadata md = mock(CredentialIssuerMetadata.class);
        when(md.credentialIssuer()).thenReturn("https://issuer.example");

        CredentialIssuerMetadata.CredentialConfiguration cfg =
                mock(CredentialIssuerMetadata.CredentialConfiguration.class);
        CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition def =
                mock(CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.class);

        when(def.type()).thenReturn(Set.of(CredentialType.LEAR_CREDENTIAL_MACHINE.getTypeId()));
        when(cfg.credentialDefinition()).thenReturn(def);

        when(cfg.cryptographicBindingMethodsSupported()).thenReturn(Set.of("did"));
        when(cfg.proofTypesSupported()).thenReturn(Map.of("jwt", jwtProofCfg(Set.of("ES256"))));

        when(md.credentialConfigurationsSupported()).thenReturn(Map.of("cfg1", cfg));

        String kid = "did:key:zDnaeiLt1XYBTBZkvfYQ5AABYFqouxpv63LYKkiw2xad9rReK#key-1";
        String jwtProof = buildDummyJwtProofWithKid(kid);

        CredentialRequest req = CredentialRequest.builder()
                .proof(Proof.builder().jwt(jwtProof).build())
                .build();

        when(proofValidationService.isProofValid(jwtProof, Set.of("ES256"), "https://issuer.example"))
                .thenReturn(Mono.just(true));

        // when
        Mono<CredentialIssuanceWorkflowImpl.BindingInfo> mono =
                callValidateAndDetermineBindingInfo(proc, md, req);

        // then
        StepVerifier.create(mono)
                .assertNext(bi -> {
                    Assertions.assertEquals(kid.split("#")[0], bi.subjectId());
                    Assertions.assertTrue(bi.cnf() instanceof Map<?, ?>);
                    Map<?, ?> cnf = (Map<?, ?>) bi.cnf();
                    Assertions.assertEquals(kid, cnf.get("kid"));
                })
                .verifyComplete();
    }


    @SuppressWarnings("unchecked")
    private Mono<CredentialIssuanceWorkflowImpl.BindingInfo> callValidateAndDetermineBindingInfo(
            CredentialProcedure proc,
            CredentialIssuerMetadata md,
            CredentialRequest req
    ) {
        try {
            Method m = CredentialIssuanceWorkflowImpl.class.getDeclaredMethod(
                    "validateAndDetermineBindingInfo",
                    CredentialProcedure.class,
                    CredentialIssuerMetadata.class,
                    CredentialRequest.class
            );
            m.setAccessible(true);
            return (Mono<CredentialIssuanceWorkflowImpl.BindingInfo>) m.invoke(
                    verifiableCredentialIssuanceWorkflow, // tu @InjectMocks
                    proc, md, req
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private static CredentialIssuerMetadata.CredentialConfiguration.ProofSigninAlgValuesSupported jwtProofCfg(Set<String> algs) {
        return new CredentialIssuerMetadata.CredentialConfiguration.ProofSigninAlgValuesSupported(algs);
    }


    private static String buildDummyJwtProofWithKid(String kid) {
        String header = "{\"alg\":\"HS256\",\"kid\":\"" + kid + "\"}";
        String payload = "{\"iss\":\"did:example:holder\",\"aud\":\"https://issuer.example\",\"iat\":1700000000,\"exp\":2000000000}";
        String h = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(header.getBytes(StandardCharsets.UTF_8));
        String p = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return h + "." + p + ".sig";
    }


    private static String b64url(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String buildDummyJwtWithHeaderJson(String headerJson, String payloadJson) {
        String h = b64url(headerJson);
        String p = b64url(payloadJson);
        return h + "." + p + ".sig";
    }

    @SuppressWarnings("unchecked")
    private static Mono<Object> invokePrivateMono(Object target, String methodName, Class<?>[] paramTypes, Object... args) throws Exception {
        Method m = target.getClass().getDeclaredMethod(methodName, paramTypes);
        m.setAccessible(true);
        return (Mono<Object>) m.invoke(target, args);
    }





}