package es.in2.issuer.backend.shared.application.workflow.impl;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.backoffice.domain.service.ProcedureRetryService;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.retry.LabelCredentialDeliveryPayload;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.entities.DeferredCredentialMetadata;
import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.JwtUtils;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.VerifiableCredentialPolicyAuthorizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;


import javax.naming.ConfigurationException;
import javax.naming.OperationNotSupportedException;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.PEND_SIGNATURE;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_MACHINE;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialIssuanceWorkflowImpl implements CredentialIssuanceWorkflow {

    private final VerifiableCredentialService verifiableCredentialService;
    private final AppConfig appConfig;
    private final ProofValidationService proofValidationService;
    private final EmailService emailService;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final VerifiableCredentialPolicyAuthorizationService verifiableCredentialPolicyAuthorizationService;
    private final TrustFrameworkService trustFrameworkService;
    private final LEARCredentialEmployeeFactory credentialEmployeeFactory;
    private final CredentialIssuerMetadataService credentialIssuerMetadataService;
    private final ProcedureRetryService procedureRetryService;
    private final JwtUtils jwtUtils;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final IssuerFactory issuerFactory;
    private final LabelCredentialFactory labelCredentialFactory;

    @Override
    public Mono<Void> execute(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String token, String idToken) {

        // Check if the format is not "json_vc_jwt"
        if (!JWT_VC_JSON.equals(preSubmittedCredentialDataRequest.format())) {
            return Mono.error(new FormatUnsupportedException("Format: " + preSubmittedCredentialDataRequest.format() + " is not supported"));
        }
        // Check if operation_mode is different to sync
        if (!preSubmittedCredentialDataRequest.operationMode().equals(SYNC)) {
            return Mono.error(new OperationNotSupportedException("operation_mode: " + preSubmittedCredentialDataRequest.operationMode() + " with schema: " + preSubmittedCredentialDataRequest.schema()));
        }

        // Validate idToken header for VerifiableCertification schema
        if (preSubmittedCredentialDataRequest.schema().equals(LABEL_CREDENTIAL) && idToken == null) {
            return Mono.error(new MissingIdTokenHeaderException("Missing required ID Token header for VerifiableCertification issuance."));
        }

        // TODO LabelCredential the email information extraction must be done after the policy validation
        // We extract the email information from the PreSubmittedCredentialDataRequest
        CredentialOfferEmailNotificationInfo emailInfo =
                extractCredentialOfferEmailInfo(preSubmittedCredentialDataRequest);

        // Validate user policy before proceeding
        return verifiableCredentialPolicyAuthorizationService.authorize(token, preSubmittedCredentialDataRequest.schema(), preSubmittedCredentialDataRequest.payload(), idToken)
                .then(verifiableCredentialService.generateVc(processId, preSubmittedCredentialDataRequest, emailInfo.email(), token)
                        .flatMap(transactionCode -> {
                            // For label credentials, sign immediately and trigger parallel delivery
                            if (LABEL_CREDENTIAL.equals(preSubmittedCredentialDataRequest.schema())) {
                                return handleLabelCredentialIssuance(processId, transactionCode, emailInfo, token);
                            }

                            return sendCredentialOfferEmail(transactionCode, emailInfo);
                        })
                );
    }

    private Mono<Void> handleLabelCredentialIssuance(
            String processId,
            String transactionCode,
            CredentialOfferEmailNotificationInfo emailInfo,
            String token
    ) {
        return deferredCredentialMetadataService.getProcedureIdByTransactionCode(transactionCode)
                .flatMap(procedureId ->
                        issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, emailInfo.email())
                                .flatMap(issuer -> labelCredentialFactory.mapIssuer(procedureId, issuer))
                                .flatMap(boundCredential ->
                                        credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, boundCredential)
                                                .thenReturn(procedureId)
                                )
                                .flatMap(procId -> credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procId, JWT_VC)
                                        .flatMap(signedCredential ->
                                                credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procId)
                                                        .then(credentialProcedureService.getCredentialProcedureById(procId))
                                                        .flatMap(credentialProcedure ->
                                                                triggerLabelCredentialParallelDelivery(
                                                                        procId,
                                                                        transactionCode,
                                                                        signedCredential,
                                                                        emailInfo,
                                                                        credentialProcedure
                                                                )
                                                        )
                                        )
                                        .onErrorResume(signingError -> {
                                            log.error("ProcessID: {} - Label credential signing failed: {}", processId, signingError.getMessage());
                                            return credentialProcedureService.updateCredentialStatusToPendSignature(procId)
                                                    .then(Mono.error(new RemoteSignatureException(
                                                            "Label credential signing failed. Credential saved with PEND_SIGNATURE status for later retry.", signingError
                                                    )));
                                        })
                                )
                );
    }

    private Mono<Void> triggerLabelCredentialParallelDelivery(
            String procedureId,
            String transactionCode,
            String signedCredential,
            CredentialOfferEmailNotificationInfo emailInfo,
            CredentialProcedure credentialProcedure
    ) {
        // Fire-and-forget: Send credential offer email
        String credentialOfferUrl = buildCredentialOfferUrl(transactionCode);
        emailService.sendCredentialActivationEmail(
                        emailInfo.email(),
                        CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                        credentialOfferUrl,
                        appConfig.getKnowledgebaseWalletUrl(),
                        emailInfo.organization()
                )
                .subscribeOn(Schedulers.boundedElastic())
                .subscribe(
                        unused -> log.info("Label credential offer email sent for procedureId: {}", procedureId),
                        error -> log.error("Failed to send label credential offer email for procedureId: {}: {}", procedureId, error.getMessage())
                );

        // Fire-and-forget: Send to response URI with retry mechanism
        return deferredCredentialMetadataService.getResponseUriByProcedureId(procedureId)
                .flatMap(responseUri ->
                        credentialProcedureService.getCredentialId(credentialProcedure)
                                .flatMap(credentialId -> {
                                    LabelCredentialDeliveryPayload payload = LabelCredentialDeliveryPayload.builder()
                                            .responseUri(responseUri)
                                            .signedCredential(signedCredential)
                                            .credentialId(credentialId)
                                            .companyEmail(credentialProcedure.getEmail())
                                            .build();

                                    // Execute delivery as fire-and-forget
                                    procedureRetryService.handleInitialAction(
                                                    UUID.fromString(procedureId),
                                                    ActionType.UPLOAD_LABEL_TO_RESPONSE_URI,
                                                    payload
                                            )
                                            .subscribeOn(Schedulers.boundedElastic())
                                            .subscribe(
                                                    unused -> log.debug("Triggered label credential delivery retry pipeline for procedureId: {}", procedureId),
                                                    error -> log.error("Failed to trigger label credential delivery retry pipeline for procedureId: {}: {}", procedureId, error.getMessage(), error)
                                            );

                                    return Mono.empty();
                                })
                )
                .then();
    }

    private Mono<Void> sendCredentialOfferEmail(
            String transactionCode,
            CredentialOfferEmailNotificationInfo info
    ) {
        String credentialOfferUrl = buildCredentialOfferUrl(transactionCode);

        return emailService.sendCredentialActivationEmail(
                        info.email(),
                        CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                        credentialOfferUrl,
                        appConfig.getKnowledgebaseWalletUrl(),
                        info.organization()
                )
                .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    private String buildCredentialOfferUrl(String transactionCode) {
        return UriComponentsBuilder
                .fromHttpUrl(appConfig.getIssuerFrontendUrl())
                .path("/credential-offer")
                .queryParam("transaction_code", transactionCode)
                .build()
                .toUriString();
    }

    // Get the necessary information to send the credential offer email
    private CredentialOfferEmailNotificationInfo extractCredentialOfferEmailInfo(PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest) {
        String schema = preSubmittedCredentialDataRequest.schema();
        var payload = preSubmittedCredentialDataRequest.payload();


        return switch (schema) {
            case LEAR_CREDENTIAL_EMPLOYEE -> {
                String email = payload.get(MANDATEE).get(EMAIL).asText();
                String org = payload.get(MANDATOR).get(ORGANIZATION).asText();
                yield new CredentialOfferEmailNotificationInfo(email, org);
            }
            case LEAR_CREDENTIAL_MACHINE -> {
                String email;
                if (preSubmittedCredentialDataRequest.email() == null || preSubmittedCredentialDataRequest.email().isBlank()) {
                    email = payload.get(MANDATOR).get(EMAIL).asText();
                    log.debug("No credential owner email found in presubmitted data. Using mandator email: {}", payload.get(MANDATOR).get(EMAIL).asText());
                } else {
                    email = preSubmittedCredentialDataRequest.email();
                }
                String org = payload.get(MANDATOR).get(ORGANIZATION).asText();
                yield new CredentialOfferEmailNotificationInfo(email, org);
            }
            case LABEL_CREDENTIAL -> {
                if (preSubmittedCredentialDataRequest.email() == null || preSubmittedCredentialDataRequest.email().isBlank()) {
                    throw new MissingEmailOwnerException("Email owner email is required for gx:LabelCredential schema");
                }
                String email = preSubmittedCredentialDataRequest.email();
                yield new CredentialOfferEmailNotificationInfo(email, appConfig.getSysTenant());
            }
            default -> throw new FormatUnsupportedException(
                    "Unknown schema: " + schema
            );
        };
    }

    @Override
    public Mono<CredentialResponse> generateVerifiableCredentialResponse(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext
    ) {

        final String procedureId = accessTokenContext.procedureId();

        return credentialProcedureService.getCredentialProcedureById(procedureId)
                .flatMap(proc -> {
                    if (LABEL_CREDENTIAL_TYPE.equals(proc.getCredentialType())
                            && proc.getCredentialStatus() == CredentialStatusEnum.VALID
                            && proc.getCredentialEncoded() != null
                            && !proc.getCredentialEncoded().isBlank()) {
                        log.info("[{}] Label credential already signed, returning stored credential for procedureId={}",
                                processId, procedureId);
                        return credentialProcedureService.getNotificationIdByProcedureId(procedureId)
                                .map(notificationId -> CredentialResponse.builder()
                                        .credentials(List.of(
                                                CredentialResponse.Credential.builder()
                                                        .credential(proc.getCredentialEncoded())
                                                        .build()
                                        ))
                                        .notificationId(notificationId)
                                        .build());
                    }

                    return proceedWithCredentialIssuance(processId, credentialRequest, accessTokenContext, proc);
                });
    }

    private Mono<CredentialResponse> proceedWithCredentialIssuance(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext,
            CredentialProcedure proc
    ) {
        final String nonce = accessTokenContext.jti();
        final String procedureId = accessTokenContext.procedureId();

        return credentialIssuerMetadataService.getCredentialIssuerMetadata(processId)
                .flatMap(md -> {
                    String email = proc.getEmail();

                    boolean responseUriPresent = accessTokenContext.responseUri() != null && !accessTokenContext.responseUri().isBlank();

                    log.info(
                            "[{}] Loaded procedure context: nonce(jti)={}, procedureId={}, operationMode={}, credentialType={}, responseUriPresent={}",
                            processId,
                            nonce,
                            procedureId,
                            proc.getOperationMode(),
                            proc.getCredentialType(),
                            responseUriPresent
                    );

                    Mono<BindingInfo> bindingInfoMono = validateAndDetermineBindingInfo(proc, md, credentialRequest)
                            .doOnNext(bi -> log.info(
                                    "[{}] Binding required -> subjectId={}, cnfKeys={}",
                                    processId,
                                    bi.subjectId(),
                                    (bi.cnf() instanceof java.util.Map<?, ?> m) ? m.keySet() : "unknown"
                            ))
                            .doOnSuccess(bi -> {
                                if (bi == null) {
                                    log.info("[{}] No cryptographic binding required for credentialType={}",
                                            processId, proc.getCredentialType());
                                }
                            });

                    Mono<CredentialResponse> vcMono = bindingInfoMono
                            .flatMap(bi -> verifiableCredentialService.buildCredentialResponse(
                                    processId,
                                    bi.subjectId(),
                                    nonce,
                                    accessTokenContext.rawToken(),
                                    email,
                                    procedureId
                            ))
                            .switchIfEmpty(Mono.defer(() -> verifiableCredentialService.buildCredentialResponse(
                                    processId,
                                    null,
                                    nonce,
                                    accessTokenContext.rawToken(),
                                    email,
                                    procedureId
                            )));

                    DeferredCredentialMetadata deferred = new DeferredCredentialMetadata();
                    deferred.setResponseUri(accessTokenContext.responseUri());
                    deferred.setProcedureId(UUID.fromString(procedureId));

                    return vcMono.flatMap(cr ->
                            handleOperationMode(
                                    proc.getOperationMode(),
                                    processId,
                                    cr,
                                    proc,
                                    deferred
                            )
                    );
                });
    }

    private Mono<BindingInfo> validateAndDetermineBindingInfo(
            CredentialProcedure credentialProcedure,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest
    ) {

        log.debug("validateAndDetermineBindingInfo: credentialType={}", credentialProcedure.getCredentialType());

        return resolveCredentialType(credentialProcedure)
                .flatMap(typeEnum -> findIssuerConfig(metadata, typeEnum)
                        .flatMap(cfg -> evaluateCryptographicBinding(cfg, typeEnum, metadata, credentialRequest))
                );
    }

    private Mono<CredentialType> resolveCredentialType(CredentialProcedure credentialProcedure) {
        final CredentialType typeEnum;
        try {
            typeEnum = CredentialType.valueOf(credentialProcedure.getCredentialType());
        } catch (IllegalArgumentException e) {
            return Mono.error(new FormatUnsupportedException(
                    "Unknown credential type: " + credentialProcedure.getCredentialType()
            ));
        }
        return Mono.just(typeEnum);
    }

    private Mono<CredentialIssuerMetadata.CredentialConfiguration> findIssuerConfig(CredentialIssuerMetadata metadata, CredentialType typeEnum) {
        return Mono.justOrEmpty(
                        metadata.credentialConfigurationsSupported()
                                .values()
                                .stream()
                                .filter(cfg -> cfg.credentialDefinition().type().contains(typeEnum.getTypeId()))
                                .findFirst()
                )
                .switchIfEmpty(Mono.error(new FormatUnsupportedException(
                        "No configuration for typeId: " + typeEnum.getTypeId()
                )));
    }

    private Mono<BindingInfo> evaluateCryptographicBinding(
            CredentialIssuerMetadata.CredentialConfiguration cfg,
            CredentialType typeEnum,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest
    ) {
        var cryptoMethods = cfg.cryptographicBindingMethodsSupported();

        boolean needsProof = cryptoMethods != null && !cryptoMethods.isEmpty();
        log.info("Binding requirement for {}: needsProof={}", typeEnum.name(), needsProof);

        if (!needsProof) {
            return Mono.empty();
        }

        String cryptoBindingMethod = selectCryptoBindingMethod(cryptoMethods, typeEnum);
        log.debug("Crypto binding method for {}: {}", typeEnum.name(), cryptoBindingMethod);

        Set<String> proofSigningAlgoritms = resolveProofSigningAlgorithms(cfg);
        log.debug("Proof signing algs for {}: {}", typeEnum.name(), proofSigningAlgoritms);

        String jwtProof = extractFirstJwtProof(credentialRequest);
        String expectedAudience = metadata.credentialIssuer();

        return validateProofAndExtractBindingInfo(jwtProof, proofSigningAlgoritms, expectedAudience, typeEnum);
    }

    private String selectCryptoBindingMethod(Set<String> cryptoMethods, CredentialType typeEnum) {
        String cryptoBindingMethod;
        try {
            cryptoBindingMethod = cryptoMethods.stream()
                    .findFirst()
                    .orElseThrow(() -> new InvalidCredentialFormatException(
                            "No cryptographic binding method configured for " + typeEnum.name()
                    ));
        } catch (InvalidCredentialFormatException e) {
            throw new InvalidCredentialFormatException("No cryptographic binding method configured");
        }
        return cryptoBindingMethod;
    }

    private Set<String> resolveProofSigningAlgorithms(CredentialIssuerMetadata.CredentialConfiguration cfg) {
        var proofTypes = cfg.proofTypesSupported();
        var jwtProofConfig = (proofTypes != null) ? proofTypes.get("jwt") : null;

        return (jwtProofConfig != null) ? jwtProofConfig.proofSigningAlgValuesSupported() : null;
    }

    private String extractFirstJwtProof(CredentialRequest credentialRequest) {
        return credentialRequest.proof() != null
                ? credentialRequest.proof().jwt()
                : null;
    }

    private Mono<BindingInfo> validateProofAndExtractBindingInfo(
            String jwtProof,
            Set<String> proofSigningAlgoritms,
            String expectedAudience,
            CredentialType typeEnum
    ) {
        if (proofSigningAlgoritms == null || proofSigningAlgoritms.isEmpty()) {
            return Mono.error(new ConfigurationException(
                    "No proof_signing_alg_values_supported configured for proof type 'jwt' " +
                            "and credential type " + typeEnum.name()
            ));
        }

        if (jwtProof == null) {
            return Mono.error(new InvalidOrMissingProofException(
                    "Missing proof for type " + typeEnum.name()
            ));
        }

        return proofValidationService
                .isProofValid(jwtProof, proofSigningAlgoritms, expectedAudience)
                .doOnNext(valid ->
                        log.info("Proof validation result for {}: {}", typeEnum.name(), valid)
                )
                .flatMap(valid -> {
                    if (!Boolean.TRUE.equals(valid)) {
                        return Mono.error(new InvalidOrMissingProofException("Invalid proof"));
                    }
                    return extractBindingInfoFromJwtProof(jwtProof);
                });
    }


    private Mono<CredentialResponse> handleOperationMode(
            String operationMode,
            String processId,
            CredentialResponse cr,
            CredentialProcedure credentialProcedure,
            DeferredCredentialMetadata deferred
    ) {

        return switch (operationMode) {
            case ASYNC -> {
                Mono<String> emailMono = Mono.just(credentialProcedure.getEmail());
                yield emailMono.flatMap(email ->
                        emailService.sendPendingCredentialNotification(email, "email.pending-credential")
                                .thenReturn(cr)
                );
            }
            case SYNC -> Mono.just(credentialProcedure)
                    .flatMap(proc -> credentialProcedureService.getCredentialStatusByProcedureId(proc.getProcedureId().toString())
                            .flatMap(status -> {
                                Mono<Void> upd = !PEND_SIGNATURE.toString().equals(status)
                                        ? credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(proc.getProcedureId().toString())
                                        : Mono.empty();

                                return upd.then(credentialProcedureService.getDecodedCredentialByProcedureId(proc.getProcedureId().toString())
                                        .zipWith(credentialProcedureService.getCredentialProcedureById(proc.getProcedureId().toString())));
                            })
                            .flatMap(tuple -> {
                                String decoded = tuple.getT1();
                                CredentialProcedure updatedCredentialProcedure = tuple.getT2();

                                CredentialType typeEnum = CredentialType.valueOf(credentialProcedure.getCredentialType());
                                if (typeEnum == CredentialType.LEAR_CREDENTIAL_EMPLOYEE) {
                                    log.info("[{}] SYNC: LEAR_CREDENTIAL_EMPLOYEE -> running TrustFramework registration check", processId);

                                    return getMandatorOrganizationIdentifier(processId, decoded);
                                }

                                if (deferred.getResponseUri() != null && !deferred.getResponseUri().isBlank()) {
                                    String encodedCredential = updatedCredentialProcedure.getCredentialEncoded();
                                    if (encodedCredential == null || encodedCredential.isBlank()) {
                                        return Mono.error(new IllegalStateException("Encoded credential not found for procedureId: " + updatedCredentialProcedure.getProcedureId()));
                                    }

                                    return credentialProcedureService.getCredentialId(credentialProcedure)
                                            .flatMap(credentialId -> {
                                                LabelCredentialDeliveryPayload payload = LabelCredentialDeliveryPayload.builder()
                                                        .responseUri(deferred.getResponseUri())
                                                        .signedCredential(encodedCredential)
                                                        .credentialId(credentialId)
                                                        .companyEmail(credentialProcedure.getEmail())
                                                        .build();
                                                
                                                // Execute delivery as fire-and-forget (completely parallel)
                                                procedureRetryService.handleInitialAction(updatedCredentialProcedure.getProcedureId(), ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, payload)
                                                        .subscribeOn(Schedulers.boundedElastic())
                                                        .subscribe();
                                                
                                                // Main flow continues immediately without waiting for upload
                                                return Mono.empty();
                                            });
                                }

                                return Mono.empty();
                            })
                    )
                    .thenReturn(cr);
            default -> Mono.error(new IllegalArgumentException("Unknown operation mode: " + operationMode));
        };
    }

    @Override
    public Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, AuthServerNonceRequest authServerNonceRequest) {
        return verifiableCredentialService.bindAccessTokenByPreAuthorizedCode
                (processId, authServerNonceRequest.accessToken(), authServerNonceRequest.preAuthorizedCode());
    }

    @Override
    public Mono<CredentialResponse> generateVerifiableCredentialDeferredResponse(
            String processId,
            DeferredCredentialRequest deferredCredentialRequest,
            AccessTokenContext accessTokenContext) {
        String transactionId = deferredCredentialRequest.transactionId();
        log.debug("ProcessID: {} Generating verifiable credential deferred response for transactionId: {}", processId, transactionId);

        return deferredCredentialMetadataService.getDeferredCredentialMetadataByAuthServerNonce(accessTokenContext.jti())
                .flatMap(deferred ->
                        credentialProcedureService.getCredentialProcedureById(deferred.getProcedureId().toString())
                                .flatMap(procedure ->
                                        verifiableCredentialService.generateDeferredCredentialResponse(procedure, transactionId)));
    }

    public record BindingInfo(String subjectId, Object cnf) {
    }

    private Mono<BindingInfo> extractBindingInfoFromJwtProof(String jwtProof) {
        return Mono.fromCallable(() -> {
            JWSObject jws = JWSObject.parse(jwtProof);
            var header = jws.getHeader().toJSONObject();

            Object kid = header.get("kid");
            Object jwk = header.get("jwk");
            Object x5c = header.get("x5c");

            int count = (kid != null ? 1 : 0) + (jwk != null ? 1 : 0) + (x5c != null ? 1 : 0);

            if (count != 1) {
                throw new ProofValidationException("Expected exactly one of kid/jwk/x5c in proof header");
            }

            // 1) kid
            if (kid != null) {
                return buildFromKid(kid);
            }
            // 2) x5c
            else if (x5c != null) {
                return buildFromX5c();
            }
            // 3) jwk
            else if (jwk != null) {
                return buildFromJwk(jwk);
            }

            throw new ProofValidationException("No key material found in proof header");
        });
    }

    private BindingInfo buildFromKid(Object kid) {
        String kidStr = kid.toString();
        String subjectId = kidStr.contains("#") ? kidStr.split("#")[0] : kidStr;

        log.info("Binding extracted from proof: cnfType=kid, subjectId={}, kidPrefix={}",
                subjectId,
                kidStr.length() > 20 ? kidStr.substring(0, 20) : kidStr
        );

        return new BindingInfo(subjectId, java.util.Map.of("kid", kidStr));
    }

    private BindingInfo buildFromX5c() throws ProofValidationException {
        throw new ProofValidationException("x5c not supported yet");
    }

    private BindingInfo buildFromJwk(Object jwk) throws ProofValidationException {
        if (!(jwk instanceof java.util.Map<?, ?> jwkMap)) {
            throw new ProofValidationException("jwk must be a JSON object");
        }
        var jwkObj = (java.util.Map<String, Object>) jwkMap;
        String subjectIdFromJwk = jwtUtils.didKeyFromJwk(jwkObj);
        if (subjectIdFromJwk == null || subjectIdFromJwk.isBlank()) {
            throw new ProofValidationException("Unable to derive did:key from jwk");
        }
        log.info("Binding extracted from proof: cnfType=jwk, subjectId={}", subjectIdFromJwk);
        return new BindingInfo(subjectIdFromJwk, java.util.Map.of("jwk", jwkObj));
    }


    private Mono<Void> getMandatorOrganizationIdentifier(String processId, String decodedCredential) {

        LEARCredentialEmployee learCredentialEmployee = credentialEmployeeFactory.mapStringToLEARCredentialEmployee(decodedCredential);

        String mandatorOrgIdentifier = learCredentialEmployee.credentialSubject().mandate().mandator().organizationIdentifier();
        if (mandatorOrgIdentifier == null || mandatorOrgIdentifier.isBlank()) {
            log.error("ProcessID: {} Mandator Organization Identifier cannot be null or empty", processId);
            return Mono.error(new IllegalArgumentException("Organization Identifier not valid"));
        }

        return saveToTrustFramework(processId, mandatorOrgIdentifier);
    }

    private Mono<Void> saveToTrustFramework(String processId, String mandatorOrgIdentifier) {

        String mandatorDid = DID_ELSI + mandatorOrgIdentifier;

        return trustFrameworkService.validateDidFormat(processId, mandatorDid)
                .flatMap(isValid -> registerDidIfValid(processId, mandatorDid, isValid));
    }

    private Mono<Void> registerDidIfValid(String processId, String did, boolean isValid) {
        if (isValid) {
            return trustFrameworkService.registerDid(processId, did);
        } else {
            log.error("ProcessID: {} Did not registered because is invalid", processId);
            return Mono.empty();
        }
    }
}