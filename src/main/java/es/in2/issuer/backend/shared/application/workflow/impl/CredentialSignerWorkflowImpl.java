package es.in2.issuer.backend.shared.application.workflow.impl;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.application.workflow.DeferredCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.exception.Base45Exception;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureInvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureConfiguration;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedCredentials;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.dto.credential.LabelCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialMachineFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl.minvws.encoding.Base45;
import org.apache.commons.compress.compressors.CompressorOutputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CWT_VC;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.JWT_VC;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialSignerWorkflowImpl implements CredentialSignerWorkflow {

    private final AccessTokenService accessTokenService;
    private final BackofficePdpService backofficePdpService;
    private final ObjectMapper objectMapper;
    private final DeferredCredentialWorkflow deferredCredentialWorkflow;
    private final RemoteSignatureService remoteSignatureService;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    private final LEARCredentialMachineFactory learCredentialMachineFactory;
    private final LabelCredentialFactory labelCredentialFactory;
    private final CredentialProcedureRepository credentialProcedureRepository;
    private final CredentialProcedureService credentialProcedureService;
    private final M2MTokenService m2mTokenService;
    private final CredentialDeliveryService credentialDeliveryService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final IssuerFactory issuerFactory;


    @Override
    public Mono<String> signAndUpdateCredentialByProcedureId(String token, String procedureId, String format) {
        log.debug("signAndUpdateCredentialByProcedureId");

        return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    try {
                        String credentialType = credentialProcedure.getCredentialType();
                        String updatedBy = credentialProcedure.getUpdatedBy();
                        log.info("Building JWT payload for credential signing for credential with type: {}", credentialType);
                        return switch (credentialType) {
                            case LABEL_CREDENTIAL_TYPE -> {
                                LabelCredential labelCredential = labelCredentialFactory
                                        .mapStringToLabelCredential(credentialProcedure.getCredentialDecoded());
                                yield labelCredentialFactory.buildLabelCredentialJwtPayload(labelCredential)
                                        .flatMap(labelCredentialFactory::convertLabelCredentialJwtPayloadInToString)
                                        .flatMap(unsignedCredential -> signCredentialOnRequestedFormat(unsignedCredential, format, token, procedureId, updatedBy));
                            }
                            case LEAR_CREDENTIAL_EMPLOYEE_TYPE -> {
                                LEARCredentialEmployee learCredentialEmployee = learCredentialEmployeeFactory
                                        .mapStringToLEARCredentialEmployee(credentialProcedure.getCredentialDecoded());
                                yield learCredentialEmployeeFactory.buildLEARCredentialEmployeeJwtPayload(learCredentialEmployee)
                                        .flatMap(learCredentialEmployeeFactory::convertLEARCredentialEmployeeJwtPayloadInToString)
                                        .flatMap(unsignedCredential -> signCredentialOnRequestedFormat(unsignedCredential, format, token, procedureId, updatedBy));
                            }
                            case LEAR_CREDENTIAL_MACHINE_TYPE -> {
                                LEARCredentialMachine learCredentialMachine = learCredentialMachineFactory
                                        .mapStringToLEARCredentialMachine(credentialProcedure.getCredentialDecoded());
                                yield learCredentialMachineFactory.buildLEARCredentialMachineJwtPayload(learCredentialMachine)
                                        .flatMap(learCredentialMachineFactory::convertLEARCredentialMachineJwtPayloadInToString)
                                        .flatMap(unsignedCredential -> signCredentialOnRequestedFormat(unsignedCredential, format, token, procedureId, updatedBy));
                            }
                            default -> {
                                log.error("Unsupported credential type: {}", credentialType);
                                yield Mono.error(new IllegalArgumentException("Unsupported credential type: " + credentialType));
                            }
                        };
                    } catch (Exception e) {
                        log.error("Error signing credential with procedure id: {} - {}", procedureId, e.getMessage(), e);
                        return Mono.error(new IllegalArgumentException("Error signing credential"));
                    }
                })
                .flatMap(signedCredential -> {
                    log.info("Update Signed Credential");
                    return updateSignedCredential(signedCredential, procedureId)
                            .thenReturn(signedCredential);
                })
                .doOnSuccess(x -> log.info("Credential Signed and updated successfully."));
    }

    private Mono<Void> updateSignedCredential(String signedCredential, String procedureId) {
        List<SignedCredentials.SignedCredential> credentials = List.of(SignedCredentials.SignedCredential.builder().credential(signedCredential).build());
        SignedCredentials signedCredentials = new SignedCredentials(credentials);
        return deferredCredentialWorkflow.updateSignedCredentials(signedCredentials, procedureId);
    }

    private Mono<String> signCredentialOnRequestedFormat(String unsignedCredential, String format, String token, String procedureId, String email) {
        return Mono.defer(() -> {
            if (format.equals(JWT_VC)) {
                return setSubIfCredentialSubjectIdPresent(unsignedCredential)
                        .flatMap(payloadToSign -> {
                            log.info("Signing credential in JADES remotely ...");
                            SignatureRequest signatureRequest = new SignatureRequest(
                                    new SignatureConfiguration(SignatureType.JADES, Collections.emptyMap()),
                                    payloadToSign
                            );

                            return remoteSignatureService.signIssuedCredential(signatureRequest, token, procedureId, email)
                                    .publishOn(Schedulers.boundedElastic())
                                    .map(SignedData::data);
                        });

            } else if (format.equals(CWT_VC)) {
                log.info(unsignedCredential);
                return generateCborFromJson(unsignedCredential)
                        .flatMap(cbor -> generateCOSEBytesFromCBOR(cbor, token, email))
                        .flatMap(this::compressAndConvertToBase45FromCOSE);
            } else {
                return Mono.error(new IllegalArgumentException("Unsupported credential format: " + format));
            }
        });
    }

    private Mono<String> setSubIfCredentialSubjectIdPresent(String unsignedCredential) {
        return Mono.fromCallable(() -> {
            JsonNode root = objectMapper.readTree(unsignedCredential);
            if (!(root instanceof ObjectNode rootObj)) {
                return unsignedCredential;
            }

            String subjectDid = extractSubjectDid(rootObj);

            if (subjectDid != null && !subjectDid.isBlank()) {
                rootObj.put("sub", subjectDid);
                return objectMapper.writeValueAsString(rootObj);
            }

            return unsignedCredential;
        })
        .subscribeOn(Schedulers.boundedElastic())
        .onErrorResume(e -> {
            log.warn(
                    "Could not set 'sub' from vc.credentialSubject.id. Keeping original payload. Reason: {}",
                    e.getMessage()
            );
            return Mono.just(unsignedCredential);
        });
    }

    private String extractSubjectDid(ObjectNode rootObj) {
        JsonNode csNode = rootObj.path("vc").path("credentialSubject");

        if (csNode.isObject()) {
            return extractIdFromObject(csNode);
        }

        if (csNode.isArray()) {
            return extractIdFromArray((ArrayNode) csNode);
        }

        return null;
    }

    private String extractIdFromObject(JsonNode csNode) {
        JsonNode idNode = csNode.path("id");
        return idNode.isTextual() ? idNode.asText() : null;
    }

    private String extractIdFromArray(ArrayNode arrayNode) {
        for (JsonNode item : arrayNode) {
            if (item != null && item.isObject()) {
                JsonNode idNode = item.path("id");
                if (idNode.isTextual() && !idNode.asText().isBlank()) {
                    return idNode.asText();
                }
            }
        }
        return null;
    }

    /**
     * Generate CBOR payload for COSE.
     *
     * @param edgcJson EDGC payload as JSON string
     * @return Mono emitting CBOR bytes
     */
    private Mono<byte[]> generateCborFromJson(String edgcJson) {
        return Mono.fromCallable(() -> CBORObject.FromJSONString(edgcJson).EncodeToBytes());
    }

    /**
     * Generate COSE bytes from CBOR bytes.
     *
     * @param cbor  CBOR bytes
     * @param token Authentication token
     * @return Mono emitting COSE bytes
     */
    private Mono<byte[]> generateCOSEBytesFromCBOR(byte[] cbor, String token, String email) {
        log.info("Signing credential in COSE format remotely ...");
        String cborBase64 = Base64.getEncoder().encodeToString(cbor);
        SignatureRequest signatureRequest = new SignatureRequest(
                new SignatureConfiguration(SignatureType.COSE, Collections.emptyMap()),
                cborBase64
        );
        return remoteSignatureService.signIssuedCredential(signatureRequest, token, "", email).map(signedData -> Base64.getDecoder().decode(signedData.data()));
    }

    /**
     * Compress COSE bytes and convert it to Base45.
     *
     * @param cose COSE Bytes
     * @return Mono emitting COSE bytes compressed and in Base45
     */
    private Mono<String> compressAndConvertToBase45FromCOSE(byte[] cose) {
        return Mono.fromCallable(() -> {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            try (CompressorOutputStream deflateOut = new CompressorStreamFactory()
                    .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, stream)) {
                deflateOut.write(cose);
            } // Automatically closed by try-with-resources
            byte[] zip = stream.toByteArray();
            return Base45.getEncoder().encodeToString(zip);
        }).onErrorResume(e -> {
            log.error("Error compressing and converting to Base45: " + e.getMessage(), e);
            return Mono.error(new Base45Exception("Error compressing and converting to Base45"));
        });
    }

    @Override
    public Mono<Void> retrySignUnsignedCredential(String processId, String authorizationHeader, String procedureId) {
        log.info("Retrying to sign credential. processId={} procedureId={}", processId, procedureId);

        return accessTokenService.getCleanBearerToken(authorizationHeader)
                .flatMap(token ->
                        backofficePdpService.validateSignCredential(processId, token, procedureId)
                                .then(Mono.just(token))
                                .zipWhen(t -> accessTokenService.getMandateeEmail(authorizationHeader))
                )
                .flatMap(tupleTokenEmail -> {
                    String token = tupleTokenEmail.getT1();
                    String email = tupleTokenEmail.getT2();

                    return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                            .switchIfEmpty(Mono.error(new CredentialProcedureNotFoundException(
                                    "Credential procedure with ID " + procedureId + " was not found"
                            )))
                            .doOnNext(credentialProcedure ->
                                    log.info("ProcessID: {} - Current credential status: {}",
                                            processId, credentialProcedure.getCredentialStatus())
                            )
                            .filter(credentialProcedure ->
                                    credentialProcedure.getCredentialStatus() == CredentialStatusEnum.PEND_SIGNATURE
                            )
                            .switchIfEmpty(Mono.error(new CredentialProcedureInvalidStatusException(
                                    "Credential procedure with ID " + procedureId + " is not in PEND_SIGNATURE status"
                            )))
                            .flatMap(credentialProcedure -> {
                                Mono<Void> updateDecodedCredentialMono =
                                        switch (credentialProcedure.getCredentialType()) {
                                            case LABEL_CREDENTIAL_TYPE ->
                                                    issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, email)
                                                            .flatMap(issuer -> labelCredentialFactory.mapIssuer(procedureId, issuer))
                                                            .flatMap(bindCredential ->
                                                                    updateDecodedCredentialByProcedureId(procedureId, bindCredential)
                                                            );

                                            case LEAR_CREDENTIAL_MACHINE_TYPE ->
                                                    learCredentialMachineFactory
                                                            .mapCredentialAndBindIssuerInToTheCredential(
                                                                    credentialProcedure.getCredentialDecoded(), procedureId, email
                                                            )
                                                            .flatMap(bindCredential ->
                                                                    updateDecodedCredentialByProcedureId(procedureId, bindCredential)
                                                            );
                                            
                                            case LEAR_CREDENTIAL_EMPLOYEE_TYPE ->
                                                    learCredentialEmployeeFactory
                                                            .mapCredentialAndBindIssuerInToTheCredential(
                                                                    credentialProcedure.getCredentialDecoded(), procedureId, email
                                                            )
                                                            .flatMap(bindCredential ->
                                                                    updateDecodedCredentialByProcedureId(procedureId, bindCredential)
                                                            );

                                            default -> {
                                                log.error("Unknown credential type: {}", credentialProcedure.getCredentialType());
                                                yield Mono.error(new IllegalArgumentException(
                                                        "Unsupported credential type: " + credentialProcedure.getCredentialType()
                                                ));
                                            }
                                        };

                                return updateDecodedCredentialMono
                                        .then(this.signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC))
                                        .flatMap(signedVc ->
                                                credentialProcedureService
                                                        .updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId)
                                                        .thenReturn(signedVc)
                                        )
                                        .flatMap(signedVc ->
                                                credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                                                        .flatMap(updatedCredentialProcedure ->
                                                                credentialProcedureRepository.save(updatedCredentialProcedure)
                                                                        .thenReturn(updatedCredentialProcedure)
                                                        )
                                                        .flatMap(updatedCredentialProcedure -> {
                                                            String credentialType = updatedCredentialProcedure.getCredentialType();
                                                            if (!LABEL_CREDENTIAL_TYPE.equals(credentialType)) {
                                                                return Mono.empty(); // do not send message if it is not LABEL_CREDENTIAL_TYPE
                                                            }

                                                            return deferredCredentialMetadataService.getResponseUriByProcedureId(procedureId)
                                                                    .switchIfEmpty(Mono.error(new IllegalStateException(
                                                                            "Missing responseUri for procedureId: " + procedureId
                                                                    )))
                                                                    .flatMap(responseUri -> {
                                                                        try {
                                                                            String companyEmail = updatedCredentialProcedure.getEmail();

                                                                            return credentialProcedureService.getCredentialId(updatedCredentialProcedure)
                                                                                    .doOnNext(credentialId ->
                                                                                            log.debug("Using credentialId for delivery: {}", credentialId)
                                                                                    )
                                                                                    .flatMap(credentialId ->
                                                                                            m2mTokenService.getM2MToken()
                                                                                                    .flatMap(m2mToken ->
                                                                                                            credentialDeliveryService.sendVcToResponseUri(
                                                                                                                    responseUri,
                                                                                                                    signedVc,
                                                                                                                    credentialId,
                                                                                                                    companyEmail,
                                                                                                                    m2mToken.accessToken()
                                                                                                            )
                                                                                                    )
                                                                                    );
                                                                        } catch (Exception e) {
                                                                            log.error("Error preparing signed VC for delivery", e);
                                                                            return Mono.error(new RuntimeException(
                                                                                    "Failed to prepare signed VC for delivery", e
                                                                            ));
                                                                        }
                                                                    });
                                                        })
                                        );
                            });
                })
                .then();
    }

    private Mono<Void> updateDecodedCredentialByProcedureId(String procedureId, String bindCredential) {
        log.info("ProcessID: {} - Credential mapped and bound to the issuer: {}", procedureId, bindCredential);
        return credentialProcedureService.updateDecodedCredentialByProcedureId(
                procedureId,
                bindCredential,
                JWT_VC
        );
    }
}
