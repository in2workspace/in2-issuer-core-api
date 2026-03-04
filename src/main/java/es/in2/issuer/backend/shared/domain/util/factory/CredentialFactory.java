package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Component
@RequiredArgsConstructor
@Slf4j
public class CredentialFactory {

    public final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    public final LEARCredentialMachineFactory learCredentialMachineFactory;
    public final LabelCredentialFactory labelCredentialFactory;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;

    public Mono<CredentialProcedureCreationRequest> mapCredentialIntoACredentialProcedureRequest(String processId, String procedureId, PreSubmittedCredentialDataRequest preSubmittedCredentialRequest, CredentialStatus credentialStatus, String email) {
        log.info("mapCredentialIntoACredentialProcedureRequest - preSubmittedCredentialRequest:{} - credentialStatus:{}", preSubmittedCredentialRequest, credentialStatus );
        JsonNode credential = preSubmittedCredentialRequest.payload();
        String operationMode = preSubmittedCredentialRequest.operationMode();
        if (preSubmittedCredentialRequest.schema().equals(LEAR_CREDENTIAL_EMPLOYEE)) {
            return learCredentialEmployeeFactory.mapAndBuildLEARCredentialEmployee(procedureId, credential, credentialStatus, operationMode, email)
                    .doOnSuccess(learCredentialEmployee -> log.info("ProcessID: {} - LEARCredentialEmployee mapped: {}", processId, credential));
        } else if (preSubmittedCredentialRequest.schema().equals(LABEL_CREDENTIAL)) {
            return labelCredentialFactory.mapAndBuildLabelCredential(procedureId, credential, credentialStatus, operationMode, email)
                    .doOnSuccess(verifiableCertification -> log.info("ProcessID: {} - Label Credential mapped: {}", processId, credential));
        } else if(preSubmittedCredentialRequest.schema().equals(LEAR_CREDENTIAL_MACHINE)) {
            return learCredentialMachineFactory.mapAndBuildLEARCredentialMachine(procedureId, credential, credentialStatus, operationMode, email)
                    .doOnSuccess(learCredentialMachine -> log.info("ProcessID: {} - LEARCredentialMachine mapped: {}", processId, credential));
        }
        return Mono.error(new CredentialTypeUnsupportedException(preSubmittedCredentialRequest.schema()));
    }

    public Mono<String> bindCryptographicCredentialSubjectId(
            String processId,
            String credentialType,
            String decodedCredential,
            String subjectDid) {

        if (credentialType.equals(LEAR_CREDENTIAL_EMPLOYEE)) {
            return learCredentialEmployeeFactory
                    .bindCryptographicCredentialSubjectId(decodedCredential, subjectDid)
                    .doOnSuccess(bound ->
                            log.info("ProcessID: {} - LEARCredentialEmployee mapped and bind to the id: {}", processId, bound));
        } else if (credentialType.equals(LEAR_CREDENTIAL_MACHINE)) {
            return learCredentialMachineFactory
                    .bindCryptographicCredentialSubjectId(decodedCredential)
                    .doOnSuccess(bound ->
                            log.info("ProcessID: {} - LEARCredentialMachine mapped and bind to the id: {}", processId, bound));
        }

        return Mono.error(new CredentialTypeUnsupportedException(credentialType));
    }


    public Mono<Void> mapCredentialBindIssuerAndUpdateDB(
            String processId,
            String procedureId,
            String decodedCredential,
            String credentialType,
            String format,
            String authServerNonce,
            String email) {

        Mono<String> bindMono = switch (credentialType) {
            case LEAR_CREDENTIAL_EMPLOYEE ->
                    learCredentialEmployeeFactory
                            .mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId, email);
            case LABEL_CREDENTIAL ->
                    labelCredentialFactory
                            .mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId, email);
            case LEAR_CREDENTIAL_MACHINE ->
                learCredentialMachineFactory
                        .mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId, email);
            default ->
                    Mono.error(new CredentialTypeUnsupportedException(credentialType));
        };
        return bindMono
                .flatMap(boundCredential -> {
                    log.info("ProcessID: {} - Credential mapped and bind to the issuer: {}", processId, boundCredential);
                    return updateDecodedAndDeferred(procedureId, boundCredential, format, authServerNonce);
                });
    }

    private Mono<Void> updateDecodedAndDeferred(
            String procedureId,
            String boundCredential,
            String format,
            String authServerNonce) {
        return credentialProcedureService
                .updateDecodedCredentialByProcedureId(procedureId, boundCredential, format)
                .then(deferredCredentialMetadataService.updateDeferredCredentialByAuthServerNonce(authServerNonce, format)
                );
    }
}
