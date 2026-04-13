package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedures;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface CredentialProcedureService {
    Mono<String> createCredentialProcedure(CredentialProcedureCreationRequest credentialProcedureCreationRequest);

    Mono<String> getCredentialTypeByProcedureId(String procedureId);

    Mono<String> getNotificationIdByProcedureId(String procedureId);

    Mono<String> getCredentialStatusByProcedureId(String procedureId);

    Mono<Void> updateDecodedCredentialByProcedureId(String procedureId, String credential);

    Mono<Void> updateDecodedCredentialByProcedureId(String procedureId, String credential, String format);

    Mono<String> getDecodedCredentialByProcedureId(String procedureId);

    Mono<String> getOperationModeByProcedureId(String procedureId);

    Flux<String> getAllIssuedCredentialByOrganizationIdentifier(String organizationIdentifier);

    Mono<CredentialProcedures> getAllProceduresVisibleFor(String organizationIdentifier);

    Mono<CredentialProcedures> getAllProceduresBasicInfoByOrganizationId(String organizationIdentifier);

    Mono<CredentialDetails> getProcedureDetailByProcedureIdAndOrganizationId(String organizationIdentifier, String procedureId);

    Mono<Void> updateCredentialProcedureCredentialStatusToValidByProcedureId(String procedureId);

    Mono<Void> updateCredentialProcedureCredentialStatusToRevoke(CredentialProcedure credentialProcedure);

    Mono<String> updatedEncodedCredentialByCredentialProcedureId(String encodedCredential, String credentialProcedureId);

    Mono<CredentialProcedure> getCredentialProcedureById(String procedureId);
    Mono<CredentialProcedure> getCredentialProcedureByNotificationId(String notificationId);
    Mono<JsonNode> getCredentialNode(CredentialProcedure credentialProcedure);
    Mono<String> getCredentialId(CredentialProcedure credentialProcedure);

    Mono<Void> updateFormatByProcedureId(String procedureId, String format);
    Mono<CredentialOfferEmailNotificationInfo> getCredentialOfferEmailInfoByProcedureId(String procedureId);
    Mono<Void> updateCredentialStatusToPendSignature(String procedureId);
}
