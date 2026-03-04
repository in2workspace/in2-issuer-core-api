package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.CredentialSerializationException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.LEARCredentialMachineJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class LEARCredentialMachineFactory {

    private final ObjectMapper objectMapper;
    private final IssuerFactory issuerFactory;

    public Mono<String> bindCryptographicCredentialSubjectId(String decodedCredentialString) {
        LEARCredentialMachine decodedCredential = mapStringToLEARCredentialMachine(decodedCredentialString);

        LEARCredentialMachine.CredentialSubject credentialSubject = decodedCredential.credentialSubject();
        if (credentialSubject == null) {
            throw new InvalidCredentialFormatException("Missing credentialSubject in LEARCredentialMachine");
        }

        LEARCredentialMachine.CredentialSubject.Mandate mandate = credentialSubject.mandate();
        if (mandate == null) {
            throw new InvalidCredentialFormatException("Missing mandate in LEARCredentialMachine.credentialSubject");
        }

        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee = mandate.mandatee();
        if (mandatee == null) {
            throw new InvalidCredentialFormatException("Missing mandatee in LEARCredentialMachine.credentialSubject.mandate");
        }

        String mandateeId = mandatee.id();
        if (mandateeId == null || mandateeId.isBlank()) {
            throw new InvalidCredentialFormatException("Missing or blank mandatee.id in LEARCredentialMachine.credentialSubject.mandate.mandatee");
        }
        return bindSubjectIdToLearCredentialMachine(decodedCredential, mandateeId)
                .flatMap(this::convertLEARCredentialMachineInToString);
    }

    public LEARCredentialMachine mapStringToLEARCredentialMachine(String learCredential)
            throws InvalidCredentialFormatException {
        try {
            log.debug(objectMapper.readValue(learCredential, LEARCredentialMachine.class).toString());
            return objectMapper.readValue(learCredential, LEARCredentialMachine.class);
        } catch (JsonProcessingException e) {
            log.error("Error parsing LEARCredentialMachine", e);
            throw new InvalidCredentialFormatException("Error parsing LEARCredentialMachine");
        }
    }

    public Mono<CredentialProcedureCreationRequest> mapAndBuildLEARCredentialMachine(String procedureId, JsonNode learCredential, CredentialStatus credentialStatus, String operationMode, String email) {
        LEARCredentialMachine.CredentialSubject baseCredentialSubject = mapJsonNodeToCredentialSubject(learCredential);
        return buildFinalLearCredentialMachine(baseCredentialSubject, credentialStatus)
                .flatMap(credentialDecoded ->
                        convertLEARCredentialMachineInToString(credentialDecoded)
                                .flatMap(credentialDecodedString ->
                                        buildCredentialProcedureCreationRequest(procedureId, credentialDecodedString, credentialDecoded, operationMode, email)
                                )
                );
    }

    private LEARCredentialMachine.CredentialSubject mapJsonNodeToCredentialSubject(JsonNode jsonNode) {
        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                objectMapper.convertValue(jsonNode, LEARCredentialMachine.CredentialSubject.Mandate.class);
        return LEARCredentialMachine.CredentialSubject.builder()
                .mandate(mandate)
                .build();
    }

    private Mono<LEARCredentialMachine> buildFinalLearCredentialMachine(LEARCredentialMachine.CredentialSubject baseCredentialSubject, CredentialStatus credentialStatus) {

        Instant currentTime = Instant.now();
        String validFrom = currentTime.toString();
        String validUntil = currentTime.plus(365, ChronoUnit.DAYS).toString();

        String credentialId = "urn:uuid:" + UUID.randomUUID();
        return Mono.just(LEARCredentialMachine.builder()
                .context(CREDENTIAL_CONTEXT_LEAR_CREDENTIAL_MACHINE)
                .id(credentialId)
                .type(List.of(LEAR_CREDENTIAL_MACHINE, VERIFIABLE_CREDENTIAL))
                .credentialSubject(baseCredentialSubject)
                .validFrom(validFrom)
                .validUntil(validUntil)
                .credentialStatus(credentialStatus)
                .build());

    }

    private Mono<String> convertLEARCredentialMachineInToString(LEARCredentialMachine credentialDecoded) {
        try {
            return Mono.just(objectMapper.writeValueAsString(credentialDecoded));
        } catch (JsonProcessingException e) {
            return Mono.error(new CredentialSerializationException("Error serializing LEARCredentialMachine to string."));
        }
    }

    private Mono<CredentialProcedureCreationRequest> buildCredentialProcedureCreationRequest(String procedureId, String decodedCredential, LEARCredentialMachine credentialDecoded, String operationMode, String email) {
        String mandatorOrgId = credentialDecoded.credentialSubject().mandate().mandator().organizationIdentifier();
        return Mono.just(
            CredentialProcedureCreationRequest.builder()
                .procedureId(procedureId)
                .organizationIdentifier(mandatorOrgId)
                .credentialDecoded(decodedCredential)
                .credentialType(CredentialType.LEAR_CREDENTIAL_MACHINE)
                .subject(credentialDecoded.credentialSubject().mandate().mandatee().domain())
                .validUntil(parseEpochSecondIntoTimestamp(parseDateToUnixTime(credentialDecoded.validUntil())))
                .operationMode(operationMode)
                .email(email)
                .build()
        );
    }

    private long parseDateToUnixTime(String date) {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME);
        return zonedDateTime.toInstant().getEpochSecond();
    }

    private Timestamp parseEpochSecondIntoTimestamp(Long unixEpochSeconds) {
        return Timestamp.from(Instant.ofEpochSecond(unixEpochSeconds));
    }

    public Mono<String> mapCredentialAndBindIssuerInToTheCredential(
            String decodedCredentialString,
            String procedureId,
            String email) {
        LEARCredentialMachine learCredentialMachine = mapStringToLEARCredentialMachine(decodedCredentialString);

        return issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, email)
                .flatMap(issuer -> bindIssuer(learCredentialMachine, issuer))
                .flatMap(this::convertLEARCredentialMachineInToString);
    }

    public Mono<LEARCredentialMachine> bindIssuer(LEARCredentialMachine learCredentialMachine, DetailedIssuer issuer) {

        return Mono.just(LEARCredentialMachine.builder()
                .context(learCredentialMachine.context())
                .id(learCredentialMachine.id())
                .type(learCredentialMachine.type())
                .name(learCredentialMachine.name())
                .description(learCredentialMachine.description())
                .issuer(issuer)
                .validFrom(learCredentialMachine.validFrom())
                .validUntil(learCredentialMachine.validUntil())
                .credentialSubject(learCredentialMachine.credentialSubject())
                .credentialStatus(learCredentialMachine.credentialStatus())
                .build());
    }

    public Mono<LEARCredentialMachineJwtPayload> buildLEARCredentialMachineJwtPayload(LEARCredentialMachine learCredentialMachine) {
        String subject = learCredentialMachine.credentialSubject().mandate().mandatee().id();

        return Mono.just(
                LEARCredentialMachineJwtPayload.builder()
                        .JwtId(UUID.randomUUID().toString())
                        .learCredentialMachine(learCredentialMachine)
                        .expirationTime(parseDateToUnixTime(learCredentialMachine.validUntil()))
                        .issuedAt(parseDateToUnixTime(learCredentialMachine.validFrom()))
                        .notValidBefore(parseDateToUnixTime(learCredentialMachine.validFrom()))
                        .issuer(learCredentialMachine.issuer().getId())
                        .subject(subject)
                        .build()
        );
    }

    public Mono<String> convertLEARCredentialMachineJwtPayloadInToString(LEARCredentialMachineJwtPayload credential) {
        try {
            return Mono.just(objectMapper.writeValueAsString(credential));
        } catch (JsonProcessingException e) {
            return Mono.error(new CredentialSerializationException("Error serializing LEARCredentialMachine JWT payload to string."));
        }
    }

    private Mono<LEARCredentialMachine> bindSubjectIdToLearCredentialMachine(
            LEARCredentialMachine decodedCredential,
            String subjectId
    ) {
        LEARCredentialMachine.CredentialSubject currentSubject = decodedCredential.credentialSubject();

        LEARCredentialMachine.CredentialSubject updatedSubject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .id(subjectId)
                        .mandate(currentSubject.mandate())
                        .build();

        return Mono.just(
                LEARCredentialMachine.builder()
                        .context(decodedCredential.context())
                        .id(decodedCredential.id())
                        .type(decodedCredential.type())
                        .name(decodedCredential.name())
                        .description(decodedCredential.description())
                        .issuer(decodedCredential.issuer())
                        .validFrom(decodedCredential.validFrom())
                        .validUntil(decodedCredential.validUntil())
                        .credentialStatus(decodedCredential.credentialStatus())
                        .credentialSubject(updatedSubject)
                        .build()
        );
    }
}
