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
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL_CONTEXT;
import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL_TYPES;

@Component
@RequiredArgsConstructor
@Slf4j
public class LabelCredentialFactory {
    private final ObjectMapper objectMapper;
    private final CredentialProcedureService credentialProcedureService;
    private final IssuerFactory issuerFactory;
    private final AccessTokenService accessTokenService;
    private final Validator validator;

    public Mono<CredentialProcedureCreationRequest> mapAndBuildLabelCredential(String procedureId, JsonNode credential, CredentialStatus credentialStatus, String operationMode, String email) {
        final LabelCredential labelCredential;
        try {
            labelCredential = objectMapper.convertValue(credential, LabelCredential.class);

            var violations = validator.validate(labelCredential);
            if (!violations.isEmpty()) {
                throw new InvalidCredentialFormatException("Invalid LabelCredential payload");
            }
        } catch (IllegalArgumentException e) {
            log.error("Error mapping LabelCredential payload", e);
            return Mono.error(new InvalidCredentialFormatException("Invalid LabelCredential payload"));
        } catch (InvalidCredentialFormatException e) {
            log.warn("Invalid LabelCredential payload: {}", e.getMessage());
            return Mono.error(e);
        }


        return buildLabelCredential(labelCredential, credentialStatus)
                .flatMap(labelCredentialDecoded ->
                        convertLabelCredentialInToString(labelCredentialDecoded)
                                .flatMap(decodedCredential ->
                                        buildCredentialProcedureCreationRequest(procedureId, decodedCredential, labelCredentialDecoded, operationMode, email)
                                )
                );
    }

    private Mono<LabelCredential> buildLabelCredential(LabelCredential credential, CredentialStatus credentialStatus) {
        // Build the LabelCredential object
        return Mono.just(LabelCredential.builder()
                .context(LABEL_CREDENTIAL_CONTEXT)
                .id("urn:uuid:" + UUID.randomUUID())
                .type(LABEL_CREDENTIAL_TYPES)
                .credentialSubject(credential.credentialSubject())
                .validFrom(credential.validFrom())
                .validUntil(credential.validUntil())
                .credentialStatus(credentialStatus)
                .build());
    }

    public Mono<String> mapIssuer(String procedureId, SimpleIssuer issuer) {
        return credentialProcedureService.getDecodedCredentialByProcedureId(procedureId)
                .flatMap(credential -> {
                    try {
                        LabelCredential labelCredential = mapStringToLabelCredential(credential);
                        return bindIssuer(labelCredential, issuer)
                                .flatMap(this::convertLabelCredentialInToString);
                    } catch (InvalidCredentialFormatException e) {
                        return Mono.error(e);
                    }
                });
    }

    public Mono<String> mapCredentialAndBindIssuerInToTheCredential(
            String decodedCredentialString,
            String procedureId,
            String email) {
        LabelCredential labelCredential = mapStringToLabelCredential(decodedCredentialString);

        return issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, email)
                .flatMap(issuer -> bindIssuer(labelCredential, issuer))
                .flatMap(this::convertLabelCredentialInToString);
    }


    public Mono<LabelCredential> bindIssuer(LabelCredential labelCredential, SimpleIssuer issuer) {
        SimpleIssuer issuerCred = SimpleIssuer.builder()
                .id(issuer.id())
                .build();

        return Mono.just(LabelCredential.builder()
                .context(labelCredential.context())
                .id(labelCredential.id())
                .type(labelCredential.type())
                .issuer(issuerCred)
                .credentialSubject(labelCredential.credentialSubject())
                .validFrom(labelCredential.validFrom())
                .validUntil(labelCredential.validUntil())
                .credentialStatus(labelCredential.credentialStatus())
                .build());
    }

    public Mono<LabelCredentialJwtPayload> buildLabelCredentialJwtPayload(LabelCredential credential) {
        return Mono.just(
                LabelCredentialJwtPayload.builder()
                        .JwtId("urn:uuid:" + UUID.randomUUID())
                        .credential(credential)
                        .expirationTime(parseDateToUnixTime(credential.validUntil()))
                        .issuedAt(parseDateToUnixTime(credential.validFrom()))
                        .notValidBefore(parseDateToUnixTime(credential.validFrom()))
                        .issuer(credential.issuer().getId())
                        .subject(credential.credentialSubject().id())
                        .build()
        );
    }

    private long parseDateToUnixTime(String date) {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME);
        return zonedDateTime.toInstant().getEpochSecond();
    }

    public LabelCredential mapStringToLabelCredential(String labelCredential)
            throws InvalidCredentialFormatException {
        try {
            log.info(objectMapper.readValue(labelCredential, LabelCredential.class).toString());
            return objectMapper.readValue(labelCredential, LabelCredential.class);
        } catch (JsonProcessingException e) {
            log.error("Error parsing LabelCredential", e);
            throw new InvalidCredentialFormatException("Error parsing LabelCredential");
        }
    }

    private Mono<String> convertLabelCredentialInToString(LabelCredential labelCredential) {
        try {

            return Mono.just(objectMapper.writeValueAsString(labelCredential));
        } catch (JsonProcessingException e) {
            return Mono.error(new CredentialSerializationException("Error serializing LabelCredential to string."));
        }
    }

    public Mono<String> convertLabelCredentialJwtPayloadInToString(LabelCredentialJwtPayload labelCredentialJwtPayload) {
        try {
            return Mono.just(objectMapper.writeValueAsString(labelCredentialJwtPayload));
        } catch (JsonProcessingException e) {
            return Mono.error(new CredentialSerializationException("Error serializing LabelCredential JWT payload to string."));
        }
    }


    private Mono<CredentialProcedureCreationRequest> buildCredentialProcedureCreationRequest(String procedureId, String decodedCredential, LabelCredential labelCredentialDecoded, String operationMode, String email) {

        return accessTokenService.getOrganizationIdFromCurrentSession()
                .flatMap(organizationId ->
                        Mono.just(CredentialProcedureCreationRequest.builder()
                                .procedureId(procedureId)
                                .organizationIdentifier(organizationId)
                                .credentialDecoded(decodedCredential)
                                .credentialType(CredentialType.LABEL_CREDENTIAL)
                                .subject(labelCredentialDecoded.credentialSubject().id())
                                .validUntil(parseEpochSecondIntoTimestamp(parseDateToUnixTime(labelCredentialDecoded.validUntil())))
                                .operationMode(operationMode)
                                .email(email)
                                .build()
                        )
                );
    }

    private Timestamp parseEpochSecondIntoTimestamp(Long unixEpochSeconds) {
        return Timestamp.from(Instant.ofEpochSecond(unixEpochSeconds));
    }
}
