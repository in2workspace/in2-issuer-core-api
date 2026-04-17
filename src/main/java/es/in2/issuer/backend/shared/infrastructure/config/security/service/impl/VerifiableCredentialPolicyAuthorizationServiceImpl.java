package es.in2.issuer.backend.shared.infrastructure.config.security.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.LEARCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.VerifiableCredentialPolicyAuthorizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.StreamSupport;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.LEAR_CREDENTIAL_MACHINE;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Utils.*;

//fixme: change to accept token that contains a LEAR Credential MAchine in Employee and Machine policies
@Service
@Slf4j
@RequiredArgsConstructor
public class VerifiableCredentialPolicyAuthorizationServiceImpl implements VerifiableCredentialPolicyAuthorizationService {

    private final AppConfig appConfig;
    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final CredentialFactory credentialFactory;
    private final VerifierService verifierService;

    @Override
    public Mono<Void> authorize(String token, String schema, JsonNode payload, String idToken) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String payloadStr = signedJWT.getPayload().toString();
                    if (!payloadStr.contains(ROLE)) {
                        return checkPolicies(token, schema, payload, idToken);
                    }else{
                        String roleClaim = jwtService.getClaimFromPayload(signedJWT.getPayload(), ROLE);
                        return authorizeByRole(roleClaim, token, schema, payload, idToken);
                    }
                });
    }

    private Mono<Void> authorizeByRole(String role, String token, String schema, JsonNode payload, String idToken) {
        role =(role != null) ? role.replace("\"", ""): role;
        if (role==null || role.isBlank()) {
            return Mono.error(new UnauthorizedRoleException("Access denied: Role is empty"));
        }
        if (LABEL_CREDENTIAL.equals(schema)) {
            return Mono.error(new UnauthorizedRoleException("Access denied: Unauthorized Role '" + role + "'"));
        }
        return switch (role) {
            case SYS_ADMIN, LER -> Mono.error(new UnauthorizedRoleException("The request is invalid. " +
                    "The roles 'SYSADMIN' and 'LER' currently have no defined permissions."));
            case LEAR -> checkPolicies(token, schema, payload, idToken);
            default -> Mono.error(new UnauthorizedRoleException("Access denied: Unauthorized Role '" + role + "'"));
        };
    }

    private Mono<Void> checkPolicies(String token, String schema, JsonNode payload, String idToken) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String vcClaim = jwtService.getClaimFromPayload(signedJWT.getPayload(), VC);
                    return mapVcToLEARCredential(vcClaim, schema)
                            .flatMap(learCredential ->
                                    switch (schema) {
                                        case LEAR_CREDENTIAL_EMPLOYEE -> authorizeLearCredentialEmployee(learCredential, payload);
                                        case LEAR_CREDENTIAL_MACHINE -> authorizeLearCredentialMachine(learCredential, payload);
                                        case LABEL_CREDENTIAL -> authorizeLabelCredential(learCredential, idToken);
                                        default ->
                                                Mono.error(new InsufficientPermissionException("Unauthorized: Unsupported schema"));
                                    }
                            );
                });
    }

    /**
     * Determines the allowed credential type based on the provided list and schema.
     * Returns a Mono emitting the allowed type.
     */
    private Mono<String> determineAllowedCredentialType(List<String> types, String schema) {
        return Mono.fromCallable(() -> {
            if (LABEL_CREDENTIAL.equals(schema)) {
                // For verifiable certification, only LEARCredentialMachine into the access token is allowed.
                if (types.contains(LEAR_CREDENTIAL_MACHINE)) {
                    return LEAR_CREDENTIAL_MACHINE;
                } else {
                    throw new InsufficientPermissionException(
                            "Unauthorized: Credential type 'LEARCredentialMachine' is required for verifiable certification.");
                }
            } else if (LEAR_CREDENTIAL_MACHINE.equals(schema)) {
                if (types.contains(LEAR_CREDENTIAL_EMPLOYEE)) {
                    return LEAR_CREDENTIAL_EMPLOYEE;
                } else {
                    throw new InsufficientPermissionException(
                            "Unauthorized: Credential type 'LEARCredentialEmployee' is required for LEARCredentialMachine.");
                }
            } else {
                // For LEAR_CREDENTIAL_EMPLOYEE schema, allow either employee or machine.
                if (types.contains(LEAR_CREDENTIAL_EMPLOYEE)) {
                    return LEAR_CREDENTIAL_EMPLOYEE;
                } else if (types.contains(LEAR_CREDENTIAL_MACHINE)) {
                    return LEAR_CREDENTIAL_MACHINE;
                } else {
                    throw new InsufficientPermissionException(
                            "Unauthorized: Credential type 'LEARCredentialEmployee' or 'LEARCredentialMachine' is required.");
                }
            }
        });
    }

    private Mono<LEARCredential> mapVcToLEARCredential(String vcClaim, String schema) {
        return checkIfCredentialTypeIsAllowedToIssue(vcClaim, schema)
                .flatMap(credentialType -> {
                    if (LEAR_CREDENTIAL_EMPLOYEE.equals(credentialType)) {
                        return Mono.fromCallable(() -> credentialFactory.learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcClaim));
                    } else if (LEAR_CREDENTIAL_MACHINE.equals(credentialType)) {
                        return Mono.fromCallable(() -> credentialFactory.learCredentialMachineFactory.mapStringToLEARCredentialMachine(vcClaim));
                    } else {
                        return Mono.error(new InsufficientPermissionException("Unsupported credential type: " + credentialType));
                    }
                });
    }

    /**
     * Checks if the credential type contained in the vcClaim is allowed for the given schema.
     * Returns a Mono emitting the allowed type if valid, or an error otherwise.
     */
    private Mono<String> checkIfCredentialTypeIsAllowedToIssue(String vcClaim, String schema) {
        return Mono.fromCallable(() -> objectMapper.readTree(vcClaim))
                .flatMap(vcJsonNode ->
                        extractCredentialTypes(vcJsonNode)
                                .flatMap(types -> determineAllowedCredentialType(types, schema))
                )
                .onErrorMap(JsonProcessingException.class, e -> new ParseErrorException("Error extracting credential type"));
    }

    /**
     * Extracts and validates the credential types from the provided JSON node.
     * Returns a Mono emitting the list of credential type strings.
     */
    private Mono<List<String>> extractCredentialTypes(JsonNode vcJsonNode) {
        return Mono.fromCallable(() -> {
            JsonNode typeNode = vcJsonNode.get("type");
            if (typeNode == null) {
                throw new InsufficientPermissionException("The credential type is missing, the credential is invalid.");
            }
            if (typeNode.isTextual()) {
                return List.of(typeNode.asText());
            } else if (typeNode.isArray()) {
                return StreamSupport.stream(typeNode.spliterator(), false)
                        .map(JsonNode::asText)
                        .toList();
            } else {
                throw new InsufficientPermissionException("Invalid format for credential type.");
            }
        });
    }

    // It checks if the signer if Mandator is IN2 or if the credential has same organizationIdentifier as the Mandator of the credential.
    private Mono<Void> authorizeLearCredentialEmployee(LEARCredential learCredential, JsonNode payload) {
        if (isSignerIssuancePolicyValid(learCredential, payload) || isMandatorIssuancePolicyValid(learCredential, payload)) {
            return Mono.empty();
        }
        return Mono.error(new InsufficientPermissionException("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."));
    }

    private Mono<Void> authorizeLabelCredential(LEARCredential learCredential, String idToken) {
        return isLabelCredentialPolicyValid(learCredential, idToken)
                .flatMap(valid -> Boolean.TRUE.equals(valid)
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException("Unauthorized: Label Credential does not meet the issuance policy.")));
    }

    private Mono<Void> authorizeLearCredentialMachine(LEARCredential learCredential, JsonNode payload) {
        if (isSignerIssuancePolicyValidLEARCredentialMachine(learCredential, payload) || isMandatorIssuancePolicyValidLEARCredentialMachine(learCredential, payload)) {
            return Mono.empty();
        }
        return Mono.error(new InsufficientPermissionException("Unauthorized: LEARCredentialMachine does not meet any issuance policies."));
    }

    // Reads mandator's organizationIdentifier for both Employee and Machine credentials
    private String resolveMandatorOrgIdentifier(LEARCredential cred) {
        // Prefer checking by declared "type" to keep it aligned with your existing logic
        if (cred.type() != null && cred.type().contains(LEAR_CREDENTIAL_MACHINE)) {
            // Machine mandator type: LEARCredentialMachine.CredentialSubject.Mandate.Mandator
            var m = extractMandatorLearCredentialMachine(cred);
            return (m != null) ? m.organizationIdentifier() : null;
        } else {
            // Employee mandator type: es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator
            var m = extractMandatorLearCredentialEmployee(cred);
            return (m != null) ? m.organizationIdentifier() : null;
        }
    }

    // Checks if signer is from the admin org. and has Onboarding/Execute power, and validates payload has at least one power
    private boolean isSignerIssuancePolicyValid(LEARCredential learCredential, JsonNode payload) {
        final String orgId = resolveMandatorOrgIdentifier(learCredential);
        if (!appConfig.getAdminOrganizationId().equals(orgId)
                || !hasLearCredentialOnboardingExecutePower(extractPowers(learCredential))) {
            return false;
        }
        // Admin - validate payload has at least one power (admin can add any power)
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class);
        return mandate != null && mandate.power() != null && !mandate.power().isEmpty();
    }

    // For machine we use similar logic but with Machine mandate type
    private boolean isSignerIssuancePolicyValidLEARCredentialMachine(LEARCredential learCredential, JsonNode payload) {
        final String orgId = resolveMandatorOrgIdentifier(learCredential);
        if (!appConfig.getAdminOrganizationId().equals(orgId)
                || !hasLearCredentialOnboardingExecutePower(extractPowers(learCredential))) {
            return false;
        }
        // Admin - validate payload has at least one power (admin can add any power)
        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class);
        return mandate != null && mandate.power() != null && !mandate.power().isEmpty();
    }

    private boolean isMandatorIssuancePolicyValid(LEARCredential learCredential, JsonNode payload) {
        if (!hasLearCredentialOnboardingExecutePower(extractPowers(learCredential))) {
            return false;
        }

        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class);

        if (mandate == null || mandate.mandator() == null) {
            return false;
        }

        String tokenMandatorOrgId = extractMandatorOrganizationIdentifier(learCredential);
        log.debug("tokenMandatorOrgId: {}", tokenMandatorOrgId);
        String payloadMandatorOrgId = mandate.mandator().organizationIdentifier();
        log.debug("payloadMandatorOrgId: {}", payloadMandatorOrgId);

        return tokenMandatorOrgId != null
                && tokenMandatorOrgId.equals(payloadMandatorOrgId)
                && payloadPowersOnlyIncludeProductOffering(mandate.power());
    }

    private boolean isMandatorIssuancePolicyValidLEARCredentialMachine(LEARCredential learCredential, JsonNode payload) {
        if (!hasLearCredentialOnboardingExecutePower(extractPowers(learCredential))) {
            return false;
        }

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class);

        if (mandate == null || mandate.mandator() == null) {
            return false;
        }

        Mandator tokenMandator = extractMandatorLearCredentialEmployee(learCredential);
        if (tokenMandator == null) {
            return false;
        }

        LEARCredentialMachine.CredentialSubject.Mandate.Mandator payloadMandator = mandate.mandator();

        return equalsSafe(payloadMandator.organizationIdentifier(), tokenMandator.organizationIdentifier())
                && equalsSafe(payloadMandator.organization(), tokenMandator.organization())
                && equalsSafe(payloadMandator.country(), tokenMandator.country())
                && equalsSafe(payloadMandator.commonName(), tokenMandator.commonName())
                && equalsSafe(payloadMandator.serialNumber(), tokenMandator.serialNumber())
                && payloadPowersOnlyIncludeProductOffering(mandate.power());
    }

    private boolean equalsSafe(String a, String b) {
        return a != null && a.equals(b);
    }

    private Mono<Boolean> isLabelCredentialPolicyValid(LEARCredential learCredential, String idToken) {
        boolean credentialValid = containsCertificationAndAttest(extractPowers(learCredential));
        return validateIdToken(idToken)
                .map(learCredentialFromIdToken -> containsCertificationAndAttest(extractPowers(learCredentialFromIdToken)))
                .map(idTokenValid -> credentialValid && idTokenValid);
    }

    /**
     * Validates the idToken by verifying its signature (without checking expiration),
     * parsing its 'vc_json' claim into a LEARCredentialEmployee.
     *
     * @param idToken the id token to validate.
     * @return a Mono emitting the LEARCredential interface if valid.
     */
    private Mono<LEARCredential> validateIdToken(String idToken) {
        // Use the verifierService's method that verifies the token without expiration check.
        return verifierService.verifyTokenWithoutExpiration(idToken)
                .then(Mono.fromCallable(() -> jwtService.parseJWT(idToken)))
                .flatMap(idSignedJWT -> {
                    // The claim is called vc_json because we use the id_token from the VCVerifier that return the vc in json string format
                    String idVcClaim = jwtService.getClaimFromPayload(idSignedJWT.getPayload(), "vc_json");
                    try {
                        String processedVc = objectMapper.readValue(idVcClaim, String.class);
                        LEARCredentialEmployee credentialEmployee = credentialFactory.learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(processedVc);
                        return Mono.just(credentialEmployee);
                    } catch (JsonProcessingException e) {
                        return Mono.error(new ParseErrorException("Error parsing id_token credential: " + e));
                    }
                });

    }

    private boolean containsCertificationAndAttest(List<Power> powers) {
        return powers.stream().anyMatch(this::isCertificationFunction) &&
                powers.stream().anyMatch(this::hasAttestAction);
    }

    private boolean isCertificationFunction(Power power) {
        return "Certification".equals(power.function());
    }

    private boolean hasAttestAction(Power power) {
        return power.action() instanceof List<?> actions ?
                actions.stream().anyMatch(action -> "Attest".equals(action.toString())) :
                "Attest".equals(power.action().toString());
    }

    private boolean hasLearCredentialOnboardingExecutePower(List<Power> powers) {

        return powers.stream().anyMatch(this::isOnboardingFunction) &&
                powers.stream().anyMatch(this::hasExecuteAction);
    }

    private boolean isOnboardingFunction(Power power) {
        return "Onboarding".equals(power.function());
    }

    private boolean hasExecuteAction(Power power) {
        return power.action() instanceof List<?> actions ?
                actions.stream().anyMatch(action -> "Execute".equals(action.toString())) :
                "Execute".equals(power.action().toString());
    }

    private boolean payloadPowersOnlyIncludeProductOffering(List<Power> powers) {
        return powers != null && !powers.isEmpty() && powers.stream().allMatch(power -> "ProductOffering".equals(power.function()));
    }
}