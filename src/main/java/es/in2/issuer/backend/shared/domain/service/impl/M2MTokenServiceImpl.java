package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.Payload;
import es.in2.issuer.backend.shared.domain.model.dto.VerifierOauth2AccessToken;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.M2MTokenService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CLIENT_ASSERTION_TYPE_VALUE;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.CLIENT_CREDENTIALS_GRANT_TYPE_VALUE;
import static es.in2.issuer.backend.shared.domain.util.Constants.CLIENT_ASSERTION_EXPIRATION_TIME;
import static es.in2.issuer.backend.shared.domain.util.Constants.CLIENT_ASSERTION_EXPIRATION_TIME_UNIT;

@Service
@Slf4j
@RequiredArgsConstructor
public class M2MTokenServiceImpl implements M2MTokenService {

    private final JWTService jwtService;
    private final AppConfig appConfig;
    private final VerifierService verifierService;

    @Override
    public Mono<VerifierOauth2AccessToken> getM2MToken() {
        log.info("[DEBUG-M2M] getM2MToken() - Starting M2M token acquisition");
        return Mono.fromCallable(this::getM2MFormUrlEncodeBodyValue)
                .doOnNext(body -> log.info("[DEBUG-M2M] getM2MToken() - Body built successfully, length: {}", body.length()))
                .doOnError(e -> log.error("[DEBUG-M2M] getM2MToken() - Error building body: {} - {}", e.getClass().getSimpleName(), e.getMessage(), e))
                .flatMap(verifierService::performTokenRequest)
                .doOnNext(token -> log.info("[DEBUG-M2M] getM2MToken() - SUCCESS! Got access token"))
                .doOnError(e -> log.error("[DEBUG-M2M] getM2MToken() - FAILED to get token: {} - {}", e.getClass().getSimpleName(), e.getMessage()));
    }

    private String getM2MFormUrlEncodeBodyValue() {
        log.info("[DEBUG-M2M] getM2MFormUrlEncodeBodyValue() - Building form body");
        
        String grantType = CLIENT_CREDENTIALS_GRANT_TYPE_VALUE;
        String clientId = appConfig.getCredentialSubjectDidKey();
        String assertionType = CLIENT_ASSERTION_TYPE_VALUE;
        
        log.info("[DEBUG-M2M] getM2MFormUrlEncodeBodyValue() - grant_type: {}", grantType);
        log.info("[DEBUG-M2M] getM2MFormUrlEncodeBodyValue() - client_id: {}", clientId);
        log.info("[DEBUG-M2M] getM2MFormUrlEncodeBodyValue() - client_assertion_type: {}", assertionType);
        
        String clientAssertion = createClientAssertion();
        log.info("[DEBUG-M2M] getM2MFormUrlEncodeBodyValue() - client_assertion length: {}", clientAssertion != null ? clientAssertion.length() : "NULL");
        log.info("[DEBUG-M2M] getM2MFormUrlEncodeBodyValue() - client_assertion preview (first 100 chars): {}", 
                clientAssertion != null && clientAssertion.length() > 100 ? clientAssertion.substring(0, 100) + "..." : clientAssertion);
        
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.GRANT_TYPE, grantType);
        parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        parameters.put(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, assertionType);
        parameters.put(OAuth2ParameterNames.CLIENT_ASSERTION, clientAssertion);

        String result = parameters.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
        
        log.info("[DEBUG-M2M] getM2MFormUrlEncodeBodyValue() - Final body built, total length: {}", result.length());
        return result;
    }


    private String createClientAssertion() {
        log.info("[DEBUG-M2M] createClientAssertion() - Creating client assertion JWT");
        
        String vcMachineString = getVCinJWTDecodedFromBase64();
        log.info("[DEBUG-M2M] createClientAssertion() - VC Machine string length: {}", vcMachineString != null ? vcMachineString.length() : "NULL");
        
        String clientId = appConfig.getCredentialSubjectDidKey();
        log.info("[DEBUG-M2M] createClientAssertion() - Client ID (DID): {}", clientId);

        Instant issueTime = Instant.now();
        long iat = issueTime.toEpochMilli();
        long exp = issueTime.plus(
                CLIENT_ASSERTION_EXPIRATION_TIME,
                ChronoUnit.valueOf(CLIENT_ASSERTION_EXPIRATION_TIME_UNIT)
        ).toEpochMilli();
        
        log.info("[DEBUG-M2M] createClientAssertion() - iat: {}, exp: {}, aud: {}", iat, exp, appConfig.getVerifierUrl());

        String vpTokenJWTString = createVPTokenJWT(vcMachineString, clientId, iat, exp);

        String vpTokenJWTBase64 = Base64.getEncoder()
                .encodeToString(vpTokenJWTString.getBytes(StandardCharsets.UTF_8));

        Payload payload = new Payload(Map.of(
                "sub", clientId,
                "iss", clientId,
                "aud", appConfig.getVerifierUrl(),
                "iat", iat,
                "exp", exp,
                "jti", UUID.randomUUID(),
                "vp_token", vpTokenJWTBase64
        ));

        String jwt = jwtService.generateJWT(payload.toString());
        log.info("[DEBUG-M2M] createClientAssertion() - Client assertion JWT created, length: {}", jwt != null ? jwt.length() : "NULL");
        return jwt;
    }

    private String createVPTokenJWT(String vcMachineString, String clientId, long iat, long exp) {
        Map<String, Object> vp = createVP(vcMachineString, clientId);

        Payload payload = new Payload(Map.of(
                "sub", clientId,
                "iss", clientId,
                "nbf", iat,
                "iat", iat,
                "exp", exp,
                "jti", UUID.randomUUID(),
                "vp", vp
        ));

        return jwtService.generateJWT(payload.toString());
    }

    private Map<String, Object> createVP(String vcMachineString, String clientId) {
        return Map.of(
                "@context", List.of("https://www.w3.org/2018/credentials/v1"),
                "holder", clientId,
                "id", "urn:uuid:" + UUID.randomUUID(),
                "type", List.of("VerifiablePresentation"),
                "verifiableCredential", List.of(vcMachineString)
        );
    }

    private String getVCinJWTDecodedFromBase64() {
        String vcTokenBase64 = appConfig.getJwtCredential();
        byte[] vcTokenDecoded = Base64.getDecoder().decode(vcTokenBase64);
        return new String(vcTokenDecoded);
    }
}

