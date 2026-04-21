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
        return Mono.fromCallable(this::getM2MFormUrlEncodeBodyValue)
                .flatMap(verifierService::performTokenRequest);
    }

    private String getM2MFormUrlEncodeBodyValue() {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.GRANT_TYPE, CLIENT_CREDENTIALS_GRANT_TYPE_VALUE);
        parameters.put(OAuth2ParameterNames.CLIENT_ID, appConfig.getCredentialSubjectDidKey());
        parameters.put(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_VALUE);
        parameters.put(OAuth2ParameterNames.CLIENT_ASSERTION, createClientAssertion());

        return parameters.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
    }


    private String createClientAssertion() {
        String vcMachineString = getVCinJWTDecodedFromBase64();
        String clientId = appConfig.getCredentialSubjectDidKey();

        Instant issueTime = Instant.now();
        long iat = issueTime.toEpochMilli();
        long exp = issueTime.plus(
                CLIENT_ASSERTION_EXPIRATION_TIME,
                ChronoUnit.valueOf(CLIENT_ASSERTION_EXPIRATION_TIME_UNIT)
        ).toEpochMilli();

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

        return jwtService.generateJWT(payload.toString());
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
