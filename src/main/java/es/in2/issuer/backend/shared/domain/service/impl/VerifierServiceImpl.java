package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.JWTVerificationException;
import es.in2.issuer.backend.shared.domain.exception.TokenFetchException;
import es.in2.issuer.backend.shared.domain.exception.WellKnownInfoFetchException;
import es.in2.issuer.backend.shared.domain.model.dto.OpenIDProviderMetadata;
import es.in2.issuer.backend.shared.domain.model.dto.VerifierOauth2AccessToken;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Date;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CONTENT_TYPE;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.CONTENT_TYPE_URL_ENCODED_FORM;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH;

@Service
@Slf4j
@RequiredArgsConstructor
public class VerifierServiceImpl implements VerifierService {

    private final AppConfig appConfig;
    private final WebClient oauth2VerifierWebClient;

    // Cache to store JWKs and avoid multiple endpoint calls
    private JWKSet cachedJWKSet;
    private final Object jwkLock = new Object();

    @Override
    public Mono<Void> verifyToken(String accessToken) {
        return parseAndValidateJwt(accessToken, true)
                .doOnSuccess(unused -> log.info("The verification of the token is valid"))
                .onErrorResume(e -> {
                    log.error("Error while verifying token", e);
                    return Mono.error(e);
                });
    }

    @Override
    public Mono<Void> verifyTokenWithoutExpiration(String accessToken) {
        // This method will not validate the expiration
        return parseAndValidateJwt(accessToken, false)
                .doOnSuccess(unused -> log.info("The verification of the token without expiration is valid"))
                .onErrorResume(e -> {
                    log.error("Error while verifying token (without expiration)", e);
                    return Mono.error(e);
                });
    }

    private Mono<Void> parseAndValidateJwt(String accessToken, boolean checkExpiration) {
        return getWellKnownInfo()
                .flatMap(metadata -> fetchJWKSet(metadata.jwksUri()))
                .flatMap(jwkSet -> {
                    try {
                        //todo usar jwtservice.parseJWT?
                        SignedJWT signedJWT = SignedJWT.parse(accessToken);
                        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

                        // Validate the issuer
                        if (!appConfig.getVerifierUrl().equals(claims.getIssuer())) {
                            log.info(appConfig.getVerifierUrl());
                            log.info(claims.getIssuer());
                            return Mono.error(new JWTVerificationException("Invalid issuer"));
                        }

                        // Validate expiration time if requested
                        if (checkExpiration && (claims.getExpirationTime() == null || new Date().after(claims.getExpirationTime()))) {
                            return Mono.error(new JWTVerificationException("Token has expired"));
                        }

                        // Verify the signature
                        JWSVerifier verifier = getJWSVerifier(signedJWT, jwkSet);
                        if (!signedJWT.verify(verifier)) {
                            return Mono.error(new JWTVerificationException("Invalid token signature"));
                        }

                        return Mono.empty(); // Valid token
                    } catch (ParseException | JOSEException e) {
                        log.error("Error parsing or verifying JWT", e);
                        return Mono.error(new JWTParsingException("Error parsing or verifying JWT (custom nou ParseAuthenticationException)"));
                    }
                });
    }

    private JWSVerifier getJWSVerifier(SignedJWT signedJWT, JWKSet jwkSet) throws JOSEException {
        String keyId = signedJWT.getHeader().getKeyID();
        JWK jwk = jwkSet.getKeyByKeyId(keyId);
        if (jwk == null) {
            throw new JOSEException("No matching JWK found for Key ID: " + keyId);
        }

        // Create the appropriate verifier based on the key type
        return switch (jwk.getKeyType().toString()) {
            case "RSA" -> new RSASSAVerifier(((RSAKey) jwk).toRSAPublicKey());
            case "EC" -> new ECDSAVerifier(((ECKey) jwk).toECPublicKey());
            case "oct" -> new MACVerifier(((OctetSequenceKey) jwk).toByteArray());
            default -> throw new JOSEException("Unsupported JWK type: " + jwk.getKeyType());
        };
    }

    private Mono<JWKSet> fetchJWKSet(String jwksUri) {
        if (cachedJWKSet != null) {
            return Mono.just(cachedJWKSet);
        }

        return Mono.defer(() -> {
            synchronized (jwkLock) {
                if (cachedJWKSet != null) {
                    return Mono.just(cachedJWKSet);
                }
                return oauth2VerifierWebClient.get()
                        .uri(jwksUri)
                        .retrieve()
                        .bodyToMono(String.class)
                        .<JWKSet>handle((jwks, sink) -> {
                            try {
                                cachedJWKSet = JWKSet.parse(jwks);
                                sink.next(cachedJWKSet);
                            } catch (ParseException e) {
                                sink.error(new JWTVerificationException("Error parsing the JWK Set"));
                            }
                        })
                        .onErrorMap(e -> new JWTVerificationException("Error fetching the JWK Set"));
            }
        });
    }

    @Override
    public Mono<OpenIDProviderMetadata> getWellKnownInfo() {
        String wellKnownInfoEndpoint = appConfig.getVerifierUrl() + AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH;

        return oauth2VerifierWebClient.get()
                .uri(wellKnownInfoEndpoint)
                .retrieve()
                .bodyToMono(OpenIDProviderMetadata.class)
                .onErrorMap(e -> new WellKnownInfoFetchException("Error fetching OpenID Provider Metadata", e));
    }

    @Override
    public Mono<VerifierOauth2AccessToken> performTokenRequest(String body) {
        return getWellKnownInfo()
                .flatMap(metadata -> oauth2VerifierWebClient.post()
                        .uri(metadata.tokenEndpoint())
                        .header(CONTENT_TYPE, CONTENT_TYPE_URL_ENCODED_FORM)
                        .bodyValue(body)
                        .retrieve()
                        .bodyToMono(VerifierOauth2AccessToken.class)
                        .onErrorMap(e -> new TokenFetchException("Error fetching the token", e)));
    }
}