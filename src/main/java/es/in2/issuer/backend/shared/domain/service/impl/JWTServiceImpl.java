package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.JWTClaimMissingException;
import es.in2.issuer.backend.shared.domain.exception.JWTCreationException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.infrastructure.crypto.CryptoComponent;
import io.github.novacrypto.base58.Base58;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.DID_KEY;

@Slf4j
@Service
@RequiredArgsConstructor
public class JWTServiceImpl implements JWTService {

    private final ObjectMapper objectMapper;
    private final CryptoComponent cryptoComponent;

    @Override
    public String generateJWT(String payload) {
        try {
            // Get ECKey
            ECKey ecJWK = cryptoComponent.getECKey();
            // Set Header
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(cryptoComponent.getECKey().getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();
            // Set Payload
            JWTClaimsSet claimsSet = convertPayloadToJWTClaimsSet(payload);
            // Create JWT for ES256 algorithm
            SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
            // Sign with a private EC key
            JWSSigner signer = new ECDSASigner(ecJWK);
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new JWTCreationException("Error creating JWT");
        }
    }

    private JWTClaimsSet convertPayloadToJWTClaimsSet(String payload) {
        try {
            JsonNode jsonNode = objectMapper.readTree(payload);
            Map<String, Object> claimsMap = objectMapper.convertValue(jsonNode, new TypeReference<>() {
            });
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            for (Map.Entry<String, Object> entry : claimsMap.entrySet()) {
                builder.claim(entry.getKey(), entry.getValue());
            }
            return builder.build();
        } catch (JsonProcessingException e) {
            log.error("Error while parsing the JWT payload", e);
            throw new JWTCreationException("Error while parsing the JWT payload");
        }

    }

    @Override
    public Mono<Boolean> validateJwtSignatureReactive(JWSObject jwsObject) {
        String kid = jwsObject.getHeader().getKeyID();
        String encodedPublicKey = extractEncodedPublicKey(kid);
        return decodePublicKeyIntoBytes(encodedPublicKey)
                .flatMap(publicKeyBytes -> validateJwtSignature(jwsObject.getParsedString(), publicKeyBytes));
    }

    @Override
    public Mono<Boolean> validateJwtSignatureWithJwkReactive(String jwt, Map<String, Object> jwkMap) {
        return Mono.fromCallable(() -> validateJwtSignatureWithJwk(jwt, jwkMap))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private boolean validateJwtSignatureWithJwk(String jwt, Map<String, Object> jwkMap) throws ProofValidationException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            JWSAlgorithm alg = signedJWT.getHeader().getAlgorithm();

            JWK jwk = parsePublicJwkOrThrow(jwkMap);
            JWSVerifier verifier = buildVerifierOrThrow(jwk, alg);

            return signedJWT.verify(verifier);

        } catch (ParseException e) {
            throw new ProofValidationException("invalid_proof: malformed jwt or jwk");
        } catch (ProofValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new ProofValidationException("invalid_proof: signature validation error");
        }
    }

    private JWK parsePublicJwkOrThrow(Map<String, Object> jwkMap) throws ParseException, ProofValidationException {
        JWK jwk = JWK.parse(jwkMap);
        if (jwk.isPrivate()) {
            throw new ProofValidationException("invalid_proof: jwk must not contain private key material");
        }
        return jwk;
    }

    private JWSVerifier buildVerifierOrThrow(JWK jwk, JWSAlgorithm alg) throws JOSEException, ProofValidationException {
        if (jwk instanceof ECKey ecKey) {
            validateAlgForEc(alg);
            return new ECDSAVerifier(ecKey.toECPublicKey());
        }

        if (jwk instanceof OctetKeyPair okp) {
            validateOkpEd25519(okp);
            validateAlgForEd25519(alg);
            return new Ed25519Verifier(okp);
        }

        throw new ProofValidationException("invalid_proof: jwk kty not supported");
    }

    private void validateAlgForEc(JWSAlgorithm alg) throws ProofValidationException {
        if (alg == null || !alg.getName().startsWith("ES")) {
            throw new ProofValidationException("invalid_proof: alg not compatible with EC JWK");
        }
    }

    private void validateOkpEd25519(OctetKeyPair okp) throws ProofValidationException {
        if (okp.getCurve() == null || !Curve.Ed25519.equals(okp.getCurve())) {
            throw new ProofValidationException(
                    "invalid_proof: only Ed25519 OKP keys are supported for signatures"
            );
        }
    }

    private void validateAlgForEd25519(JWSAlgorithm alg) throws ProofValidationException {
        if (!JWSAlgorithm.EdDSA.equals(alg)) {
            throw new ProofValidationException("invalid_proof: alg not compatible with Ed25519 JWK");
        }
    }


    public String extractEncodedPublicKey(String kid) {
        String prefix = DID_KEY;
        String encodedPublicKey;

        if (kid.contains("#")) {
            encodedPublicKey = kid.substring(kid.indexOf("#") + 1);
        } else if (kid.contains(prefix)) {
            encodedPublicKey = kid.substring(kid.indexOf(prefix) + prefix.length());
        } else {
            throw new IllegalArgumentException("'kid' format not correct");
        }

        return encodedPublicKey;
    }


    private Mono<Boolean> validateJwtSignature(String jwtString, byte[] publicKeyBytes) {
        return Mono.fromCallable(() -> {
            try {
                log.debug("validateJwtSignature");
                // Set the curve as secp256r1
                ECCurve curve = new SecP256R1Curve();
                BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length));

                // Recover the Y coordinate from the X coordinate and the curve
                BigInteger y = curve.decodePoint(publicKeyBytes).getYCoord().toBigInteger();

                ECPoint point = new ECPoint(x, y);

                // Fetch the ECParameterSpec for secp256r1
                ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
                ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());

                // Create a KeyFactory and generate the public key
                KeyFactory kf = KeyFactory.getInstance("EC");
                ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
                PublicKey publicKey = kf.generatePublic(pubKeySpec);

                // Parse the JWT and create a verifier
                SignedJWT signedJWT = SignedJWT.parse(jwtString);
                ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);

                // Verify the signature
                return signedJWT.verify(verifier);
            } catch (Exception e) {
                return false; // In case of any exception, return false
            }
        });
    }

    private Mono<byte[]> decodePublicKeyIntoBytes(String publicKey) {
        return Mono.fromCallable(() -> {
            // Remove the prefix "z" to get the multibase encoded string
            if (!publicKey.startsWith("z")) {
                throw new IllegalArgumentException("Invalid Public Key.");
            }
            String multibaseEncoded = publicKey.substring(1);

            // Multibase decode (Base58) the encoded part to get the bytes
            byte[] decodedBytes = Base58.base58Decode(multibaseEncoded);

            // Multicodec prefix is fixed for "0x1200" for the secp256r1 curve
            int prefixLength = 2;

            // Extract public key bytes after the multicodec prefix
            byte[] publicKeyBytes = new byte[decodedBytes.length - prefixLength];
            System.arraycopy(decodedBytes, prefixLength, publicKeyBytes, 0, publicKeyBytes.length);

            return publicKeyBytes;
        });
    }

    @Override
    public SignedJWT parseJWT(String jwt) {
        try {
            return SignedJWT.parse(jwt);
        } catch (ParseException e) {
            log.error("Error when parsing JWTs: {}", e.getMessage());
            throw new JWTParsingException("Error when parsing JWTs");
        }
    }

    @Override
    public Payload getPayloadFromSignedJWT(SignedJWT signedJWT) {
        return signedJWT.getPayload();
    }

    @Override
    public String getClaimFromPayload(Payload payload, String claimName) {
        Object claimValue = payload.toJSONObject().get(claimName);
        if (claimValue == null) {
            throw new JWTClaimMissingException(String.format("The '%s' claim is missing or empty in the JWT payload.", claimName));
        }
        try {
            return objectMapper.writeValueAsString(claimValue);
        } catch (JsonProcessingException e) {
            throw new JWTClaimMissingException(String.format("Failed to serialize '%s' claim to JSON: %s", claimName, e.getMessage()));
        }
    }

    @Override
    public Long getExpirationFromToken(String token) {
        Payload payload = getPayloadFromSignedJWT(parseJWT(token));
        Object claimValue = payload.toJSONObject().get("exp");
        if (claimValue == null) {
            throw new JWTClaimMissingException("The 'exp' claim is missing in the JWT payload.");
        }
        if (claimValue instanceof Number number) {
            return number.longValue();
        } else {
            throw new JWTClaimMissingException("The 'exp' claim is not a valid number in the JWT payload.");
        }
    }

    @Override
    public String resolvePrincipal(Jwt jwt) {
        Optional<String> email = extractMandateeEmail(jwt);
        log.debug("resolvePrincipal - extracted email: {}", email.orElse("<empty>"));

        String resolved = email
                .filter(e -> !e.isBlank())
                .orElse("anonymous");

        log.debug("resolvePrincipal - returning: {}", resolved);
        return resolved;
    }

    @Override
    public Optional<String> extractMandateeEmail(Jwt jwt) {
        log.debug("Extracting email from JWT");
        Map<String, Object> claims = jwt.getClaims();

        // Resolve VC from either 'vc' (object) or 'vc_json' (stringified JSON)
        Map<String, Object> vc = resolveVc(claims);

        Map<String, Object> cs = asMap(vc.get("credentialSubject"));
        Map<String, Object> mandate = asMap(cs.get("mandate"));
        Map<String, Object> mandatee = asMap(mandate.get("mandatee"));
        Object email = mandatee.get("email");
        if (email == null) {
            email = mandatee.get("emailAddress");
        }

        if (email instanceof String s) {
            log.debug("Email from the mandatee: {}", email);
            return Optional.of(s);
        }

        // Fallback: top-level "email" (in the ID token)
        Object topEmail = claims.get("email");
        if (topEmail == null) {
            topEmail = claims.get("emailAddress");
        }
        if (topEmail instanceof String s2) {
            log.debug("Email from top level: {}", topEmail);
            return Optional.of(s2);
        }

        return Optional.empty();
    }

    /** Extract VC as a Map from either 'vc' or 'vc_json' (string). */
    private Map<String, Object> resolveVc(Map<String, Object> claims) {
        Object vcObj = claims.get("vc");
        if (vcObj instanceof Map<?, ?>) {
            return asMap(vcObj);
        }

        Object vcJsonObj = claims.get("vc_json");
        if (vcJsonObj instanceof String s && !s.isBlank()) {
            try {
                return objectMapper.readValue(s, new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>(){});
            } catch (Exception e) {
                log.warn("Failed to parse vc_json string", e);
                return Map.of();
            }
        }
        // In case the IDP already places vc_json as an object
        return asMap(vcJsonObj);
    }

    // --- helpers ---

    /** Defensive map casting to avoid ClassCastException. */
    private Map<String, Object> asMap(Object v) {
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> safe = new HashMap<>();
            m.forEach((k, val) -> { if (k instanceof String s) safe.put(s, val); });
            return safe;
        }
        return Map.of();
    }

}
