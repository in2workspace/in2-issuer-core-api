package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import es.in2.issuer.backend.shared.domain.util.JwtUtils;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.RemoteSignatureConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import es.in2.issuer.backend.shared.infrastructure.repository.DeferredCredentialMetadataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class RemoteSignatureServiceImpl implements RemoteSignatureService {

    private final ObjectMapper objectMapper;
    private final HttpUtils httpUtils;
    private final JwtUtils jwtUtils;
    private final RemoteSignatureConfig remoteSignatureConfig;
    private final HashGeneratorService hashGeneratorService;
    private static final String ACCESS_TOKEN_NAME = "access_token";
    private static final String SAD_NAME = "SAD";
    private static final String CERTIFICATES = "certificates";
    private static final String SERIALIZING_ERROR = "Error serializing request body to JSON";
    private final CredentialProcedureRepository credentialProcedureRepository;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final DeferredCredentialMetadataRepository deferredCredentialMetadataRepository;
    private final CredentialProcedureService credentialProcedureService;
    private final AppConfig appConfig;
    private final EmailService emailService;
    private final List<Map.Entry<String, String>> headers = new ArrayList<>();
    private final Map<String, Object> requestBody = new HashMap<>();
    private String credentialID;
    private String credentialPassword;
    private String clientId;
    private String clientSecret;

    /**
     * Signs an ISSUED credential (user-related credential).
     *
     * <p>
     * Issued credentials represent user-facing identities such as:
     * <ul>
     *   <li>Employee credentials</li>
     *   <li>Machine credentials</li>
     *   <li>Label / badge credentials</li>
     * </ul>
     *
     * <p>
     * These credentials have a special signing lifecycle:
     * <ul>
     *   <li>The signature may be <b>deferred</b> if the remote signing fails</li>
     *   <li>After retries are exhausted, the flow switches to <b>ASYNC mode</b></li>
     *   <li>An additional <b>post-processing step</b> is triggered (e.g. email notification)</li>
     * </ul>
     *
     * <p>
     * Deferred metadata is removed only after a successful signature.
     *
     */
    @Override
    //TODO Cuando se implementen los "settings" del issuer, se debe pasar el clientId, secret, etc. como parámetros en lugar de var entorno
    public Mono<SignedData> signIssuedCredential(
            SignatureRequest signatureRequest,
            String token,
            String procedureId,
            String email
    ) {
        log.debug(
                "RemoteSignatureServiceImpl - signIssuedCredential, signatureRequest: {}, token: {}, procedureId: {}, email: {}",
                signatureRequest, token, procedureId, email
        );

        return signWithRetry(signatureRequest, token, "signIssuedCredential")
                .doOnSuccess(result -> {
                    log.info("Successfully Signed");
                    log.info("Procedure with id: {}", procedureId);
                    log.info("at time: {}", new Date());
                    deferredCredentialMetadataService.deleteDeferredCredentialMetadataById(procedureId);
                })
                .onErrorResume(throwable -> {
                    log.error("Error after 3 retries, switching to ASYNC mode.");
                    log.error("Error Time: {}", new Date());
                    return handlePostRecoverError(procedureId, email)
                            .then(Mono.error(new RemoteSignatureException(
                                    "Signature Failed, changed to ASYNC mode",
                                    throwable
                            )));
                });
    }

    /**
     * Signs a SYSTEM credential.
     *
     * <p>
     * System credentials are internal, platform-level credentials and
     * <b>do not follow the issued credential lifecycle</b>.
     *
     * <p>
     * Characteristics:
     * <ul>
     *   <li>No deferred signing</li>
     *   <li>No async recovery flow</li>
     *   <li>No post-signature handling (email, procedure tracking, etc.)</li>
     * </ul>
     *
     * <p>
     * Example of system credentials:
     * <ul>
     *   <li>VC StatusListCredential</li>
     * </ul>
     *
     */
    @Override
    public Mono<SignedData> signSystemCredential(
            SignatureRequest signatureRequest,
            String token
    ) {
        log.debug(
                "RemoteSignatureServiceImpl - signSystemCredential, signatureRequest: {}, token: {}",
                signatureRequest, token
        );

        return signWithRetry(signatureRequest, token, "signSystemCredential");
    }

    private Mono<SignedData> signWithRetry(
            SignatureRequest signatureRequest,
            String token,
            String operationName
    ) {
        return Mono.defer(() -> executeSigningFlow(signatureRequest, token))
                .doOnSuccess(signedData -> {
                    int signedLength = (signedData != null && signedData.data() != null)
                            ? signedData.data().length()
                            : 0;

                    log.info(
                            "Remote signing succeeded ({}). resultType={}, signedLength={}",
                            operationName,
                            signedData != null ? signedData.type() : null,
                            signedLength
                    );
                })
                .retryWhen(
                        Retry.backoff(3, Duration.ofSeconds(1))
                                .maxBackoff(Duration.ofSeconds(5))
                                .jitter(0.5)
                                .filter(this::isRecoverableError)
                                .doBeforeRetry(retrySignal -> {
                                    long attempt = retrySignal.totalRetries() + 1;
                                    Throwable failure = retrySignal.failure();
                                    String msg = failure != null ? failure.getMessage() : "n/a";

                                    log.warn(
                                            "Retrying remote signing ({}). attempt={} of 3, reason={}",
                                            operationName, attempt, msg
                                    );
                                })
                )
                .doOnError(ex ->
                        log.error(
                                "Remote signing failed after retries ({}). reason={}",
                                operationName, ex.getMessage(), ex
                        )
                );
    }

    public boolean isRecoverableError(Throwable throwable) {
        if (throwable instanceof WebClientResponseException ex) {
            return ex.getStatusCode().is5xxServerError();
        } else return throwable instanceof ConnectException || throwable instanceof TimeoutException;
    }

    public Mono<Boolean> validateCredentials() {
        log.info("Validating credentials");
        SignatureRequest signatureRequest = SignatureRequest.builder().build();
        return requestAccessToken(signatureRequest, SIGNATURE_REMOTE_SCOPE_SERVICE)
                .flatMap(this::validateCertificate);
    }

    private Mono<SignedData> executeSigningFlow(SignatureRequest signatureRequest, String token) {
        return getSignedSignature(signatureRequest, token)
                .flatMap(response -> {
                    try {
                        return Mono.just(toSignedData(response));
                    } catch (SignedDataParsingException ex) {
                        return Mono.error(new RemoteSignatureException("Error parsing signed data", ex));
                    }
                });
    }

    public Mono<Boolean> validateCertificate(String accessToken) {
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        String credentialListEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/list";
        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));

        requestBody.clear();
        requestBody.put("credentialInfo", true);
        requestBody.put(CERTIFICATES, "chain");
        requestBody.put("certInfo", true);
        requestBody.put("authInfo", true);
        requestBody.put("onlyValid", true);
        requestBody.put("lang", 0);
        requestBody.put("clientData", "string");
        try {
            ObjectMapper objectMapperIntern = new ObjectMapper();
            String requestBodyJson = objectMapperIntern.writeValueAsString(requestBody);
            return httpUtils.postRequest(credentialListEndpoint, headers, requestBodyJson)
                    .flatMap(responseJson -> {
                        try {
                            Map<String, List<String>> responseMap = objectMapperIntern.readValue(responseJson, Map.class);
                            List<String> receivedCredentialIDs = responseMap.get("credentialIDs");
                            boolean isValid = receivedCredentialIDs != null &&
                                    receivedCredentialIDs.stream()
                                            .anyMatch(id -> id.trim().equalsIgnoreCase(credentialID.trim()));
                            return Mono.just(isValid);
                        } catch (JsonProcessingException e) {
                            return Mono.error(new RemoteSignatureException("Error parsing certificate list response", e));
                        }
                    })
                    .switchIfEmpty(Mono.just(false))
                    .doOnError(error -> log.error("Error validating certificate: {}", error.getMessage()));
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException(SERIALIZING_ERROR, e));
        }
    }

    public Mono<String> getSignedSignature(SignatureRequest signatureRequest, String token) {
        return switch (remoteSignatureConfig.getRemoteSignatureType()) {
            case SIGNATURE_REMOTE_TYPE_SERVER -> getSignedDocumentDSS(signatureRequest, token);
            case SIGNATURE_REMOTE_TYPE_CLOUD -> getSignedDocumentExternal(signatureRequest);
            default -> Mono.error(new RemoteSignatureException("Remote signature service not available"));
        };
    }

    private Mono<String> getSignedDocumentDSS(SignatureRequest signatureRequest, String token) {
        String signatureRemoteServerEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/api/v1"
                + remoteSignatureConfig.getRemoteSignatureSignPath();
        String signatureRequestJSON;

        log.info("Requesting signature to DSS service");

        try {
            signatureRequestJSON = objectMapper.writeValueAsString(signatureRequest);
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException(SERIALIZING_ERROR, e));
        }
        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, token));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        return httpUtils.postRequest(signatureRemoteServerEndpoint, headers, signatureRequestJSON)
                .doOnError(error -> log.error("Error signing credential with server method: {}", error.getMessage()));
    }

    public Mono<String> getSignedDocumentExternal(SignatureRequest signatureRequest) {
        log.info("Requesting signature to external service");
        return requestAccessToken(signatureRequest, SIGNATURE_REMOTE_SCOPE_CREDENTIAL)
                .flatMap(accessToken -> requestSad(accessToken)
                        .flatMap(sad -> sendSignatureRequest(signatureRequest, accessToken, sad)
                                .flatMap(responseJson -> processSignatureResponse(signatureRequest, responseJson))));
    }

    public Mono<String> requestSad(String accessToken) {
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        int numSignatures = 1;
        String authDataId = "password";
        String authDataValue = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        String signatureGetSadEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/authorize";

        requestBody.clear();
        requestBody.put(CREDENTIAL_ID, credentialID);
        requestBody.put(NUM_SIGNATURES, numSignatures);
        Map<String, String> authEntry = new HashMap<>();
        authEntry.put(AUTH_DATA_ID, authDataId);
        authEntry.put(AUTH_DATA_VALUE, authDataValue);
        requestBody.put(AUTH_DATA, List.of(authEntry));

        String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(requestBody);
        } catch (JsonProcessingException e) {
            return Mono.error(new SadException("Error serializing JSON request body"));
        }


        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        return httpUtils.postRequest(signatureGetSadEndpoint, headers, jsonBody)
                .flatMap(responseJson -> Mono.fromCallable(() -> {
                    try {
                        Map<String, Object> responseMap = objectMapper.readValue(responseJson, Map.class);
                        if (!responseMap.containsKey(SAD_NAME)) {
                            throw new SadException("SAD missing in response");
                        }
                        return (String) responseMap.get(SAD_NAME);
                    } catch (JsonProcessingException e) {
                        throw new SadException("Error parsing SAD response");
                    }
                }))
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized: Invalid credentials"));
                    }
                    return Mono.error(ex);
                })
                .doOnError(error -> log.error("Error retrieving access token: {}", error.getMessage()));
    }

    public Mono<String> requestAccessToken(SignatureRequest signatureRequest, String scope) {
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        credentialPassword = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        clientId = remoteSignatureConfig.getRemoteSignatureClientId();
        clientSecret = remoteSignatureConfig.getRemoteSignatureClientSecret();
        String grantType = "client_credentials";
        String signatureGetAccessTokenEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/oauth2/token";
        String hashAlgorithmOID = "2.16.840.1.101.3.4.2.1";

        requestBody.clear();
        requestBody.put("grant_type", grantType);
        requestBody.put("scope", scope);
        if (scope.equals(SIGNATURE_REMOTE_SCOPE_CREDENTIAL)) {
            requestBody.put("authorization_details", buildAuthorizationDetails(signatureRequest.data(), hashAlgorithmOID));
        }

        String requestBodyString = requestBody.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .reduce((p1, p2) -> p1 + "&" + p2)
                .orElse("");

        String basicAuthHeader = "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, basicAuthHeader));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
        return httpUtils.postRequest(signatureGetAccessTokenEndpoint, headers, requestBodyString)
                .flatMap(responseJson -> Mono.fromCallable(() -> {
                    try {
                        Map<String, Object> responseMap = objectMapper.readValue(responseJson, Map.class);
                        if (!responseMap.containsKey(ACCESS_TOKEN_NAME)) {
                            throw new AccessTokenException("Access token missing in response");
                        }
                        return (String) responseMap.get(ACCESS_TOKEN_NAME);
                    } catch (JsonProcessingException e) {
                        throw new AccessTokenException("Error parsing access token response", e);
                    }
                }))
                .onErrorResume(WebClientResponseException.class, ex -> {
                    log.error("❌ Access token endpoint [{}] returned {} {}",
                            signatureGetAccessTokenEndpoint, ex.getStatusCode(), ex.getStatusText());
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized: Invalid credentials"));
                    }
                    return Mono.error(new RemoteSignatureException("Remote service error while retrieving access token", ex));
                })
                .onErrorResume(UnknownHostException.class, ex -> {
                    log.error("❌ Could not resolve host [{}] - check DNS or VPN", signatureGetAccessTokenEndpoint);
                    return Mono.error(new RemoteSignatureException("Signature service unreachable: DNS resolution failed", ex));
                })
                .onErrorResume(Exception.class, ex -> {
                    log.error("❌ Unexpected error accessing [{}]: {}", signatureGetAccessTokenEndpoint, ex.getMessage());
                    return Mono.error(new RemoteSignatureException("Unexpected error retrieving access token", ex));
                });
    }

    public Mono<String> requestCertificateInfo(String accessToken, String credentialID) {
        String credentialsInfoEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/info";
        requestBody.clear();
        requestBody.put(CREDENTIAL_ID, credentialID);
        requestBody.put(CERTIFICATES, "chain");
        requestBody.put("certInfo", "true");
        requestBody.put("authInfo", "true");

        String requestBodySignature;
        try {
            requestBodySignature = objectMapper.writeValueAsString(requestBody);
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException(SERIALIZING_ERROR, e));
        }
        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        return httpUtils.postRequest(credentialsInfoEndpoint, headers, requestBodySignature)
                .doOnError(error -> log.error("Error sending credential to sign: {}", error.getMessage()));
    }

    public Mono<DetailedIssuer> extractIssuerFromCertificateInfo(String certificateInfo) {
        try {
            log.info("Starting extraction of issuer from certificate info");
            JsonNode certificateInfoNode = objectMapper.readTree(certificateInfo);
            String subjectDN = certificateInfoNode.get("cert").get("subjectDN").asText();
            String serialNumber = certificateInfoNode.get("cert").get("serialNumber").asText();
            LdapName ldapDN = new LdapName(subjectDN);
            Map<String, String> dnAttributes = new HashMap<>();

            for (Rdn rdn : ldapDN.getRdns()) {
                dnAttributes.put(rdn.getType(), rdn.getValue().toString());
            }
            JsonNode certificatesArray = certificateInfoNode.get("cert").get(CERTIFICATES);

            Mono<String> organizationIdentifierMono = (certificatesArray != null && certificatesArray.isArray())
                    ? Flux.fromIterable(certificatesArray)
                    .concatMap(certNode -> {
                        String base64Cert = certNode.asText();
                        byte[] decodedBytes = Base64.getDecoder().decode(base64Cert);
                        String decodedCert = new String(decodedBytes, StandardCharsets.UTF_8);
                        Pattern pattern = Pattern.compile("organizationIdentifier\\s*=\\s*([\\w\\-]+)");
                        Matcher matcher = pattern.matcher(decodedCert);
                        if (matcher.find()) {
                            return Mono.just(matcher.group(1));
                        } else {
                            return extractOrgFromX509(decodedBytes);
                        }
                    })
                    .next()
                    : Mono.empty();

            return organizationIdentifierMono
                    .switchIfEmpty(Mono.error(new OrganizationIdentifierNotFoundException("organizationIdentifier not found in the certificate.")))
                    .flatMap(orgId -> {
                        if (orgId == null || orgId.isEmpty()) {
                            return Mono.error(new OrganizationIdentifierNotFoundException("organizationIdentifier not found in the certificate."));
                        }
                        DetailedIssuer detailedIssuer = DetailedIssuer.builder()
                                .id(DID_ELSI + orgId)
                                .organizationIdentifier(orgId)
                                .organization(dnAttributes.get("O"))
                                .country(dnAttributes.get("C"))
                                .commonName(dnAttributes.get("CN"))
                                .serialNumber(serialNumber)
                                .build();
                        return Mono.just(detailedIssuer);
                    });
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException("Error parsing certificate info", e));
        } catch (InvalidNameException e) {
            return Mono.error(new RuntimeException("Error parsing subjectDN", e));
        } catch (Exception e) {
            return Mono.error(new RuntimeException("Unexpected error", e));
        }
    }

    public Mono<String> extractOrgFromX509(byte[] decodedBytes) {
        return Mono.defer(() -> {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedBytes));
                String certAsString = x509Certificate.toString();
                Pattern certPattern = Pattern.compile("OID\\.2\\.5\\.4\\.97=([^,\\s]+)");
                Matcher certMatcher = certPattern.matcher(certAsString);
                if (certMatcher.find()) {
                    String orgId = certMatcher.group(1);
                    return Mono.just(orgId);
                } else {
                    return Mono.empty();
                }
            } catch (Exception e) {
                log.debug("Error parsing certificate: {}", e.getMessage());
                return Mono.empty();
            }
        });
    }

    //TODO Eliminar la función cuando el mail de Jesús no sea un problema
    public Mono<String> getMandatorMail(String procedureId) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    try {
                        JsonNode credential = objectMapper.readTree(credentialProcedure.getCredentialDecoded());
                        if (credential.get(CREDENTIAL_SUBJECT).get(MANDATE).get(MANDATOR).get(EMAIL).asText().equals("jesus.ruiz@in2.es")) {
                            return Mono.just("domesupport@in2.es");
                        } else {
                            return Mono.just(credential.get(CREDENTIAL_SUBJECT).get(MANDATE).get(MANDATOR).get(EMAIL).asText());
                        }
                    } catch (JsonProcessingException e) {
                        return Mono.error(new RuntimeException());
                    }

                });
    }

    public Mono<String> getMandatorMailLearCredentialMachine(String procedureId) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    try {
                        JsonNode credential = objectMapper.readTree(credentialProcedure.getCredentialDecoded());
                        if (credential.get(CREDENTIAL_SUBJECT).get(MANDATE).get(MANDATOR).get(EMAIL).asText().equals("jesus.ruiz@in2.es")) {
                            return Mono.just("domesupport@in2.es");
                        } else {
                            return Mono.just(credential.get(CREDENTIAL_SUBJECT).get(MANDATE).get(MANDATOR).get(EMAIL).asText());
                        }
                    } catch (JsonProcessingException e) {
                        return Mono.error(new RuntimeException());
                    }
                });
    }


    private Mono<String> sendSignatureRequest(SignatureRequest signatureRequest, String accessToken, String sad) {
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        String signatureRemoteServerEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/signatures/signDoc";
        String signatureQualifier = "eu_eidas_aesealqc";
        String signatureFormat = "J";
        String conformanceLevel = "Ades-B";
        String signAlgorithm = "OID_sign_algorithm";

        String base64Document = Base64.getEncoder().encodeToString(signatureRequest.data().getBytes(StandardCharsets.UTF_8));
        requestBody.clear();
        requestBody.put(CREDENTIAL_ID, credentialID);
        requestBody.put(SAD_NAME, sad);
        requestBody.put("signatureQualifier", signatureQualifier);
        List<Map<String, String>> documents = List.of(
                Map.of(
                        "document", base64Document,
                        "signature_format", signatureFormat,
                        "conformance_level", conformanceLevel,
                        "signAlgo", signAlgorithm
                )
        );
        requestBody.put("documents", documents);

        String requestBodySignature;
        try {
            requestBodySignature = objectMapper.writeValueAsString(requestBody);
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException(SERIALIZING_ERROR, e));
        }

        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        return httpUtils.postRequest(signatureRemoteServerEndpoint, headers, requestBodySignature)
                .doOnError(error -> log.error("Error sending credential to sign: {}", error.getMessage()));
    }

    public Mono<String> processSignatureResponse(SignatureRequest signatureRequest, String responseJson) {
        return Mono.fromCallable(() -> {
            try {
                Map<String, List<String>> responseMap = objectMapper.readValue(responseJson, Map.class);
                List<String> documentsWithSignatureList = responseMap.get("DocumentWithSignature");

                if (documentsWithSignatureList == null || documentsWithSignatureList.isEmpty()) {
                    throw new SignatureProcessingException("No signature found in the response");
                }
                String documentsWithSignature = documentsWithSignatureList.get(0);
                String documentsWithSignatureDecoded = new String(Base64.getDecoder().decode(documentsWithSignature), StandardCharsets.UTF_8);
                String receivedPayloadDecoded = jwtUtils.decodePayload(documentsWithSignatureDecoded);
                if (jwtUtils.areJsonsEqual(receivedPayloadDecoded, signatureRequest.data())) {
                    return objectMapper.writeValueAsString(Map.of(
                            "type", signatureRequest.configuration().type().name(),
                            "data", documentsWithSignatureDecoded
                    ));
                } else {
                    throw new SignatureProcessingException("Signed payload received does not match the original data");
                }
            } catch (JsonProcessingException e) {
                throw new SignatureProcessingException("Error parsing signature response", e);
            }
        });
    }

    private String buildAuthorizationDetails(String unsignedCredential, String hashAlgorithmOID) {
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        credentialPassword = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        try {
            Map<String, Object> authorizationDetails = new HashMap<>();
            authorizationDetails.put("type", SIGNATURE_REMOTE_SCOPE_CREDENTIAL);
            authorizationDetails.put(CREDENTIAL_ID, credentialID);
            authorizationDetails.put("credentialPassword", credentialPassword);
            String hashedCredential = hashGeneratorService.generateHash(unsignedCredential, hashAlgorithmOID);
            List<Map<String, String>> documentDigests = null;
            if (hashedCredential != null) {
                documentDigests = List.of(
                        Map.of("hash", hashedCredential, "label", "Issued Credential")
                );
            }
            authorizationDetails.put("documentDigests", documentDigests);
            authorizationDetails.put("hashAlgorithmOID", hashAlgorithmOID);

            return objectMapper.writeValueAsString(List.of(authorizationDetails));
        } catch (JsonProcessingException | HashGenerationException e) {
            throw new AuthorizationDetailsException("Error generating authorization details", e);
        }
    }


    private SignedData toSignedData(String signedSignatureResponse) throws SignedDataParsingException {
        try {
            return objectMapper.readValue(signedSignatureResponse, SignedData.class);
        } catch (IOException e) {
            log.error("Error: {}", e.getMessage());
            throw new SignedDataParsingException("Error parsing signed data");
        }
    }

    public Mono<Void> handlePostRecoverError(String procedureId, String email) {
        log.info("handlePostRecoverError");
        log.info("Received email: {}", email);

        UUID id = UUID.fromString(procedureId);
        String domain = appConfig.getIssuerFrontendUrl();

        // Fetch once and reuse the same result
        Mono<CredentialProcedure> cachedProc = credentialProcedureRepository
                .findByProcedureId(id)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("No CredentialProcedure for " + procedureId)))
                .cache();

        // Update operation mode and status
        Mono<Void> updateOperationMode = cachedProc
                .flatMap(cp -> {
                    cp.setOperationMode(ASYNC);
                    cp.setCredentialStatus(CredentialStatusEnum.PEND_SIGNATURE);
                    return credentialProcedureRepository.save(cp)
                            .doOnSuccess(saved -> log.info("Updated operationMode to Async - Procedure"))
                            .then();
                });

        // Update deferred metadata
        Mono<Void> updateDeferredMetadata = deferredCredentialMetadataRepository.findByProcedureId(id)
                .switchIfEmpty(Mono.fromRunnable(() ->
                        log.error("No deferred metadata found for procedureId: {}", procedureId)
                ).then(Mono.empty()))
                .flatMap(deferred -> {
                    deferred.setOperationMode(ASYNC);
                    return deferredCredentialMetadataRepository.save(deferred)
                            .doOnSuccess(saved -> log.info("Updated operationMode to Async - Deferred"))
                            .then();
                });

        // Send email using provided email or fallback to updatedBy value
        Mono<Void> sendEmail = cachedProc.flatMap(cp -> {
            String org = cp.getOrganizationIdentifier();
            String updatedBy = cp.getUpdatedBy();
            log.debug("updatedBy in procedure: {}", updatedBy);

            String targetEmail = (email != null && !email.isBlank()) ? email : updatedBy;
            log.info("Preparing email for org {} (to {})", org, targetEmail);

            return emailService.sendPendingSignatureCredentialNotification(
                    targetEmail,
                    "email.pending-credential-notification",
                    procedureId,
                    domain
            );
        });

        return updateOperationMode
                .then(updateDeferredMetadata)
                .then(sendEmail);
    }

}