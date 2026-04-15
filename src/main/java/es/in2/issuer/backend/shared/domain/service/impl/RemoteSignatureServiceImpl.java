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
        log.info("╔════════════════════════════════════════════════════════════════╗");
        log.info("║         SIGN ISSUED CREDENTIAL - START                         ║");
        log.info("╚════════════════════════════════════════════════════════════════╝");
        log.info("📋 [SIGN ISSUED] Procedure ID: {}", procedureId);
        log.info("📋 [SIGN ISSUED] Email: {}", email);
        log.info("📋 [SIGN ISSUED] Signature Type: {}", signatureRequest.configuration().type());
        log.info("📋 [SIGN ISSUED] Data Length: {} chars", signatureRequest.data() != null ? signatureRequest.data().length() : 0);
        log.debug("📋 [SIGN ISSUED] Token: {}", token);
        log.debug("📋 [SIGN ISSUED] Full Request: {}", signatureRequest);

        return signWithRetry(signatureRequest, token, "signIssuedCredential")
                .doOnSuccess(result -> {
                    log.info("╔════════════════════════════════════════════════════════════════╗");
                    log.info("║         SIGN ISSUED CREDENTIAL - SUCCESS ✅                    ║");
                    log.info("╚════════════════════════════════════════════════════════════════╝");
                    log.info("📋 [SIGN ISSUED] Successfully Signed");
                    log.info("📋 [SIGN ISSUED] Procedure with id: {}", procedureId);
                    log.info("📋 [SIGN ISSUED] Timestamp: {}", new Date());
                    log.info("📋 [SIGN ISSUED] Result Type: {}", result != null ? result.type() : "null");
                    log.info("📋 [SIGN ISSUED] Deleting deferred credential metadata...");
                    deferredCredentialMetadataService.deleteDeferredCredentialMetadataById(procedureId);
                })
                .onErrorResume(throwable -> {
                    log.error("╔════════════════════════════════════════════════════════════════╗");
                    log.error("║         SIGN ISSUED CREDENTIAL - FAILED ❌                     ║");
                    log.error("╚════════════════════════════════════════════════════════════════╝");
                    log.error("📋 [SIGN ISSUED] Error after 3 retries, switching to ASYNC mode.");
                    log.error("📋 [SIGN ISSUED] Error Time: {}", new Date());
                    log.error("📋 [SIGN ISSUED] Error Type: {}", throwable.getClass().getSimpleName());
                    log.error("📋 [SIGN ISSUED] Error Message: {}", throwable.getMessage());
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
        log.info("╔════════════════════════════════════════════════════════════════╗");
        log.info("║         SIGN SYSTEM CREDENTIAL - START                         ║");
        log.info("╚════════════════════════════════════════════════════════════════╝");
        log.info("🔧 [SIGN SYSTEM] Signature Type: {}", signatureRequest.configuration().type());
        log.info("🔧 [SIGN SYSTEM] Data Length: {} chars", signatureRequest.data() != null ? signatureRequest.data().length() : 0);
        log.debug("🔧 [SIGN SYSTEM] Token: {}", token);
        log.debug("🔧 [SIGN SYSTEM] Full Request: {}", signatureRequest);

        return signWithRetry(signatureRequest, token, "signSystemCredential")
                .doOnSuccess(result -> {
                    log.info("╔════════════════════════════════════════════════════════════════╗");
                    log.info("║         SIGN SYSTEM CREDENTIAL - SUCCESS ✅                    ║");
                    log.info("╚════════════════════════════════════════════════════════════════╝");
                    log.info("🔧 [SIGN SYSTEM] Result Type: {}", result != null ? result.type() : "null");
                })
                .doOnError(error -> {
                    log.error("╔════════════════════════════════════════════════════════════════╗");
                    log.error("║         SIGN SYSTEM CREDENTIAL - FAILED ❌                     ║");
                    log.error("╚════════════════════════════════════════════════════════════════╝");
                    log.error("🔧 [SIGN SYSTEM] Error: {}", error.getMessage(), error);
                });
    }

    private Mono<SignedData> signWithRetry(
            SignatureRequest signatureRequest,
            String token,
            String operationName
    ) {
        log.info("🔄 [RETRY WRAPPER] Starting {} with retry mechanism (max 3 attempts)", operationName);
        
        return Mono.defer(() -> executeSigningFlow(signatureRequest, token))
                .doOnSuccess(signedData -> {
                    int signedLength = (signedData != null && signedData.data() != null)
                            ? signedData.data().length()
                            : 0;

                    log.info("🔄 [RETRY WRAPPER] ✅ Remote signing succeeded ({}). resultType={}, signedLength={}",
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
                                    String errorType = failure != null ? failure.getClass().getSimpleName() : "Unknown";

                                    log.warn("🔄 [RETRY WRAPPER] ⚠️ Retrying remote signing ({}).", operationName);
                                    log.warn("🔄 [RETRY WRAPPER] ⚠️ Attempt: {} of 3", attempt);
                                    log.warn("🔄 [RETRY WRAPPER] ⚠️ Error Type: {}", errorType);
                                    log.warn("🔄 [RETRY WRAPPER] ⚠️ Reason: {}", msg);
                                    
                                    if (failure instanceof WebClientResponseException webEx) {
                                        log.warn("🔄 [RETRY WRAPPER] ⚠️ HTTP Status: {}", webEx.getStatusCode());
                                    }
                                })
                )
                .doOnError(ex -> {
                    log.error("🔄 [RETRY WRAPPER] ❌ Remote signing failed after retries ({}).", operationName);
                    log.error("🔄 [RETRY WRAPPER] ❌ Final error: {}", ex.getMessage(), ex);
                });
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
        
        log.info("📜 [VALIDATE CERT] Endpoint: {}", credentialListEndpoint);
        log.info("📜 [VALIDATE CERT] Credential ID to validate: {}", credentialID);
        
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
            log.info("📜 [VALIDATE CERT] Request Body: {}", requestBodyJson);
            log.info("📜 [VALIDATE CERT] Headers: Authorization=Bearer *****, Content-Type={}", MediaType.APPLICATION_JSON_VALUE);
            
            return httpUtils.postRequest(credentialListEndpoint, headers, requestBodyJson)
                    .doOnSuccess(response -> {
                        log.info("📜 [VALIDATE CERT] ✅ Response received, length: {} chars", response != null ? response.length() : 0);
                        log.debug("📜 [VALIDATE CERT] Response Body: {}", response);
                    })
                    .flatMap(responseJson -> {
                        try {
                            Map<String, List<String>> responseMap = objectMapperIntern.readValue(responseJson, Map.class);
                            log.info("📜 [VALIDATE CERT] Response keys: {}", responseMap.keySet());
                            
                            List<String> receivedCredentialIDs = responseMap.get("credentialIDs");
                            log.info("📜 [VALIDATE CERT] Received credential IDs: {}", receivedCredentialIDs);
                            
                            boolean isValid = receivedCredentialIDs != null &&
                                    receivedCredentialIDs.stream()
                                            .anyMatch(id -> id.trim().equalsIgnoreCase(credentialID.trim()));
                            
                            if (isValid) {
                                log.info("📜 [VALIDATE CERT] ✅ Credential validation successful");
                            } else {
                                log.warn("📜 [VALIDATE CERT] ⚠️ Credential validation failed - ID not found in list");
                            }
                            return Mono.just(isValid);
                        } catch (JsonProcessingException e) {
                            log.error("📜 [VALIDATE CERT] ❌ Error parsing certificate list response", e);
                            return Mono.error(new RemoteSignatureException("Error parsing certificate list response", e));
                        }
                    })
                    .switchIfEmpty(Mono.just(false))
                    .doOnError(error -> {
                        log.error("📜 [VALIDATE CERT] ❌ Error validating certificate: {}", error.getMessage(), error);
                        if (error instanceof WebClientResponseException webEx) {
                            log.error("📜 [VALIDATE CERT] ❌ HTTP Status: {}", webEx.getStatusCode());
                            log.error("📜 [VALIDATE CERT] ❌ Response Body: {}", webEx.getResponseBodyAsString());
                        }
                    });
        } catch (JsonProcessingException e) {
            log.error("📜 [VALIDATE CERT] ❌ Failed to serialize request body", e);
            return Mono.error(new RemoteSignatureException(SERIALIZING_ERROR, e));
        }
    }

    public Mono<String> getSignedSignature(SignatureRequest signatureRequest, String token) {
        String signatureType = remoteSignatureConfig.getRemoteSignatureType();
        log.info("🔀 [SIGNATURE ROUTING] Remote Signature Type: {}", signatureType);
        log.info("🔀 [SIGNATURE ROUTING] Available types: {} (DSS), {} (Cloud)", 
                SIGNATURE_REMOTE_TYPE_SERVER, SIGNATURE_REMOTE_TYPE_CLOUD);
        
        return switch (signatureType) {
            case SIGNATURE_REMOTE_TYPE_SERVER -> {
                log.info("🔀 [SIGNATURE ROUTING] ➡️ Routing to DSS Service");
                yield getSignedDocumentDSS(signatureRequest, token);
            }
            case SIGNATURE_REMOTE_TYPE_CLOUD -> {
                log.info("🔀 [SIGNATURE ROUTING] ➡️ Routing to External Cloud Service");
                yield getSignedDocumentExternal(signatureRequest);
            }
            default -> {
                log.error("🔀 [SIGNATURE ROUTING] ❌ Unknown signature type: {}", signatureType);
                yield Mono.error(new RemoteSignatureException("Remote signature service not available"));
            }
        };
    }

    private Mono<String> getSignedDocumentDSS(SignatureRequest signatureRequest, String token) {
        String signatureRemoteServerEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/api/v1"
                + remoteSignatureConfig.getRemoteSignatureSignPath();
        String signatureRequestJSON;

        log.info("🔑 [DSS SIGNATURE] Requesting signature to DSS service");
        log.info("🔑 [DSS SIGNATURE] Endpoint: {}", signatureRemoteServerEndpoint);

        try {
            signatureRequestJSON = objectMapper.writeValueAsString(signatureRequest);
            log.info("🔑 [DSS SIGNATURE] Request Body Length: {} chars", signatureRequestJSON.length());
            log.debug("🔑 [DSS SIGNATURE] Request Body: {}", signatureRequestJSON);
        } catch (JsonProcessingException e) {
            log.error("🔑 [DSS SIGNATURE] ❌ Failed to serialize request body", e);
            return Mono.error(new RemoteSignatureException(SERIALIZING_ERROR, e));
        }
        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, token));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        log.info("🔑 [DSS SIGNATURE] Headers: Authorization=*****, Content-Type={}", MediaType.APPLICATION_JSON_VALUE);
        
        return httpUtils.postRequest(signatureRemoteServerEndpoint, headers, signatureRequestJSON)
                .doOnSuccess(response -> {
                    log.info("🔑 [DSS SIGNATURE] ✅ Response received, length: {} chars", response != null ? response.length() : 0);
                    log.debug("🔑 [DSS SIGNATURE] Response Body: {}", response);
                })
                .doOnError(error -> {
                    log.error("🔑 [DSS SIGNATURE] ❌ Error signing credential with server method: {}", error.getMessage(), error);
                    if (error instanceof WebClientResponseException webEx) {
                        log.error("🔑 [DSS SIGNATURE] ❌ HTTP Status: {}", webEx.getStatusCode());
                        log.error("🔑 [DSS SIGNATURE] ❌ Response Body: {}", webEx.getResponseBodyAsString());
                    }
                });
    }

    public Mono<String> getSignedDocumentExternal(SignatureRequest signatureRequest) {
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] ========== STARTING EXTERNAL SIGNATURE FLOW ==========");
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] Requesting signature to external cloud service");
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] Signature Type: {}", signatureRequest.configuration().type());
        
        return requestAccessToken(signatureRequest, SIGNATURE_REMOTE_SCOPE_CREDENTIAL)
                .doOnSuccess(token -> log.info("🌐 [EXTERNAL SIGNATURE FLOW] ✅ Step 1/3: Access Token obtained"))
                .flatMap(accessToken -> requestSad(accessToken)
                        .doOnSuccess(sad -> log.info("🌐 [EXTERNAL SIGNATURE FLOW] ✅ Step 2/3: SAD obtained"))
                        .flatMap(sad -> sendSignatureRequest(signatureRequest, accessToken, sad)
                                .doOnSuccess(response -> log.info("🌐 [EXTERNAL SIGNATURE FLOW] ✅ Step 3/3: Signature response received"))
                                .flatMap(responseJson -> processSignatureResponse(signatureRequest, responseJson)
                                        .doOnSuccess(result -> log.info("🌐 [EXTERNAL SIGNATURE FLOW] ========== EXTERNAL SIGNATURE FLOW COMPLETED ==========")))))
                .doOnError(error -> log.error("🌐 [EXTERNAL SIGNATURE FLOW] ❌ Flow failed: {}", error.getMessage(), error));
    }

    public Mono<String> requestSad(String accessToken) {
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        int numSignatures = 1;
        String authDataId = "password";
        String authDataValue = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        String signatureGetSadEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/authorize";

        log.info("🔐 [REQUEST SAD] Endpoint: {}", signatureGetSadEndpoint);
        log.info("🔐 [REQUEST SAD] Credential ID: {}", credentialID);
        log.info("🔐 [REQUEST SAD] Number of Signatures: {}", numSignatures);

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
            // Sanitize password from logs
            String sanitizedBody = jsonBody.replaceAll("(\"" + AUTH_DATA_VALUE + "\"\s*:\s*\")[^\"]*", "$1*****");
            log.info("🔐 [REQUEST SAD] Request Body: {}", sanitizedBody);
        } catch (JsonProcessingException e) {
            log.error("🔐 [REQUEST SAD] ❌ Failed to serialize request body", e);
            return Mono.error(new SadException("Error serializing JSON request body"));
        }

        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        log.info("🔐 [REQUEST SAD] Headers: Authorization=Bearer *****, Content-Type={}", MediaType.APPLICATION_JSON_VALUE);
        
        return httpUtils.postRequest(signatureGetSadEndpoint, headers, jsonBody)
                .doOnSuccess(response -> {
                    log.info("🔐 [REQUEST SAD] ✅ Raw response received, length: {} chars", response != null ? response.length() : 0);
                    log.debug("🔐 [REQUEST SAD] Response Body: {}", response);
                })
                .flatMap(responseJson -> Mono.fromCallable(() -> {
                    try {
                        Map<String, Object> responseMap = objectMapper.readValue(responseJson, Map.class);
                        if (!responseMap.containsKey(SAD_NAME)) {
                            log.error("🔐 [REQUEST SAD] ❌ SAD missing in response. Available keys: {}", responseMap.keySet());
                            throw new SadException("SAD missing in response");
                        }
                        String sad = (String) responseMap.get(SAD_NAME);
                        log.info("🔐 [REQUEST SAD] ✅ SAD extracted successfully, length: {} chars", sad != null ? sad.length() : 0);
                        return sad;
                    } catch (JsonProcessingException e) {
                        log.error("🔐 [REQUEST SAD] ❌ Error parsing SAD response", e);
                        throw new SadException("Error parsing SAD response");
                    }
                }))
                .onErrorResume(WebClientResponseException.class, ex -> {
                    log.error("🔐 [REQUEST SAD] ❌ HTTP Status: {}", ex.getStatusCode());
                    log.error("🔐 [REQUEST SAD] ❌ Response Body: {}", ex.getResponseBodyAsString());
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized: Invalid credentials"));
                    }
                    return Mono.error(ex);
                })
                .doOnError(error -> log.error("🔐 [REQUEST SAD] ❌ Error retrieving SAD: {}", error.getMessage(), error));
    }

    public Mono<String> requestAccessToken(SignatureRequest signatureRequest, String scope) {
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        credentialPassword = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        clientId = remoteSignatureConfig.getRemoteSignatureClientId();
        clientSecret = remoteSignatureConfig.getRemoteSignatureClientSecret();
        String grantType = "client_credentials";
        String signatureGetAccessTokenEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/oauth2/token";
        String hashAlgorithmOID = "2.16.840.1.101.3.4.2.1";

        log.info("🎫 [ACCESS TOKEN] Endpoint: {}", signatureGetAccessTokenEndpoint);
        log.info("🎫 [ACCESS TOKEN] Grant Type: {}", grantType);
        log.info("🎫 [ACCESS TOKEN] Scope: {}", scope);
        log.info("🎫 [ACCESS TOKEN] Client ID: {}", clientId);

        requestBody.clear();
        requestBody.put("grant_type", grantType);
        requestBody.put("scope", scope);
        if (scope.equals(SIGNATURE_REMOTE_SCOPE_CREDENTIAL)) {
            String authDetails = buildAuthorizationDetails(signatureRequest.data(), hashAlgorithmOID);
            requestBody.put("authorization_details", authDetails);
            log.info("🎫 [ACCESS TOKEN] Authorization Details included (length: {} chars)", authDetails.length());
            log.debug("🎫 [ACCESS TOKEN] Authorization Details: {}", authDetails);
        }

        String requestBodyString = requestBody.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .reduce((p1, p2) -> p1 + "&" + p2)
                .orElse("");

        log.info("🎫 [ACCESS TOKEN] Request Body Length: {} chars", requestBodyString.length());
        log.debug("🎫 [ACCESS TOKEN] Request Body (raw): {}", requestBodyString);

        String basicAuthHeader = "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, basicAuthHeader));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
        log.info("🎫 [ACCESS TOKEN] Headers: Authorization=Basic *****, Content-Type={}", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        
        return httpUtils.postRequest(signatureGetAccessTokenEndpoint, headers, requestBodyString)
                .doOnSuccess(response -> {
                    log.info("🎫 [ACCESS TOKEN] ✅ Raw response received, length: {} chars", response != null ? response.length() : 0);
                    log.debug("🎫 [ACCESS TOKEN] Response Body: {}", response);
                })
                .flatMap(responseJson -> Mono.fromCallable(() -> {
                    try {
                        Map<String, Object> responseMap = objectMapper.readValue(responseJson, Map.class);
                        if (!responseMap.containsKey(ACCESS_TOKEN_NAME)) {
                            log.error("🎫 [ACCESS TOKEN] ❌ Access token missing in response. Available keys: {}", responseMap.keySet());
                            throw new AccessTokenException("Access token missing in response");
                        }
                        String token = (String) responseMap.get(ACCESS_TOKEN_NAME);
                        log.info("🎫 [ACCESS TOKEN] ✅ Access token extracted successfully, length: {} chars", token != null ? token.length() : 0);
                        return token;
                    } catch (JsonProcessingException e) {
                        log.error("🎫 [ACCESS TOKEN] ❌ Error parsing access token response", e);
                        throw new AccessTokenException("Error parsing access token response", e);
                    }
                }))
                .onErrorResume(WebClientResponseException.class, ex -> {
                    log.error("🎫 [ACCESS TOKEN] ❌ Endpoint [{}] returned {} {}",
                            signatureGetAccessTokenEndpoint, ex.getStatusCode(), ex.getStatusText());
                    log.error("🎫 [ACCESS TOKEN] ❌ Response Body: {}", ex.getResponseBodyAsString());
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized: Invalid credentials"));
                    }
                    return Mono.error(new RemoteSignatureException("Remote service error while retrieving access token", ex));
                })
                .onErrorResume(UnknownHostException.class, ex -> {
                    log.error("🎫 [ACCESS TOKEN] ❌ Could not resolve host [{}] - check DNS or VPN", signatureGetAccessTokenEndpoint);
                    return Mono.error(new RemoteSignatureException("Signature service unreachable: DNS resolution failed", ex));
                })
                .onErrorResume(Exception.class, ex -> {
                    log.error("🎫 [ACCESS TOKEN] ❌ Unexpected error accessing [{}]: {}", signatureGetAccessTokenEndpoint, ex.getMessage(), ex);
                    return Mono.error(new RemoteSignatureException("Unexpected error retrieving access token", ex));
                });
    }

    public Mono<String> requestCertificateInfo(String accessToken, String credentialID) {
        String credentialsInfoEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/info";
        
        log.info("📋 [CERT INFO] Endpoint: {}", credentialsInfoEndpoint);
        log.info("📋 [CERT INFO] Credential ID: {}", credentialID);
        
        requestBody.clear();
        requestBody.put(CREDENTIAL_ID, credentialID);
        requestBody.put(CERTIFICATES, "chain");
        requestBody.put("certInfo", "true");
        requestBody.put("authInfo", "true");

        String requestBodySignature;
        try {
            requestBodySignature = objectMapper.writeValueAsString(requestBody);
            log.info("📋 [CERT INFO] Request Body: {}", requestBodySignature);
        } catch (JsonProcessingException e) {
            log.error("📋 [CERT INFO] ❌ Failed to serialize request body", e);
            return Mono.error(new RuntimeException(SERIALIZING_ERROR, e));
        }
        
        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        log.info("📋 [CERT INFO] Headers: Authorization=Bearer *****, Content-Type={}", MediaType.APPLICATION_JSON_VALUE);
        
        return httpUtils.postRequest(credentialsInfoEndpoint, headers, requestBodySignature)
                .doOnSuccess(response -> {
                    log.info("📋 [CERT INFO] ✅ Response received, length: {} chars", response != null ? response.length() : 0);
                    log.debug("📋 [CERT INFO] Response Body: {}", response);
                })
                .doOnError(error -> {
                    log.error("📋 [CERT INFO] ❌ Error requesting certificate info: {}", error.getMessage(), error);
                    if (error instanceof WebClientResponseException webEx) {
                        log.error("📋 [CERT INFO] ❌ HTTP Status: {}", webEx.getStatusCode());
                        log.error("📋 [CERT INFO] ❌ Response Body: {}", webEx.getResponseBodyAsString());
                    }
                });
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

        log.info("✍️ [SIGN REQUEST] Endpoint: {}", signatureRemoteServerEndpoint);
        log.info("✍️ [SIGN REQUEST] Credential ID: {}", credentialID);
        log.info("✍️ [SIGN REQUEST] Signature Qualifier: {}", signatureQualifier);
        log.info("✍️ [SIGN REQUEST] Signature Format: {}", signatureFormat);
        log.info("✍️ [SIGN REQUEST] Conformance Level: {}", conformanceLevel);
        log.info("✍️ [SIGN REQUEST] Sign Algorithm: {}", signAlgorithm);
        log.info("✍️ [SIGN REQUEST] Original Document Length: {} chars", signatureRequest.data().length());

        String base64Document = Base64.getEncoder().encodeToString(signatureRequest.data().getBytes(StandardCharsets.UTF_8));
        log.info("✍️ [SIGN REQUEST] Base64 Encoded Document Length: {} chars", base64Document.length());
        
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
            // Sanitize SAD from logs
            String sanitizedBody = requestBodySignature.replaceAll("(\"" + SAD_NAME + "\"\s*:\s*\")[^\"]*", "$1*****");
            log.info("✍️ [SIGN REQUEST] Request Body Length: {} chars", requestBodySignature.length());
            log.debug("✍️ [SIGN REQUEST] Request Body (sanitized): {}", sanitizedBody);
        } catch (JsonProcessingException e) {
            log.error("✍️ [SIGN REQUEST] ❌ Failed to serialize request body", e);
            return Mono.error(new RuntimeException(SERIALIZING_ERROR, e));
        }

        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        log.info("✍️ [SIGN REQUEST] Headers: Authorization=Bearer *****, Content-Type={}", MediaType.APPLICATION_JSON_VALUE);
        
        return httpUtils.postRequest(signatureRemoteServerEndpoint, headers, requestBodySignature)
                .doOnSuccess(response -> {
                    log.info("✍️ [SIGN REQUEST] ✅ Raw response received, length: {} chars", response != null ? response.length() : 0);
                    log.debug("✍️ [SIGN REQUEST] Response Body: {}", response);
                })
                .doOnError(error -> {
                    log.error("✍️ [SIGN REQUEST] ❌ Error sending credential to sign: {}", error.getMessage(), error);
                    if (error instanceof WebClientResponseException webEx) {
                        log.error("✍️ [SIGN REQUEST] ❌ HTTP Status: {}", webEx.getStatusCode());
                        log.error("✍️ [SIGN REQUEST] ❌ Response Body: {}", webEx.getResponseBodyAsString());
                    }
                });
    }

    public Mono<String> processSignatureResponse(SignatureRequest signatureRequest, String responseJson) {
        log.info("📦 [PROCESS RESPONSE] Starting signature response processing");
        log.info("📦 [PROCESS RESPONSE] Response JSON Length: {} chars", responseJson != null ? responseJson.length() : 0);
        log.debug("📦 [PROCESS RESPONSE] Response JSON: {}", responseJson);
        
        return Mono.fromCallable(() -> {
            try {
                Map<String, List<String>> responseMap = objectMapper.readValue(responseJson, Map.class);
                log.info("📦 [PROCESS RESPONSE] Response keys: {}", responseMap.keySet());
                
                List<String> documentsWithSignatureList = responseMap.get("DocumentWithSignature");

                if (documentsWithSignatureList == null || documentsWithSignatureList.isEmpty()) {
                    log.error("📦 [PROCESS RESPONSE] ❌ No signature found in the response");
                    throw new SignatureProcessingException("No signature found in the response");
                }
                
                log.info("📦 [PROCESS RESPONSE] Number of signed documents: {}", documentsWithSignatureList.size());
                String documentsWithSignature = documentsWithSignatureList.get(0);
                log.info("📦 [PROCESS RESPONSE] Signed document (base64) length: {} chars", documentsWithSignature.length());
                
                String documentsWithSignatureDecoded = new String(Base64.getDecoder().decode(documentsWithSignature), StandardCharsets.UTF_8);
                log.info("📦 [PROCESS RESPONSE] Decoded signed document length: {} chars", documentsWithSignatureDecoded.length());
                log.debug("📦 [PROCESS RESPONSE] Decoded signed document: {}", documentsWithSignatureDecoded);
                
                String receivedPayloadDecoded = jwtUtils.decodePayload(documentsWithSignatureDecoded);
                log.info("📦 [PROCESS RESPONSE] Extracted payload length: {} chars", receivedPayloadDecoded.length());
                log.debug("📦 [PROCESS RESPONSE] Extracted payload: {}", receivedPayloadDecoded);
                
                log.info("📦 [PROCESS RESPONSE] Validating payload matches original data...");
                if (jwtUtils.areJsonsEqual(receivedPayloadDecoded, signatureRequest.data())) {
                    log.info("📦 [PROCESS RESPONSE] ✅ Payload validation successful - signatures match");
                    String result = objectMapper.writeValueAsString(Map.of(
                            "type", signatureRequest.configuration().type().name(),
                            "data", documentsWithSignatureDecoded
                    ));
                    log.info("📦 [PROCESS RESPONSE] ✅ Final result prepared, length: {} chars", result.length());
                    return result;
                } else {
                    log.error("📦 [PROCESS RESPONSE] ❌ Payload validation failed - signed payload does not match original");
                    log.error("📦 [PROCESS RESPONSE] ❌ Original data length: {}", signatureRequest.data().length());
                    log.error("📦 [PROCESS RESPONSE] ❌ Received payload length: {}", receivedPayloadDecoded.length());
                    throw new SignatureProcessingException("Signed payload received does not match the original data");
                }
            } catch (JsonProcessingException e) {
                log.error("📦 [PROCESS RESPONSE] ❌ Error parsing signature response", e);
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