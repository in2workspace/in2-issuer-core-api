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
import java.time.Instant;
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
        Instant startTime = Instant.now();
        log.info("╔════════════════════════════════════════════════════════════════╗");
        log.info("║         SIGN ISSUED CREDENTIAL - START                         ║");
        log.info("╚════════════════════════════════════════════════════════════════╝");
        log.info("📋 [SIGN ISSUED] ⏱️ Start Time: {}", startTime);
        log.info("📋 [SIGN ISSUED] Procedure ID: {}", procedureId);
        log.info("📋 [SIGN ISSUED] Email: {}", email);
        log.info("📋 [SIGN ISSUED] Signature Type: {}", signatureRequest.configuration().type());
        log.info("📋 [SIGN ISSUED] Data Length: {} chars", signatureRequest.data() != null ? signatureRequest.data().length() : 0);
        log.info("📋 [SIGN ISSUED] 🔑 Token (first 50 chars): {}", token != null && token.length() > 50 ? token.substring(0, 50) + "..." : token);
        log.info("📋 [SIGN ISSUED] 📄 Signature Configuration: {}", signatureRequest.configuration());
        log.info("📋 [SIGN ISSUED] 📄 Full Data to Sign:\n{}", signatureRequest.data());

        return signWithRetry(signatureRequest, token, "signIssuedCredential")
                .doOnSuccess(result -> {
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("╔════════════════════════════════════════════════════════════════╗");
                    log.info("║         SIGN ISSUED CREDENTIAL - SUCCESS ✅                    ║");
                    log.info("╚════════════════════════════════════════════════════════════════╝");
                    log.info("📋 [SIGN ISSUED] Successfully Signed");
                    log.info("📋 [SIGN ISSUED] Procedure with id: {}", procedureId);
                    log.info("📋 [SIGN ISSUED] ⏱️ End Time: {}", endTime);
                    log.info("📋 [SIGN ISSUED] ⏱️ Total Duration: {} ms", durationMs);
                    log.info("📋 [SIGN ISSUED] Result Type: {}", result != null ? result.type() : "null");
                    log.info("📋 [SIGN ISSUED] 📄 Signed Data Length: {} chars", result != null && result.data() != null ? result.data().length() : 0);
                    log.info("📋 [SIGN ISSUED] 📄 Full Signed Data:\n{}", result != null ? result.data() : "null");
                    log.info("📋 [SIGN ISSUED] Deleting deferred credential metadata...");
                    deferredCredentialMetadataService.deleteDeferredCredentialMetadataById(procedureId);
                })
                .onErrorResume(throwable -> {
                    Instant errorTime = Instant.now();
                    long durationMs = Duration.between(startTime, errorTime).toMillis();
                    log.error("╔════════════════════════════════════════════════════════════════╗");
                    log.error("║         SIGN ISSUED CREDENTIAL - FAILED ❌                     ║");
                    log.error("╚════════════════════════════════════════════════════════════════╝");
                    log.error("📋 [SIGN ISSUED] Error after 3 retries, switching to ASYNC mode.");
                    log.error("📋 [SIGN ISSUED] ⏱️ Error Time: {}", errorTime);
                    log.error("📋 [SIGN ISSUED] ⏱️ Total Duration until failure: {} ms", durationMs);
                    log.error("📋 [SIGN ISSUED] Error Type: {}", throwable.getClass().getSimpleName());
                    log.error("📋 [SIGN ISSUED] Error Message: {}", throwable.getMessage());
                    log.error("📋 [SIGN ISSUED] 📄 Full Stack Trace:", throwable);
                    if (throwable instanceof WebClientResponseException webEx) {
                        log.error("📋 [SIGN ISSUED] 🌐 HTTP Status Code: {}", webEx.getStatusCode());
                        log.error("📋 [SIGN ISSUED] 🌐 HTTP Status Text: {}", webEx.getStatusText());
                        log.error("📋 [SIGN ISSUED] 🌐 Response Headers: {}", webEx.getHeaders());
                        log.error("📋 [SIGN ISSUED] 🌐 Response Body:\n{}", webEx.getResponseBodyAsString());
                    }
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
        Instant startTime = Instant.now();
        log.info("╔════════════════════════════════════════════════════════════════╗");
        log.info("║         SIGN SYSTEM CREDENTIAL - START                         ║");
        log.info("╚════════════════════════════════════════════════════════════════╝");
        log.info("🔧 [SIGN SYSTEM] ⏱️ Start Time: {}", startTime);
        log.info("🔧 [SIGN SYSTEM] Signature Type: {}", signatureRequest.configuration().type());
        log.info("🔧 [SIGN SYSTEM] Data Length: {} chars", signatureRequest.data() != null ? signatureRequest.data().length() : 0);
        log.info("🔧 [SIGN SYSTEM] 🔑 Token (first 50 chars): {}", token != null && token.length() > 50 ? token.substring(0, 50) + "..." : token);
        log.info("🔧 [SIGN SYSTEM] 📄 Signature Configuration: {}", signatureRequest.configuration());
        log.info("🔧 [SIGN SYSTEM] 📄 Full Data to Sign:\n{}", signatureRequest.data());

        return signWithRetry(signatureRequest, token, "signSystemCredential")
                .doOnSuccess(result -> {
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("╔════════════════════════════════════════════════════════════════╗");
                    log.info("║         SIGN SYSTEM CREDENTIAL - SUCCESS ✅                    ║");
                    log.info("╚════════════════════════════════════════════════════════════════╝");
                    log.info("🔧 [SIGN SYSTEM] ⏱️ End Time: {}", endTime);
                    log.info("🔧 [SIGN SYSTEM] ⏱️ Total Duration: {} ms", durationMs);
                    log.info("🔧 [SIGN SYSTEM] Result Type: {}", result != null ? result.type() : "null");
                    log.info("🔧 [SIGN SYSTEM] 📄 Signed Data Length: {} chars", result != null && result.data() != null ? result.data().length() : 0);
                    log.info("🔧 [SIGN SYSTEM] 📄 Full Signed Data:\n{}", result != null ? result.data() : "null");
                })
                .doOnError(error -> {
                    Instant errorTime = Instant.now();
                    long durationMs = Duration.between(startTime, errorTime).toMillis();
                    log.error("╔════════════════════════════════════════════════════════════════╗");
                    log.error("║         SIGN SYSTEM CREDENTIAL - FAILED ❌                     ║");
                    log.error("╚════════════════════════════════════════════════════════════════╝");
                    log.error("🔧 [SIGN SYSTEM] ⏱️ Error Time: {}", errorTime);
                    log.error("🔧 [SIGN SYSTEM] ⏱️ Total Duration until failure: {} ms", durationMs);
                    log.error("🔧 [SIGN SYSTEM] Error Type: {}", error.getClass().getSimpleName());
                    log.error("🔧 [SIGN SYSTEM] Error Message: {}", error.getMessage());
                    log.error("🔧 [SIGN SYSTEM] 📄 Full Stack Trace:", error);
                    if (error instanceof WebClientResponseException webEx) {
                        log.error("🔧 [SIGN SYSTEM] 🌐 HTTP Status Code: {}", webEx.getStatusCode());
                        log.error("🔧 [SIGN SYSTEM] 🌐 HTTP Status Text: {}", webEx.getStatusText());
                        log.error("🔧 [SIGN SYSTEM] 🌐 Response Headers: {}", webEx.getHeaders());
                        log.error("🔧 [SIGN SYSTEM] 🌐 Response Body:\n{}", webEx.getResponseBodyAsString());
                    }
                });
    }

    private Mono<SignedData> signWithRetry(
            SignatureRequest signatureRequest,
            String token,
            String operationName
    ) {
        Instant retryStartTime = Instant.now();
        log.info("🔄 [RETRY WRAPPER] ════════════════════════════════════════════════════════");
        log.info("🔄 [RETRY WRAPPER] ⏱️ Start Time: {}", retryStartTime);
        log.info("🔄 [RETRY WRAPPER] Starting {} with retry mechanism", operationName);
        log.info("🔄 [RETRY WRAPPER] Retry Configuration: max 3 attempts, backoff 1-5 seconds, jitter 0.5");
        log.info("🔄 [RETRY WRAPPER] 📄 Signature Type: {}", signatureRequest.configuration().type());
        log.info("🔄 [RETRY WRAPPER] 📄 Data Length: {} chars", signatureRequest.data() != null ? signatureRequest.data().length() : 0);

        return Mono.defer(() -> executeSigningFlow(signatureRequest, token))
                .doOnSuccess(signedData -> {
                    int signedLength = (signedData != null && signedData.data() != null)
                            ? signedData.data().length()
                            : 0;

                    Instant successTime = Instant.now();
                    long durationMs = Duration.between(retryStartTime, successTime).toMillis();
                    log.info("🔄 [RETRY WRAPPER] ════════════════════════════════════════════════════════");
                    log.info("🔄 [RETRY WRAPPER] ✅ Remote signing succeeded ({})", operationName);
                    log.info("🔄 [RETRY WRAPPER] ⏱️ Total Duration: {} ms", durationMs);
                    log.info("🔄 [RETRY WRAPPER] 📄 Result Type: {}", signedData != null ? signedData.type() : null);
                    log.info("🔄 [RETRY WRAPPER] 📄 Signed Data Length: {} chars", signedLength);
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

                                    log.warn("🔄 [RETRY WRAPPER] ════════════════════════════════════════════════════════");
                                    log.warn("🔄 [RETRY WRAPPER] ⚠️ Retrying remote signing ({}).", operationName);
                                    log.warn("🔄 [RETRY WRAPPER] ⚠️ Attempt: {} of 3", attempt);
                                    log.warn("🔄 [RETRY WRAPPER] ⚠️ Error Type: {}", errorType);
                                    log.warn("🔄 [RETRY WRAPPER] ⚠️ Error Message: {}", msg);
                                    log.warn("🔄 [RETRY WRAPPER] ⏱️ Time since start: {} ms", Duration.between(retryStartTime, Instant.now()).toMillis());

                                    if (failure instanceof WebClientResponseException webEx) {
                                        log.warn("🔄 [RETRY WRAPPER] ⚠️ HTTP Status Code: {}", webEx.getStatusCode());
                                        log.warn("🔄 [RETRY WRAPPER] ⚠️ HTTP Status Text: {}", webEx.getStatusText());
                                        log.warn("🔄 [RETRY WRAPPER] ⚠️ Response Headers: {}", webEx.getHeaders());
                                        log.warn("🔄 [RETRY WRAPPER] ⚠️ Response Body:\n{}", webEx.getResponseBodyAsString());
                                    }
                                })
                )
                .doOnError(ex -> {
                    Instant errorTime = Instant.now();
                    long durationMs = Duration.between(retryStartTime, errorTime).toMillis();
                    log.error("🔄 [RETRY WRAPPER] ════════════════════════════════════════════════════════");
                    log.error("🔄 [RETRY WRAPPER] ❌ Remote signing failed after all retries ({})", operationName);
                    log.error("🔄 [RETRY WRAPPER] ⏱️ Total Duration until failure: {} ms", durationMs);
                    log.error("🔄 [RETRY WRAPPER] ❌ Final Error Type: {}", ex.getClass().getSimpleName());
                    log.error("🔄 [RETRY WRAPPER] ❌ Final Error Message: {}", ex.getMessage());
                    log.error("🔄 [RETRY WRAPPER] 📄 Full Stack Trace:", ex);
                });
    }

    public boolean isRecoverableError(Throwable throwable) {
        boolean isRecoverable;
        String reason;
        
        if (throwable instanceof WebClientResponseException ex) {
            isRecoverable = ex.getStatusCode().is5xxServerError();
            reason = String.format("WebClientResponseException with status %s (5xx=%s)", ex.getStatusCode(), isRecoverable);
        } else if (throwable instanceof ConnectException) {
            isRecoverable = true;
            reason = "ConnectException - network connectivity issue";
        } else if (throwable instanceof TimeoutException) {
            isRecoverable = true;
            reason = "TimeoutException - request timed out";
        } else {
            isRecoverable = false;
            reason = String.format("Non-recoverable error type: %s", throwable.getClass().getSimpleName());
        }
        
        log.info("🔄 [RECOVERABLE CHECK] Error Type: {}", throwable.getClass().getSimpleName());
        log.info("🔄 [RECOVERABLE CHECK] Error Message: {}", throwable.getMessage());
        log.info("🔄 [RECOVERABLE CHECK] Is Recoverable: {} ({})", isRecoverable, reason);
        
        return isRecoverable;
    }

    public Mono<Boolean> validateCredentials() {
        Instant startTime = Instant.now();
        log.info("🔐 [VALIDATE CREDENTIALS] ════════════════════════════════════════════════════════");
        log.info("🔐 [VALIDATE CREDENTIALS] ⏱️ Start Time: {}", startTime);
        log.info("🔐 [VALIDATE CREDENTIALS] Starting credentials validation");
        SignatureRequest signatureRequest = SignatureRequest.builder().build();
        log.info("🔐 [VALIDATE CREDENTIALS] Built empty signature request for validation");
        
        return requestAccessToken(signatureRequest, SIGNATURE_REMOTE_SCOPE_SERVICE)
                .doOnSuccess(token -> log.info("🔐 [VALIDATE CREDENTIALS] ✅ Access token obtained for validation"))
                .flatMap(this::validateCertificate)
                .doOnSuccess(isValid -> {
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("🔐 [VALIDATE CREDENTIALS] ════════════════════════════════════════════════════════");
                    log.info("🔐 [VALIDATE CREDENTIALS] ✅ Validation completed");
                    log.info("🔐 [VALIDATE CREDENTIALS] ⏱️ Total Duration: {} ms", durationMs);
                    log.info("🔐 [VALIDATE CREDENTIALS] Result: {}", isValid ? "VALID ✅" : "INVALID ❌");
                })
                .doOnError(error -> {
                    Instant errorTime = Instant.now();
                    long durationMs = Duration.between(startTime, errorTime).toMillis();
                    log.error("🔐 [VALIDATE CREDENTIALS] ❌ Validation failed after {} ms", durationMs);
                    log.error("🔐 [VALIDATE CREDENTIALS] ❌ Error: {}", error.getMessage(), error);
                });
    }

    private Mono<SignedData> executeSigningFlow(SignatureRequest signatureRequest, String token) {
        Instant startTime = Instant.now();
        log.info("⚙️ [EXECUTE SIGNING] ════════════════════════════════════════════════════════");
        log.info("⚙️ [EXECUTE SIGNING] ⏱️ Start Time: {}", startTime);
        log.info("⚙️ [EXECUTE SIGNING] Starting signing flow execution");
        log.info("⚙️ [EXECUTE SIGNING] Signature Type: {}", signatureRequest.configuration().type());
        log.info("⚙️ [EXECUTE SIGNING] 📄 Data Length: {} chars", signatureRequest.data() != null ? signatureRequest.data().length() : 0);

        return getSignedSignature(signatureRequest, token)
                .doOnSuccess(response -> {
                    log.info("⚙️ [EXECUTE SIGNING] ✅ Received signed signature response");
                    log.info("⚙️ [EXECUTE SIGNING] 📄 Response Length: {} chars", response != null ? response.length() : 0);
                })
                .flatMap(response -> {
                    try {
                        log.info("⚙️ [EXECUTE SIGNING] Converting response to SignedData...");
                        SignedData signedData = toSignedData(response);
                        Instant endTime = Instant.now();
                        long durationMs = Duration.between(startTime, endTime).toMillis();
                        log.info("⚙️ [EXECUTE SIGNING] ════════════════════════════════════════════════════════");
                        log.info("⚙️ [EXECUTE SIGNING] ✅ Signing flow completed successfully");
                        log.info("⚙️ [EXECUTE SIGNING] ⏱️ Total Duration: {} ms", durationMs);
                        return Mono.just(signedData);
                    } catch (SignedDataParsingException ex) {
                        log.error("⚙️ [EXECUTE SIGNING] ❌ Error parsing signed data: {}", ex.getMessage(), ex);
                        return Mono.error(new RemoteSignatureException("Error parsing signed data", ex));
                    }
                })
                .doOnError(error -> {
                    Instant errorTime = Instant.now();
                    long durationMs = Duration.between(startTime, errorTime).toMillis();
                    log.error("⚙️ [EXECUTE SIGNING] ❌ Signing flow failed after {} ms: {}", durationMs, error.getMessage());
                });
    }

    public Mono<Boolean> validateCertificate(String accessToken) {
        Instant startTime = Instant.now();
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        String credentialListEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/list";

        log.info("📜 [VALIDATE CERT] ════════════════════════════════════════════════════════");
        log.info("📜 [VALIDATE CERT] ⏱️ Start Time: {}", startTime);
        log.info("📜 [VALIDATE CERT] Endpoint: {}", credentialListEndpoint);
        log.info("📜 [VALIDATE CERT] Credential ID to validate: {}", credentialID);
        log.info("📜 [VALIDATE CERT] 🔑 Access Token (first 50 chars): {}", accessToken != null && accessToken.length() > 50 ? accessToken.substring(0, 50) + "..." : accessToken);

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
                        Instant endTime = Instant.now();
                        long durationMs = Duration.between(startTime, endTime).toMillis();
                        log.info("📜 [VALIDATE CERT] ✅ Response received");
                        log.info("📜 [VALIDATE CERT] ⏱️ Request Duration: {} ms", durationMs);
                        log.info("📜 [VALIDATE CERT] 📄 Response Length: {} chars", response != null ? response.length() : 0);
                        log.info("📜 [VALIDATE CERT] 📄 Full Response Body:\n{}", response);
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
        log.info("🔀 [SIGNATURE ROUTING] ════════════════════════════════════════════════════════");
        log.info("🔀 [SIGNATURE ROUTING] Remote Signature Type configured: {}", signatureType);
        log.info("🔀 [SIGNATURE ROUTING] Available types: {} (DSS Server), {} (Cloud External)",
                SIGNATURE_REMOTE_TYPE_SERVER, SIGNATURE_REMOTE_TYPE_CLOUD);
        log.info("🔀 [SIGNATURE ROUTING] Remote Signature Domain: {}", remoteSignatureConfig.getRemoteSignatureDomain());

        return switch (signatureType) {
            case SIGNATURE_REMOTE_TYPE_SERVER -> {
                log.info("🔀 [SIGNATURE ROUTING] ➡️ Routing to DSS Server Service (type={})", signatureType);
                log.info("🔀 [SIGNATURE ROUTING] Sign Path: {}", remoteSignatureConfig.getRemoteSignatureSignPath());
                yield getSignedDocumentDSS(signatureRequest, token);
            }
            case SIGNATURE_REMOTE_TYPE_CLOUD -> {
                log.info("🔀 [SIGNATURE ROUTING] ➡️ Routing to External Cloud Service (type={})", signatureType);
                log.info("🔀 [SIGNATURE ROUTING] Credential ID: {}", remoteSignatureConfig.getRemoteSignatureCredentialId());
                log.info("🔀 [SIGNATURE ROUTING] Client ID: {}", remoteSignatureConfig.getRemoteSignatureClientId());
                yield getSignedDocumentExternal(signatureRequest);
            }
            default -> {
                log.error("🔀 [SIGNATURE ROUTING] ❌ Unknown/Unsupported signature type: {}", signatureType);
                log.error("🔀 [SIGNATURE ROUTING] ❌ Expected one of: {}, {}", SIGNATURE_REMOTE_TYPE_SERVER, SIGNATURE_REMOTE_TYPE_CLOUD);
                yield Mono.error(new RemoteSignatureException("Remote signature service not available"));
            }
        };
    }

    private Mono<String> getSignedDocumentDSS(SignatureRequest signatureRequest, String token) {
        Instant startTime = Instant.now();
        String signatureRemoteServerEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/api/v1"
                + remoteSignatureConfig.getRemoteSignatureSignPath();
        String signatureRequestJSON;

        log.info("🔑 [DSS SIGNATURE] ════════════════════════════════════════════════════════");
        log.info("🔑 [DSS SIGNATURE] ⏱️ Start Time: {}", startTime);
        log.info("🔑 [DSS SIGNATURE] Requesting signature to DSS service");
        log.info("🔑 [DSS SIGNATURE] Endpoint: {}", signatureRemoteServerEndpoint);
        log.info("🔑 [DSS SIGNATURE] 🔑 Token (first 50 chars): {}", token != null && token.length() > 50 ? token.substring(0, 50) + "..." : token);

        try {
            signatureRequestJSON = objectMapper.writeValueAsString(signatureRequest);
            log.info("🔑 [DSS SIGNATURE] 📤 Request Body Length: {} chars", signatureRequestJSON.length());
            log.info("🔑 [DSS SIGNATURE] 📤 Full Request Body:\n{}", signatureRequestJSON);
        } catch (JsonProcessingException e) {
            log.error("🔑 [DSS SIGNATURE] ❌ Failed to serialize request body", e);
            return Mono.error(new RemoteSignatureException(SERIALIZING_ERROR, e));
        }
        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, token));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        log.info("🔑 [DSS SIGNATURE] 📤 Headers: Authorization={}, Content-Type={}", token != null && token.length() > 30 ? token.substring(0, 30) + "..." : token, MediaType.APPLICATION_JSON_VALUE);

        return httpUtils.postRequest(signatureRemoteServerEndpoint, headers, signatureRequestJSON)
                .doOnSuccess(response -> {
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("🔑 [DSS SIGNATURE] ✅ Response received");
                    log.info("🔑 [DSS SIGNATURE] ⏱️ Request Duration: {} ms", durationMs);
                    log.info("🔑 [DSS SIGNATURE] 📥 Response Length: {} chars", response != null ? response.length() : 0);
                    log.info("🔑 [DSS SIGNATURE] 📥 Full Response Body:\n{}", response);
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
        Instant startTime = Instant.now();
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] ══════════════════════════════════════════════════");
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] ⏱️ Start Time: {}", startTime);
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] Requesting signature to external cloud service");
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] Signature Type: {}", signatureRequest.configuration().type());
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] 📄 Configuration: {}", signatureRequest.configuration());
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] 📄 Data to Sign Length: {} chars", signatureRequest.data() != null ? signatureRequest.data().length() : 0);
        log.info("🌐 [EXTERNAL SIGNATURE FLOW] 📄 Full Data to Sign:\n{}", signatureRequest.data());

        return requestAccessToken(signatureRequest, SIGNATURE_REMOTE_SCOPE_CREDENTIAL)
                .doOnSuccess(token -> {
                    log.info("🌐 [EXTERNAL SIGNATURE FLOW] ✅ Step 1/3: Access Token obtained");
                    log.info("🌐 [EXTERNAL SIGNATURE FLOW] 🔑 Token Length: {} chars", token != null ? token.length() : 0);
                })
                .flatMap(accessToken -> requestSad(accessToken)
                        .doOnSuccess(sad -> {
                            log.info("🌐 [EXTERNAL SIGNATURE FLOW] ✅ Step 2/3: SAD obtained");
                            log.info("🌐 [EXTERNAL SIGNATURE FLOW] 🔐 SAD Length: {} chars", sad != null ? sad.length() : 0);
                        })
                        .flatMap(sad -> sendSignatureRequest(signatureRequest, accessToken, sad)
                                .doOnSuccess(response -> {
                                    log.info("🌐 [EXTERNAL SIGNATURE FLOW] ✅ Step 3/3: Signature response received");
                                    log.info("🌐 [EXTERNAL SIGNATURE FLOW] 📥 Response Length: {} chars", response != null ? response.length() : 0);
                                })
                                .flatMap(responseJson -> processSignatureResponse(signatureRequest, responseJson)
                                        .doOnSuccess(result -> {
                                            Instant endTime = Instant.now();
                                            long durationMs = Duration.between(startTime, endTime).toMillis();
                                            log.info("🌐 [EXTERNAL SIGNATURE FLOW] ══════════════════════════════════════════════════");
                                            log.info("🌐 [EXTERNAL SIGNATURE FLOW] ⏱️ Total Duration: {} ms", durationMs);
                                            log.info("🌐 [EXTERNAL SIGNATURE FLOW] ✅ EXTERNAL SIGNATURE FLOW COMPLETED");
                                            log.info("🌐 [EXTERNAL SIGNATURE FLOW] 📄 Final Result Length: {} chars", result != null ? result.length() : 0);
                                        }))))
                .doOnError(error -> {
                    Instant errorTime = Instant.now();
                    long durationMs = Duration.between(startTime, errorTime).toMillis();
                    log.error("🌐 [EXTERNAL SIGNATURE FLOW] ❌ Flow failed after {} ms", durationMs);
                    log.error("🌐 [EXTERNAL SIGNATURE FLOW] ❌ Error Type: {}", error.getClass().getSimpleName());
                    log.error("🌐 [EXTERNAL SIGNATURE FLOW] ❌ Error Message: {}", error.getMessage());
                    log.error("🌐 [EXTERNAL SIGNATURE FLOW] 📄 Full Stack Trace:", error);
                    if (error instanceof WebClientResponseException webEx) {
                        log.error("🌐 [EXTERNAL SIGNATURE FLOW] 🌐 HTTP Status: {}", webEx.getStatusCode());
                        log.error("🌐 [EXTERNAL SIGNATURE FLOW] 🌐 Response Headers: {}", webEx.getHeaders());
                        log.error("🌐 [EXTERNAL SIGNATURE FLOW] 🌐 Response Body:\n{}", webEx.getResponseBodyAsString());
                    }
                });
    }

    public Mono<String> requestSad(String accessToken) {
        Instant startTime = Instant.now();
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        int numSignatures = 1;
        String authDataId = "password";
        String authDataValue = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        String signatureGetSadEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/authorize";

        log.info("🔐 [REQUEST SAD] ════════════════════════════════════════════════════════");
        log.info("🔐 [REQUEST SAD] ⏱️ Start Time: {}", startTime);
        log.info("🔐 [REQUEST SAD] Endpoint: {}", signatureGetSadEndpoint);
        log.info("🔐 [REQUEST SAD] Credential ID: {}", credentialID);
        log.info("🔐 [REQUEST SAD] Number of Signatures: {}", numSignatures);
        log.info("🔐 [REQUEST SAD] 🔑 Access Token (first 50 chars): {}", accessToken != null && accessToken.length() > 50 ? accessToken.substring(0, 50) + "..." : accessToken);

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
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("🔐 [REQUEST SAD] ✅ Raw response received");
                    log.info("🔐 [REQUEST SAD] ⏱️ Request Duration: {} ms", durationMs);
                    log.info("🔐 [REQUEST SAD] 📥 Response Length: {} chars", response != null ? response.length() : 0);
                    log.info("🔐 [REQUEST SAD] 📥 Full Response Body:\n{}", response);
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
        Instant startTime = Instant.now();
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        credentialPassword = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        clientId = remoteSignatureConfig.getRemoteSignatureClientId();
        clientSecret = remoteSignatureConfig.getRemoteSignatureClientSecret();
        String grantType = "client_credentials";
        String signatureGetAccessTokenEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/oauth2/token";
        String hashAlgorithmOID = "2.16.840.1.101.3.4.2.1";

        log.info("🎫 [ACCESS TOKEN] ════════════════════════════════════════════════════════");
        log.info("🎫 [ACCESS TOKEN] ⏱️ Start Time: {}", startTime);
        log.info("🎫 [ACCESS TOKEN] Endpoint: {}", signatureGetAccessTokenEndpoint);
        log.info("🎫 [ACCESS TOKEN] Grant Type: {}", grantType);
        log.info("🎫 [ACCESS TOKEN] Scope: {}", scope);
        log.info("🎫 [ACCESS TOKEN] Client ID: {}", clientId);
        log.info("🎫 [ACCESS TOKEN] Credential ID: {}", credentialID);
        log.info("🎫 [ACCESS TOKEN] Hash Algorithm OID: {}", hashAlgorithmOID);

        requestBody.clear();
        requestBody.put("grant_type", grantType);
        requestBody.put("scope", scope);
        if (scope.equals(SIGNATURE_REMOTE_SCOPE_CREDENTIAL)) {
            String authDetails = buildAuthorizationDetails(signatureRequest.data(), hashAlgorithmOID);
            requestBody.put("authorization_details", authDetails);
            log.info("🎫 [ACCESS TOKEN] Authorization Details included (length: {} chars)", authDetails.length());
            log.info("🎫 [ACCESS TOKEN] 📄 Authorization Details:\n{}", authDetails);
        }

        String requestBodyString = requestBody.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .reduce((p1, p2) -> p1 + "&" + p2)
                .orElse("");

        log.info("🎫 [ACCESS TOKEN] 📤 Request Body Length: {} chars", requestBodyString.length());
        log.info("🎫 [ACCESS TOKEN] 📤 Full Request Body (form-urlencoded):\n{}", requestBodyString);

        String basicAuthHeader = "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, basicAuthHeader));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
        log.info("🎫 [ACCESS TOKEN] Headers: Authorization=Basic *****, Content-Type={}", MediaType.APPLICATION_FORM_URLENCODED_VALUE);

        return httpUtils.postRequest(signatureGetAccessTokenEndpoint, headers, requestBodyString)
                .doOnSuccess(response -> {
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("🎫 [ACCESS TOKEN] ✅ Raw response received");
                    log.info("🎫 [ACCESS TOKEN] ⏱️ Request Duration: {} ms", durationMs);
                    log.info("🎫 [ACCESS TOKEN] 📥 Response Length: {} chars", response != null ? response.length() : 0);
                    log.info("🎫 [ACCESS TOKEN] 📥 Full Response Body:\n{}", response);
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
        Instant startTime = Instant.now();
        String credentialsInfoEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/info";

        log.info("📋 [CERT INFO] ════════════════════════════════════════════════════════");
        log.info("📋 [CERT INFO] ⏱️ Start Time: {}", startTime);
        log.info("📋 [CERT INFO] Endpoint: {}", credentialsInfoEndpoint);
        log.info("📋 [CERT INFO] Credential ID: {}", credentialID);
        log.info("📋 [CERT INFO] 🔑 Access Token (first 50 chars): {}", accessToken != null && accessToken.length() > 50 ? accessToken.substring(0, 50) + "..." : accessToken);

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
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("📋 [CERT INFO] ✅ Response received");
                    log.info("📋 [CERT INFO] ⏱️ Request Duration: {} ms", durationMs);
                    log.info("📋 [CERT INFO] 📥 Response Length: {} chars", response != null ? response.length() : 0);
                    log.info("📋 [CERT INFO] 📥 Full Response Body:\n{}", response);
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
        Instant startTime = Instant.now();
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        String signatureRemoteServerEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/signatures/signDoc";
        String signatureQualifier = "eu_eidas_aesealqc";
        String signatureFormat = "J";
        String conformanceLevel = "Ades-B";
        String signAlgorithm = "OID_sign_algorithm";

        log.info("✍️ [SIGN REQUEST] ════════════════════════════════════════════════════════");
        log.info("✍️ [SIGN REQUEST] ⏱️ Start Time: {}", startTime);
        log.info("✍️ [SIGN REQUEST] Endpoint: {}", signatureRemoteServerEndpoint);
        log.info("✍️ [SIGN REQUEST] Credential ID: {}", credentialID);
        log.info("✍️ [SIGN REQUEST] Signature Qualifier: {}", signatureQualifier);
        log.info("✍️ [SIGN REQUEST] Signature Format: {}", signatureFormat);
        log.info("✍️ [SIGN REQUEST] Conformance Level: {}", conformanceLevel);
        log.info("✍️ [SIGN REQUEST] Sign Algorithm: {}", signAlgorithm);
        log.info("✍️ [SIGN REQUEST] 🔑 Access Token (first 50 chars): {}", accessToken != null && accessToken.length() > 50 ? accessToken.substring(0, 50) + "..." : accessToken);
        log.info("✍️ [SIGN REQUEST] 🔐 SAD (first 50 chars): {}", sad != null && sad.length() > 50 ? sad.substring(0, 50) + "..." : sad);
        log.info("✍️ [SIGN REQUEST] 📄 Original Document Length: {} chars", signatureRequest.data().length());
        log.info("✍️ [SIGN REQUEST] 📄 Original Document:\n{}", signatureRequest.data());

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
            log.info("✍️ [SIGN REQUEST] 📤 Request Body Length: {} chars", requestBodySignature.length());
            log.info("✍️ [SIGN REQUEST] 📤 Full Request Body (sanitized):\n{}", sanitizedBody);
        } catch (JsonProcessingException e) {
            log.error("✍️ [SIGN REQUEST] ❌ Failed to serialize request body", e);
            return Mono.error(new RuntimeException(SERIALIZING_ERROR, e));
        }

        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        log.info("✍️ [SIGN REQUEST] 📤 Headers: Authorization=Bearer *****, Content-Type={}", MediaType.APPLICATION_JSON_VALUE);

        return httpUtils.postRequest(signatureRemoteServerEndpoint, headers, requestBodySignature)
                .doOnSuccess(response -> {
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("✍️ [SIGN REQUEST] ✅ Raw response received");
                    log.info("✍️ [SIGN REQUEST] ⏱️ Request Duration: {} ms", durationMs);
                    log.info("✍️ [SIGN REQUEST] 📥 Response Length: {} chars", response != null ? response.length() : 0);
                    log.info("✍️ [SIGN REQUEST] 📥 Full Response Body:\n{}", response);
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
        Instant startTime = Instant.now();
        log.info("📦 [PROCESS RESPONSE] ════════════════════════════════════════════════════════");
        log.info("📦 [PROCESS RESPONSE] ⏱️ Start Time: {}", startTime);
        log.info("📦 [PROCESS RESPONSE] Starting signature response processing");
        log.info("📦 [PROCESS RESPONSE] 📥 Response JSON Length: {} chars", responseJson != null ? responseJson.length() : 0);
        log.info("📦 [PROCESS RESPONSE] 📥 Full Response JSON:\n{}", responseJson);

        return Mono.fromCallable(() -> {
            try {
                Map<String, List<String>> responseMap = objectMapper.readValue(responseJson, Map.class);
                log.info("📦 [PROCESS RESPONSE] Response keys: {}", responseMap.keySet());
                log.info("📦 [PROCESS RESPONSE] 📄 Full Response Map: {}", responseMap);

                List<String> documentsWithSignatureList = responseMap.get("DocumentWithSignature");

                if (documentsWithSignatureList == null || documentsWithSignatureList.isEmpty()) {
                    log.error("📦 [PROCESS RESPONSE] ❌ No signature found in the response");
                    log.error("📦 [PROCESS RESPONSE] ❌ Available keys in response: {}", responseMap.keySet());
                    throw new SignatureProcessingException("No signature found in the response");
                }

                log.info("📦 [PROCESS RESPONSE] Number of signed documents: {}", documentsWithSignatureList.size());
                String documentsWithSignature = documentsWithSignatureList.get(0);
                log.info("📦 [PROCESS RESPONSE] 📄 Signed document (base64) length: {} chars", documentsWithSignature.length());
                log.info("📦 [PROCESS RESPONSE] 📄 Signed document (base64):\n{}", documentsWithSignature);

                String documentsWithSignatureDecoded = new String(Base64.getDecoder().decode(documentsWithSignature), StandardCharsets.UTF_8);
                log.info("📦 [PROCESS RESPONSE] 📄 Decoded signed document length: {} chars", documentsWithSignatureDecoded.length());
                log.info("📦 [PROCESS RESPONSE] 📄 Decoded signed document (JWT):\n{}", documentsWithSignatureDecoded);

                String receivedPayloadDecoded = jwtUtils.decodePayload(documentsWithSignatureDecoded);
                log.info("📦 [PROCESS RESPONSE] 📄 Extracted payload length: {} chars", receivedPayloadDecoded.length());
                log.info("📦 [PROCESS RESPONSE] 📄 Extracted payload:\n{}", receivedPayloadDecoded);

                log.info("📦 [PROCESS RESPONSE] 🔍 Validating payload matches original data...");
                log.info("📦 [PROCESS RESPONSE] 📄 Original data for comparison:\n{}", signatureRequest.data());
                if (jwtUtils.areJsonsEqual(receivedPayloadDecoded, signatureRequest.data())) {
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("📦 [PROCESS RESPONSE] ✅ Payload validation successful - signatures match");
                    log.info("📦 [PROCESS RESPONSE] ⏱️ Processing Duration: {} ms", durationMs);
                    String result = objectMapper.writeValueAsString(Map.of(
                            "type", signatureRequest.configuration().type().name(),
                            "data", documentsWithSignatureDecoded
                    ));
                    log.info("📦 [PROCESS RESPONSE] ✅ Final result prepared, length: {} chars", result.length());
                    log.info("📦 [PROCESS RESPONSE] 📄 Final Result:\n{}", result);
                    return result;
                } else {
                    log.error("📦 [PROCESS RESPONSE] ❌ Payload validation failed - signed payload does not match original");
                    log.error("📦 [PROCESS RESPONSE] ❌ Original data length: {}", signatureRequest.data().length());
                    log.error("📦 [PROCESS RESPONSE] ❌ Received payload length: {}", receivedPayloadDecoded.length());
                    log.error("📦 [PROCESS RESPONSE] ❌ Original data:\n{}", signatureRequest.data());
                    log.error("📦 [PROCESS RESPONSE] ❌ Received payload:\n{}", receivedPayloadDecoded);
                    throw new SignatureProcessingException("Signed payload received does not match the original data");
                }
            } catch (JsonProcessingException e) {
                log.error("📦 [PROCESS RESPONSE] ❌ Error parsing signature response", e);
                throw new SignatureProcessingException("Error parsing signature response", e);
            }
        });
    }

    private String buildAuthorizationDetails(String unsignedCredential, String hashAlgorithmOID) {
        log.info("🔒 [AUTH DETAILS] ════════════════════════════════════════════════════════");
        log.info("🔒 [AUTH DETAILS] Building authorization details for credential signing");
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        credentialPassword = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        log.info("🔒 [AUTH DETAILS] Credential ID: {}", credentialID);
        log.info("🔒 [AUTH DETAILS] Hash Algorithm OID: {}", hashAlgorithmOID);
        log.info("🔒 [AUTH DETAILS] 📄 Unsigned Credential Length: {} chars", unsignedCredential != null ? unsignedCredential.length() : 0);
        log.info("🔒 [AUTH DETAILS] 📄 Unsigned Credential:\n{}", unsignedCredential);
        try {
            Map<String, Object> authorizationDetails = new HashMap<>();
            authorizationDetails.put("type", SIGNATURE_REMOTE_SCOPE_CREDENTIAL);
            authorizationDetails.put(CREDENTIAL_ID, credentialID);
            authorizationDetails.put("credentialPassword", credentialPassword);
            String hashedCredential = hashGeneratorService.generateHash(unsignedCredential, hashAlgorithmOID);
            log.info("🔒 [AUTH DETAILS] 🔐 Hashed Credential: {}", hashedCredential);
            List<Map<String, String>> documentDigests = null;
            if (hashedCredential != null) {
                documentDigests = List.of(
                        Map.of("hash", hashedCredential, "label", "Issued Credential")
                );
                log.info("🔒 [AUTH DETAILS] 📄 Document Digests: {}", documentDigests);
            }
            authorizationDetails.put("documentDigests", documentDigests);
            authorizationDetails.put("hashAlgorithmOID", hashAlgorithmOID);

            String result = objectMapper.writeValueAsString(List.of(authorizationDetails));
            log.info("🔒 [AUTH DETAILS] ✅ Authorization details built successfully");
            log.info("🔒 [AUTH DETAILS] 📄 Result Length: {} chars", result.length());
            log.info("🔒 [AUTH DETAILS] 📄 Full Authorization Details:\n{}", result);
            return result;
        } catch (JsonProcessingException | HashGenerationException e) {
            log.error("🔒 [AUTH DETAILS] ❌ Error generating authorization details: {}", e.getMessage(), e);
            throw new AuthorizationDetailsException("Error generating authorization details", e);
        }
    }


    private SignedData toSignedData(String signedSignatureResponse) throws SignedDataParsingException {
        log.info("🔄 [TO SIGNED DATA] Converting response to SignedData object");
        log.info("🔄 [TO SIGNED DATA] 📄 Input Length: {} chars", signedSignatureResponse != null ? signedSignatureResponse.length() : 0);
        log.info("🔄 [TO SIGNED DATA] 📄 Input:\n{}", signedSignatureResponse);
        try {
            SignedData result = objectMapper.readValue(signedSignatureResponse, SignedData.class);
            log.info("🔄 [TO SIGNED DATA] ✅ Successfully parsed SignedData");
            log.info("🔄 [TO SIGNED DATA] 📄 Result Type: {}", result.type());
            log.info("🔄 [TO SIGNED DATA] 📄 Result Data Length: {} chars", result.data() != null ? result.data().length() : 0);
            return result;
        } catch (IOException e) {
            log.error("🔄 [TO SIGNED DATA] ❌ Error parsing signed data: {}", e.getMessage(), e);
            throw new SignedDataParsingException("Error parsing signed data");
        }
    }

    public Mono<Void> handlePostRecoverError(String procedureId, String email) {
        Instant startTime = Instant.now();
        log.info("🔄 [POST RECOVER] ════════════════════════════════════════════════════════");
        log.info("🔄 [POST RECOVER] ⏱️ Start Time: {}", startTime);
        log.info("🔄 [POST RECOVER] Starting post-recovery error handling");
        log.info("🔄 [POST RECOVER] Procedure ID: {}", procedureId);
        log.info("🔄 [POST RECOVER] Received Email: {}", email);

        UUID id = UUID.fromString(procedureId);
        String domain = appConfig.getIssuerFrontendUrl();
        log.info("🔄 [POST RECOVER] Issuer Frontend URL: {}", domain);

        // Fetch once and reuse the same result
        Mono<CredentialProcedure> cachedProc = credentialProcedureRepository
                .findByProcedureId(id)
                .doOnSuccess(proc -> {
                    if (proc != null) {
                        log.info("🔄 [POST RECOVER] ✅ Found CredentialProcedure for ID: {}", procedureId);
                        log.info("🔄 [POST RECOVER] 📄 Current Status: {}", proc.getCredentialStatus());
                        log.info("🔄 [POST RECOVER] 📄 Current Operation Mode: {}", proc.getOperationMode());
                        log.info("🔄 [POST RECOVER] 📄 Organization: {}", proc.getOrganizationIdentifier());
                        log.info("🔄 [POST RECOVER] 📄 Updated By: {}", proc.getUpdatedBy());
                    }
                })
                .switchIfEmpty(Mono.fromRunnable(() -> 
                        log.error("🔄 [POST RECOVER] ❌ No CredentialProcedure found for ID: {}", procedureId)
                ).then(Mono.error(new IllegalArgumentException("No CredentialProcedure for " + procedureId))))
                .cache();

        // Update operation mode and status
        Mono<Void> updateOperationMode = cachedProc
                .flatMap(cp -> {
                    log.info("🔄 [POST RECOVER] 🔧 Updating CredentialProcedure operation mode to ASYNC");
                    log.info("🔄 [POST RECOVER] 🔧 Updating status to PEND_SIGNATURE");
                    cp.setOperationMode(ASYNC);
                    cp.setCredentialStatus(CredentialStatusEnum.PEND_SIGNATURE);
                    return credentialProcedureRepository.save(cp)
                            .doOnSuccess(saved -> {
                                log.info("🔄 [POST RECOVER] ✅ CredentialProcedure updated successfully");
                                log.info("🔄 [POST RECOVER] 📄 New Status: {}", saved.getCredentialStatus());
                                log.info("🔄 [POST RECOVER] 📄 New Operation Mode: {}", saved.getOperationMode());
                            })
                            .then();
                });

        // Update deferred metadata
        Mono<Void> updateDeferredMetadata = deferredCredentialMetadataRepository.findByProcedureId(id)
                .doOnSuccess(deferred -> {
                    if (deferred != null) {
                        log.info("🔄 [POST RECOVER] ✅ Found DeferredCredentialMetadata for procedure ID: {}", procedureId);
                        log.info("🔄 [POST RECOVER] 📄 Current Deferred Operation Mode: {}", deferred.getOperationMode());
                    }
                })
                .switchIfEmpty(Mono.fromRunnable(() ->
                        log.error("🔄 [POST RECOVER] ⚠️ No deferred metadata found for procedureId: {}", procedureId)
                ).then(Mono.empty()))
                .flatMap(deferred -> {
                    log.info("🔄 [POST RECOVER] 🔧 Updating DeferredCredentialMetadata operation mode to ASYNC");
                    deferred.setOperationMode(ASYNC);
                    return deferredCredentialMetadataRepository.save(deferred)
                            .doOnSuccess(saved -> {
                                log.info("🔄 [POST RECOVER] ✅ DeferredCredentialMetadata updated successfully");
                                log.info("🔄 [POST RECOVER] 📄 New Deferred Operation Mode: {}", saved.getOperationMode());
                            })
                            .then();
                });

        // Send email using provided email or fallback to updatedBy value
        Mono<Void> sendEmail = cachedProc.flatMap(cp -> {
            String org = cp.getOrganizationIdentifier();
            String updatedBy = cp.getUpdatedBy();
            log.info("🔄 [POST RECOVER] 📧 Preparing to send notification email");
            log.info("🔄 [POST RECOVER] 📧 Organization: {}", org);
            log.info("🔄 [POST RECOVER] 📧 Updated By (fallback email): {}", updatedBy);

            String targetEmail = (email != null && !email.isBlank()) ? email : updatedBy;
            log.info("🔄 [POST RECOVER] 📧 Target Email (after fallback logic): {}", targetEmail);
            log.info("🔄 [POST RECOVER] 📧 Email Template: email.pending-credential-notification");
            log.info("🔄 [POST RECOVER] 📧 Domain for link: {}", domain);

            return emailService.sendPendingSignatureCredentialNotification(
                    targetEmail,
                    "email.pending-credential-notification",
                    procedureId,
                    domain
            ).doOnSuccess(v -> log.info("🔄 [POST RECOVER] ✅ Notification email sent successfully to: {}", targetEmail))
             .doOnError(e -> log.error("🔄 [POST RECOVER] ❌ Failed to send notification email to: {} - Error: {}", targetEmail, e.getMessage()));
        });

        return updateOperationMode
                .then(updateDeferredMetadata)
                .then(sendEmail)
                .doOnSuccess(v -> {
                    Instant endTime = Instant.now();
                    long durationMs = Duration.between(startTime, endTime).toMillis();
                    log.info("🔄 [POST RECOVER] ════════════════════════════════════════════════════════");
                    log.info("🔄 [POST RECOVER] ✅ Post-recovery error handling completed successfully");
                    log.info("🔄 [POST RECOVER] ⏱️ Total Duration: {} ms", durationMs);
                })
                .doOnError(e -> {
                    Instant errorTime = Instant.now();
                    long durationMs = Duration.between(startTime, errorTime).toMillis();
                    log.error("🔄 [POST RECOVER] ════════════════════════════════════════════════════════");
                    log.error("🔄 [POST RECOVER] ❌ Post-recovery error handling failed after {} ms", durationMs);
                    log.error("🔄 [POST RECOVER] ❌ Error: {}", e.getMessage(), e);
                });
    }

}