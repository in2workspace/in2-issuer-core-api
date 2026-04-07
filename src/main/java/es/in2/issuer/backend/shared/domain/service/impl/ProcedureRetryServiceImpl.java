package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.retry.LabelCredentialDeliveryPayload;
import es.in2.issuer.backend.shared.domain.model.entities.ProcedureRetry;
import es.in2.issuer.backend.shared.domain.model.enums.ActionType;
import es.in2.issuer.backend.shared.domain.model.enums.RetryStatus;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.infrastructure.repository.ProcedureRetryRepository;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.net.ConnectException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeoutException;

@Service
@Slf4j
@RequiredArgsConstructor
public class ProcedureRetryServiceImpl implements ProcedureRetryService {

    private final ProcedureRetryRepository procedureRetryRepository;
    private final ObjectMapper objectMapper;
    private final CredentialDeliveryService credentialDeliveryService;
    private final M2MTokenService m2mTokenService;
    private final EmailService emailService;
    private final CredentialProcedureRepository credentialProcedureRepository;

    // Retry configuration constants - can be overridden via method parameters
    private static final int INITIAL_RETRY_ATTEMPTS = 3;
    private static final Duration[] INITIAL_RETRY_DELAYS = {
            Duration.ofMinutes(1),
            Duration.ofMinutes(5), 
            Duration.ofMinutes(15)
    };
    private static final Duration EXHAUSTION_THRESHOLD = Duration.ofDays(14);

    @Override
    public Mono<Void> createRetryRecord(UUID procedureId, ActionType actionType, Object payload) {
        return Mono.fromCallable(() -> {
            try {
                String payloadJson = objectMapper.writeValueAsString(payload);
                
                ProcedureRetry retryRecord = ProcedureRetry.builder()
                        .id(UUID.randomUUID())
                        .procedureId(procedureId)
                        .actionType(actionType)
                        .status(RetryStatus.PENDING)
                        .attemptCount(0)
                        .firstFailureAt(Instant.now())
                        .payload(payloadJson)
                        .build();
                
                return retryRecord;
            } catch (Exception e) {
                log.error("Error creating retry record payload for procedure {}: {}", procedureId, e.getMessage(), e);
                throw new RuntimeException("Failed to serialize retry payload", e);
            }
        })
        .subscribeOn(Schedulers.boundedElastic())
        .flatMap(procedureRetryRepository::save)
        .flatMap(savedRecord -> sendFirstFailureNotification(savedRecord.getProcedureId(), actionType))
        .doOnSuccess(unused -> log.info("Created retry record for procedure {} with action {}", procedureId, actionType))
        .onErrorResume(e -> {
            log.error("Failed to create retry record for procedure {}: {}", procedureId, e.getMessage(), e);
            return Mono.empty(); // Don't fail the main flow, just log the error
        });
    }

    @Override
    public Mono<Void> retryAction(UUID procedureId, ActionType actionType) {
        return procedureRetryRepository.findByProcedureIdAndActionType(procedureId, actionType)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("No retry record found for procedure " + procedureId + " and action " + actionType)))
                .filter(record -> record.getStatus() == RetryStatus.PENDING)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Retry record is not in PENDING status")))
                .flatMap(this::executeRetryAction);
    }

    @Override
    public Mono<Void> executeUploadLabelToResponseUri(LabelCredentialDeliveryPayload payload) {
        return executeUploadLabelToResponseUri(payload, INITIAL_RETRY_ATTEMPTS, INITIAL_RETRY_DELAYS);
    }

    public Mono<Void> executeUploadLabelToResponseUri(LabelCredentialDeliveryPayload payload, 
                                                      Integer customRetryAttempts, 
                                                      Duration[] customRetryDelays) {
        log.info("Executing upload label credential to response URI: {}", payload.responseUri());
        
        int attempts = customRetryAttempts != null ? customRetryAttempts : INITIAL_RETRY_ATTEMPTS;
        Duration[] delays = customRetryDelays != null ? customRetryDelays : INITIAL_RETRY_DELAYS;
        
        return m2mTokenService.getM2MToken()
                .flatMap(m2mToken -> 
                    credentialDeliveryService.sendVcToResponseUri(
                            payload.responseUri(),
                            payload.signedCredential(),
                            payload.credentialId(),
                            payload.companyEmail(),
                            m2mToken.accessToken()
                    )
                )
                .retryWhen(createInitialRetrySpec("executeUploadLabelToResponseUri", attempts, delays))
                .doOnSuccess(unused -> log.info("Successfully uploaded label credential to response URI"))
                .onErrorMap(e -> {
                    log.error("Failed to upload label credential after retries: {}", e.getMessage(), e);
                    return new RuntimeException("Failed to upload label credential", e);
                });
    }

    @Override
    public Mono<Void> markRetryAsCompleted(UUID procedureId, ActionType actionType) {
        return procedureRetryRepository.findByProcedureIdAndActionType(procedureId, actionType)
                .flatMap(record -> {
                    record.setStatus(RetryStatus.COMPLETED);
                    return procedureRetryRepository.save(record);
                })
                .flatMap(completedRecord -> sendSuccessNotification(procedureId, actionType))
                .doOnSuccess(unused -> log.info("Marked retry as completed for procedure {} with action {}", procedureId, actionType))
                .then();
    }

    @Override
    public Mono<Void> markRetryAsExhausted() {
        return markRetryAsExhausted(EXHAUSTION_THRESHOLD);
    }

    public Mono<Void> markRetryAsExhausted(Duration customExhaustionThreshold) {
        Duration threshold = customExhaustionThreshold != null ? customExhaustionThreshold : EXHAUSTION_THRESHOLD;
        Instant exhaustionThreshold = Instant.now().minus(threshold);
        
        return procedureRetryRepository.findPendingRecordsOlderThan(exhaustionThreshold)
                .flatMap(record -> {
                    log.info("Marking retry as exhausted for procedure {} with action {} (first failure at: {})", 
                            record.getProcedureId(), record.getActionType(), record.getFirstFailureAt());
                    
                    record.setStatus(RetryStatus.RETRY_EXHAUSTED);
                    return procedureRetryRepository.save(record)
                            .flatMap(exhaustedRecord -> sendExhaustionNotification(record.getProcedureId(), record.getActionType()));
                })
                .doOnNext(unused -> log.info("Processed retry exhaustion check"))
                .then();
    }

    @Override
    public Mono<Void> processPendingRetries() {
        return procedureRetryRepository.findByStatus(RetryStatus.PENDING)
                .flatMap(this::executeRetryAction)
                .doOnError(e -> log.error("Error processing retry: {}", e.getMessage(), e))
                .onErrorContinue((error, item) -> log.warn("Continuing after error processing retry: {}", error.getMessage()))
                .then()
                .doOnSuccess(unused -> log.info("Completed processing all pending retries"));
    }

    private Mono<Void> executeRetryAction(ProcedureRetry retryRecord) {
        log.info("Executing retry attempt {} for procedure {} with action {}", 
                retryRecord.getAttemptCount() + 1, retryRecord.getProcedureId(), retryRecord.getActionType());

        return switch (retryRecord.getActionType()) {
            case UPLOAD_LABEL_TO_RESPONSE_URI -> executeUploadRetry(retryRecord);
        };
    }

    private Mono<Void> executeUploadRetry(ProcedureRetry retryRecord) {
        return Mono.fromCallable(() -> {
            try {
                return objectMapper.readValue(retryRecord.getPayload(), LabelCredentialDeliveryPayload.class);
            } catch (Exception e) {
                log.error("Error deserializing retry payload for procedure {}: {}", retryRecord.getProcedureId(), e.getMessage(), e);
                throw new RuntimeException("Failed to deserialize retry payload", e);
            }
        })
        .subscribeOn(Schedulers.boundedElastic())
        .flatMap(this::executeUploadLabelToResponseUri)
        .flatMap(unused -> {
            // Success - mark as completed
            return markRetryAsCompleted(retryRecord.getProcedureId(), retryRecord.getActionType());
        })
        .onErrorResume(e -> {
            // Failure - increment attempt count and update last attempt
            log.warn("Retry attempt failed for procedure {}: {}", retryRecord.getProcedureId(), e.getMessage());
            
            retryRecord.setAttemptCount(retryRecord.getAttemptCount() + 1);
            retryRecord.setLastAttemptAt(Instant.now());
            
            return procedureRetryRepository.save(retryRecord)
                    .doOnSuccess(unused -> log.info("Updated retry record with attempt count {} for procedure {}", 
                            retryRecord.getAttemptCount(), retryRecord.getProcedureId()))
                    .then();
        });
    }

    private Retry createInitialRetrySpec(String operationName) {
        return createInitialRetrySpec(operationName, INITIAL_RETRY_ATTEMPTS, INITIAL_RETRY_DELAYS);
    }

    private Retry createInitialRetrySpec(String operationName, int attempts, Duration[] delays) {
        return Retry.backoff(attempts, delays[0])
                .maxBackoff(delays.length > 2 ? delays[2] : delays[delays.length - 1])
                .jitter(0.2)
                .filter(this::isRecoverableError)
                .doBeforeRetry(retrySignal -> {
                    long attempt = retrySignal.totalRetries() + 1;
                    Duration nextDelay = attempt <= delays.length ? 
                            delays[(int)attempt - 1] : delays[delays.length - 1];
                    
                    log.warn("Retrying {} attempt {} of {}, next delay: {}, reason: {}", 
                            operationName, attempt, attempts, nextDelay, 
                            retrySignal.failure() != null ? retrySignal.failure().getMessage() : "n/a");
                });
    }

    private boolean isRecoverableError(Throwable throwable) {
        if (throwable instanceof WebClientResponseException ex) {
            return ex.getStatusCode().is5xxServerError();
        }
        return throwable instanceof ConnectException || 
               throwable instanceof TimeoutException ||
               throwable instanceof WebClientRequestException;
    }

    private Mono<Void> sendFirstFailureNotification(UUID procedureId, ActionType actionType) {
        return credentialProcedureRepository.findByProcedureId(procedureId)
                .flatMap(credentialProcedure -> {
                    String email = credentialProcedure.getEmail();
                    if (email == null || email.isBlank()) {
                        log.warn("No email found for procedure {}, skipping first failure notification", procedureId);
                        return Mono.empty();
                    }
                    
                    log.info("Sending first failure notification for procedure {} to email {}", procedureId, email);
                    return emailService.sendResponseUriFailed(email, procedureId.toString(), "");
                })
                .doOnSuccess(unused -> log.info("Sent first failure notification for procedure {}", procedureId))
                .onErrorResume(e -> {
                    log.error("Failed to send first failure notification for procedure {}: {}", procedureId, e.getMessage(), e);
                    return Mono.empty();
                });
    }

    private Mono<Void> sendSuccessNotification(UUID procedureId, ActionType actionType) {
        return credentialProcedureRepository.findByProcedureId(procedureId)
                .flatMap(credentialProcedure -> {
                    String email = credentialProcedure.getEmail();
                    if (email == null || email.isBlank()) {
                        log.warn("No email found for procedure {}, skipping success notification", procedureId);
                        return Mono.empty();
                    }
                    
                    log.info("Sending retry success notification for procedure {} to email {}", procedureId, email);
                    return emailService.sendCredentialSignedNotification(
                            email, 
                            "Credential Delivery Successful", 
                            "Your credential has been successfully delivered after retry."
                    );
                })
                .doOnSuccess(unused -> log.info("Sent success notification for procedure {}", procedureId))
                .onErrorResume(e -> {
                    log.error("Failed to send success notification for procedure {}: {}", procedureId, e.getMessage(), e);
                    return Mono.empty();
                });
    }

    private Mono<Void> sendExhaustionNotification(UUID procedureId, ActionType actionType) {
        return credentialProcedureRepository.findByProcedureId(procedureId)
                .flatMap(credentialProcedure -> {
                    String email = credentialProcedure.getEmail();
                    if (email == null || email.isBlank()) {
                        log.warn("No email found for procedure {}, skipping exhaustion notification", procedureId);
                        return Mono.empty();
                    }
                    
                    log.info("Sending retry exhaustion notification for procedure {} to email {}", procedureId, email);
                    return emailService.sendResponseUriFailed(email, procedureId.toString(), "");
                })
                .doOnSuccess(unused -> log.info("Sent exhaustion notification for procedure {}", procedureId))
                .onErrorResume(e -> {
                    log.error("Failed to send exhaustion notification for procedure {}: {}", procedureId, e.getMessage());
                    return Mono.empty();
                });
    }
}