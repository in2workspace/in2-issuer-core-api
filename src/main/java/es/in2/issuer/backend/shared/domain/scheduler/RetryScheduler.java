package es.in2.issuer.backend.shared.domain.scheduler;

import es.in2.issuer.backend.shared.domain.service.ProcedureRetryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;

@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class RetryScheduler {

    private final ProcedureRetryService procedureRetryService;

    @Scheduled(fixedRate = 12 * 60 * 60 * 1000) // Every 12 hours (in milliseconds)
    public Mono<Void> processRetries() {
        log.info("Scheduled Task - Executing retry processing at: {}", Instant.now());
        
        return procedureRetryService.processPendingRetries()
                .then(procedureRetryService.markRetryAsExhausted())
                .doOnSuccess(unused -> log.info("Completed scheduled retry processing"))
                .doOnError(e -> log.error("Error during scheduled retry processing: {}", e.getMessage(), e))
                .onErrorResume(e -> Mono.empty()); // Don't let the scheduler stop on errors
    }
}