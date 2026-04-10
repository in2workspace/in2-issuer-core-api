package es.in2.issuer.backend.shared.domain.scheduler;

import es.in2.issuer.backend.backoffice.domain.service.ProcedureRetryService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RetrySchedulerTest {

    @Mock
    private ProcedureRetryService procedureRetryService;

    @InjectMocks
    private RetryScheduler retryScheduler;

    @Test
    void processRetries_bothStepsSucceed_completesAndLogsSuccess() {
        when(procedureRetryService.processPendingRetries()).thenReturn(Mono.empty());
        when(procedureRetryService.markRetryAsExhausted()).thenReturn(Mono.empty());

        StepVerifier.create(retryScheduler.processRetries())
                .verifyComplete();

        verify(procedureRetryService).processPendingRetries();
        verify(procedureRetryService).markRetryAsExhausted();
    }

    @Test
    void processRetries_processPendingRetriesFails_errorSwallowed_schedulerDoesNotStop() {
        // .then() is short-circuited when processPendingRetries fails (its Mono is not subscribed to),
        // but markRetryAsExhausted() is called eagerly to construct the chain.
        // The outer onErrorResume swallows the error so the scheduler keeps running.
        when(procedureRetryService.processPendingRetries())
                .thenReturn(Mono.error(new RuntimeException("Scheduler processing error")));
        when(procedureRetryService.markRetryAsExhausted()).thenReturn(Mono.empty());

        StepVerifier.create(retryScheduler.processRetries())
                .verifyComplete();
    }

    @Test
    void processRetries_markRetryAsExhaustedFails_errorSwallowed_schedulerContinues() {
        when(procedureRetryService.processPendingRetries()).thenReturn(Mono.empty());
        when(procedureRetryService.markRetryAsExhausted())
                .thenReturn(Mono.error(new RuntimeException("Exhaustion check error")));

        StepVerifier.create(retryScheduler.processRetries())
                .verifyComplete();

        verify(procedureRetryService).processPendingRetries();
        verify(procedureRetryService).markRetryAsExhausted();
    }
}
