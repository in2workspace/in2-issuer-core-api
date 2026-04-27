package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriDeliveryResult;
import es.in2.issuer.backend.shared.domain.model.enums.RetryableActionType;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;

public interface RetryableActionHandler<T> {

    RetryableActionType getActionType();

    Class<T> getPayloadType();

    default int getInitialRetryAttempts() {
        return 3;
    }

    default Duration[] getInitialRetryDelays() {
        return new Duration[]{
                Duration.ofMinutes(2),
                Duration.ofMinutes(5),
                Duration.ofMinutes(15)
        };
    }

    Mono<ResponseUriDeliveryResult> execute(T payload);

    Mono<Void> onInitialSuccess(T payload, ResponseUriDeliveryResult result);

    Mono<Void> onInitialFailure(T payload);

    Mono<Void> onScheduledSuccess(T payload, ResponseUriDeliveryResult result);

    default Mono<Void> onSchedulerFailure(T payload, UUID procedureId) {
        return Mono.empty();
    }

    Mono<Void> onExhausted(T payload, UUID procedureId);
}
