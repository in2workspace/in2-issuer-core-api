package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.shared.domain.exception.RetryConfigurationException;
import es.in2.issuer.backend.shared.domain.model.enums.RetryableActionType;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class RetryableActionHandlerRegistry {

    private final Map<RetryableActionType, RetryableActionHandler<?>> handlers;

    public RetryableActionHandlerRegistry(List<RetryableActionHandler<?>> handlers) {
        this.handlers = handlers.stream()
                .collect(Collectors.toMap(RetryableActionHandler::getActionType, Function.identity()));
    }

    @SuppressWarnings("unchecked")
    public <T> RetryableActionHandler<T> getHandler(RetryableActionType actionType) {
        RetryableActionHandler<?> handler = handlers.get(actionType);
        if (handler == null) {
            throw new RetryConfigurationException("No handler registered for action type: " + actionType);
        }
        return (RetryableActionHandler<T>) handler;
    }
}
