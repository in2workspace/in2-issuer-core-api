package es.in2.issuer.backend.shared.domain.exception;

public class RetryConfigurationException extends RuntimeException {
    public RetryConfigurationException(String message) {
        super(message);
    }
}
