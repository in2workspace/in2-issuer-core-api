package es.in2.issuer.backend.shared.domain.exception;

public class RetryPayloadException extends RuntimeException {
    public RetryPayloadException(String message) {
        super(message);
    }

    public RetryPayloadException(String message, Throwable cause) {
        super(message, cause);
    }
}
