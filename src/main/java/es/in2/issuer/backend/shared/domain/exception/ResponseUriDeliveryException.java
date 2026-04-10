package es.in2.issuer.backend.shared.domain.exception;

import lombok.Getter;

@Getter
public class ResponseUriDeliveryException extends RuntimeException {
    private final int httpStatusCode;
    private final String responseUri;
    private final String credentialId;

    public ResponseUriDeliveryException(String message, int httpStatusCode, String responseUri, String credentialId) {
        super(message);
        this.httpStatusCode = httpStatusCode;
        this.responseUri = responseUri;
        this.credentialId = credentialId;
    }

    public ResponseUriDeliveryException(
            String message,
            int httpStatusCode,
            String responseUri,
            String credentialId,
            Throwable cause
    ) {
        super(message, cause);
        this.httpStatusCode = httpStatusCode;
        this.responseUri = responseUri;
        this.credentialId = credentialId;
    }
}
