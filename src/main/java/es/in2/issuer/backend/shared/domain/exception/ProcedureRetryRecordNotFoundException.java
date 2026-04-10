package es.in2.issuer.backend.shared.domain.exception;

public class ProcedureRetryRecordNotFoundException extends RuntimeException {
    public ProcedureRetryRecordNotFoundException(String message) {
        super(message);
    }
}
