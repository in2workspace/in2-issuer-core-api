-- Create procedure_retry table for retry mechanism
CREATE TABLE IF NOT EXISTS issuer.procedure_retry (
    id uuid PRIMARY KEY UNIQUE DEFAULT uuid_generate_v4(),
    procedure_id uuid NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    attempt_count INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    first_failure_at TIMESTAMPTZ NOT NULL,
    payload TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(320),
    updated_by VARCHAR(320),
    
    -- Foreign key constraint to credential_procedure
    CONSTRAINT fk_procedure_retry_procedure_id 
        FOREIGN KEY (procedure_id) 
        REFERENCES issuer.credential_procedure(procedure_id) 
        ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_procedure_retry_status ON issuer.procedure_retry(status);
CREATE INDEX IF NOT EXISTS idx_procedure_retry_procedure_action ON issuer.procedure_retry(procedure_id, action_type);
CREATE INDEX IF NOT EXISTS idx_procedure_retry_first_failure ON issuer.procedure_retry(first_failure_at);

-- Add comments for documentation
COMMENT ON TABLE issuer.procedure_retry IS 'Tracks retry attempts for external actions that fail after initial execution';
COMMENT ON COLUMN issuer.procedure_retry.action_type IS 'Type of action: UPLOAD_LABEL_TO_RESPONSE_URI, etc.';
COMMENT ON COLUMN issuer.procedure_retry.status IS 'Retry status: PENDING, COMPLETED, RETRY_EXHAUSTED';
COMMENT ON COLUMN issuer.procedure_retry.attempt_count IS 'Number of scheduler-based retry attempts (not Reactor retries)';
COMMENT ON COLUMN issuer.procedure_retry.payload IS 'JSON payload with data needed to reconstruct the action';