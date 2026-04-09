# Retry Mechanism Implementation

## Overview

This implementation provides a comprehensive retry mechanism for external actions in the issuer core API. The system handles failures in credential delivery to external response URIs with automatic recovery.

## Key Features

### 1. Initial Execution with Short Retries
- Uses Reactor's `Retry` with configurable delays (default: 5s, 10s, 15s)
- Retries only on recoverable errors (5xx responses, connection issues, timeouts, 408/429/401/403)
- If all initial retries fail, creates a retry record for scheduler-based recovery
- Sends initial failure notification when entering retry mode

### 2. Scheduler-Based Recovery (Configurable interval)
- Processes all PENDING retry records using the same retry logic as initial execution
- Tracks attempt counts (scheduler attempts only, not Reactor retries)
- Updates retry records with success/failure status
- Increments attempt count on each scheduler failure

### 3. Exhaustion Policy (Configurable threshold)
- Marks retries as RETRY_EXHAUSTED after configurable threshold (default: 30 seconds for testing, typically longer in production)
- Sends exhaustion notification when threshold is exceeded
- Prevents infinite retry attempts

### 4. Email Notifications
- **First failure**: `sendResponseUriFailed()` when entering retry mode
- **Success**: `sendCertificationUploaded()` when retry succeeds after initial failure
- **Exhaustion**: `sendResponseUriExhausted()` when retries are exhausted
- **HTML response**: `sendResponseUriAcceptedWithHtml()` if marketplace provides custom HTML response
- No notifications for intermediate retry attempts

## Configuration

The retry behavior can be customized via method parameters when calling the service methods. Default values are:

```java
// Default values (can be overridden)
private static final int INITIAL_RETRY_ATTEMPTS = 3;
private static final Duration[] INITIAL_RETRY_DELAYS = {
    Duration.ofSeconds(5),    // First retry after 5 seconds
    Duration.ofSeconds(10),   // Second retry after 10 seconds  
    Duration.ofSeconds(15)    // Third retry after 15 seconds
    // Note: Original config with minutes commented out for deployment customization:
    // Duration.ofMinutes(1),   // First retry after 1 minute
    // Duration.ofMinutes(5),   // Second retry after 5 minutes  
    // Duration.ofMinutes(15)   // Third retry after 15 minutes
};
private static final Duration EXHAUSTION_THRESHOLD = Duration.ofSeconds(30);
// (Note: This is for testing; production typically uses Duration.ofMinutes(2) or longer)
```

### Usage Examples

```java
// Handle initial action (automatically retries and creates retry record if needed)
UUID procedureId = UUID.randomUUID();
LabelCredentialDeliveryPayload payload = new LabelCredentialDeliveryPayload(...);
procedureRetryService.handleInitialAction(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, payload);

// Process all pending retries (typically called by scheduler)
procedureRetryService.processPendingRetries();

// Manually retry a specific action
procedureRetryService.retryAction(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);

// Mark retry as completed
procedureRetryService.markRetryAsCompleted(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);

// Mark old pending retries as exhausted (using default 30-second threshold)
procedureRetryService.markRetryAsExhausted();

// Mark old pending retries as exhausted (using custom 2-minute threshold)
procedureRetryService.markRetryAsExhausted(Duration.ofMinutes(2));

// Create retry record manually
procedureRetryService.createRetryRecord(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, payload);
```

## Database Schema

### `procedure_retry` Table
- `id`: Unique identifier
- `procedure_id`: Links to credential_procedure
- `action_type`: ENUM (UPLOAD_LABEL_TO_RESPONSE_URI, ...)
- `status`: PENDING, COMPLETED, RETRY_EXHAUSTED
- `attempt_count`: Scheduler-based attempts (not Reactor retries)
- `first_failure_at`: Timestamp of initial failure
- `last_attempt_at`: Timestamp of last scheduler attempt
- `payload`: JSON with action reconstruction data

## Integration Points

### Workflow Integration
- Called via `ProcedureRetryService.handleInitialAction()` after credential signing
- Handles both immediate delivery and retry record creation on failure
- Sends appropriate notifications (success, initial failure, or exhaustion)

### Scheduler Integration
- `ProcedureRetryService.processPendingRetries()` processes all PENDING retry records
- Called by a scheduled task at configurable intervals
- Reuses the same delivery and retry logic as initial execution
- Updates attempt counts and status for each retry

### Components Added
- `ProcedureRetryService`: Service interface for retry operations
- `ProcedureRetryServiceImpl`: Implementation with configurable retry logic
- `ProcedureRetryRepository`: Data access for retry records
- `RetryScheduler`: Scheduled task for processing pending retries
- `LabelCredentialDeliveryPayload`: Payload DTO for delivery/retry operations
- `ActionType`: Enum for action types (UPLOAD_LABEL_TO_RESPONSE_URI, etc.)
- `RetryStatus`: Enum for retry status (PENDING, COMPLETED, RETRY_EXHAUSTED)

## Error Handling

### Recoverable Errors (Will Retry)
- **5xx server errors** (500-599 and similar exceptions)
- **408 Request Timeout**
- **429 Too Many Requests**
- **401 Unauthorized**
- **403 Forbidden**
- **Connection errors** (`ConnectException`)
- **Timeout exceptions** (`TimeoutException`)
- **WebClient request exceptions** (`WebClientRequestException`) 
- **ResponseUriDeliveryException** with any of above status codes

### Non-Recoverable Errors (Will Not Retry)
- 4xx client errors (except 408, 429, 401, 403)
- Validation errors
- Other non-retryable exceptions

## Usage

### For Label Credential Delivery
```java
// The service automatically handles retry on failure
// Called from CredentialSignerWorkflow or similar
UUID procedureId = UUID.randomUUID();
LabelCredentialDeliveryPayload payload = LabelCredentialDeliveryPayload.builder()
    .credentialId("cred-123")
    .responseUri("https://marketplace.example.com/callback")
    .signedCredential("vc_jwt_token")
    .companyEmail("company@example.com")
    .build();

procedureRetryService.handleInitialAction(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI, payload);
// Returns Mono<Void>, will attempt delivery with retries, create retry record if needed, and send notifications
```

### For Scheduler Processing
```java
// Called by scheduled task (e.g., every 12 hours)
procedureRetryService.processPendingRetries();
// Processes all PENDING retry records, updates status, sends notifications
```

### For Manual Retry Operations
```java
// Retry a specific procedure/action
procedureRetryService.retryAction(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);

// Mark as completed manually
procedureRetryService.markRetryAsCompleted(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);

// Mark old pending retries as exhausted
procedureRetryService.markRetryAsExhausted(Duration.ofMinutes(2));
```

## Extending for New Actions

To add support for a new action type:

1. Add new action to `ActionType` enum:
   ```java
   public enum ActionType {
       UPLOAD_LABEL_TO_RESPONSE_URI,
       YOUR_NEW_ACTION
   }
   ```

2. Create a payload DTO for your action (similar to `LabelCredentialDeliveryPayload`)

3. Add a handler method in `ProcedureRetryServiceImpl`:
   ```java
   private Mono<Void> handleScheduledYourNewAction(ProcedureRetry retryRecord) {
       // Implement your action-specific retry logic
   }
   ```

4. Add case to `executeRetryAction()` switch statement:
   ```java
   private Mono<Void> executeRetryAction(ProcedureRetry retryRecord) {
       return switch (retryRecord.getActionType()) {
           case UPLOAD_LABEL_TO_RESPONSE_URI -> handleScheduledLabelDelivery(retryRecord);
           case YOUR_NEW_ACTION -> handleScheduledYourNewAction(retryRecord);
       };
   }
   ```

5. Call from initial workflow similarly to `handleInitialAction()`

## Monitoring

The system provides comprehensive logging for:
- Initial delivery attempts and failures
- Retry record creation
- Scheduler execution
- Retry attempts and outcomes
- Email notification status

All retry operations include procedure IDs and action types for correlation.