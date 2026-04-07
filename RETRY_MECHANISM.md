# Retry Mechanism Implementation

## Overview

This implementation provides a comprehensive retry mechanism for external actions in the issuer core API. The system handles failures in credential delivery to external response URIs with automatic recovery.

## Key Features

### 1. Initial Execution with Short Retries
- Uses Reactor's `Retry.backoff()` with configurable delays (default: 1min, 5min, 15min)
- Retries only on recoverable errors (5xx responses, connection issues, timeouts)
- If all initial retries fail, creates a retry record for scheduler-based recovery

### 2. Scheduler-Based Recovery (Every 12 hours)
- Processes all PENDING retry records using the same retry logic as initial execution
- Tracks attempt counts (scheduler attempts only, not Reactor retries)
- Updates retry records with success/failure status

### 3. Exhaustion Policy (14 days)
- Marks retries as RETRY_EXHAUSTED after configurable threshold
- Prevents infinite retry attempts

### 4. Email Notifications
- **First failure**: When entering retry mode
- **Success**: When retry succeeds after initial failure
- **Exhaustion**: When retries are exhausted after 14 days
- No notifications for intermediate retry attempts

## Configuration

The retry behavior can be customized via method parameters when calling the service methods. Default values are:

```java
// Default values (can be overridden)
private static final int INITIAL_RETRY_ATTEMPTS = 3;
private static final Duration[] INITIAL_RETRY_DELAYS = {
    Duration.ofMinutes(1),   // First retry after 1 minute
    Duration.ofMinutes(5),   // Second retry after 5 minutes  
    Duration.ofMinutes(15)   // Third retry after 15 minutes
};
private static final Duration EXHAUSTION_THRESHOLD = Duration.ofDays(14);
```

### Usage Examples

```java
// Using default retry parameters
procedureRetryService.executeUploadLabelToResponseUri(payload);

// Using custom retry parameters
Duration[] customDelays = {Duration.ofMinutes(2), Duration.ofMinutes(10), Duration.ofMinutes(30)};
procedureRetryService.executeUploadLabelToResponseUri(payload, 5, customDelays);

// Using default exhaustion threshold
procedureRetryService.markRetryAsExhausted();

// Using custom exhaustion threshold (7 days instead of 14)
procedureRetryService.markRetryAsExhausted(Duration.ofDays(7));
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

### CredentialSignerWorkflowImpl
- **Before**: Direct call to `credentialDeliveryService.sendVcToResponseUri()`
- **After**: Calls `deliverLabelCredentialWithRetry()` which handles both initial attempts and retry record creation
- **M2M Authentication**: Still present, moved to `ProcedureRetryService.executeUploadLabelToResponseUri()`

### Components Added
- `ProcedureRetryService`: Service interface for retry operations
- `ProcedureRetryServiceImpl`: Implementation with configurable retry logic
- `RetryScheduler`: Scheduled task running every 12 hours
- `RetryConfiguration`: Spring Boot configuration properties
- `LabelCredentialDeliveryPayload`: Payload for delivery/retry operations
- `ActionType` & `RetryStatus`: Enums for action types and retry status

## Error Handling

### Recoverable Errors (Will Retry)
- 5xx server errors (`WebClientResponseException` with 5xx status)
- Connection exceptions (`ConnectException`)
- Timeout exceptions (`TimeoutException`)
- WebClient request exceptions (`WebClientRequestException`)

### Non-Recoverable Errors (Will Not Retry)
- 4xx client errors
- Authentication/authorization failures
- Validation errors

## Usage

### For Label Credential Delivery
```java
// The workflow automatically handles retry on failure
credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(token, procedureId, format);
```

### For Manual Retry Operations
```java
// Retry a specific procedure/action
procedureRetryService.retryAction(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);

// Mark as completed manually
procedureRetryService.markRetryAsCompleted(procedureId, ActionType.UPLOAD_LABEL_TO_RESPONSE_URI);
```

### Extending for New Actions
1. Add new enum to `ActionType`
2. Create payload DTO for the action
3. Add case to `ProcedureRetryServiceImpl.executeRetryAction()`
4. Implement action-specific retry logic

## Monitoring

The system provides comprehensive logging for:
- Initial delivery attempts and failures
- Retry record creation
- Scheduler execution
- Retry attempts and outcomes
- Email notification status

All retry operations include procedure IDs and action types for correlation.