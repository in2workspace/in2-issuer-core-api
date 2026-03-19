# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.2.16](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.16)
### Fixed
- Set a public CORS configuration for the `/oauth/token` endpoint.
- Made the fields inside the Label credential subject mandatory.
- Make proof optional in credential request body.

## [v2.2.15](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.15)
### Fixed
- Ensure DID key consistency in M2M flow: use mandatee.id DID for sub, credentialSubject.id, and mandatee.id fields.

## [v2.2.14](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.14)
### Fixed
- Allow issuing LEARCredentialEmployee using an access token whose embedded VC is either LEARCredentialEmployee or LEARCredentialMachine (issuance policies).

## [v2.2.13](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.13)
### Changed
- Create bitstring-encoded lists using MSB-first ordering.

## [v2.2.12](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.12)
### Changed
- Update Failure case in Notification Endpoint.

## [v2.2.10](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.10)
### Fixed
- Don't send mail when Deferred Credential fails.

## [v2.2.9](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.9)
### Added
- Notification Endpoint implemented

## [v2.2.8](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.8)
### Changed
- Update refresh token.
- Update deferred credential flow.

## [v2.2.7](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.7)
### Added
- Cryptographic Binding implemented

## [v2.2.6](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.6)
### Changed
- Set vault's secret mounts as environment variable.
- Remove 'actuator/' path from health and prometheus base path.

## [v2.2.5](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.5)
### Fixed
- LEARCredentials mandator validation by OrgId.

## [v2.2.4](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.4)
### Added
- LEARCredentialMachine async signature.

## [v2.2.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.3)
### Fixed
- Prevent retrying the signature process when the credential procedure is not in PEND_SIGNATURE status.

## [v2.2.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.2)
### Changed
- Add org ID validation for notification and async signature flows.

## [v2.2.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.1)
### Added
- Add environment variable `sys-admin`, use it instead of constant DEFAULT_ORGANIZATION_NAME, which was used in email templates.

## [v2.2.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.0)
### Added
- Make admin organization identifier configurable (add adminOrganizationId env variable).
- When fetching procedures, if the authenticated user is an admin, fetch across all organizations.
- When fetching a procedure, if the authenticated user is an admin, don't restrict by organization.
- Enable R2DBC auditing to auto-populate `created_at`, `updated_at`, `created_by`, and `updated_by`.
- Resolve auditing principal from the JWT access token (prefer ID token when available).

### Changed
- For Employee and Machine credentials, set the `organization_identifier` field with the mandator email.
- `updated_at` in `CredentialProcedure` and related entities is now managed automatically by Spring Data (no manual updates).
- `subject_email` in `CredentialProcedure` and related entities has been renamed to `email`.
- In "activate credential" email Spanish template, replace "Estimado/a ," by "Hola,"

### Fixed
- Change deprecated build image openjdk:17-alpine by eclipse-temurin:17-jdk-alpine
- Send signature failure emails to the authenticated requester’s email, not the credential mandator’s updated email.

### Removed
- Sign controller (unused).

## [v2.1.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.1.1)
### Added
- Get default language from configuration, use it to translate messages (emails, PIN description).

## [v2.1.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.1.0)
### Changed
- If LEARCredentialMachine issuance presubmitted data contains credential_owner_email, use it as owner email.
- Don't include name in emails.

### Fixed
- When sending Label Credential to VC URI, send it encoded.

## [v2.0.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.0.0)
### Added
- Label credential issuance.
- LEARCredentialMachine issuance.
- Sign access request.
- Revocation endpoint.
- Revoke and expired credential notification.
- Handle error when sending PIN and when serializing credential.
- Handle errors in security chains flow.

### Changed
- Adapt endpoints to oid4vci.
- Refactor SecurityConfig credential issuer filters.
- Standardize error handling to RFC 7807 across all endpoints.
- Move GlobalExceptionHandler to shared module and add specific ControllerAdvice for each domain.
- Remove unused exceptions.



## [v1.7.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.7.0)
### Added
- Added remote signature configuration.

## [v1.6.9](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.9)
### Fixed
- Store Verifiable certification metadata after issuance
- Send Verifiable certification to responseUri after remote signature
- Modify the message sent after successful remote signature; adapt it to Verifiable Certification

## [v1.6.8](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.8)
### Fixed
- Error on credential request contract.

## [v1.6.7](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.7)
### Fixed
- When updating transaction code, delete previous one

## [v1.6.6](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.6)
### Fixed
- OID4VCI cors configuration.

## [v1.6.5](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.5)
### Fixed
- Refactor configs.

## [v1.6.4](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.4)
### Feature
- Migrate from Keycloak extension.

## [v1.6.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.3)
### Fixed
- Problem with public cors configuration.

## [v1.6.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.2)
### Fixed
- Separate internal and external issuing endpoints to be able to apply different authentication filters.
- Use M2M token when issuing Verifiable Certifications.

## [v1.6.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.1)
### Fixed
- Handle error during mail sending on the credential offer.

## [v1.6.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.0)
### Changed
- Added role claim and validations.
- Modified authenticator to allow access exclusively with the "LEAR" role, returning a 401 error for any other role.

## [v1.5.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.5.2)
### Fixed
- Fixed parsing learCredentialEmployee

## [v1.5.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.5.1)
### Fixed
- Fixed parsing certificates

## [v1.5.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.5.0)
### Added
- Added support to sign the credential with an external service.
- Now issuer is created with data from the external service.
- Error handling for the external service flows.
- Added controller to handle manual signature after failed attempts.

## [v1.4.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.4.3)
### Fixed
- Solve error on schema importation for flyway migration.

## [v1.4.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.4.1)
### Fixed
- Solve error during credential serialization.

## [v1.4.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.4.0)
### Added
- Compatibility with LEARCredentialMachine to issue LEARCredentialEmployee.

## [v1.3.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.3.0)
### Changed
- The issuer now issues only LearCredentialEmployee v2.

## [v1.2.5](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.5)
### Changed
- Changing environment variable for wallet knowledge redirection to email.
- Changed email template implementation for better compatibility.

## [v1.2.4](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.4)
### Changed
- Fix a problem with a cors endpoint.

## [v1.2.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.3)
### Added
- Add cors configuration for externals clients on the issuance endpoint.

### Changed
- Change email template styles, improve compatibility accross different email providers (e.g., Gmail)


## [v1.2.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.2)
### Added
- Add scheduled task to set EXPIRED status to credentials that have expired.

## [v1.2.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.1)
### Added
- Add support for requesting a fresh QR code if the previous one has expired or was an error during the proccess of

## [v1.2.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.0)
### Added
- Validation of authentication for issuance against the verifier.
- Verifiable Certifications issuance and sending to response_uri.
### Changed
- List credentials in order from newest to oldest.

## [v1.1.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.1.3)
### Changed
- Change the Credential Offer email template

## [v1.1.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.1.2)
### Changed
- Change the order of the received email from the pin during the issuance of a credential.

## [v1.1.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.1.1)
### Fixed
- Fixed LEARCredentialEmployee data model. Implement W3C DATA model v2.0 (validFrom, validUntil). 

## v1.1.0
### Added
- LEARCredentialEmployee issuance in a synchronous way.
- DOME Trust Framework integration to register issuers and participants.
### Changed
- Issuances API to support various issuance types.

## [Unreleased]: v0.7.0
- LEARCredential compliance.

## [Unreleased]: v0.6.0
- DOME profile compliance.

## [Unreleased]: v0.5.0
- Deferred credential emission.
- tx_code support for PIN.
- Persistence of emitted credentials in ddb.
- Retrieval and management of emitted credentials.

## [Unreleased]: v0.4.0
- Hexagonal pattern.
- Credential Offer endpoint requiere type of credential.
- DOME profile refactor and fixes.
- Batch credential support (extra)

## [Unreleased]: v0.3.0
- Support for credentials in JWT and CWT.
- Remove of external libraries for CV generation
- Native credential payload generation.
- Local emission.

## [Unreleased]: v0.2.0
- Adapter for Abstract Configuration loading.
- Support for Configurations from YAML file.
- Support for Configurations from Azure App Configuration.

## [Unreleased]: v0.1.0
- Successful build and tests.
- Compatibility with standard dependencies and plugins.
- Migration of files.

[release]:
