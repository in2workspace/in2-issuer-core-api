package es.in2.issuer.backend.shared.domain.util;

import java.util.List;
import java.util.concurrent.TimeUnit;

public final class Constants {
    public static final String LEAR_CREDENTIAL = "LEARCredential";
    public static final String JWT_VC_JSON = "jwt_vc_json";
    public static final String VERIFIABLE_CREDENTIAL = "VerifiableCredential";
    public static final String LEAR_CREDENTIAL_EMPLOYEE = "LEARCredentialEmployee";
    public static final String LEAR_CREDENTIAL_MACHINE = "LEARCredentialMachine";
    public static final String LABEL_CREDENTIAL = "gx:LabelCredential";
    public static final List<String> LABEL_CREDENTIAL_TYPES = List.of(LABEL_CREDENTIAL, VERIFIABLE_CREDENTIAL);
    public static final String LABEL_CREDENTIAL_TYPE = "LABEL_CREDENTIAL";
    public static final String LEAR_CREDENTIAL_EMPLOYEE_TYPE = "LEAR_CREDENTIAL_EMPLOYEE";
    public static final String LEAR_CREDENTIAL_MACHINE_TYPE = "LEAR_CREDENTIAL_MACHINE";
    public static final String LEAR = "LEAR";
    public static final String VC = "vc";
    public static final String ROLE = "role";

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    public static final String REFRESH_TOKEN_GRANT_TYPE = "refresh_token";
    public static final String CREDENTIALS_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
    public static final String CREDENTIALS_EUDISTACK_CONTEXT = "https://credentials.eudistack.eu/.well-known/credentials";
    public static final String CREDENTIALS_EUDISTACK_LEAR_CREDENTIAL_EMPLOYEE_CONTEXT = CREDENTIALS_EUDISTACK_CONTEXT + "/lear_credential_employee/w3c/v3";
    public static final String CREDENTIALS_EUDISTACK_LEAR_CREDENTIAL_MACHINE_CONTEXT = CREDENTIALS_EUDISTACK_CONTEXT + "/lear_credential_machine/w3c/v2";
    public static final List<String> LEAR_CREDENTIAL_EMPLOYEE_CONTEXT = List.of(CREDENTIALS_CONTEXT_V2, CREDENTIALS_EUDISTACK_LEAR_CREDENTIAL_EMPLOYEE_CONTEXT);
    public static final List<String> CREDENTIAL_CONTEXT_LEAR_CREDENTIAL_MACHINE = List.of(CREDENTIALS_CONTEXT_V2, CREDENTIALS_EUDISTACK_LEAR_CREDENTIAL_MACHINE_CONTEXT);
    public static final List<String> LABEL_CREDENTIAL_CONTEXT = List.of(CREDENTIALS_CONTEXT_V2, "https://w3id.org/gaia-x/development#");
    // EXPIRATION TIMES
    public static final Integer CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME = 10;
    public static final Integer VERIFIABLE_CREDENTIAL_JWT_CACHE_EXPIRATION_TIME = 10;
    public static final Integer CLIENT_ASSERTION_EXPIRATION_TIME = 2;
    public static final String CLIENT_ASSERTION_EXPIRATION_TIME_UNIT = "MINUTES";
    public static final long REFRESH_TOKEN_EXPIRATION = 30;
    public static final TimeUnit REFRESH_TOKEN_EXPIRATION_TIME_UNIT = TimeUnit.DAYS;

    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final long PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES = 5;
    public static final String ENGLISH = "en";
    public static final String DEFAULT_USER_NAME = "Cloud Provider";
    public static final String LEAR_CREDENTIAL_MACHINE_DESCRIPTION = "Verifiable Credential for machines";

    public static final Long DEFERRED_CREDENTIAL_POLLING_INTERVAL = 3600L;
    public static final String PRODUCT_SPECIFICATION_ID = "productSpecificationId";
    public static final String CREDENTIAL_ID = "credentialId";
}
