package es.in2.issuer.backend.shared.domain.util;

import com.nimbusds.jose.util.Base64URL;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.LEARCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import reactor.core.publisher.Mono;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_MACHINE;

public final class Utils {

    private Utils() {
        throw new IllegalStateException("Utility class");
    }

    public static Mono<String> generateCustomNonce() {
        return convertUUIDToBytes(UUID.randomUUID())
                .map(uuidBytes -> Base64URL.encode(uuidBytes).toString());
    }

    private static Mono<byte[]> convertUUIDToBytes(UUID uuid) {
        return Mono.fromSupplier(() -> {
            ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
            byteBuffer.putLong(uuid.getMostSignificantBits());
            byteBuffer.putLong(uuid.getLeastSignificantBits());
            return byteBuffer.array();
        });
    }

    public static Mandator extractMandatorLearCredentialEmployee(LEARCredential credential) {
        List<String> types = credential.type();
        if (types.contains(LEAR_CREDENTIAL_EMPLOYEE)) {
            return ((LEARCredentialEmployee) credential).credentialSubject().mandate().mandator();
        }
        throw new InvalidCredentialFormatException("Unsupported credential type: " + types);
    }

    public static LEARCredentialMachine.CredentialSubject.Mandate.Mandator extractMandatorLearCredentialMachine(LEARCredential credential) {
        List<String> types = credential.type();
        if (types.contains(LEAR_CREDENTIAL_MACHINE)) {
            return ((LEARCredentialMachine) credential).credentialSubject().mandate().mandator();
        }
        throw new InvalidCredentialFormatException("Unsupported credential type: " + types);
    }

    public static String extractMandatorOrganizationIdentifier(LEARCredential credential) {
        List<String> types = credential.type();
        if (types.contains(LEAR_CREDENTIAL_EMPLOYEE)) {
            Mandator m = ((LEARCredentialEmployee) credential).credentialSubject().mandate().mandator();
            return m != null ? m.organizationIdentifier() : null;
            } else if (types.contains(LEAR_CREDENTIAL_MACHINE)) {
            var m = ((LEARCredentialMachine) credential).credentialSubject().mandate().mandator();
            return m != null ? m.organizationIdentifier() : null;
            }
        throw new InvalidCredentialFormatException("Unsupported credential type: " + types);
    }

    public static List<Power> extractPowers(LEARCredential credential) {
        List<String> types = credential.type();
        if (types.contains(LEAR_CREDENTIAL_EMPLOYEE)) {
            return ((LEARCredentialEmployee) credential).credentialSubject().mandate().power();
        } else if (types.contains(LEAR_CREDENTIAL_MACHINE)) {
            return ((LEARCredentialMachine) credential).credentialSubject().mandate().power();
        }
        throw new InvalidCredentialFormatException("Unsupported credential type: " + types);
    }
}
