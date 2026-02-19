package es.in2.issuer.backend.shared.domain.util;

import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.LEARCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UtilsTest {

    @Test
    void testGenerateCustomNonce() {
        StepVerifier.create(Utils.generateCustomNonce())
                .assertNext(nonce -> {
                    assertNotNull(nonce);
                    assertFalse(nonce.isEmpty());
                    assertDoesNotThrow(() -> Base64.getUrlDecoder().decode(nonce));
                })
                .verifyComplete();
    }

    @Test
    void extractMandatorOrganizationIdentifier_employee_returnsOrganizationIdentifier() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("ORG-EMP-001")
                .build();

        var mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(mandator)
                .build();

        var subject = LEARCredentialEmployee.CredentialSubject.builder()
                .mandate(mandate)
                .build();

        var credential = LEARCredentialEmployee.builder()
                .type(List.of("LEARCredentialEmployee"))
                .credentialSubject(subject)
                .build();

        String result = Utils.extractMandatorOrganizationIdentifier(credential);

        assertEquals("ORG-EMP-001", result);
    }

    @Test
    void extractMandatorOrganizationIdentifier_employee_withNullMandator_returnsNull() {
        var mandate = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(null)
                .build();

        var subject = LEARCredentialEmployee.CredentialSubject.builder()
                .mandate(mandate)
                .build();

        var credential = LEARCredentialEmployee.builder()
                .type(List.of("LEARCredentialEmployee"))
                .credentialSubject(subject)
                .build();

        String result = Utils.extractMandatorOrganizationIdentifier(credential);

        assertNull(result);
    }

    @Test
    void extractMandatorOrganizationIdentifier_machine_returnsOrganizationIdentifier() {
        var mandator = LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                .organizationIdentifier("ORG-MACH-001")
                .build();

        var mandate = LEARCredentialMachine.CredentialSubject.Mandate.builder()
                .mandator(mandator)
                .build();

        var subject = LEARCredentialMachine.CredentialSubject.builder()
                .mandate(mandate)
                .build();

        var credential = LEARCredentialMachine.builder()
                .type(List.of("LEARCredentialMachine"))
                .credentialSubject(subject)
                .build();

        String result = Utils.extractMandatorOrganizationIdentifier(credential);

        assertEquals("ORG-MACH-001", result);
    }

    @Test
    void extractMandatorOrganizationIdentifier_machine_withNullMandator_returnsNull() {
        var mandate = LEARCredentialMachine.CredentialSubject.Mandate.builder()
                .mandator(null)
                .build();

        var subject = LEARCredentialMachine.CredentialSubject.builder()
                .mandate(mandate)
                .build();

        var credential = LEARCredentialMachine.builder()
                .type(List.of("LEARCredentialMachine"))
                .credentialSubject(subject)
                .build();

        String result = Utils.extractMandatorOrganizationIdentifier(credential);

        assertNull(result);
    }

    @Test
    void extractMandatorOrganizationIdentifier_unsupportedType_throwsException() {
        LEARCredential credential = mock(LEARCredential.class);
        when(credential.type()).thenReturn(List.of("SomeOtherCredentialType"));

        InvalidCredentialFormatException ex = assertThrows(
                InvalidCredentialFormatException.class,
                () -> Utils.extractMandatorOrganizationIdentifier(credential)
        );

        assertTrue(ex.getMessage().contains("Unsupported credential type"));
        assertTrue(ex.getMessage().contains("SomeOtherCredentialType"));
    }
}
