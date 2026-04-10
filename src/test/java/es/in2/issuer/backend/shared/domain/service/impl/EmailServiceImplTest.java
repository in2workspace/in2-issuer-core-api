package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.mail.javamail.JavaMailSender;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceImplTest {

    @Mock private JavaMailSender javaMailSender;
    @Mock private TemplateEngine templateEngine;
    @Mock private MailProperties mailProperties;
    @Mock private CredentialProcedureService credentialProcedureService;
    @Mock private TranslationService translationService;

    @InjectMocks
    private EmailServiceImpl emailService;

    @BeforeEach
    void setUpLenient() {
        // lenient because some tests short-circuit before these are called
        lenient().when(mailProperties.getUsername()).thenReturn("user@example.com");
        lenient().when(translationService.getLocale()).thenReturn("en");
        // Pass-through translation (may not be used in every test)
        lenient().when(translationService.translate(any(String.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void testSendTxCodeNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        // Template now includes locale suffix
        when(templateEngine.process(eq("pin-email-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendTxCodeNotification("to@example.com", "subject.key", "1234"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendCredentialActivationEmail() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("activate-credential-email-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(
                emailService.sendCredentialActivationEmail("to@example.com", "subject.key", "link", "knowledgebaseUrl","organization")
        ).verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendPendingCredentialNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-pending-notification-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendPendingCredentialNotification("to@example.com", "subject.key"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendPendingSignatureCredentialNotification(){
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-pending-signature-notification-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendPendingSignatureCredentialNotification("to@example.com", "subject.key", "\"John\"", "domain"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendCredentialSignedNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-signed-notification-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendCredentialSignedNotification("to@example.com", "subject.key", "additionalInfo"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriFailed_sendsEmailSuccessfully(){
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("response-uri-failed-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendResponseUriFailed("to@example.com", "productId", "guideUrl"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriFailed_handlesException(){
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        StepVerifier.create(emailService.sendResponseUriFailed("to@example.com", "productId", "guideUrl"))
                .expectError(RuntimeException.class) // service does not map this one
                .verify();
    }

    @Test
    void sendResponseUriExhausted_sendsEmailSuccessfully(){
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("response-uri-exhausted-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendResponseUriExhausted("to@example.com", "productId", "guideUrl"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriExhausted_handlesException(){
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        StepVerifier.create(emailService.sendResponseUriExhausted("to@example.com", "productId", "guideUrl"))
                .expectError(RuntimeException.class) // service does not map this one
                .verify();
    }

    @Test
    void sendCertificationUploaded_sendsEmailSuccessfully(){
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("certification-uploaded-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendCertificationUploaded("to@example.com", "productId"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendCertificationUploaded_handlesException(){
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        StepVerifier.create(emailService.sendCertificationUploaded("to@example.com", "productId"))
                .expectError(RuntimeException.class) // service does not map this one
                .verify();
    }

    @Test
    void sendResponseUriAcceptedWithHtml_sendsEmailSuccessfully() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);

        StepVerifier.create(emailService.sendResponseUriAcceptedWithHtml("to@example.com", "productId", "htmlContent"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriAcceptedWithHtml_handlesException() {
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        StepVerifier.create(emailService.sendResponseUriAcceptedWithHtml("to@example.com", "productId", "htmlContent"))
                .expectError(RuntimeException.class) // service does not map this one
                .verify();
    }

    @Test
    void notifyIfCredentialStatusChanges_returnsEmptyWhenStatusDifferent() {
        // Real status is REVOKED but expected is EXPIRED -> no email should be sent
        CredentialProcedure credential = mock(CredentialProcedure.class);
        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);

        StepVerifier.create(emailService.notifyIfCredentialStatusChanges(credential, "EXPIRED"))
                .verifyComplete();

        // No email or credential service should be invoked
        verifyNoInteractions(javaMailSender, templateEngine, credentialProcedureService);
    }

    @Test
    void notifyIfCredentialStatusChanges_sendsExpiredEmail_andSetsTemplateVariables() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        // Template now includes locale suffix
        when(templateEngine.process(eq("revoked-expired-credential-email-en"), any(Context.class)))
                .thenReturn("htmlContent");

        // Mocked credential
        CredentialProcedure credential = mock(CredentialProcedure.class);
        UUID procedureId = UUID.randomUUID();
        when(credential.getProcedureId()).thenReturn(procedureId);
        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.EXPIRED);
        when(credential.getCredentialType()).thenReturn("LEARCredentialEmployee");

        // New flow: first get credentialId, then email info
        when(credentialProcedureService.getCredentialId(credential)).thenReturn(Mono.just("cred-123"));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo(
                        "to@example.com", "ACME Corp"
                )));

        StepVerifier.create(emailService.notifyIfCredentialStatusChanges(credential, "EXPIRED"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);

        // Capture the Context to check the added variables
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email-en"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();

        // Subject/title for EXPIRED are set in the service (title is hardcoded English there)
        Assertions.assertEquals("email.expired.title", ctx.getVariable("title"));
        // Context variables built by buildEmailContext(...)
        Assertions.assertEquals("ACME Corp", ctx.getVariable("organization"));
        Assertions.assertEquals("cred-123", ctx.getVariable("credentialId"));
        Assertions.assertEquals("LEARCredentialEmployee", ctx.getVariable("type"));
        Assertions.assertEquals("EXPIRED", ctx.getVariable("credentialStatus"));
    }

    @Test
    void notifyIfCredentialStatusChanges_sendsRevokedEmail_andSetsRevokedTitle() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("revoked-expired-credential-email-en"), any(Context.class)))
                .thenReturn("htmlContent");

        CredentialProcedure credential = mock(CredentialProcedure.class);
        UUID procedureId = UUID.randomUUID();
        when(credential.getProcedureId()).thenReturn(procedureId);
        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);
        when(credential.getCredentialType()).thenReturn("LEARCredentialEmployee");

        when(credentialProcedureService.getCredentialId(credential)).thenReturn(Mono.just("cred-999"));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo(
                        "to@example.com", "Umbrella Inc"
                )));

        StepVerifier.create(emailService.notifyIfCredentialStatusChanges(credential, "REVOKED"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);

        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email-en"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();

        // Subject/title for REVOKED (title is hardcoded English in service)
        Assertions.assertEquals("email.revoked.title", ctx.getVariable("title"));
        // Key variables
        Assertions.assertEquals("Umbrella Inc", ctx.getVariable("organization"));
        Assertions.assertEquals("cred-999", ctx.getVariable("credentialId"));
        Assertions.assertEquals("LEARCredentialEmployee", ctx.getVariable("type"));
        Assertions.assertEquals("REVOKED", ctx.getVariable("credentialStatus"));
    }

    @Test
    void notifyIfCredentialStatusChanges_mapsErrorsToEmailCommunicationException() {
        // When getCredentialId(...) fails, it should propagate as EmailCommunicationException per service mapping
        CredentialProcedure credential = mock(CredentialProcedure.class);
        when(credential.getCredentialStatus()).thenReturn(CredentialStatusEnum.EXPIRED);
        // Avoid NPE: provide a non-null procedureId
        when(credential.getProcedureId()).thenReturn(UUID.randomUUID());

        when(credentialProcedureService.getCredentialId(credential))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(emailService.notifyIfCredentialStatusChanges(credential, "EXPIRED"))
                .expectError(es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException.class)
                .verify();

        // Ensure no email info is requested if getCredentialId(...) already failed
        verify(credentialProcedureService, never()).getCredentialOfferEmailInfoByProcedureId(anyString());
        verifyNoInteractions(javaMailSender, templateEngine);
    }
}
