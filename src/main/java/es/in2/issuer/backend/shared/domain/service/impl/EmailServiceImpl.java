package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeUtility;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.InputStreamSource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.StreamUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.UTF_8;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {
    private static final String PRODUCT_ID = "productId";

    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;
    private final MailProperties mailProperties;
    private final CredentialProcedureService credentialProcedureService;
    private final TranslationService translationService;

    @Override
    public Mono<Void> sendTxCodeNotification(String to, String subject, String pin) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);

            String translated = translationService.translate(subject);
            String encodedSubject = MimeUtility.encodeText(translated, StandardCharsets.UTF_8.name(), "B");

            helper.setSubject(encodedSubject);

            Context context = new Context();
            context.setVariable("pin", pin);
            String htmlContent = templateEngine.process("pin-email-" + translationService.getLocale(), context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        })
                .subscribeOn(Schedulers.boundedElastic()).then()
                .onErrorMap(ex -> new EmailCommunicationException("Error when sending tx code notification"));
    }

    @Override
    public Mono<Void> sendCredentialActivationEmail(String to, String subject, String link, String knowledgebaseWalletUrl, String organization) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(translationService.translate(subject));

            ClassPathResource imgResource = new ClassPathResource("static/images/qr-wallet.png");
            String imageResourceName = imgResource.getFilename();

            InputStream imageStream = imgResource.getInputStream();
            byte[] imageBytes = StreamUtils.copyToByteArray(imageStream);

            Context context = new Context();
            context.setVariable("link", link);
            context.setVariable("organization", organization);
            context.setVariable("knowledgebaseWalletUrl", knowledgebaseWalletUrl);
            context.setVariable("imageResourceName", "cid:" + imageResourceName);

            String htmlContent = templateEngine.process("activate-credential-email-" + translationService.getLocale(), context);
            helper.setText(htmlContent, true);

            final InputStreamSource imageSource = new ByteArrayResource(imageBytes);
            if (imageResourceName != null) {
                helper.addInline(imageResourceName, imageSource, MimeTypeUtils.IMAGE_PNG_VALUE);
            }

            javaMailSender.send(mimeMessage);

            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> sendPendingCredentialNotification(String to, String subject) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(translationService.translate(subject));

            Context context = new Context();
            String htmlContent = templateEngine.process("credential-pending-notification-" + translationService.getLocale(), context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> sendPendingSignatureCredentialNotification(String to, String subject, String id, String domain){
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(translationService.translate(subject));

            Context context = new Context();
            context.setVariable("id", id);
            context.setVariable("domain", domain);
            String htmlContent = templateEngine.process("credential-pending-signature-notification-" + translationService.getLocale(), context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> sendCredentialSignedNotification(String to, String subject, String additionalInfo) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(translationService.translate(subject));

            Context context = new Context();
            context.setVariable("additionalInfo", translationService.translate(additionalInfo));
            String htmlContent = templateEngine.process("credential-signed-notification-"  + translationService.getLocale(), context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> sendResponseUriFailed(String to, String productId, String guideUrl) {
        return sendTemplatedEmail(
                to,
                "email.unsuccessful-submission",
                "response-uri-failed",
                context -> {
                    context.setVariable(PRODUCT_ID, productId);
                    context.setVariable("guideUrl", guideUrl);
                }
        );
    }

    @Override
    public Mono<Void> sendResponseUriExhausted(String to, String productId, String guideUrl) {
        return sendTemplatedEmail(
                to,
                "email.retry-exhausted-submission",
                "response-uri-exhausted",
                context -> {
                    context.setVariable(PRODUCT_ID, productId);
                    context.setVariable("guideUrl", guideUrl);
                }
        );
    }

    @Override
    public Mono<Void> sendCertificationUploaded(String to, String productId) {
        return sendTemplatedEmail(
                to,
                "email.certification-uploaded",
                "certification-uploaded",
                context -> context.setVariable(PRODUCT_ID, productId)
        );
    }

    @Override
    public Mono<Void> sendResponseUriAcceptedWithHtml(String to, String productId, String htmlContent) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailProperties.getUsername());
            helper.setTo(to);
            helper.setSubject(translationService.translate("email.missing-documents-certification") + productId);

            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> notifyIfCredentialStatusChanges(CredentialProcedure credentialProcedure, String expectedStatus) {
        if (!credentialProcedure.getCredentialStatus().toString().equalsIgnoreCase(expectedStatus)) {
            return Mono.empty();
        }

        return credentialProcedureService
                .getCredentialId(credentialProcedure)
                .flatMap(credentialId ->
                        credentialProcedureService
                                .getCredentialOfferEmailInfoByProcedureId(credentialProcedure.getProcedureId().toString())
                                .flatMap(info ->
                                        sendCredentialRevokedOrExpiredNotificationEmail(
                                                info.email(),
                                                info.organization(),
                                                credentialId,
                                                credentialProcedure.getCredentialType(),
                                                expectedStatus
                                        )
                                )
                )
                //todo don't pass procedure id, pass credential id instead
                .onErrorMap(e -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                .doOnError(e -> log.error("Error sending '{}' email for credential procedure {}", expectedStatus, credentialProcedure.getProcedureId().toString()));
    }

    private Mono<Void> sendCredentialRevokedOrExpiredNotificationEmail(String to, String organization, String credentialId, String type, String credentialStatus){
        return Mono.fromCallable(() -> {
            try {
                MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);

                helper.setFrom(mailProperties.getUsername());
                helper.setTo(to);

                Context context = buildEmailContext(organization, credentialId, type, credentialStatus);

                switch (credentialStatus) {
                    case "REVOKED" -> {
                        helper.setSubject(translationService.translate("email.revoked.subject"));
                        context.setVariable("title", translationService.translate("email.revoked.title"));
                    }
                    case "EXPIRED" -> {
                        helper.setSubject(translationService.translate("email.expired.subject"));
                        context.setVariable("title", translationService.translate("email.expired.title"));
                    }
                    default -> helper.setSubject(translationService.translate("email.default-status.subject"));

                }
                String htmlContent = templateEngine.process("revoked-expired-credential-email-"  + translationService.getLocale(), context);
                helper.setText(htmlContent, true);

                javaMailSender.send(mimeMessage);
            } catch (MessagingException e) {
                throw new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE);
            }

            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    private Context buildEmailContext(String organization, String credentialId, String type, String credentialStatus) {
        Context context = new Context();
        context.setVariable("organization", organization);
        context.setVariable("credentialId", credentialId);
        context.setVariable("type", type);
        context.setVariable("credentialStatus", credentialStatus);
        return context;
    }

    private Mono<Void> sendTemplatedEmail(
            String to,
            String subjectKey,
            String templateName,
            Consumer<Context> contextCustomizer
    ) {
        return Mono.fromCallable(() -> {
            try {
                MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
                helper.setFrom(mailProperties.getUsername());
                helper.setTo(to);
                helper.setSubject(translationService.translate(subjectKey));

                Context context = new Context();
                contextCustomizer.accept(context);

                String htmlContent = templateEngine.process(templateName + "-" + translationService.getLocale(), context);
                helper.setText(htmlContent, true);

                javaMailSender.send(mimeMessage);
                return null;
            } catch (MessagingException e) {
                throw new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

}
