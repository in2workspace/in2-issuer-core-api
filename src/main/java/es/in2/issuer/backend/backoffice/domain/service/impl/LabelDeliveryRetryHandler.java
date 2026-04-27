package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.service.RetryableActionHandler;
import es.in2.issuer.backend.shared.domain.model.dto.ResponseUriDeliveryResult;
import es.in2.issuer.backend.shared.domain.model.dto.retry.LabelCredentialDeliveryPayload;
import es.in2.issuer.backend.shared.domain.model.enums.RetryableActionType;
import es.in2.issuer.backend.shared.domain.service.CredentialDeliveryService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.M2MTokenService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class LabelDeliveryRetryHandler implements RetryableActionHandler<LabelCredentialDeliveryPayload> {

    private final CredentialDeliveryService credentialDeliveryService;
    private final M2MTokenService m2mTokenService;
    private final EmailService emailService;
    private final AppConfig appConfig;

    @Override
    public RetryableActionType getActionType() {
        return RetryableActionType.UPLOAD_LABEL_TO_RESPONSE_URI;
    }

    @Override
    public Class<LabelCredentialDeliveryPayload> getPayloadType() {
        return LabelCredentialDeliveryPayload.class;
    }

    @Override
    public Mono<ResponseUriDeliveryResult> execute(LabelCredentialDeliveryPayload payload) {
        log.debug("[DELIVERY] Attempting delivery to response URI for credId: {}", payload.credentialId());
        return m2mTokenService.getM2MToken()
                .flatMap(m2mToken -> credentialDeliveryService.deliverLabelToResponseUri(
                        payload.responseUri(),
                        payload.signedCredential(),
                        payload.credentialId(),
                        m2mToken.accessToken()
                ));
    }

    @Override
    public Mono<Void> onInitialSuccess(LabelCredentialDeliveryPayload payload, ResponseUriDeliveryResult result) {
        return sendSuccessNotificationSafely(payload.email(), payload.productSpecificationId(), payload.credentialId(), result);
    }

    @Override
    public Mono<Void> onInitialFailure(LabelCredentialDeliveryPayload payload) {
        return Mono.when(
                sendFailureNotificationSafely(appConfig.getLabelUploadCertifierEmail(), payload.productSpecificationId(), payload.credentialId(), payload.email(), "certifier"),
                sendFailureNotificationSafely(appConfig.getLabelUploadMarketplaceEmail(), payload.productSpecificationId(), payload.credentialId(), payload.email(), "marketplace")
        );
    }

    @Override
    public Mono<Void> onScheduledSuccess(LabelCredentialDeliveryPayload payload, ResponseUriDeliveryResult result) {
        return Mono.when(
                sendSuccessNotificationSafely(payload.email(), payload.productSpecificationId(), payload.credentialId(), result),
                sendSuccessNotificationSafely(appConfig.getLabelUploadCertifierEmail(), payload.productSpecificationId(), payload.credentialId(), result),
                sendSuccessNotificationSafely(appConfig.getLabelUploadMarketplaceEmail(), payload.productSpecificationId(), payload.credentialId(), result)
        );
    }

    @Override
    public Mono<Void> onExhausted(LabelCredentialDeliveryPayload payload, UUID procedureId) {
        return Mono.when(
                sendExhaustionNotificationSafely(appConfig.getLabelUploadCertifierEmail(), payload.productSpecificationId(), payload.credentialId(), payload.email(), procedureId, "certifier"),
                sendExhaustionNotificationSafely(appConfig.getLabelUploadMarketplaceEmail(), payload.productSpecificationId(), payload.credentialId(), payload.email(), procedureId, "marketplace")
        );
    }

    private Mono<Void> sendSuccessNotificationSafely(String email, String productSpecificationId, String credentialId, ResponseUriDeliveryResult result) {
        if (email == null || email.isBlank()) {
            log.warn("[NOTIFICATION] No email available for success notification, credId: {}", credentialId);
            return Mono.empty();
        }

        Mono<Void> emailMono;
        if (result.acceptedWithHtml() && result.html() != null) {
            emailMono = emailService.sendResponseUriAcceptedWithHtml(email, credentialId, result.html());
        } else {
            emailMono = emailService.sendCertificationUploaded(email, productSpecificationId, credentialId);
        }

        return emailMono
                .doOnSuccess(unused -> log.info("[NOTIFICATION] Success email sent for credId: {}", credentialId))
                .onErrorResume(e -> {
                    log.error("[NOTIFICATION] Failed to send success email for credId: {}: {}", credentialId, e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<Void> sendFailureNotificationSafely(String email, String productSpecificationId, String credentialId, String providerEmail, String recipientType) {
        if (email == null || email.isBlank()) {
            log.warn("[NOTIFICATION] No {} email available for failure notification, productSpecId: {}", recipientType, productSpecificationId);
            return Mono.empty();
        }

        return emailService.sendResponseUriFailed(
                        email,
                        productSpecificationId,
                        credentialId,
                        providerEmail,
                        appConfig.getKnowledgeBaseUploadCertificationGuideUrl()
                )
                .doOnSuccess(unused -> log.info("[NOTIFICATION] Failure email sent to {} for productSpecId: {}, credId: {}", recipientType, productSpecificationId, credentialId))
                .onErrorResume(e -> {
                    log.error("[NOTIFICATION] Failed to send failure email to {} for productSpecId: {}, credId: {}: {}",
                            recipientType, productSpecificationId, credentialId, e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<Void> sendExhaustionNotificationSafely(String email, String productSpecificationId, String credentialId, String providerEmail, UUID procedureId, String recipientType) {
        if (email == null || email.isBlank()) {
            log.warn("[NOTIFICATION] No {} email available for exhaustion notification, procedure: {}", recipientType, procedureId);
            return Mono.empty();
        }

        return emailService.sendResponseUriExhausted(email, productSpecificationId, credentialId, providerEmail, appConfig.getKnowledgeBaseUploadCertificationGuideUrl())
                .doOnSuccess(unused -> log.info("[NOTIFICATION] Exhaustion email sent to {} for procedure: {}, productSpecId: {}, credId: {}",
                        recipientType, procedureId, productSpecificationId, credentialId))
                .onErrorResume(e -> {
                    log.error("[NOTIFICATION] Failed to send exhaustion email to {} for procedure: {}, productSpecId: {}, credId: {}: {}",
                            recipientType, procedureId, productSpecificationId, credentialId, e.getMessage());
                    return Mono.empty();
                });
    }
}
