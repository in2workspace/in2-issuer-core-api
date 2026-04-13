package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.backoffice.domain.service.SendReminderService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class SendReminderServiceImpl implements SendReminderService {

    private final AppConfig appConfig;
    private final AccessTokenService accessTokenService;
    private final BackofficePdpService backofficePdpService;
    private final EmailService emailService;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;

    @Override
    public Mono<Void> sendReminder(String processId, String procedureId, String bearerToken) {
        // TODO this flow doesn't udpate the credential procedure, but we should consider updating the "udpated_by" field for auditing and maybe have the last person to send a reminder to receive the failed signature email
        log.info("sendNotification processId={} organizationId={}", processId, procedureId);

        return accessTokenService.getCleanBearerToken(bearerToken)
                .flatMap(token -> backofficePdpService.validateSendReminder(processId, token, procedureId)
                        .then(credentialProcedureService.getCredentialProcedureById(procedureId))
                )
                .zipWhen(credentialProcedure -> credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId))
                .flatMap(tuple -> {
                    final var credentialProcedure = tuple.getT1();
                    final var emailInfo = tuple.getT2();

                    return switch (credentialProcedure.getCredentialStatus()) {
                        // TODO we need to remove the withdraw status from the condition since the v1.2.0 version is deprecated but in order to support retro compatibility issues we will keep it for now.
                        case DRAFT, WITHDRAWN ->
                            deferredCredentialMetadataService
                                    .updateTransactionCodeInDeferredCredentialMetadata(procedureId)
                                    .flatMap(newTransactionCode ->
                                            emailService.sendCredentialActivationEmail(
                                                    emailInfo.email(),
                                                    CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                                                    appConfig.getIssuerFrontendUrl() + "/credential-offer?transaction_code=" + newTransactionCode,
                                                    appConfig.getKnowledgebaseWalletUrl(),
                                                    emailInfo.organization()
                                            )
                                    )
                                    .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));

                        // ??
                        case PEND_DOWNLOAD ->
                            emailService.sendCredentialSignedNotification(
                                    credentialProcedure.getEmail(),
                                    CREDENTIAL_READY,
                                    "email.you-can-use-wallet"
                            );

                        default -> Mono.empty();
                    };
                })
                .then();
    }
}
