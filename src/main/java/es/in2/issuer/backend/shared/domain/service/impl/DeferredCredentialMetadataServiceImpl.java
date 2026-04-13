package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialAlreadyIssuedException;
import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialMetadataDeferredResponse;
import es.in2.issuer.backend.shared.domain.model.entities.DeferredCredentialMetadata;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import es.in2.issuer.backend.shared.infrastructure.repository.DeferredCredentialMetadataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Service
@RequiredArgsConstructor
@Slf4j
public class DeferredCredentialMetadataServiceImpl implements DeferredCredentialMetadataService {
    private final DeferredCredentialMetadataRepository deferredCredentialMetadataRepository;
    private final CacheStore<String> cacheStoreForTransactionCode;
    private final CacheStore<String> cacheStoreForCTransactionCode;

    @Override
    public Mono<Void> validateTransactionCode(String transactionCode) {
        log.debug("Validating transactionCode: " + transactionCode);
        return cacheStoreForTransactionCode.get(transactionCode).flatMap(cacheStoreForTransactionCode::delete);
    }

    @Override
    public Mono<String> validateCTransactionCode(String cTransactionCode) {
        log.debug("Validating cTransactionCode: " + cTransactionCode);
        return cacheStoreForCTransactionCode.get(cTransactionCode)
                .flatMap(transactionCode -> cacheStoreForCTransactionCode.delete(cTransactionCode)
                        .then(Mono.just(transactionCode)));
    }

    @Override
    public Mono<Void> updateAuthServerNonceByAuthServerNonce(String accessToken, String preAuthCode) {
        return deferredCredentialMetadataRepository.findByAuthServerNonce(preAuthCode)
                .flatMap(deferredCredentialMetadata -> {
                    log.debug("Entity with: " + preAuthCode + "found");
                    deferredCredentialMetadata.setAuthServerNonce(accessToken);
                    return deferredCredentialMetadataRepository.save(deferredCredentialMetadata)
                            .then();
                })
                .doOnError(error -> log.debug("Entity with: " + preAuthCode + " not found"));
    }

    @Override
    public Mono<String> createDeferredCredentialMetadata(String procedureId, String operationMode, String responseUri) {
        log.debug("Creating deferred credential metadata: procedureId={}, operationMode={}, responseUri={}", procedureId, operationMode, responseUri);
        return generateCustomNonce()
                .flatMap(nonce -> cacheStoreForTransactionCode.add(nonce, nonce))
                .flatMap(transactionCode -> {
                    DeferredCredentialMetadata deferredCredentialMetadata = DeferredCredentialMetadata
                            .builder()
                            .procedureId(UUID.fromString(procedureId))
                            .transactionCode(transactionCode)
                            .operationMode(operationMode)
                            .responseUri(responseUri)
                            .build();
                    return deferredCredentialMetadataRepository.save(deferredCredentialMetadata)
                            .then(Mono.just(transactionCode));
                });
    }

    @Override
    public Mono<Map<String, Object>> updateCacheStoreForCTransactionCode(String transactionCode) {
        return generateCustomNonce()
                .flatMap(cTransactionCode ->
                        cacheStoreForCTransactionCode.add(cTransactionCode, transactionCode)
                                .then(
                                        cacheStoreForCTransactionCode.getCacheExpiryInSeconds()
                                                .map(expiry -> Map.of(
                                                        "cTransactionCode", cTransactionCode,
                                                        "cTransactionCodeExpiresIn", expiry
                                                ))
                                )
                );
    }

    @Override
    public Mono<String> getResponseUriByProcedureId(String procedureId) {
        return deferredCredentialMetadataRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(deferredCredentialMetadata -> {
                    String responseUri = deferredCredentialMetadata.getResponseUri();
                    return Mono.justOrEmpty(responseUri);
                });
    }

    @Override
    public Mono<String> updateTransactionCodeInDeferredCredentialMetadata(String procedureId) {
        return deferredCredentialMetadataRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(existingDeferredCredentialMetadata ->
                        cacheStoreForTransactionCode.delete(existingDeferredCredentialMetadata.getTransactionCode())
                                .then(generateCustomNonce()
                                        .flatMap(nonce ->
                                                cacheStoreForTransactionCode.add(nonce, nonce)
                                                        .thenReturn(nonce)
                                                        .doOnNext(existingDeferredCredentialMetadata::setTransactionCode)
                                        )
                                        .flatMap(newNonce ->
                                                deferredCredentialMetadataRepository.save(existingDeferredCredentialMetadata)
                                                        .thenReturn(newNonce)
                                        )
                                )
                );
    }


    @Override
    public Mono<String> getProcedureIdByTransactionCode(String transactionCode) {
        log.debug("Getting procedureId by transactionCode: {}", transactionCode);
        return deferredCredentialMetadataRepository.findByTransactionCode(transactionCode)
                .flatMap(deferredCredentialMetadata -> {
                    String procedureId = deferredCredentialMetadata.getProcedureId().toString();
                    log.debug("Found procedureId: {} for transactionCode: {}", procedureId, transactionCode);
                    return Mono.just(procedureId);
                })
                .switchIfEmpty(Mono.error(new CredentialAlreadyIssuedException("The credential has already been issued")));
    }

    @Override
    public Mono<DeferredCredentialMetadata> getDeferredCredentialMetadataByAuthServerNonce(String authServerNonce) {
        return deferredCredentialMetadataRepository.findByAuthServerNonce(authServerNonce)
                .switchIfEmpty(Mono.error(new CredentialAlreadyIssuedException("The credential has already been issued")))
                .doOnNext(deferredCredentialMetadata -> log.debug("Found DeferredCredentialMetadata for authServerNonce: {}", authServerNonce));
    }

    @Override
    public Mono<String> getOperationModeByAuthServerNonce(String authServerNonce) {
        return deferredCredentialMetadataRepository.findByAuthServerNonce(authServerNonce)
                .flatMap(deferredCredentialMetadata -> Mono.just(deferredCredentialMetadata.getOperationMode()));
    }

    @Override
    public Mono<String> getOperationModeByProcedureId(String procedureId) {
        return deferredCredentialMetadataRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(deferredCredentialMetadata -> Mono.just(deferredCredentialMetadata.getOperationMode()));
    }

    @Override
    public Mono<Void> updateAuthServerNonceByTransactionCode(String transactionCode, String authServerNonce) {
        return deferredCredentialMetadataRepository.findByTransactionCode(transactionCode)
                .flatMap(deferredCredentialMetadata -> {
                    deferredCredentialMetadata.setAuthServerNonce(authServerNonce);
                    return deferredCredentialMetadataRepository.save(deferredCredentialMetadata)
                            .then();
                });
    }

    @Override
    public Mono<String> updateDeferredCredentialMetadataByAuthServerNonce(String authServerNonce) {
        String transactionId = UUID.randomUUID().toString();
        return deferredCredentialMetadataRepository.findByAuthServerNonce(authServerNonce)
                .flatMap(deferredCredentialMetadata -> {
                    deferredCredentialMetadata.setTransactionId(transactionId);
                    return deferredCredentialMetadataRepository.save(deferredCredentialMetadata)
                            .then(Mono.just(transactionId));
                })
                .doOnSuccess(result -> log.info("Updated deferred Metadata"));
    }

    @Override
    public Mono<Void> updateDeferredCredentialByAuthServerNonce(String authServerNonce, String format) {
        return deferredCredentialMetadataRepository.findByAuthServerNonce(authServerNonce)
                .flatMap(deferredCredentialMetadata -> {
                    deferredCredentialMetadata.setVcFormat(format);
                    return deferredCredentialMetadataRepository.save(deferredCredentialMetadata)
                            .then();
                })
                .doOnSuccess(result -> log.info("Updated deferred Credential"));
    }

    @Override
    public Mono<Void> updateVcByProcedureId(String vc, String procedureId) {
        return deferredCredentialMetadataRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(deferredCredentialMetadata -> {
                    deferredCredentialMetadata.setVc(vc);
                    return deferredCredentialMetadataRepository.save(deferredCredentialMetadata)
                            .then();
                });
    }

    @Override
    public Mono<DeferredCredentialMetadataDeferredResponse> getVcByTransactionId(String transactionId) {
        return deferredCredentialMetadataRepository.findByTransactionId(transactionId)
                .flatMap(deferredCredentialMetadata -> {
                    if (deferredCredentialMetadata.getVc() != null) {
                        return Mono.just(DeferredCredentialMetadataDeferredResponse.builder()
                                .vc(deferredCredentialMetadata.getVc())
                                .id(deferredCredentialMetadata.getId().toString())
                                .procedureId(deferredCredentialMetadata.getProcedureId().toString())
                                .build());
                    } else {
                        String freshTransactionId = UUID.randomUUID().toString();
                        deferredCredentialMetadata.setTransactionId(freshTransactionId);
                        return deferredCredentialMetadataRepository.save(deferredCredentialMetadata)
                                .flatMap(deferredCredentialMetadata1 -> Mono.just(DeferredCredentialMetadataDeferredResponse.builder().transactionId(
                                                deferredCredentialMetadata1.getTransactionId())
                                        .id(deferredCredentialMetadata.getId().toString())
                                        .build()));
                    }
                });
    }

    @Override
    public Mono<Void> deleteDeferredCredentialMetadataById(String id) {
        return deferredCredentialMetadataRepository.deleteById(UUID.fromString(id));
    }

    @Override
    public Mono<Void> deleteDeferredCredentialMetadataByAuthServerNonce(String authServerNonce) {
        return deferredCredentialMetadataRepository.deleteByAuthServerNonce(authServerNonce);
    }

    @Override
    public Mono<Void> updateFormatByProcedureId(String procedureId, String format) {
        return deferredCredentialMetadataRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(deferredCredentialMetadata -> {
                    deferredCredentialMetadata.setVcFormat(format);
                    return deferredCredentialMetadataRepository.save(deferredCredentialMetadata)
                            .then();
                });
    }

    @Override
    public Mono<String> getFormatByProcedureId(String procedureId) {
        return deferredCredentialMetadataRepository.findByProcedureId(UUID.fromString(procedureId))
                .map(DeferredCredentialMetadata::getVcFormat);
    }

    @Override
    public Mono<String> getTransactionCodeByProcedureId(String procedureId) {
        log.debug("Getting transactionCode by procedureId: {}", procedureId);
        return deferredCredentialMetadataRepository.findByProcedureId(UUID.fromString(procedureId))
                .map(DeferredCredentialMetadata::getTransactionCode)
                .doOnNext(transactionCode -> log.debug("Found transactionCode: {} for procedureId: {}", transactionCode, procedureId));
    }
}
