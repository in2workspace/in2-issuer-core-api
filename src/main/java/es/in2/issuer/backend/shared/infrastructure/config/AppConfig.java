package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.adapter.ConfigAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.adapter.factory.ConfigAdapterFactory;
import es.in2.issuer.backend.shared.infrastructure.config.properties.AppProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.IssuerIdentityProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.LabelUploadProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class AppConfig {

    private final ConfigAdapter configAdapter;
    private final AppProperties appProperties;
    private final IssuerIdentityProperties issuerIdentityProperties;
    private final CorsProperties corsProperties;
    private final LabelUploadProperties labelUploadProperties;

    public AppConfig(
            ConfigAdapterFactory configAdapterFactory,
            AppProperties appProperties,
            IssuerIdentityProperties issuerIdentityProperties,
            CorsProperties corsProperties,
            LabelUploadProperties labelUploadProperties
    ) {
        this.configAdapter = configAdapterFactory.getAdapter();
        this.appProperties = appProperties;
        this.issuerIdentityProperties = issuerIdentityProperties;
        this.corsProperties = corsProperties;
        this.labelUploadProperties = labelUploadProperties;
    }

    public String getIssuerBackendUrl() {
        return configAdapter.getConfiguration(appProperties.url());
    }

    public String getIssuerFrontendUrl() {
        return configAdapter.getConfiguration(appProperties.issuerFrontendUrl());
    }

    public String getKnowledgebaseWalletUrl() {
        return configAdapter.getConfiguration(appProperties.knowledgeBase().walletGuideUrl());
    }

    public String getWalletFrontendUrl() {
        return configAdapter.getConfiguration(appProperties.walletUrl());
    }

    public String getKnowledgeBaseUploadCertificationGuideUrl() {
        return configAdapter.getConfiguration(appProperties.knowledgeBase().uploadCertificationGuideUrl());
    }

    public String getConfigSource() {
        return configAdapter.getConfiguration(appProperties.configSource());
    }

    public String getCredentialSubjectDidKey() {
        return issuerIdentityProperties.credentialSubjectDidKey();
    }

    public String getJwtCredential() {
        return issuerIdentityProperties.jwtCredential();
    }

    public String getCryptoPrivateKey() {
        return issuerIdentityProperties.crypto().privateKey();
    }

    public List<String> getExternalCorsAllowedOrigins() {
        return corsProperties.externalAllowedOrigins();
    }
    public List<String> getDefaultCorsAllowedOrigins() {
        return corsProperties.defaultAllowedOrigins();
    }

    public String getTrustFrameworkUrl() {
        return configAdapter.getConfiguration(appProperties.trustFrameworkUrl());
    }

    public String getVerifierUrl() {
        return configAdapter.getConfiguration(appProperties.verifierUrl());
    }

    public String getDefaultLang() {
        return configAdapter.getConfiguration(appProperties.defaultLang());
    }

    public String getAdminOrganizationId() {
        return configAdapter.getConfiguration(appProperties.adminOrganizationId());
    }

    public String getSysTenant(){
        return configAdapter.getConfiguration(appProperties.sysTenant());
    }

    public String getLabelUploadCertifierEmail() {
        return labelUploadProperties.certifierEmail();
    }

    public String getLabelUploadMarketplaceEmail() {
        return labelUploadProperties.marketplaceEmail();
    }
}
