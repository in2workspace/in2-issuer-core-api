package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.OPTIONS;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;


@Configuration
@RequiredArgsConstructor
public class PublicCORSConfig {

    private final AppConfig appConfig;

    /**
     * Public CORS configuration source.
     */
    @Bean
    public UrlBasedCorsConfigurationSource publicCorsConfigurationSource() {

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // Open config for public endpoints
        CorsConfiguration openConfig = new CorsConfiguration();
        openConfig.setAllowedOriginPatterns(List.of("https://*"));
        openConfig.setAllowedMethods(List.of("GET", "POST", OPTIONS));
        openConfig.setAllowedHeaders(List.of("*"));
        openConfig.setAllowCredentials(false);
        openConfig.setMaxAge(1800L);

        source.registerCorsConfiguration(CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH, openConfig);
        source.registerCorsConfiguration(AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH, openConfig);
        source.registerCorsConfiguration(CORS_CREDENTIAL_OFFER_PATH, openConfig);
        source.registerCorsConfiguration(OAUTH_TOKEN_PATH, openConfig);

        // Restricted config
        CorsConfiguration externalConfig = new CorsConfiguration();
        externalConfig.setAllowedOrigins(appConfig.getExternalCorsAllowedOrigins());
        externalConfig.setAllowedMethods(List.of("POST", OPTIONS));
        externalConfig.setAllowedHeaders(List.of("*"));
        externalConfig.setAllowCredentials(false);
        externalConfig.setMaxAge(1800L);

        source.registerCorsConfiguration(VCI_ISSUANCES_PATH, externalConfig);

        CorsConfiguration oid4vciConfig = new CorsConfiguration();
        oid4vciConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", OPTIONS));
        oid4vciConfig.setAllowedHeaders(List.of("*"));
        oid4vciConfig.setAllowCredentials(false);
        oid4vciConfig.setMaxAge(1800L);

        source.registerCorsConfiguration(OID4VCI_CREDENTIAL_OFFER_PATH, oid4vciConfig);
        source.registerCorsConfiguration(OID4VCI_CREDENTIAL_PATH, oid4vciConfig);

        return source;
    }
}
