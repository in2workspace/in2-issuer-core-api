package es.in2.issuer.backend.shared.infrastructure.config.properties;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "label-upload")
@Validated
public record LabelUploadProperties(
        @NotBlank @Email String certifierEmail,
        @NotBlank @Email String marketplaceEmail
) {

    @ConstructorBinding
    public LabelUploadProperties(String certifierEmail, String marketplaceEmail) {
        this.certifierEmail = certifierEmail;
        this.marketplaceEmail = marketplaceEmail;
    }
}
