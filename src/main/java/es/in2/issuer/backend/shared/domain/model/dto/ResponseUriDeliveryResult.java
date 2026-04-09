package es.in2.issuer.backend.shared.domain.model.dto;

public record ResponseUriDeliveryResult(boolean acceptedWithHtml, String html) {

    public static ResponseUriDeliveryResult success() {
        return new ResponseUriDeliveryResult(false, null);
    }

    public static ResponseUriDeliveryResult acceptedWithHtml(String html) {
        return new ResponseUriDeliveryResult(true, html);
    }
}
