package com.qrshield.web;

import com.qrshield.core.SafeBrowsingProvider;
import com.qrshield.core.ThreatIntelProvider;
import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {
    /** Holder because a Spring bean cannot be null: provider() is null when the integration is off. */
    public record ProviderHolder(ThreatIntelProvider provider) {}

    @Bean
    public ProviderHolder providerHolder(QrShieldProperties props) {
        boolean enabled = "safebrowsing".equalsIgnoreCase(props.getTiProvider())
                && props.getSafeBrowsingApiKey() != null && !props.getSafeBrowsingApiKey().isBlank();
        return new ProviderHolder(enabled
                ? new SafeBrowsingProvider(props.getSafeBrowsingApiKey(), Duration.ofSeconds(props.getTiTimeoutSeconds()))
                : null);
    }
}
