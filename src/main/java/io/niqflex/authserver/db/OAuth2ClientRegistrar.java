package io.niqflex.authserver.db;

/**
import com.google.common.collect.ImmutableList;
import io.niqflex.authserver.config.AuthorizationServerConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.esapi.Logger;
import org.owasp.esapi.logging.slf4j.Slf4JLogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;


@Slf4j
//@Component
@RequiredArgsConstructor
public class OAuth2ClientRegistrar {

    @Autowired
    static PasswordEncoder passwordEncoder;

    static Logger logger = new Slf4JLogFactory().getLogger(AuthorizationServerConfig.class);


    public static List<RegisteredClient> getClientsToRegister() {
         try {
             Instant t1 = Instant.now();
             long hours = 2;
             long minutes = 30;
             Instant t2 = t1.plus(hours, ChronoUnit.HOURS).plus(minutes, ChronoUnit.MINUTES);
             String data = String.format("now:  %s and later:  %s", t1, t2);
             logger.error(Logger.EVENT_SUCCESS, data);

             return ImmutableList.of(
                     RegisteredClient.withId(UUID.randomUUID().toString())
                              Steve Riesenberg Client Reg Start
                             .clientId("messaging-client")
                             //.clientSecret("{noop}secret")
                             .clientSecret(passwordEncoder.encode("secret"))
                             .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                             .redirectUri("http://127.0.0.1:8080/authorized")
                              Steve Riesenberg  Client Reg End
                             .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                             .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                             .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                             .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                             //.postLogoutRedirectUri("http://127.0.0.1:8080/index")
                             .scope(OidcScopes.OPENID)
                             .scope(OidcScopes.PROFILE)
                             .scope("message.read")
                             .scope("message.write")
                             .tokenSettings(getTokenSettings())
                             .clientIdIssuedAt(Instant.now())
                             .clientSecretExpiresAt(
                                      Instant.now().plus(Hour, ChronoUnit.HOURS) .plus(MINUTES, ChronoUnit.MINUTES)
                                     Instant.now().plus(0, ChronoUnit.HOURS).plus(30,
                                             ChronoUnit.MINUTES)
                             )
                             .clientSettings(getClientSettings())
                             .build(),
                     RegisteredClient.withId("niqflex")
                             .clientId("niqffy")
                             .clientSecret(passwordEncoder.encode("TmlxZmxleC1iYXNhbGFtaQ"))
                             .redirectUri("http://127.0.0.1:9966/login/oauth2/code/niqflex")
                             .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                             .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                             .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                             .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                             .scope(OidcScopes.OPENID)
                             .scope(OidcScopes.PROFILE)
                             .scope("message.read")
                             .scope("message.write")
                             .tokenSettings(getTokenSettings())
                             .clientIdIssuedAt(Instant.now())
                             .clientSecretExpiresAt(
                                      Instant.now().plus(Hour, ChronoUnit.HOURS) .plus(MINUTES, ChronoUnit.MINUTES)
                                     Instant.now().plus(0, ChronoUnit.HOURS).plus(30,
                                             ChronoUnit.MINUTES)
                             )
                             .clientSettings(getClientSettings())
                             .build()

             );
         }
         catch (Exception ex) {
             logger.error(Logger.EVENT_FAILURE, ex.getLocalizedMessage(), ex);
             throw new RuntimeException(ex.getMessage());
         }

    }

    private static ClientSettings getClientSettings(){
        return ClientSettings.builder()
                //.jwkSetUrl("")
                .requireProofKey(true)
                //.tokenEndpointAuthenticationSigningAlgorithm(JwsAlgorithm.)
                .requireAuthorizationConsent(false)
                .build();
    }

    private static TokenSettings getTokenSettings() {
        // @formatter:off
        long numberOfMinutes = 30;
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(numberOfMinutes))
                .build();
        // @formatter:on
    }

    private static Instant getExpiryDate(int additionalMinutes) {
        return Instant.now()
                .plus(additionalMinutes, ChronoUnit.MINUTES);
    }





}
*/


