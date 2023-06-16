/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
updated
*/
package io.niqflex.authserver.authn;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.niqflex.authserver.deviceauthn.DeviceClientAuthenticationConverter;
import io.niqflex.authserver.deviceauthn.DeviceClientAuthenticationProvider;
import io.niqflex.authserver.federation.FederatedIdentityIdTokenCustomizer;
import io.niqflex.authserver.jose.Jwks;
import org.owasp.esapi.Logger;
import org.owasp.esapi.logging.slf4j.Slf4JLogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Steve Riesenberg
 * @since 1.1
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
	private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

	/**
	 http://localhost:9000/.well-known/openid-configuration
	 http://localhost:9000/.well-known/oauth-authorization-server
	 */
	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	ObjectMapper objectMapper;

	Logger logger = new Slf4JLogFactory().getLogger(AuthorizationServerConfig.class);

	private static final List<String> ALLOWED_HEADERS = List.of(
			"Access-Control-Allow-Origin",
			"x-requested-with",
			"Authorization"
	);
	private static final List<String> ALLOWED_METHODS = List.of("POST");
	private static final List<String> ALLOWED_ALL = List.of(
			"http://127.0.0.1:8080",
			"http://127.0.0.1:8081",
			"http://127.0.0.1:8082",
			"http://127.0.0.1:9494",
			"http://127.0.0.1:9494/niqflex/"
	);

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(ALLOWED_ALL);
		configuration.setAllowedMethods(ALLOWED_METHODS);
		configuration.setAllowedHeaders(ALLOWED_HEADERS);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(
			HttpSecurity http, RegisteredClientRepository registeredClientRepository,
			AuthorizationServerSettings authorizationServerSettings) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		/*
		 * This sample demonstrates the use of a public client that does not
		 * store credentials or authenticate with the authorization server.
		 *
		 * The following components show how to customize the authorization
		 * server to allow for device clients to perform requests to the
		 * OAuth 2.0 Device Authorization Endpoint and Token Endpoint without
		 * a clientId/clientSecret.
		 *
		 * CAUTION: These endpoints will not require any authentication, and can
		 * be accessed by any client that has a valid clientId.
		 *
		 * It is therefore RECOMMENDED to carefully monitor the use of these
		 * endpoints and employ any additional protections as needed, which is
		 * outside the scope of this sample.
		 */
		DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
				new DeviceClientAuthenticationConverter(
						authorizationServerSettings.getDeviceAuthorizationEndpoint());
		DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
				new DeviceClientAuthenticationProvider(registeredClientRepository);

		// @formatter:off
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
				deviceAuthorizationEndpoint.verificationUri("/activate")
			)
			.deviceVerificationEndpoint(deviceVerificationEndpoint ->
				deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)
			)
			.clientAuthentication(clientAuthentication ->
				clientAuthentication
					.authenticationConverter(deviceClientAuthenticationConverter)
					.authenticationProvider(deviceClientAuthenticationProvider)
			)
			.authorizationEndpoint(authorizationEndpoint ->
				authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
			.oidc(withDefaults());	// Enable OpenID Connect 1.0
		// @formatter:on

		// @formatter:off
		http
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			.oauth2ResourceServer(oauth2ResourceServer ->
				oauth2ResourceServer.jwt(withDefaults())
			)
	        .cors(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	// @formatter:off

	Consumer<Set<String>> scopes = scope ->  {
		scope.add(OidcScopes.OPENID);
		scope.add(OidcScopes.PROFILE);
		scope.add(OidcScopes.EMAIL);
		scope.add("niqflex.read");
		scope.add("niqflex.write");
		scope.add("niqflex.update");
		scope.add("read");
		scope.add("write");
		scope.add("update");
	};

	Consumer<Set<String>> redirectUris = uris ->  {
		/** default Authorization Response redirection endpoint */
		uris.add("http://127.0.0.1:8080/login/oauth2/callback/studio");
		uris.add("http://127.0.0.1:8080/login/oauth2/code/studio");
		uris.add("http://127.0.0.1:8081/login/oauth2/code/studioz");
		uris.add("http://127.0.0.1:8081/login/oauth2/callback/studio");
		uris.add("http://127.0.0.1:8081/login/oauth2/callback/studioz");
		uris.add("http://127.0.0.1:8081/login/oauth2/code/studio");
		uris.add("http://127.0.0.1:8082/login/oauth2/code/studio");
		uris.add("http://127.0.0.1:8082/login/oauth2/callback/studio");
		uris.add("chrome-extension://liacakmdhalagfjlfdofigfoiocghoej/swagger/index.html");
		uris.add("http://127.0.0.1:9494/niqflex/webjars/swagger-ui/oauth2-redirect.html");
		uris.add("http://127.0.0.1:9494/login/oauth2/code/openapi");
		uris.add("http://localhost:9494/api/swagger.json");
		uris.add("http://127.0.0.1:8082/login/oauth2/callback/studioz");
		uris.add("http://127.0.0.1:8082/login/oauth2/code/studioz");

	};
	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("bmlx@niqflex.io")
				.clientSecret(passwordEncoder.encode("ZGFzc3liaWx5"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
				.tokenSettings(getTokenSettings())
				.redirectUris(redirectUris)
				.scopes(scopes)
				.clientName("NiQFlex")
				.clientIdIssuedAt(Instant.now())
				.build();

		RegisteredClient messageClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret(passwordEncoder.encode("secret"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("message.read")
				.scope("message.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();

		RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("device-messaging-client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.scope("message.read")
				.scope("message.write")
				.build();
/**
		RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("dbmlx@niqflex.io")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.scope("niqflex.read")
				.scope("niqflex.write")
				.build();
*/
		// Save registered client's in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		registeredClientRepository.save(registeredClient);
		registeredClientRepository.save(deviceClient);
		registeredClientRepository.save(messageClient);

		return registeredClientRepository;
	}
	// @formatter:on

	@Bean
	public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		// Will be used by the ConsentController
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
		return new FederatedIdentityIdTokenCustomizer();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public EmbeddedDatabase embeddedDatabase() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
	}

	private TokenSettings getTokenSettings() {
		// @formatter:off
		/**
		 Instant d = Instant.EPOCH.ofEpochSecond(1500);
		 long numberOfMinutes = 10;
		 */
		return TokenSettings.builder()
				.authorizationCodeTimeToLive(Duration.ofMinutes(10))
				.deviceCodeTimeToLive(Duration.ofMinutes(10))
				.refreshTokenTimeToLive(Duration.ofMinutes(10))
				.reuseRefreshTokens(true)
				.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
				.accessTokenTimeToLive(Duration.ofMinutes(10))
				.build();
		// @formatter:on
	}

	/** Not In Use */
	// @Bean
	public DataSource dataSource() {
		DriverManagerDataSource driverManagerDataSource = new DriverManagerDataSource();
		driverManagerDataSource.setUrl("jdbc:h2:file:~/OAuth2DB;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
		driverManagerDataSource.setUsername("sa");
		driverManagerDataSource.setPassword("");
		driverManagerDataSource.setDriverClassName("org.h2.Driver");
		return driverManagerDataSource;
	}

	/**
	 //@Bean
	 public SimpleDriverDataSource simpleDriverDataSource() throws ClassNotFoundException {
	 return new SimpleDriverDataSource(
	 new Driver(),
	 "jdbc:h2:file:~/OAuth2DB;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
	 "sa",
	 ""
	 );
	 }


	 //@Bean
	 public Connection connection() throws ClassNotFoundException, SQLException {
	 Connection conn = DriverManager.getConnection(
	 "jdbc:h2:file:~/OAuth2DB;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE", "sa", "");
	 return conn;
	 }


	 //@Bean
	 public JdbcTemplate jdbcTemplate(DataSource dataSource) throws ClassNotFoundException, SQLException {
	 return new JdbcTemplate(dataSource, true);
	 }
	 */

	private List<RegisteredClient> getClientsToRegister() {
		//ClientRegistration is a representation of a client registered with an OAuth 2.0 or OpenID Connect 1.0 Provider.
		try {
			Instant t1 = Instant.now();
			Instant D = Instant.EPOCH.plus(10, ChronoUnit.MINUTES);
			long hours = 2;
			long minutes = 30;
			Instant t2 = t1.plus(hours, ChronoUnit.HOURS).plus(minutes, ChronoUnit.MINUTES);
			String data = String.format("now:  %s and later:  %s", t1, t2);
			logger.error(Logger.EVENT_SUCCESS, data);

			return ImmutableList.of(
					RegisteredClient.withId(UUID.randomUUID().toString())
							/** Steve Riesenberg Client Reg Start */
							.clientId("messaging-client")
							//.clientSecret("{noop}secret")
							.clientSecret(passwordEncoder.encode("secret"))
							.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
							.redirectUri("http://127.0.0.1:8080/authorized")
							/** Steve Riesenberg  Client Reg End */
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
									/** Instant.now().plus(Hour, ChronoUnit.HOURS) .plus(MINUTES, ChronoUnit.MINUTES)*/
									Instant.now().plus(0, ChronoUnit.HOURS).plus(30,
											ChronoUnit.MINUTES)
							)
							.clientSettings(getClientSettings())
							.build(),
					RegisteredClient.withId("niqflex")
							.clientId("niqzzy")
							.clientSecret(passwordEncoder.encode("dassybilly")) //"TmlxZmxleC1iYXNhbGFtaQ"
							.redirectUri("http://127.0.0.1:8080/login/oauth2/code/niqflex")
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
									/** Instant.now().plus(Hour, ChronoUnit.HOURS) .plus(MINUTES, ChronoUnit.MINUTES)*/
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

	private ClientSettings getClientSettings(){
		return ClientSettings.builder()
				//.jwkSetUrl("")
				.requireProofKey(true)
				//.tokenEndpointAuthenticationSigningAlgorithm(JwsAlgorithm.)
				.requireAuthorizationConsent(false)
				.build();
	}



	private Instant getExpiryDate(int additionalMinutes) {
		return Instant.EPOCH.ofEpochSecond(1500);
		//return Instant.now().plus(additionalMinutes, ChronoUnit.MINUTES);
	}


}
