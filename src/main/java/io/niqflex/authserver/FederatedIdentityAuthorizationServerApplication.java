package io.niqflex.authserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import org.owasp.esapi.*;
import org.owasp.esapi.logging.slf4j.Slf4JLogFactory;
import org.owasp.esapi.logging.slf4j.Slf4JLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.ExitCodeGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

@SpringBootApplication
public class FederatedIdentityAuthorizationServerApplication extends SpringBootServletInitializer {

	Logger logger = new Slf4JLogFactory().getLogger(FederatedIdentityAuthorizationServerApplication.class);

	@Autowired
	JdbcTemplate jdbcTemplate;

	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	ObjectMapper objectMapper;

	@Bean
	public ExitCodeGenerator exitCodeGenerator() {
		return () -> 42;
	}

	@EventListener(ApplicationReadyEvent.class)
	public void findRegisteredClient() {
		try {
			JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
			RegisteredClient client = registeredClientRepository.findByClientId("bmlx@niqflex.io");
			//RegisteredClient clienta = registeredClientRepository.findById("TmlxZmxleC1iYXNhbGFtaQ").orElseThrow();;
			String data = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(client );
			logger.error(Logger.EVENT_SUCCESS, data);


            /**
			ClientRegistration clientReg = clientRegistrationRepository.findByRegistrationId("niqflex");
			String info = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(clientReg);
			logger.error(Logger.EVENT_SUCCESS, info);
			return data;
			*/
		}
		catch (Exception ex){
			logger.error(Logger.EVENT_FAILURE, ex.getLocalizedMessage(), ex);
			//throw new RuntimeException(ex.getLocalizedMessage());
		}

	}

	//@Bean
	public CommandLineRunner commandLineRunner(){

		return new CommandLineRunner() {
			@Override
			public void run(String... args) throws Exception {
				//"classpath:data/employees.dat"
				try {
					/**
					 System.setProperty("org.owasp.esapi.opsteam", "classpath:ESAPI.properties");
					 System.setProperty("org.owasp.esapi.devteam", "classpath:ESAPI.properties");
					 System.setProperty("org.owasp.esapi.opsteam", "classpath:niqflex.properties");
					 System.setProperty("org.owasp.esapi.resources", "classpath:ESAPI.properties");
					 log.info("ESAPI Configuration {}", System.getProperty("org.owasp.esapi.opsteam"));
					 */
					ESAPI.securityConfiguration().getStringProp("ESAPI.Logger");
					ESAPI.securityConfiguration().getStringProp("ESAPI.Authenticator");
					ESAPI.securityConfiguration().getStringProp("ESAPI.Validator");
					ESAPI.securityConfiguration().getStringProp("ESAPI.Encryptor");

					//Validator validator = DefaultValidator.getInstance();
					Authenticator authenticator = ESAPI.authenticator();;

					logger.info(Logger.EVENT_SUCCESS, "********Create ESAPI User**********");
					String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
					String password = authenticator.generateStrongPassword();
					User user = authenticator.createUser(accountName, password, password);
					Assert.isTrue(user.verifyPassword(password), "In valid user");

					Assert.isTrue(logger instanceof Slf4JLogger, "logger instanceof Slf4JLogger");
					logger.info(Logger.EVENT_SUCCESS, "********OWASP Enterprise Security API (ESAPI) it works**********");
				}
				catch (RuntimeException ex){
					logger.error(Logger.EVENT_FAILURE, ex.getLocalizedMessage(), ex);
				}
			}
		};
	}

	@Override
	public void onStartup(ServletContext servletContext) throws ServletException {
		super.onStartup(servletContext);
		servletContext.getServletRegistration(DispatcherServletAutoConfiguration.DEFAULT_DISPATCHER_SERVLET_BEAN_NAME)
				/** How to handle HTTP OPTIONS with Spring MVC */
				.setInitParameter("dispatchOptionsRequest", "true");
	}

	public static void main(String[] args) {
		SpringApplication.run(FederatedIdentityAuthorizationServerApplication.class, args);
	}

}
