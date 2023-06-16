package io.niqflex.authserver.config;

import com.google.common.collect.ImmutableMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;

import java.util.Map;

@Slf4j
@Configuration(proxyBeanMethods = false)
public class AppConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
        String idForEncode = "sha256";
        Map<String, PasswordEncoder> encoders= ImmutableMap.of(
                idForEncode, new StandardPasswordEncoder()
        );
        return new DelegatingPasswordEncoder(idForEncode, encoders);
        //return PasswordEncoderFactories.createDelegatingPasswordEncoder();

    }








}
