package com.spring.security.jwt_oauth2;

import com.spring.security.jwt_oauth2.config.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RSAKeyRecord.class)
public class JwtOauth2Application {

	public static void main(String[] args) {
		SpringApplication.run(JwtOauth2Application.class, args);
	}

}
