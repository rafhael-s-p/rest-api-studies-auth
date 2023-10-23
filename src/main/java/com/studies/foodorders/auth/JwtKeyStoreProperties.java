package com.studies.foodorders.auth;

import javax.validation.constraints.NotBlank;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Validated
@Component
@Getter
@Setter
@ConfigurationProperties("security.jwt.keystore")
public class JwtKeyStoreProperties {

	@NotBlank
	private String path;
	
	@NotBlank
	private String password;
	
	@NotBlank
	private String keypairAlias;

}
