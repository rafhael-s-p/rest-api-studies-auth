package com.studies.foodorders.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtKeyStoreProperties jwtKeyStoreProperties;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                    .withClient("web-client")
                    .secret(passwordEncoder.encode("1234"))
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("write", "read")
                    .accessTokenValiditySeconds(60 * 60 * 6) // 6 hours (default is 12 hours)
                    .refreshTokenValiditySeconds(7 * 24 * 60 * 60) // 7 days

                .and()
                    .withClient("any-back-end-application")
                    .secret(passwordEncoder.encode("1234"))
                    .authorizedGrantTypes("client_credentials")
                    .scopes("write", "read")
                /*
                * It must request a code by the url
                * http://localhost:8081/oauth/authorize?response_type=code&client_id=client-oauth2-authorization-code&state=abcd&redirect_uri=http://localhost:8082
                *
                * PKCE Plain
                * http://localhost:8081/oauth/authorize?response_type=code&client_id=client-oauth2-authorization-code&redirect_uri=http://localhost:8082&code_challenge=ABcd&code_challenge_method=plain
                *
                * PKCE SHA-256
                * http://localhost:8081/oauth/authorize?response_type=code&client_id=client-oauth2-authorization-code&redirect_uri=http://localhost:8082&code_challenge=F4BP93803TyWD7lruWDpi3BDrPuIYFUlaboOSVCANiM&code_challenge_method=s256
                *
                * Link to generate Code Verifier and Code Challenge
                * https://tonyxu-io.github.io/pkce-generator/
                *
                * */
                .and()
                    .withClient("client-oauth2-authorization-code")
                    .secret(passwordEncoder.encode("1234"))
                    .authorizedGrantTypes("authorization_code")
                    .scopes("write", "read")
                    .redirectUris("http://localhost:8082")
                /*
                 * It must request a code by the url
                 * http://localhost:8081/oauth/authorize?response_type=token&client_id=implicit-grant-type-user&state=abcd&redirect_uri=http://localhost:8082
                 * */
                .and()
                    .withClient("implicit-grant-type-user")
                    .authorizedGrantTypes("implicit")
                    .scopes("write", "read")
                    .redirectUris("http://localhost:8082")
                .and()
                    .withClient("checktoken")
                    .secret(passwordEncoder.encode("check1234"));
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
//		security.checkTokenAccess("isAuthenticated()"); It's necessary to set client user and password
        security.checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false)
                .accessTokenConverter(jwtAccessTokenConverter())
                .tokenGranter(tokenGranter(endpoints));
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();

        var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
        var keyStorePass = jwtKeyStoreProperties.getPassword();
        var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();

        var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
        var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);

        jwtAccessTokenConverter.setKeyPair(keyPair);

        return jwtAccessTokenConverter;
    }

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());

        var granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

        return new CompositeTokenGranter(granters);
    }

}
