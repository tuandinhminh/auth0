package com.example.demo1.config;

import com.auth0.AuthenticationController;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.example.demo1.controller.LogoutController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;


@Configuration
@EnableWebSecurity
public class WebSecurity {

    @Configuration
    @Order(1)
    public static class BasicAuthConfig extends WebSecurityConfigurerAdapter {

        @Bean
        public LogoutSuccessHandler logoutSuccessfulHandler() {
            return new LogoutController();
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .cors().and().csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/users").hasRole("ADMINISTRATOR")
                    .antMatchers("/admins").hasRole("ADMIN")
                    .antMatchers("/login", "/auth0/*", "/auth0").permitAll()
                    .anyRequest().authenticated()

                    .and()
                    .formLogin()
                    .defaultSuccessUrl("/name")

                    .and()
                    .logout()
                    .logoutSuccessHandler(logoutSuccessfulHandler())
                    .deleteCookies("JSESSIONID")
                    .and()
                    .exceptionHandling()
                    .accessDeniedPage("/403")
            ;
        }

    }

    @Configuration
    @Order(2)
    public static class Auth0Config extends WebSecurityConfigurerAdapter {

        @Value(value = "${com.auth0.domain}")
        private String domain;

        @Value(value = "${com.auth0.clientId}")
        private String clientId;

        @Value(value = "${com.auth0.clientSecret}")
        private String clientSecret;

        @Value(value = "${com.auth0.managementApi.grantType}")
        private String grantType;

        @Autowired
        private CustomAuthenticationProvider authProvider;

        // create two users, admin and user
        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(authProvider);
        }

        @Autowired
        public void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(authProvider);
        }

        @Bean
        public LogoutSuccessHandler logoutSuccessHandler() {
            return new LogoutController();
        }

        @Bean
        public AuthenticationController authenticationController() throws UnsupportedEncodingException {
            JwkProvider jwkProvider = new JwkProviderBuilder(domain).build();
            return AuthenticationController.newBuilder(domain, clientId, clientSecret)
                    .withJwkProvider(jwkProvider)
                    .build();
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/auth0/*")
                    .permitAll()
                    .anyRequest()
                    .authenticated()

                    .and()
                    .formLogin()
                    .loginPage("/auth0/in")

                    .and()
                    .exceptionHandling()
                    .accessDeniedPage("/403")
                    .and()
                    .csrf()
                    .disable();
        }

        public String getDomain() {
            return domain;
        }

        public String getClientId() {
            return clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public String getLogoutUrl() {
            return "https://" + getDomain() + "/v2/logout";
        }

        public String getContextPath(HttpServletRequest request) {
            String path = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
            return path;
        }

    }
}