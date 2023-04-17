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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;


@Configuration
@EnableWebSecurity
public class WebSecurity {

    @Configuration
    public static class BasicAuthConfig {

        @Bean
        @Order(1)
        public SecurityFilterChain configure(HttpSecurity http) throws Exception {
            http
                    .cors().and().csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/users").hasRole("ADMINISTRATOR")
                    .antMatchers("/admins").hasRole("ADMIN")
                    .antMatchers("/login", "/auth0/out").permitAll()
                    .anyRequest().authenticated()

                    .and()
                    .formLogin()
                    .defaultSuccessUrl("/name")

                    .and()
                    .logout()
                    .logoutUrl("/logout")
                    .deleteCookies("JSESSIONID")
            ;
            return http.build();
        }

    }

    @Configuration
    public static class Auth0Config {

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

        @Bean
        public AuthenticationManager authManager(HttpSecurity http) throws Exception {
            AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
            authenticationManagerBuilder.authenticationProvider(authProvider);
            return authenticationManagerBuilder.build();
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

        @Bean
        @Order(2)
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
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
                    .logout()
                    .logoutUrl("/auth0/out")
                    .logoutSuccessHandler(logoutSuccessHandler())
                    .deleteCookies("JSESSIONID")
                    .and()
                    .exceptionHandling()
                    .accessDeniedPage("/403")
                    .and()
                    .csrf()
                    .disable();
            return http.build();
        }

        public String getDomain() {
            return domain;
        }

        public String getClientId() {
            return clientId;
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