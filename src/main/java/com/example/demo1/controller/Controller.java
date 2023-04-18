package com.example.demo1.controller;

import com.auth0.AuthenticationController;
import com.auth0.IdentityVerificationException;
import com.auth0.Tokens;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo1.config.WebSecurity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class Controller {

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMINISTRATOR')")
    public String hello() {
        return "hello";
    }

    @GetMapping("/admins")
    @PreAuthorize("hasRole('ADMINISTRATOR')")
    public String hello1() {
        return "admins";
    }

    @GetMapping("/name")
    @PreAuthorize("hasRole('ADMINISTRATOR')")
    public String hello(Authentication authentication) {
        return authentication.getName();
    }

    @Autowired
    private AuthenticationController authenticationController;

    @Autowired
    private WebSecurity.Auth0Config config;

    @GetMapping(value = "/auth0/in")
    protected void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUri = config.getContextPath(request) + "/auth0/callback";
        String authorizeUrl = authenticationController.buildAuthorizeUrl(request, response, redirectUri)
                .withScope("openid email")
                .build();
        response.sendRedirect(authorizeUrl);
    }

    @GetMapping(value="/auth0/callback")
    public void callback(HttpServletRequest request, HttpServletResponse response) throws IOException, IdentityVerificationException {
        Tokens tokens = authenticationController.handle(request, response);

        DecodedJWT jwt = JWT.decode(tokens.getIdToken());
        TestingAuthenticationToken authToken2 = new TestingAuthenticationToken(jwt.getSubject(), jwt.getToken());
        authToken2.setAuthenticated(true);

        SecurityContextHolder.getContext().setAuthentication(authToken2);
        response.sendRedirect(config.getContextPath(request) + "/auth0");
    }
}
