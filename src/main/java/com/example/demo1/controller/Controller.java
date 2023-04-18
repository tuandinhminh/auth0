package com.example.demo1.controller;

import com.auth0.AuthenticationController;
import com.auth0.IdentityVerificationException;
import com.auth0.Tokens;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo1.config.WebSecurity;
import com.example.demo1.dto.Auth0RoleDto;
import com.example.demo1.utils.WebClientUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

@RestController
public class Controller {

    @GetMapping("/users")
    public String getUsers() {
        return "users";
    }

    @GetMapping("/admins")
    public String getAdmins() {
        return "admins";
    }

    @GetMapping("/name")
    public String getName(Authentication authentication) {
        return authentication.getName();
    }

    @Autowired
    private AuthenticationController authenticationController;

    @Autowired
    private WebSecurity.Auth0Config config;

    @Autowired
    private WebClientUtil webClientUtil;

    @GetMapping(value = "/auth0/in")
    protected void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUri = config.getContextPath(request) + "/auth0/callback";
        String authorizeUrl = authenticationController.buildAuthorizeUrl(request, response, redirectUri)
                .withScope("openid email")
                .build();
        response.sendRedirect(authorizeUrl);
    }

    @GetMapping(value="/auth0/callback")
    public void callback(HttpServletRequest request, HttpServletResponse response) throws IOException, IdentityVerificationException, ExecutionException, InterruptedException {
        Tokens tokens = authenticationController.handle(request, response);

        DecodedJWT jwt = JWT.decode(tokens.getIdToken());
        String userId = jwt.getClaims().get("sub").asString();
        Set<Auth0RoleDto> roles = webClientUtil.getRequest("https://" + config.getDomain() + "/api/v2/users/"+ userId +"/roles"
                , new ParameterizedTypeReference<Set<Auth0RoleDto>>() {
        }).get();
        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> role.getName().startsWith("ROLE_") ? role.getName() : "ROLE_" + role.getName())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        TestingAuthenticationToken authToken2 = new TestingAuthenticationToken(jwt.getSubject(), jwt.getToken(), authorities);
        authToken2.setAuthenticated(true);

        SecurityContextHolder.getContext().setAuthentication(authToken2);
        response.sendRedirect(config.getContextPath(request) + "/auth0");
    }
}
