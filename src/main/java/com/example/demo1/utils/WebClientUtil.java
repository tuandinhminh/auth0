package com.example.demo1.utils;

import com.example.demo1.config.WebSecurity;
import com.example.demo1.dto.Auth0TokenDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static com.example.demo1.constant.WebclientConstant.*;

@Component
@Slf4j
@RequiredArgsConstructor
public class WebClientUtil {
    @Value("${com.auth0.audience}")
    private String auth0ProfileAudience;
    @Autowired
    private WebSecurity.Auth0Config config;

    HttpClient httpClient = HttpClient.create();
    private final WebClient client = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(httpClient))
            .build();

    public String getAccessToken() {
        try {
            LinkedMultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("grant_type", CLIENT_CREDENTIALS);
            map.add("client_id", config.getClientId());
            map.add("client_secret", config.getClientSecret());
            map.add(AUDIENCE, auth0ProfileAudience);
            return client.post()
                    .uri(URI.create("https://" + config.getDomain() + GET_TOKEN_URL))
                    .body(BodyInserters.fromFormData(map))
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE).retrieve()
                    .bodyToMono(Auth0TokenDto.class)
                    .toFuture().get().getAccessToken();

        } catch (InterruptedException | ExecutionException e) {
            log.error("CALL AUTH0 ERROR {}", e.getMessage());
        }
        return null;
    }

    public <R> CompletableFuture<R> getRequest(String url, ParameterizedTypeReference<R> responseType) {
        String accessToken = getAccessToken();
        return client.get()
                .uri(url)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken).retrieve()
                .bodyToMono(responseType)
                .toFuture();
    }
}
