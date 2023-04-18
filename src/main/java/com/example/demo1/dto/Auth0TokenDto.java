package com.example.demo1.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class Auth0TokenDto {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("scope")
    private String scope;
    @JsonProperty("expires_in")
    private int expiresIn;
    @JsonProperty("token_type")
    private String tokenType;
}
