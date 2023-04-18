package com.example.demo1.constant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Constant for Webclient
 */
@Component
public final class WebclientConstant {

    public static final String GET_TOKEN_URL = "/oauth/token";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String AUDIENCE = "audience";
}
