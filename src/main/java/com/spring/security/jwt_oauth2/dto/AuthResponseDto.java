package com.spring.security.jwt_oauth2.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.spring.security.jwt_oauth2.enums.TokenTypeEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponseDto {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("access_token_expiry")
    private int accessTokenExpiry;

    @JsonProperty("token_type")
    private TokenTypeEnum tokenType;

    @JsonProperty("user_name")
    private String userName;

}