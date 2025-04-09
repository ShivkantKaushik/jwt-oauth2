package com.spring.security.jwt_oauth2.service;

import com.spring.security.jwt_oauth2.dto.AuthResponseDto;
import com.spring.security.jwt_oauth2.entity.RefreshTokenEntity;
import com.spring.security.jwt_oauth2.entity.UserInfoEntity;
import com.spring.security.jwt_oauth2.enums.TokenTypeEnum;
import com.spring.security.jwt_oauth2.jwtauth.JwtTokenGenerator;
import com.spring.security.jwt_oauth2.repo.RefreshTokenRepo;
import com.spring.security.jwt_oauth2.repo.UserInfoRepo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserInfoRepo userInfoRepo;
    private final RefreshTokenRepo refreshTokenRepo;
    private final JwtTokenGenerator jwtTokenGenerator;
    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse httpServletResponse) {
        try
        {
            var userInfoEntity = userInfoRepo.findByEmailId(authentication.getName())
                    .orElseThrow(()->{
                        log.error("[AuthService:userSignInAuth] User :{} not found",authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND,"USER NOT FOUND ");});


            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            createRefreshTokenCookie(httpServletResponse,refreshToken);



            log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated",userInfoEntity.getUserName());
            return  AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15 * 60)
                    .userName(userInfoEntity.getUserName())
                    .tokenType(TokenTypeEnum.Bearer)
                    .build();


        }catch (Exception e){
            log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
        }
    }



    private void saveRefreshToken(UserInfoEntity userInfoEntity, String refreshToken){

        var refreshTokenEntity = RefreshTokenEntity.builder()
                .user(userInfoEntity)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();

        refreshTokenRepo.save(refreshTokenEntity);

    }

    private Cookie createRefreshTokenCookie(HttpServletResponse response, String refreshToken){

        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60);

        response.addCookie(refreshTokenCookie);

        return refreshTokenCookie;
    }


}
