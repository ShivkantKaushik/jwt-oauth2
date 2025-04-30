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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;

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

        //From reddit
//        All cookies are sent back as part of all requests to your server. Setting httponly means that the cookie is not readable by any JavaScript on the page but only used in http requests.
//
//                This makes sure that even if an attacker somehow manages to inject and execute a malicious script on your page they still won’t be able to access the cookie and it’s contents. That’s why it’s safer.
//
//        The cookie is however still sent back to your server with every request so you still have access to its contents server side. Using https also adds an additional layer of protection against man in the middle attacks.
//
//                You should also make sure that the domain for the cookie is properly set and restricted to just your domain.
//
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60);

        response.addCookie(refreshTokenCookie);

        return refreshTokenCookie;
    }


    public Object getAccessTokenUsingRefreshToken(String authorizationHeader) {

        if( ! authorizationHeader.startsWith("Bearer")){
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Token type not bearer.");
        }


        final String refreshToken = authorizationHeader.substring(7);

        RefreshTokenEntity refreshTokenEntity = refreshTokenRepo.findByRefreshToken(refreshToken)
                .filter(token -> !token.isRevoked()).orElseThrow( () -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh Token revoked.")
                );


        UserInfoEntity userInfoEntity = refreshTokenEntity.getUser();

        Authentication authentication = createAuthenticationObject(userInfoEntity);

        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

        return AuthResponseDto.builder().accessToken(accessToken)
                .accessTokenExpiry(1)
                .userName(userInfoEntity.getUserName())
                .tokenType(TokenTypeEnum.Bearer)
                .build();


    }


    private static Authentication createAuthenticationObject(UserInfoEntity userInfoEntity){

        String username = userInfoEntity.getUserName();
        String password = userInfoEntity.getPassword();
        String roles = userInfoEntity.getRoles();

        GrantedAuthority[] grantedAuthorities = Arrays.stream(roles.split(",")).map(
                String::trim
        ).toArray(GrantedAuthority[]::new);


        //this UsernamePasswordAuthenticationToken extends Authentication Interface
        //so this can be used to generate authentication object
        return new UsernamePasswordAuthenticationToken(username,password,Arrays.asList(grantedAuthorities));

    }

}
