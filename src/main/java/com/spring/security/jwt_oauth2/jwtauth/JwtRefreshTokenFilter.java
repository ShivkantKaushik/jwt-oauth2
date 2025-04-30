package com.spring.security.jwt_oauth2.jwtauth;


import com.spring.security.jwt_oauth2.config.RSAKeyRecord;
import com.spring.security.jwt_oauth2.enums.TokenTypeEnum;
import com.spring.security.jwt_oauth2.repo.RefreshTokenRepo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtRefreshTokenFilter extends OncePerRequestFilter {

    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepo refreshTokenRepo;



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try{

            log.debug("Inside JwtRefreshTokenFilter ", request.getRequestURI());

            String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();


            if (!authHeader.startsWith(TokenTypeEnum.Bearer.name())) {
                filterChain.doFilter(request, response);
                return;
            }

            final String token = authHeader.substring(7);

            final Jwt jwtRefreshToken = jwtDecoder.decode(token);

            final String username = jwtTokenUtils.getUserName(jwtRefreshToken);


            //if there is no user logged in then only providing access token by refresh token, may be this is the meaning
            if( !username.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){

                //check if refresh token is present in db and valid

                boolean isRefreshTokenInDBAndNotRevoked = refreshTokenRepo.findByRefreshToken(jwtRefreshToken.getTokenValue())
                        .map(token1 -> !token1.isRevoked()).orElseThrow( () -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Inside JwtRefreshTokenFilter, Token revoked."));



                //get user details

                UserDetails userDetails = jwtTokenUtils.userDetails(username);


                if( jwtTokenUtils.isTokenValid(jwtRefreshToken, userDetails) && isRefreshTokenInDBAndNotRevoked ){

                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();


                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    securityContext.setAuthentication(authentication);

                    SecurityContextHolder.setContext(securityContext);


                }

            }

            log.debug("Completed JwtRefreshTokenFilter");

            //proceed to next filter
            filterChain.doFilter(request,response);




        }catch (Exception e){
            log.error("Exception in JwtRefreshTokenFilter", e);
        }

    }
}
