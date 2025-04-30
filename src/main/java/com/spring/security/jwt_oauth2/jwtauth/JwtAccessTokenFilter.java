package com.spring.security.jwt_oauth2.jwtauth;

import com.spring.security.jwt_oauth2.config.RSAKeyRecord;
import com.spring.security.jwt_oauth2.enums.TokenTypeEnum;
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
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class JwtAccessTokenFilter extends OncePerRequestFilter {

    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;

    //concern :- in filter chain we are using .addFilterBefore(new JwtAccessTokenFilter(rsaKeyRecord, jwtTokenUtils), UsernamePasswordAuthenticationFilter.class)
    //but in JwtAccessTokenFilter class, we are not stopping the flow if we do not validate jwt token
    //we are just not creating security context, if token is not valid
    //so could not it be the case, that somehow token is invalid, but username and password are still correct
    //like may be it is expired, but username and password are still correct
    //then req will go to UsernamePasswordAuthenticationFilter, and it will create security context


    //Ans, yes for that what we can do, instead of calling filterChain.doFilter(request,response);
    //we can type return;, now it will not proceed to next filter, and will return without securitycontext
    //doFilter only forward to next filter in filter chain, so if want to stop, we can call return
    //like we are doing it in below code, when token is not starting with bearer

    //but for other conditions we are not returning we are just not setting security context
    //so for that, for now, it is getting failed at decoding token
    //when we decode expired token it is throwing exception, and it doest not move to next filter

    //it is working for now, but in future there may be some claim that will not throw exception
    //and it will move to next filter and set context, so in that case, we should use return;





    //Also, why return after doFilter()

//    Great question! The return statement in your filter is not redundant—it actually serves a purpose even after calling filterChain.doFilter(request, response). Here's why:
//    Why use return after filterChain.doFilter()?
//    Prevents Further Execution
//    Once the request is passed to the next filter using filterChain.doFilter(), we don't want any more logic in the current filter to execute.
//    Without return, additional code in the filter might run unintentionally, possibly modifying the response.
//    Avoids Unwanted Side Effects
//    If there are logging statements, transformations, or other operations after doFilter(), they could alter the response unexpectedly.
//            return ensures that the filter's job is done, and nothing more happens.



    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try{
            log.info("[JwtAccessTokenFilter:doFilterInternal] :: Started ");

            log.info("[JwtAccessTokenFilter:doFilterInternal]Filtering the Http Request:{}",request.getRequestURI());

            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            JwtDecoder jwtDecoder =  NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();

            if(!authHeader.startsWith(TokenTypeEnum.Bearer.name())){
                filterChain.doFilter(request,response);
                return;
            }

            final String token = authHeader.substring(7);
            final Jwt jwtToken = jwtDecoder.decode(token);


            final String userName = jwtTokenUtils.getUserName(jwtToken);

            if(!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){

                UserDetails userDetails = jwtTokenUtils.userDetails(userName);
                if(jwtTokenUtils.isTokenValid(jwtToken,userDetails)){
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }
            log.info("[JwtAccessTokenFilter:doFilterInternal] Completed");

            filterChain.doFilter(request,response);
        }catch (JwtValidationException jwtValidationException){
            log.error("[JwtAccessTokenFilter:doFilterInternal] Exception due to :{}",jwtValidationException.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE,jwtValidationException.getMessage());
        }
    }
}
