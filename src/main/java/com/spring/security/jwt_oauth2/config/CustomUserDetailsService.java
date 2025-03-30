package com.spring.security.jwt_oauth2.config;

import com.spring.security.jwt_oauth2.repo.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserInfoRepo userInfoRepo;



    //security filter chain will call this function, but it will pass user name
    //it receive from basic auth creds, but here we are using email id
    //so in basic auth at place of username pass email id
    @Override
    public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
        return userInfoRepo
                .findByEmailId(emailId)
                .map(CustomUserDetails::new)
                .orElseThrow(()-> new UsernameNotFoundException("UserEmail: "+emailId+" does not exist"));
    }
}

