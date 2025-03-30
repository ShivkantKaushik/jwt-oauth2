package com.spring.security.jwt_oauth2.repo;

import com.spring.security.jwt_oauth2.entity.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserInfoRepo extends JpaRepository<UserInfoEntity,Long> {

    Optional<UserInfoEntity> findByEmailId(String emailId);

}
