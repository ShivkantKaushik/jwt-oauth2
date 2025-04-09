package com.spring.security.jwt_oauth2.repo;

import com.spring.security.jwt_oauth2.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshTokenEntity, Long> {



}

