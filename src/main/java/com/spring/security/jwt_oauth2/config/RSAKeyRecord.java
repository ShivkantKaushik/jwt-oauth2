package com.spring.security.jwt_oauth2.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


//record are for data carriage, means we can just get the data from them
//but can not set, all fields are final, once set can't be set again
//its used to remove boilerplate code, like constructors, getters, toString, equals
//get using someObj.name
//no need to create constructor, just give values while creating obj
// new RSAKeyRecord(pubkey, privKey)



//this annotation is used, to set, variable values from application.properties
//variable names should match with, property in application.properties
@ConfigurationProperties(prefix = "jwt")
public record RSAKeyRecord (RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey){

}