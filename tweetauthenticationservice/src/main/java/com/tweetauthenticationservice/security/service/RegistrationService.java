package com.tweetauthenticationservice.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.tweetauthenticationservice.client.UpdateServiceClient;
import com.tweetauthenticationservice.payload.ForgotPasswordRequest;
import com.tweetauthenticationservice.payload.RegisterationRequest;

import feign.FeignException;
@Service
public class RegistrationService {
	
	@Autowired
	private  PasswordEncoder passwordEncoder;
	
	@Autowired
	UpdateServiceClient updateServiceClient;
	
	
	public ResponseEntity<String>  registrationUser(RegisterationRequest registerRequest) {
		
		registerRequest.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
		try {
		return updateServiceClient.registerUser(registerRequest);
		} catch(FeignException.Conflict e) {
			return new ResponseEntity<>(e.contentUTF8(), HttpStatus.valueOf(e.status()));
		}
	}
	
	public ResponseEntity<String> forgotPassword( ForgotPasswordRequest forgotPasswordRequest, String loginId){
		
		try {
			return updateServiceClient.forgotPassword(forgotPasswordRequest, loginId);
		} catch(FeignException.NotFound e) {
			return new ResponseEntity<>(e.contentUTF8(), HttpStatus.valueOf(e.status()));
		} catch(FeignException e) {
			return new ResponseEntity<>(e.contentUTF8(), HttpStatus.valueOf(e.status()));
		}
	}


}
