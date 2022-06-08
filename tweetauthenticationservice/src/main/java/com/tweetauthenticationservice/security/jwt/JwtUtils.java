package com.tweetauthenticationservice.security.jwt;

import io.jsonwebtoken.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.tweetauthenticationservice.payload.ValidationResponse;
import com.tweetauthenticationservice.security.service.JwtSignature;

import java.util.Date;

/**
 * This is JwtUtils class
 *
 */
@Component
public class JwtUtils {

	@Autowired
	private transient JwtSignature jwtSignature;

	/** 
	 * This method generated the jwt token using userName,
	 *  secret Key and jwt Expiration time.
	 */
	public String generateJwtToken(final String userName) {

		final int jwtExpiration = jwtSignature.getJwtExpirationMs();

		final String secret = jwtSignature.getJwtSecret();

		return Jwts.builder().setSubject(userName).setIssuedAt(new Date())
				.setExpiration(new Date(new Date().getTime() + jwtExpiration))
				.signWith(SignatureAlgorithm.HS256, secret).compact();
	}

	/**
	 * This method is used to get userName from Jwt token.
	 */
	public String getUserNameFromJwtToken(final String token) {
		final String jwtSecret = jwtSignature.getJwtSecret();
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}

	/**
	 * This method is used validation of user Jwt token.
	 */
	public ResponseEntity<ValidationResponse> validateJwtToken(final String authToken) {
		ValidationResponse validationResponse = new ValidationResponse();
		try {
			final String jwtSecret = jwtSignature.getJwtSecret();
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
			
			validationResponse.setIsSuccess(true);
			validationResponse.setMessage("Validated Successfully....");
			validationResponse.setUserId(getUserNameFromJwtToken(authToken));
			
			return new ResponseEntity<>(validationResponse,HttpStatus.OK);

		} catch (Exception e) {
			validationResponse.setIsSuccess(false);
			validationResponse.setMessage("JWT Token is Not Valid");
			validationResponse.setUserId("");
			return new ResponseEntity<>(validationResponse,HttpStatus.UNAUTHORIZED);
		}
		
	}
}
