package com.tweetauthenticationservice.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.tweetauthenticationservice.client.UpdateServiceClient;
import com.tweetauthenticationservice.payload.LoginResponse;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * This class is used for load User Credential
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	private transient final UpdateServiceClient updateServiceClient;

	@Autowired
	public UserDetailsServiceImpl(final UpdateServiceClient updateServiceClient) {
		this.updateServiceClient = updateServiceClient;
	}

	/**
	 *This method is used to load userCredentials from update-service database
	 */
	@Override
	public UserDetails loadUserByUsername(final String userName) throws UsernameNotFoundException {
		LoginResponse login = updateServiceClient.login(userName);
		return new User(login.getLoginId(),login.getPassword(), Arrays.stream(login.getRole().split(",")).map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList()));
	}
}
