package com.example.security_jwt.service;


import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.security_jwt.model.User;
import com.example.security_jwt.repository.UserRepository;


@Service
public class CustomUserDetailService implements UserDetailsService {
	
	private final UserRepository userRepository;
	
	public CustomUserDetailService(UserRepository userRepository) {
		this.userRepository=userRepository;
	}
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		User user=userRepository.findByUsername(username).orElseThrow(()-> new UsernameNotFoundException("User not found - "+username));
	
		
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), user.getRole().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList()) );
	}
}
