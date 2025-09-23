package com.example.security_jwt.security;

import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import com.example.security_jwt.model.Role;
import com.example.security_jwt.model.User;
import com.example.security_jwt.repository.UserRepository;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
	//secret key
	private static final SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);
	//expiration time
	private final int jwtExpirationMs = 86400000;
	
	//DI of UserRepository
	private UserRepository userRepository;
	
	public JwtUtil(UserRepository userRepository) {
		this.userRepository=userRepository;
	}
	
	//Generate Token
	public String generateToken(String username) {
		Optional<User> user = userRepository.findByUsername(username);
		Set<Role> roles = user.get().getRole();
		
		//add roles to token
		return Jwts.builder().setSubject(username).claim("roles",roles.stream().map(role->role.getName()).collect(Collectors.joining(","))).setIssuedAt(new Date()).setExpiration(new Date(new Date().getTime()+jwtExpirationMs)).signWith(secretKey).compact();
	}
	
	//Extract Username
	public String extractUsername(String token) {
		return Jwts.parserBuilder().setSigningKey (secretKey).build().parseClaimsJws(token).getBody().getSubject();
	}
	
	// Extract roles
	public Set<String> extractRoles (String token) {
		String rolesString = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws (token).getBody().get("roles", String.class);
		return Set.of(rolesString);
	}
	
	//Token Validation
	public boolean isTokenValid (String token) {
		try {
		Jwts.parserBuilder().setSigningKey (secretKey).build().parseClaimsJws (token);
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			return false;
		}
	}
}
