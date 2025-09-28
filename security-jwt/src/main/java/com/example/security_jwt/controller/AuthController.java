package com.example.security_jwt.controller;

import java.util.HashSet;
import java.util.Set;


import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.security_jwt.dto.RegisterRequest;
import com.example.security_jwt.model.Role;
import com.example.security_jwt.model.User;
import com.example.security_jwt.repository.RoleRepository;
import com.example.security_jwt.repository.UserRepository;
import com.example.security_jwt.security.JwtUtil;

@RestController
@RequestMapping("/auth")
public class AuthController {
	private final AuthenticationManager authenticationManager;

	private final JwtUtil jwtUtil;
	
	private final UserRepository userRepository;
	
	private final RoleRepository roleRepository;
	
	private final PasswordEncoder passwordEncoder;
	
	public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil, UserRepository userRepository,
			RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
		super();
		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.passwordEncoder = passwordEncoder;
	}

	//register user api
	@PostMapping("/register")
	public ResponseEntity<String> register(@RequestBody RegisterRequest registerRequest){
		
		//check if username already exists?
		if(userRepository.findByUsername(registerRequest.getUsername()).isPresent()) {
			return ResponseEntity.badRequest().body("username is already taken");
		}
		
		User newUser = new User();
		newUser.setUsername(registerRequest.getUsername());
		String encodedPw= passwordEncoder.encode(registerRequest.getPassword());
		newUser.setPassword(encodedPw);
		System.out.println(encodedPw);
		
		//convert role name to role entities and assign to user
		
		Set<Role> roles = new HashSet<>();
		for(String roleName: registerRequest.getRoles()) {
			Role role = roleRepository.findByName(roleName).orElseThrow(()->new RuntimeException("Role not found"+roleName));
			roles.add(role);
		}
		
		newUser.setRole(roles);
		userRepository.save(newUser);
		return ResponseEntity.ok("user"+ newUser.getUsername()+ "registred successfully");
	}
	
	//login API
	@PostMapping("*/login")
	public ResponseEntity<String> login(@RequestBody User loginRequest){
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
		}catch(Exception e) {
			System.out.println("Exception: "+e);
		}
		String token = jwtUtil.generateToken(loginRequest.getUsername());
		
		return ResponseEntity.ok(token);
	}

}
