package com.bezkoder.springjwt.security.services;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.bezkoder.springjwt.models.ConfirmationToken;
import com.bezkoder.springjwt.models.ERole;
import com.bezkoder.springjwt.models.Role;
import com.bezkoder.springjwt.models.User;
import com.bezkoder.springjwt.payload.request.SignupRequest;
import com.bezkoder.springjwt.repository.ConfirmationTokenRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import com.bezkoder.springjwt.repository.RoleRepository;

@Service
public class AuthService {
	  @Autowired
	    private UserRepository userRepository;
	  @Autowired
	    private RoleRepository roleRepository;
	    
	    @Autowired
	    private PasswordEncoder passwordEncoder;

	    @Autowired
	    private ConfirmationTokenRepository confirmationTokenRepository;
	    
	    public User findByEmail(String email) {
	        return userRepository.findByEmail(email).get();        
	    }

	    public boolean existsByEmail(String email) {
	        return userRepository.existsByEmail(email);
	    }

	    public User save(User user){
	        return userRepository.save(user);
	    }

	    public User saveUser(SignupRequest signUpRequest) {
	        User user = new User();
	        user.setFirstname(signUpRequest.getFirstname());
	        user.setLastname(signUpRequest.getLastname());
	        user.setEmail(signUpRequest.getEmail());
	        user.setPassword(signUpRequest.getPassword());
	        user.setPassword(passwordEncoder.encode(user.getPassword()));
	        Set<String> strRoles = signUpRequest.getRole();
			Set<Role> roles = new HashSet<>();

			if (strRoles == null) {
				Role userRole = roleRepository.findByName(ERole.ROLE_USER)
						.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
				roles.add(userRole);
			} else {
				strRoles.forEach(role -> {
					switch (role) {
					case "admin":
						Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(adminRole);

						break;
					case "mod":
						Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(modRole);

						break;
					default:
						Role userRole = roleRepository.findByName(ERole.ROLE_USER)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(userRole);
					}
				});
			}

			user.setRoles(roles);
			userRepository.save(user);

	        return userRepository.save(user);
	    }

	    public boolean changePassword(String email, String password) {
	        User user = findByEmail(email);
	        user.setPassword(passwordEncoder.encode(password));
	        if(save(user) != null) {
	            return true;
	        }
	        return false;
	    }

	    public ConfirmationToken createToken(User user) {
	        ConfirmationToken confirmationToken = new ConfirmationToken(user);
	        return confirmationTokenRepository.save(confirmationToken);
	    }
	    public ConfirmationToken findByConfirmationToken(String token) {
	        return confirmationTokenRepository.findByConfirmationToken(token);
	    }
	    public void deleteToken(ConfirmationToken confirmationToken) {
	        this.confirmationTokenRepository.delete(confirmationToken);
	    }
}
