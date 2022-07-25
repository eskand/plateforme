package com.bezkoder.springjwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.bezkoder.springjwt.models.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
	 @Query("SELECT u.emailVerified FROM User u WHERE u.email = ?1")
	    Boolean findEmailVerifiedByEmail(String email);

	
	Optional<User> findByEmail(String email);
	Boolean existsByEmail(String email);
}
