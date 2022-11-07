package com.in.pathshala.donarblood.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.in.pathshala.donarblood.model.User;

public interface UserRepository extends JpaRepository<User,Long>{

	User findByEmail(String email);
//	Boolean existsByUsername(String username);
//	Boolean existsByEmail(String email);
	
}