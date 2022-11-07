package com.in.pathshala.donarblood.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.in.pathshala.donarblood.model.Seller;

@Repository
public interface SellerRepository1 extends JpaRepository<Seller,Long>{

	Seller findByEmail(String email);
	
	@Query("select s from Seller s where s.email=:email")
	Optional<Seller> findByEmailId(String email);

	
}
