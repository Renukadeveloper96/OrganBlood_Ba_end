package com.in.pathshala.donarblood.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.in.pathshala.donarblood.model.Doctor;
@Repository
public interface DoctorRepository extends JpaRepository<Doctor,Long>{

}
