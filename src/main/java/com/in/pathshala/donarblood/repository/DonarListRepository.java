package com.in.pathshala.donarblood.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.in.pathshala.donarblood.model.DonorList;



@Repository
public interface DonarListRepository extends JpaRepository<DonorList,Long>{

}
