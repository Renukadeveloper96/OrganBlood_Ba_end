package com.in.pathshala.donarblood.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.in.pathshala.donarblood.Service.DonorListService;
import com.in.pathshala.donarblood.dto.BaseResponseDTO;
import com.in.pathshala.donarblood.model.DonorList;

@RestController
public class DonorListController {

	Logger logger=LoggerFactory.getLogger(DonorListController.class);
	@Autowired
	DonorListService donorListService;
	
	@CrossOrigin(origins="http://localhost:4200/")
	@GetMapping(value="/getAllDonorList")
	public ResponseEntity<?> getAllDonarList(){
		logger.info("Requesting getAllBook from BookController");
		List<DonorList>result=donorListService.getAllDonorList();
		if(result!=null) {
			logger.info("result of All  Donar List from Donar Controller is excecuted");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(true);
			responseDto.setHttpCode("200");
			responseDto.setData(result);
			return ResponseEntity.ok(responseDto);
		}
		else {
			logger.error("All  Donor List is null");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(false);
			responseDto.setHttpCode("400");
			responseDto.setData(result);
			return ResponseEntity.badRequest().body(responseDto);
		}
	}
	@CrossOrigin(origins="http://localhost:4200/")
	@GetMapping(value="/DonorListById/{id}")
	public ResponseEntity<?> findDonorListById(@PathVariable("id") long id){
		logger.info("Requesting getbookByID from book controller");
		DonorList result =donorListService.findDonorListById(id);
		if(result!=null) {
			logger.info("result of find Donar list By Id from Donar list controller is executed");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(true);
			responseDto.setHttpCode("200");
			responseDto.setData(result);
			return ResponseEntity.ok(responseDto);
		}else {
			logger.error("find Donor list list is null");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(false);
			responseDto.setHttpCode("400");
			responseDto.setData(result);
			return ResponseEntity.badRequest().body(responseDto);
		}
		
	}
	@CrossOrigin(origins="http://localhost:4200/")
	@PostMapping(value="/createDonorList")
	public ResponseEntity<?>saveDonorList(@RequestBody DonorList donorList){
		logger.info("Requesting savebook from book controller");
		DonorList result =donorListService.saveDonorList(donorList);
		if(result!=null) {
			logger.info("result of save Donor list from book controller is executed");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(true);
			responseDto.setHttpCode("200");
			responseDto.setData(result);
			return ResponseEntity.ok(responseDto);
		}
		else {
			logger.error("save Donor list is null");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(false);
			responseDto.setHttpCode("400");
			responseDto.setData(result);
			return ResponseEntity.badRequest().body(responseDto);
		}
	}
	@PutMapping(value="/updateDonorList")
	public ResponseEntity<?> updateDonarList (@RequestBody DonorList donorListRequest){
//		logger.info("User Id coming from Request::" + bookRequest.getBook_id());
		DonorList result=donorListService.findDonorListById(donorListRequest.getId());
		if(result!=null) {
		logger.info("result of Update Donar list is executed");
		result.setName(donorListRequest.getName());
		result.setDateBirth(donorListRequest.getDateBirth());
		result.setAddress(donorListRequest.getAddress());
		result.setMobileNo(donorListRequest.getMobileNo());
		result.setBloodGroup(donorListRequest.getBloodGroup());
		result.setAddNote(donorListRequest.getAddNote());
		result=donorListService.updateDonorList(result);
		BaseResponseDTO responseDto=new BaseResponseDTO();
		responseDto.setError(true);
		responseDto.setHttpCode("200");
		responseDto.setData(result);
		return ResponseEntity.ok(responseDto);
	}
		else {
			logger.error("Update Donar list  is null");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(false);
			responseDto.setHttpCode("400");
			responseDto.setData(result);
			return ResponseEntity.badRequest().body(responseDto);
	}
	}
	@DeleteMapping("/deleteDonorList/{id}")
	public void deleteDonorList(@PathVariable long id) {
	 logger.info("Donar List Deleting by id is executed");
	 donorListService.deleteDonorListById(id);
}
}
