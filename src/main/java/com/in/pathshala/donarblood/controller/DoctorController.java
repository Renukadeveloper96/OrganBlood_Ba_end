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

import com.in.pathshala.donarblood.Service.DoctorService;
import com.in.pathshala.donarblood.dto.BaseResponseDTO;
import com.in.pathshala.donarblood.model.Doctor;

@RestController
public class DoctorController {

	Logger logger=LoggerFactory.getLogger(DoctorController.class);
	
	@Autowired
	DoctorService doctorService;
	
	
	@CrossOrigin(origins="http://localhost:4200/")
	@GetMapping(value="/getAllDoctor")
	public ResponseEntity<?> getAllDoctor(){
		logger.info("get All Doctor is excecuted from Doctor Controller");
		List<Doctor> result=doctorService.getAllDoctor();
		if(result!=null) {
			logger.info("result of All  Doctor List from Doctor Controller is excecuted");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(true);
			responseDto.setHttpCode("200");
			responseDto.setData(result);
			return ResponseEntity.ok(responseDto);
		}
		else {
			logger.error("All Doctor List is null");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(false);
			responseDto.setHttpCode("400");
			responseDto.setData(result);
			return ResponseEntity.badRequest().body(responseDto);
		}
	}
	
	@CrossOrigin(origins="http://localhost:4200/")
	@GetMapping(value="/DoctorListById/{id}")
	public ResponseEntity<?> findDoctorById(@PathVariable("id") long id){
		logger.info("Requesting getbookByID from book controller");
		Doctor result =doctorService.findDoctorById(id);
		if(result!=null) {
			logger.info("result of find Doctor list By Id from Doctor list controller is executed");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(true);
			responseDto.setHttpCode("200");
			responseDto.setData(result);
			return ResponseEntity.ok(responseDto);
		}else {
			logger.error("find Doctor list list is null");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(false);
			responseDto.setHttpCode("400");
			responseDto.setData(result);
			return ResponseEntity.badRequest().body(responseDto);
		}
	}
	
	@CrossOrigin(origins="http://localhost:4200/")
	@PostMapping(value="/createDoctor")
	public ResponseEntity<?>saveDoctor(@RequestBody Doctor doctor){
		logger.info("Requesting save Doctor from Doctor controller");
		Doctor result =doctorService.saveDoctor(doctor);
		if(result!=null) {
			logger.info("result of save Doctor list from Doctor controller is executed");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(true);
			responseDto.setHttpCode("200");
			responseDto.setData(result);
			return ResponseEntity.ok(responseDto);
		}
		else {
			logger.error("save Donar list is null");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(false);
			responseDto.setHttpCode("400");
			responseDto.setData(result);
			return ResponseEntity.badRequest().body(responseDto);
		}
	}
	
	@CrossOrigin(origins="http://localhost:4200/")
	@PutMapping(value="/updateDoctor")
	public ResponseEntity<?> updateDoctor (@RequestBody Doctor doctorRequest){
//		logger.info("User Id coming from Request::" + bookRequest.getBook_id());
		Doctor result=doctorService.findDoctorById(doctorRequest.getId());
		if(result!=null) {
		logger.info("result of Update Donar list is executed");
		result.setName(doctorRequest.getName());
		result.setEmail(doctorRequest.getEmail());
		result.setAge(doctorRequest.getAge());
		result.setSpecialization(doctorRequest.getSpecialization());
		result.setNameOfHospital(doctorRequest.getNameOfHospital());
		result.setDoctorAddress(doctorRequest.getDoctorAddress());
		
		result.setMobileNo(doctorRequest.getMobileNo());
		result.setHospitalAddress(doctorRequest.getHospitalAddress());
		result=doctorService.updateDoctor(result);
		BaseResponseDTO responseDto=new BaseResponseDTO();
		responseDto.setError(true);
		responseDto.setHttpCode("200");
		responseDto.setData(result);
		return ResponseEntity.ok(responseDto);
	}
		else {
			logger.error("Update Doctor list  is null");
			BaseResponseDTO responseDto=new BaseResponseDTO();
			responseDto.setError(false);
			responseDto.setHttpCode("400");
			responseDto.setData(result);
			return ResponseEntity.badRequest().body(responseDto);
	}
	}
	
	@CrossOrigin(origins="http://localhost:4200/")
	@DeleteMapping("/deleteDoctor/{id}")
	public void deleteDonarList(@PathVariable long id) {
	 logger.info("Doctor List Deleting by id is executed");
	 doctorService.deleteDoctorById(id);
}
	
}
