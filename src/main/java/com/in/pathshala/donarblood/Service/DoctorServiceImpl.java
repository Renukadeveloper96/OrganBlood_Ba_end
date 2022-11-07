package com.in.pathshala.donarblood.Service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.in.pathshala.donarblood.model.Doctor;
import com.in.pathshala.donarblood.repository.DoctorRepository;

@Service
public class DoctorServiceImpl implements DoctorService{

	Logger logger=LoggerFactory.getLogger(DoctorServiceImpl.class);
	
	@Autowired
	DoctorRepository doctorRepository;

	@Override
	public List<Doctor> getAllDoctor() {
		try {
			logger.info("all Doctor from Doctor Service Impl");
			return doctorRepository.findAll();
		}
		catch(Exception e) {
			logger.error("try catch block in  all Doctor from Doctor Service Impl ");
			return null;
		}
	}

	@Override
	public Doctor findDoctorById(long id) {
		try {
			logger.info("find Doctor by id from Doctor Service Impl");
			return doctorRepository.findById(id).get();
		}
		catch(Exception e) {
			logger.error("try catch block in  Doctor by id from Doctor Service Impl ");
			return null;
		}
	}

	@Override
	public Doctor saveDoctor(Doctor doctor) {
		try {
			logger.info("create Doctor from Doctor Service Impl");
			return doctorRepository.save(doctor);
		}
		catch(Exception e) {
			logger.error("try catch block in create Doctor from Doctor Service Impl ");
			return null;
		}
	}

	@Override
	public Doctor updateDoctor(Doctor doctor) {
		try {
			logger.info("update Doctor from Doctor Service Impl");
			return doctorRepository.save(doctor);
		}
		catch(Exception e) {
			logger.error("try catch block in update Doctor from Doctor Service Impl ");
			return null;
		}
	}

	@Override
	public void deleteDoctorById(long id) {
		logger.info("delete Doctor from Doctor Service Impl");
		doctorRepository.deleteById(id);
		
	}
	
}
