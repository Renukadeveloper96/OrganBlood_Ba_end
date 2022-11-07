package com.in.pathshala.donarblood.Service;

import java.util.List;

import com.in.pathshala.donarblood.model.Doctor;

public interface DoctorService {
	
	public List<Doctor>getAllDoctor();
	public Doctor findDoctorById(long id);
	public Doctor saveDoctor(Doctor doctor);
	public Doctor updateDoctor(Doctor doctor);
	public void deleteDoctorById(long id);
}
