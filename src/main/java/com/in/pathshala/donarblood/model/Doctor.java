package com.in.pathshala.donarblood.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="Doctor")
public class Doctor {
	@Id
	@GeneratedValue(strategy =GenerationType.IDENTITY)
	@Column(name="id")
	private long id;
	private String name;
	private String email;
	private int age;
	private String Specialization;
	private String nameOfHospital;
	private String doctorAddress;
	private String mobileNo;
	private String hospitalAddress;
	
	public Doctor() {}

	public Doctor(long id, String name, String email, int age, String specialization, String nameOfHospital,
			String doctorAddress, String mobileNo, String hospitalAddress) {
		super();
		this.id = id;
		this.name = name;
		this.email = email;
		this.age = age;
		Specialization = specialization;
		this.nameOfHospital = nameOfHospital;
		this.doctorAddress = doctorAddress;
		this.mobileNo = mobileNo;
		this.hospitalAddress = hospitalAddress;
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public int getAge() {
		return age;
	}

	public void setAge(int age) {
		this.age = age;
	}

	public String getSpecialization() {
		return Specialization;
	}

	public void setSpecialization(String specialization) {
		Specialization = specialization;
	}

	public String getNameOfHospital() {
		return nameOfHospital;
	}

	public void setNameOfHospital(String nameOfHospital) {
		this.nameOfHospital = nameOfHospital;
	}

	public String getDoctorAddress() {
		return doctorAddress;
	}

	public void setDoctorAddress(String doctorAddress) {
		this.doctorAddress = doctorAddress;
	}

	public String getMobileNo() {
		return mobileNo;
	}

	public void setMobileNo(String mobileNo) {
		this.mobileNo = mobileNo;
	}

	public String getHospitalAddress() {
		return hospitalAddress;
	}

	public void setHospitalAddress(String hospitalAddress) {
		this.hospitalAddress = hospitalAddress;
	}

	@Override
	public String toString() {
		return "Doctor [id=" + id + ", name=" + name + ", email=" + email + ", age=" + age + ", Specialization="
				+ Specialization + ", nameOfHospital=" + nameOfHospital + ", doctorAddress=" + doctorAddress
				+ ", mobileNo=" + mobileNo + ", hospitalAddress=" + hospitalAddress + "]";
	}
	
	
	
}
