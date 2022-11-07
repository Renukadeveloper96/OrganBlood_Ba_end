package com.in.pathshala.donarblood.User;

public class SignupDto {
	private String name;
	private int age;
	private String mobileNo;
	private String address;
	private String email;
	private String password;
	
	public SignupDto() {}

	public SignupDto(String name, int age, String mobileNo, String address, String email, String password) {
		super();
		this.name = name;
		this.age = age;
		this.mobileNo = mobileNo;
		this.address = address;
		this.email = email;
		this.password = password;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public int getAge() {
		return age;
	}

	public void setAge(int age) {
		this.age = age;
	}

	public String getMobileNo() {
		return mobileNo;
	}

	public void setMobileNo(String mobileNo) {
		this.mobileNo = mobileNo;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public String toString() {
		return "SignupDto [name=" + name + ", age=" + age + ", mobileNo=" + mobileNo + ", address=" + address
				+ ", email=" + email + ", password=" + password + "]";
	}
	
	
}