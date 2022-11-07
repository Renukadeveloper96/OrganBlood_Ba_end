package com.in.pathshala.donarblood.model;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="donalrList")
public class  DonorList{
@Id
@GeneratedValue(strategy =GenerationType.IDENTITY)
@Column(name="id")
private long id;
private String name;
private String dateBirth;
private String address;
private long mobileNo;
private String bloodGroup;
private String addNote;
public DonorList() {
}
public DonorList(long id, String name, String dateBirth, String address, long mobileNo, String bloodGroup,
		String addNote) {
	super();
	this.id = id;
	this.name = name;
	this.dateBirth = dateBirth;
	this.address = address;
	this.mobileNo = mobileNo;
	this.bloodGroup = bloodGroup;
	this.addNote = addNote;
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
public String getDateBirth() {
	return dateBirth;
}
public void setDateBirth(String dateBirth) {
	this.dateBirth = dateBirth;
}
public String getAddress() {
	return address;
}
public void setAddress(String address) {
	this.address = address;
}
public long getMobileNo() {
	return mobileNo;
}
public void setMobileNo(long mobileNo) {
	this.mobileNo = mobileNo;
}
public String getBloodGroup() {
	return bloodGroup;
}
public void setBloodGroup(String bloodGroup) {
	this.bloodGroup = bloodGroup;
}
public String getAddNote() {
	return addNote;
}
public void setAddNote(String addNote) {
	this.addNote = addNote;
}
@Override
public String toString() {
	return "DonarList [id=" + id + ", name=" + name + ", dateBirth=" + dateBirth + ", address=" + address
			+ ", mobileNo=" + mobileNo + ", bloodGroup=" + bloodGroup + ", addNote=" + addNote + "]";
}

}