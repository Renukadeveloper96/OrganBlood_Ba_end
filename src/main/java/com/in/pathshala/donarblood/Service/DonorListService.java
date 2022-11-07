package com.in.pathshala.donarblood.Service;

import java.util.List;

import com.in.pathshala.donarblood.model.DonorList;



public interface DonorListService {
	public List<DonorList>getAllDonorList();
	public DonorList findDonorListById(long id);
	public DonorList saveDonorList(DonorList donorList);
	public DonorList updateDonorList(DonorList donorList);
	public void deleteDonorListById(long id);
}
