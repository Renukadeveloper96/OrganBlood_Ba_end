package com.in.pathshala.donarblood.Service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import com.in.pathshala.donarblood.model.DonorList;
import com.in.pathshala.donarblood.repository.DonarListRepository;

@Service
public class DonorListServiceImpl implements DonorListService{

	@Autowired
	DonarListRepository donorListRepository;
	Logger logger =LoggerFactory.getLogger(DonorListServiceImpl.class);
	@Override
	public List<DonorList> getAllDonorList() {
		try {
			logger.info("get All donar list from DonarListServiceImpl");
			return donorListRepository.findAll();
		}
		catch(Exception e) {
			logger.info("try catch block in get All donar list from DonarListServiceImpl");
			return null;
		}
	}

	@Override
	public DonorList findDonorListById(long id) {
		try {
			logger.info("get donar list find By Id   from DonarListServiceImpl");
			return donorListRepository.findById(id).get();
		}
		catch(Exception e) {
			logger.info("try catch block in get donar list find By Id   from DonarListServiceImpl");
			return null;
		}
	}

	@Override
	public DonorList saveDonorList(DonorList donorList) {
		try {
			logger.info("save donar list   from DonarListServiceImpl");
			return donorListRepository.save(donorList);
		}
		catch(Exception e) {
			logger.info("try catch block in save donar list   from DonarListServiceImpl");
			return null;
		}
	}

	@Override
	public DonorList updateDonorList(DonorList donorList) {
		try {
			logger.info("update Donar List  from DonarListServiceImpl");
			return donorListRepository.save(donorList);
		}
		catch(Exception e) {
			logger.info("try catch block in update Donar List  from DonarListServiceImpl");
			return null;
		}
	}

	@Override
	public void deleteDonorListById(long id) {
			logger.info("delete Donar List By Id  from DonarListServiceImpl");
			donorListRepository.deleteById(id);
	}

}
