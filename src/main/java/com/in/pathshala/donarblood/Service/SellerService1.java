package com.in.pathshala.donarblood.Service;

import java.util.List;

import com.in.pathshala.donarblood.Seller.SignInDto;
import com.in.pathshala.donarblood.Seller.SignInResponseDto;
import com.in.pathshala.donarblood.Seller.SignupDto;
import com.in.pathshala.donarblood.dto.ResponseDto;
import com.in.pathshala.donarblood.model.Seller;


public interface SellerService1 {
	List<Seller> findAll();//2
    Seller findSellerById(long id);
    public Seller saveSeller(Seller seller);
    public Seller updateSeller(Seller seller);
    public void deleteSellerById(long id);
	ResponseDto signup(SignupDto signupDto);
	SignInResponseDto signIn(SignInDto signInDto);  
}
