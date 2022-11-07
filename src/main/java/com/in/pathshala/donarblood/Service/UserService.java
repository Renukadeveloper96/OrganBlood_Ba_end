package com.in.pathshala.donarblood.Service;

import java.util.List;

import com.in.pathshala.donarblood.User.SignInDto;
import com.in.pathshala.donarblood.User.SignInResponseDto;
import com.in.pathshala.donarblood.User.SignupDto;
import com.in.pathshala.donarblood.dto.ResponseDto;
import com.in.pathshala.donarblood.model.User;



public interface UserService {
	List<User> findAll();//2
	User findUserById(long id);
    public User saveUser(User user);
    public User updateUser(User user);
    public void deleteUserById(long id);
	ResponseDto signup(SignupDto signupDto);
	SignInResponseDto signIn(SignInDto signInDto);
}