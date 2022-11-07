package com.in.pathshala.donarblood.controller;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.in.pathshala.donarblood.Service.AuthenticationService;
import com.in.pathshala.donarblood.Service.UserService;
import com.in.pathshala.donarblood.User.SignInDto;
import com.in.pathshala.donarblood.User.SignInResponseDto;
import com.in.pathshala.donarblood.User.SignupDto;
import com.in.pathshala.donarblood.dto.ResponseDto;
import com.in.pathshala.donarblood.exceptions.AuthenticationFailException;
import com.in.pathshala.donarblood.model.User;
import com.in.pathshala.donarblood.repository.UserRepository;


@RequestMapping("user")
@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
public class UserController {

Logger logger = LoggerFactory.getLogger(UserController.class);
	
	@Autowired
	UserService userService;
	
	@Autowired
    AuthenticationService authenticationService;
	
	@Autowired
    UserRepository userRepository;
	
	//signup:localhost:8085/user/signup
		@PostMapping("/signup")
		public ResponseDto signup(@RequestBody SignupDto signupDto) throws NoSuchAlgorithmException {
			return userService.signup(signupDto);
		}	
		//localhost:8085/user/all?token=24d7755e-8916-4a03-b43d-4ad61ef4afe2
		@GetMapping("/all")
	    public List<User> findAllSeller(@RequestParam("token") String token) {
	        authenticationService.authenticate(token);
	        return userRepository.findAll();
	    }
//		//localhost:8085/user/all/2?token=24d7755e-8916-4a03-b43d-4ad61ef4afe2
		//localhost:8085/seller/all/9
		@GetMapping("/all/{id}")
	    public User findUserById(@PathVariable long id ) throws AuthenticationFailException {
			return userRepository.findById(id).get();
	    }
		//deleteProduct:localhost:8085/seller/deleteSeller/8
		@DeleteMapping("/deleteSeller/{id}")
		public void deleteUser(@PathVariable long id) {
		 logger.info("Deleting by id is executed");
		 userService.deleteUserById(id);
		 
	}
		//signin:localhost:8085/seller/signin
		@PostMapping("/signin")
		public  SignInResponseDto signIn(@RequestBody SignInDto signInDto) {
			return userService.signIn(signInDto);
		}
		
}
