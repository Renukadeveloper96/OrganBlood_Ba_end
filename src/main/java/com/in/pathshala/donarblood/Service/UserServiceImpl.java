package com.in.pathshala.donarblood.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;

import javax.transaction.Transactional;
import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.in.pathshala.donarblood.User.SignInDto;
import com.in.pathshala.donarblood.User.SignInResponseDto;
import com.in.pathshala.donarblood.User.SignupDto;
import com.in.pathshala.donarblood.config.MessageStrings;
import com.in.pathshala.donarblood.dto.ResponseDto;
import com.in.pathshala.donarblood.exceptions.AuthenticationFailException;
import com.in.pathshala.donarblood.exceptions.CustomException;
import com.in.pathshala.donarblood.model.AuthenticationToken;
import com.in.pathshala.donarblood.model.User;
import com.in.pathshala.donarblood.repository.UserRepository;
import com.in.pathshala.donarblood.utils.Helper;



@Service
public class UserServiceImpl implements UserService{

	Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	AuthenticationService authenticationService;
	
	@Transactional
	
	@Override
	public ResponseDto signup(SignupDto signupDto) {
		String message;
		String status;
		if (Objects.nonNull(userRepository.findByEmail(signupDto.getEmail()))) {
			throw new CustomException("User Already Present");
		}
		String encryptedpassword = signupDto.getPassword();
		try {
			encryptedpassword = hashPassword(signupDto.getPassword());
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		User user = new User(0, signupDto.getName(), signupDto.getAge(), signupDto.getMobileNo(),
				signupDto.getAddress(), signupDto.getEmail(),encryptedpassword);
		userRepository.save(user);
		// save to user
		// create the token
		final AuthenticationToken authenticationToken = new AuthenticationToken(user);
		authenticationService.saveConfirmationToken(authenticationToken);
		ResponseDto responseDto = new ResponseDto(status = "success", message = "Registration successful");
		return responseDto;
	}

	@Override
	public List<User> findAll() {
		try {
			logger.info("requesting findAll from SellerRepository1");
			return userRepository.findAll();
		} catch (Exception e) {
			logger.error("try catch block in findAll from SellerRepository1");
			return null;
		}
	}

	@Override
	public User findUserById(long id) {
		try {
			logger.info("requesting findAll from SellerRepository1");
			return userRepository.findById(id).get();
		} catch (Exception e) {
			logger.error("try catch block in findAll from SellerRepository1");
			return null;
		}
	}

	@Override
	public User saveUser(User user) {
		try {
			logger.info("requesting updateSeller from SellerServiceImpl");
			return userRepository.save(user);
		} catch (Exception e) {
			logger.info("try catch block updateSeller in SellerRepository");
			return null;
		}
	}

	@Override
	public User updateUser(User user) {
		try {
			logger.info("requesting updateSeller from SellerServiceImpl");
			return userRepository.save(user);
		} catch (Exception e) {
			logger.info("try catch block updateSeller in SellerRepository");
			return null;
		}
	}

	@Override
	public void deleteUserById(long id) {
		userRepository.deleteById(id);
		
	}
	@Override
	public SignInResponseDto signIn(SignInDto signInDto) {
		User user = userRepository.findByEmail(signInDto.getEmail());
		if (!Helper.notNull(user)) {
			throw new AuthenticationFailException("User Not Present");
		}
		try {
			// check if password is right
			if (!user.getPassword().equals(hashPassword(signInDto.getPassword()))) {
				// password does not match
				throw new AuthenticationFailException(MessageStrings.WRONG_PASSWORD);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			logger.error("hashing password failed {}", e.getMessage());
			throw new CustomException(e.getMessage());
		}

		AuthenticationToken token = authenticationService.getToken(user);

		if (!Helper.notNull(token)) {
			// token not present
			throw new CustomException("token not present");
		}
		return new SignInResponseDto("success", token.getToken());
	}

	String hashPassword(String password) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(password.getBytes());
		byte[] digest = md.digest();
		String myHash = DatatypeConverter.printHexBinary(digest).toUpperCase();
		return myHash;
	}

}
