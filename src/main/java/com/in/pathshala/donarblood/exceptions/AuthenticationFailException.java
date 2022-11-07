package com.in.pathshala.donarblood.exceptions;

public class AuthenticationFailException extends IllegalArgumentException{
	public AuthenticationFailException(String msg) {
		super(msg);
	}
}

