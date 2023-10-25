package com.studies.foodorders.auth.core;

import com.studies.foodorders.auth.domain.Users;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

@Getter
public class AuthUser extends User {

	private static final long serialVersionUID = 1L;

	private Long userId;
	private String fullName;
	
	public AuthUser(Users users) {
		super(users.getEmail(), users.getPassword(), Collections.emptyList());
		
		this.userId = users.getId();
		this.fullName = users.getName();
	}
	
}
