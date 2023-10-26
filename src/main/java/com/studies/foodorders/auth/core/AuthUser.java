package com.studies.foodorders.auth.core;

import com.studies.foodorders.auth.domain.Users;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Collections;

@Getter
public class AuthUser extends User {

	private static final long serialVersionUID = 1L;

	private Long userId;
	private String fullName;
	
	public AuthUser(Users users, Collection<? extends GrantedAuthority> authorities) {
		super(users.getEmail(), users.getPassword(), authorities);
		
		this.userId = users.getId();
		this.fullName = users.getName();
	}
	
}
