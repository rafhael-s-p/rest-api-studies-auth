package com.studies.foodorders.auth.core;

import com.studies.foodorders.auth.domain.Users;
import com.studies.foodorders.auth.domain.UsersRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JpaUserDetailsService implements UserDetailsService {

	@Autowired
	private UsersRepository usersRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Users users = usersRepository.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with email provided"));
		
		return new AuthUser(users);
	}

}
