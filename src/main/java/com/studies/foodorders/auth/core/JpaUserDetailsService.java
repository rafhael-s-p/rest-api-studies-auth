package com.studies.foodorders.auth.core;

import com.studies.foodorders.auth.domain.Users;
import com.studies.foodorders.auth.domain.UsersRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
public class JpaUserDetailsService implements UserDetailsService {

	@Autowired
	private UsersRepository usersRepository;

	@Transactional(readOnly = true)
	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
		Users user = usersRepository.findByEmail(userName)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with email provided"));
		
		return new AuthUser(user, getAuthorities(user));
	}

	private Collection<GrantedAuthority> getAuthorities(Users user) {
		return user.getGroups().stream()
				.flatMap(group -> group.getPermissions().stream())
				.map(permission -> new SimpleGrantedAuthority(permission.getName().toUpperCase()))
				.collect(Collectors.toSet());
	}

}
