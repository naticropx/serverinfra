/**
 * 
 */
package com.infra.security.service.impl;

import com.infra.security.service.UserGroupManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@Transactional
public class UserGroupManagerImpl implements UserGroupManager {
	
	private static final String ADMINISTRATOR = "Administrator";
	private static final String ROLE_ADMIN = "ROLE_ADMIN";
	private static final String ROLE_ANONYMOUS = "ROLE_ANONYMOUS";

	@Autowired
    private JdbcUserDetailsManager jdbcUserDetailsManager;
	
	@Override
	public void createAndAuthenticateUser(String username, String group) {
		if (!jdbcUserDetailsManager.userExists(username)) {
			UserDetails userDetails = new User(username, username, new ArrayList<GrantedAuthority>());
			jdbcUserDetailsManager.createUser(userDetails);
		}
		
		List<String> allGroups = jdbcUserDetailsManager.findAllGroups();
		if (!allGroups.contains(group)) {
			if (group.equalsIgnoreCase(ADMINISTRATOR)) {
				List<GrantedAuthority> grantedAuthority = new ArrayList<>();
				grantedAuthority.add(new SimpleGrantedAuthority(ROLE_ADMIN));
				jdbcUserDetailsManager.createGroup(group, grantedAuthority);
			} else {
				List<GrantedAuthority> grantedAuthority = new ArrayList<>();
				grantedAuthority.add(new SimpleGrantedAuthority(ROLE_ANONYMOUS));
				jdbcUserDetailsManager.createGroup(group, grantedAuthority);
			}
		}
		
		boolean userExistInGroup = jdbcUserDetailsManager.findUsersInGroup(group).contains(username);
		if (!userExistInGroup) {
			jdbcUserDetailsManager.addUserToGroup(username, group);
		}
		
		setAuthentication(username);
	}
	
	@Override
	public void createUserWithAuthoriy(String username, String authority) {
		if (!jdbcUserDetailsManager.userExists(username)) {
			List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
			grantedAuthorities.add(new SimpleGrantedAuthority(authority));
			UserDetails userDetails = new User(username, username, grantedAuthorities);
			jdbcUserDetailsManager.createUser(userDetails);
		}
	}
	
	@Override
	public List<String> listAllGroups() {
		List<String> foundGroups = jdbcUserDetailsManager.findAllGroups();
		foundGroups.remove(ADMINISTRATOR);
		return foundGroups;
	}
	
	@Override
	public List<GrantedAuthority> listGroupAuthorities(String groupName) {
		return jdbcUserDetailsManager.findGroupAuthorities(groupName);
	}
	
	@Override
	public void addRolesToGroup(String group, String[] roles) {
		removeAllAuthoritiesFromGroup(group);
		addAuthoritiesToGroup(group, roles);
	}

	private void addAuthoritiesToGroup(String group, String[] roles) {
		if (roles.length == 0) {
			jdbcUserDetailsManager.addGroupAuthority(group, new SimpleGrantedAuthority(ROLE_ANONYMOUS));
		}
		
		for (String role : roles) {
			String newRole = role.replaceAll("[^\\w\\s\\-_]", "");
			jdbcUserDetailsManager.addGroupAuthority(group, new SimpleGrantedAuthority(newRole.toUpperCase()));
		}
	}

	private void removeAllAuthoritiesFromGroup(String group) {
		List<GrantedAuthority> groupAuthorities = jdbcUserDetailsManager.findGroupAuthorities(group);
		for (GrantedAuthority grantedAuthority : groupAuthorities) {
			jdbcUserDetailsManager.removeGroupAuthority(group, grantedAuthority);
		}
	}

	@Override
	public void setAuthentication(String username) {
		UserDetails user = jdbcUserDetailsManager.loadUserByUsername(username);
		Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}
}