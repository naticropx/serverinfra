package com.infra.security.service;

import com.cropxapp.AbstractSecurityTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class UserTest extends AbstractSecurityTest {
	
	/**
	 * 
	 */
	private static final String USER_NAME = "user";
	private static final String ROLE_USER = "ROLE_USER";

	@Autowired
    private UserGroupManager userGroupManager;
	@Autowired
    private JdbcUserDetailsManager jdbcUserDetailsManager;
	
	private UserDetails user = null;
	
	@Before
	public void setup() {
		userGroupManager.createUserWithAuthoriy(USER_NAME, ROLE_USER);
		user = jdbcUserDetailsManager.loadUserByUsername(USER_NAME);
		userGroupManager.setAuthentication(USER_NAME);
	}
	
	@Test
	public void checkUser() {
		assertThat(user, is(notNullValue()));
		assertThat(user, isA(UserDetails.class));
		GrantedAuthority roleUser = new SimpleGrantedAuthority(ROLE_USER);
		assertThat(user.getAuthorities().contains(roleUser), is(true));
	}
	
	@After
	public void tearDown() {
		jdbcUserDetailsManager.deleteUser(USER_NAME);
	}
}