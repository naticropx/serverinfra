/**
 * 
 */
package com.infra.security.service;

import com.cropxapp.farm.model.Farm;
import com.cropxapp.farm.service.FarmService;
import com.infra.security.service.impl.SecurityTestService;
import com.cropxapp.AbstractSecurityTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * @author Thiago
 *
 */
public class SecurityAclTest extends AbstractSecurityTest {

	private static final Logger log = LoggerFactory.getLogger(SecurityAclTest.class);

	@Autowired
    private FarmService farmService;
	@Autowired
    private UserGroupManager userGroupManager;
	@Autowired
    private JdbcUserDetailsManager jdbcUserDetailsManager;
	@Autowired
    private AclManager aclManager;
	@Autowired
	private SecurityTestService securityTestService;

	private static final String TEST_GROUP = "testGroup";
	private static final String USER_ADMIN = "admin";
	private static final String USER_USER = "user";
	private static final String USER_USER2 = "user2";

	private Farm farm = null;
	private Farm farm2 = null;
	private List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
	private UserDetails user = null;

	@Rule public ExpectedException exception = ExpectedException.none();
	
	@Before
	public void setup() {
		userGroupManager.createUserWithAuthoriy(USER_ADMIN, "ROLE_ADMIN");
		userGroupManager.createUserWithAuthoriy(USER_USER, "ROLE_USER");
		userGroupManager.createUserWithAuthoriy(USER_USER2, "ROLE_USER");

		authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
		jdbcUserDetailsManager.createGroup(TEST_GROUP, authorities);

		jdbcUserDetailsManager.addUserToGroup(USER_USER2,TEST_GROUP);

		Farm p1 = new Farm();
		p1.setName("Farm");
		p1.setLocation("/farm");
		farm = farmService.saveOrUpdate(p1);
    	Farm p2 = new Farm();
		p2.setName("Farm2");
		p2.setLocation("/farm2");
		farm2 = farmService.saveOrUpdate(p2);

		userGroupManager.setAuthentication(USER_ADMIN);
		aclManager.addPermission(Farm.class, farm.getId(), new PrincipalSid(USER_ADMIN), BasePermission.ADMINISTRATION);
		aclManager.addPermission(Farm.class, farm2.getId(), new PrincipalSid(TEST_GROUP), BasePermission.ADMINISTRATION);
	}

	@After
	public void tearDown() {
		jdbcUserDetailsManager.deleteUser(USER_ADMIN);
		jdbcUserDetailsManager.deleteUser(USER_USER);
		jdbcUserDetailsManager.deleteUser(USER_USER2);
		jdbcUserDetailsManager.deleteGroup(TEST_GROUP);
		farmService.deleteAll();
		aclManager.deleteAllGrantedAcl();
		SecurityContextHolder.getContext().setAuthentication(null);
	}
	
	@Test
	public void testUserHasNoAccessToFarm() {
		boolean isGranted = aclManager.isPermissionGranted(Farm.class, farm.getId(), new PrincipalSid(USER_USER), BasePermission.READ);
		assertThat(isGranted, is(false));
	}
	
	@Test
	public void testAdminHasNoAccessToFarmAsRead() {
		boolean isGranted = aclManager.isPermissionGranted(Farm.class, farm.getId(), new PrincipalSid(USER_ADMIN), BasePermission.READ);
		assertThat(isGranted, is(false));
	}
	
	@Test
	public void testAdminHasAccessToFarmAsAdministration() {
		boolean isGranted = aclManager.isPermissionGranted(Farm.class, farm.getId(), new PrincipalSid(USER_ADMIN), BasePermission.ADMINISTRATION);
		assertThat(isGranted, is(true));
	}
	
	@Test
	public void testAdminHasAccessToMethodHasRoleAdmin() {
		userGroupManager.setAuthentication(USER_ADMIN);
		assertThat(securityTestService.testHasRoleAdmin(), is(true));
	}
	
	@Test
	public void testUserHasNoAccessToMethodHasRoleAdmin() {
		userGroupManager.setAuthentication(USER_USER);
		exception.expect(AccessDeniedException.class);
		securityTestService.testHasRoleAdmin();
	}
	
	@Test
	public void testAdminHasAccessToMethodHasPermissionAdministration() {
		userGroupManager.setAuthentication(USER_ADMIN);
		assertThat(securityTestService.testHasPermissionAdministrationOnFarm(farm), is(true));
	}

	@Test
	public void testUser2InGroupAdminHasAccessToMethodHasRoleAdmin() {
		userGroupManager.setAuthentication(USER_USER2);
		assertThat(securityTestService.testHasRoleAdmin(), is(true));
	}

	@Test
	public void testUser2InGroupHasAccessToMethodHasPermissionAdministration() {
		userGroupManager.setAuthentication(USER_USER2);
		assertThat(securityTestService.testHasPermissionAdministrationOnFarm(farm2), is(true));
	}

	@Test
	public void testUser2InGroupHasNoAccessToMethodHasPermissionAdministration() {
		userGroupManager.setAuthentication(USER_USER2);
		exception.expect(AccessDeniedException.class);
		securityTestService.testHasPermissionAdministrationOnFarm(farm);
	}

	@Test
	public void testUserHasNoAccessToMethodHasPermissionAdministration() {
		userGroupManager.setAuthentication(USER_USER);
		exception.expect(AccessDeniedException.class);
		securityTestService.testHasPermissionAdministrationOnFarm(farm);
	}
	
	@Test
	public void testUserHasNoAccessToMethodHasPermissionRead() {
		userGroupManager.setAuthentication(USER_USER);
		exception.expect(AccessDeniedException.class);
		securityTestService.testHasPermissionReadOnFarm(farm);
	}
	
	@Test
	public void testAdminHasNoAccessToMethodPermissionRead() {
		userGroupManager.setAuthentication(USER_ADMIN);
		exception.expect(AccessDeniedException.class);
		securityTestService.testHasPermissionReadOnFarm(farm);
	}
	
	@Test
	public void testUserHasAclPermissionBasedOnRole() {
		aclManager.addPermission(Farm.class, farm.getId(), new GrantedAuthoritySid("ROLE_USER"), BasePermission.READ);
		userGroupManager.setAuthentication(USER_USER);
		assertThat(securityTestService.testHasPermissionReadOnFarm(farm), is(true));
	}
	
	@Test
	public void testRemoveAclPermissionFromUser() {
		aclManager.addPermission(Farm.class, farm.getId(), new GrantedAuthoritySid("ROLE_USER"), BasePermission.READ);
		userGroupManager.setAuthentication(USER_USER);
		assertThat(securityTestService.testHasPermissionReadOnFarm(farm), is(true));
		
		userGroupManager.setAuthentication(USER_ADMIN);
		aclManager.removePermission(Farm.class, farm.getId(), new GrantedAuthoritySid("ROLE_USER"), BasePermission.READ);
		
		userGroupManager.setAuthentication(USER_USER);
		exception.expect(AccessDeniedException.class);
		securityTestService.testHasPermissionReadOnFarm(farm);
	}

	@Test
	public void testFilterList() {

		farmService.deleteAll();
		aclManager.deleteAllGrantedAcl();

		for (int i = 0; i < 5; i++) {
			Farm m = new Farm();
			m.setName("farm " + i);
			m.setLocation("/farm/" + i);

			Farm newFarm = farmService.saveOrUpdate(m);

			if (i < 2) {
				aclManager.addPermission(Farm.class, newFarm.getId(), new GrantedAuthoritySid("ROLE_ADMIN"), BasePermission.ADMINISTRATION);
			} else {
				aclManager.addPermission(Farm.class, newFarm.getId(), new GrantedAuthoritySid("ROLE_USER"), BasePermission.READ);
			}
		}

		userGroupManager.setAuthentication(USER_ADMIN);
		assertThat(farmService.testFilterFarm(farmService.findAll()).size(), is(equalTo(2)));

		userGroupManager.setAuthentication(USER_USER);
		exception.expect(AccessDeniedException.class);
		farmService.testFilterFarm(farmService.findAll());
	}
	
	@Test
	public void encodePassword() {
		StandardPasswordEncoder encoder = new StandardPasswordEncoder("com/test");
		String result = encoder.encode(USER_ADMIN);
		assertTrue(encoder.matches(USER_ADMIN, result));
	}
}