/**
 * 
 */
package com.infra.security.service;

import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public interface UserGroupManager {
	
	/**
	 * @param username
	 * @param group
	 */
	public void createAndAuthenticateUser(String username, String group);
	
	/**
	 * @param username
	 * @param authority
	 */
	public void createUserWithAuthoriy(String username, String authority);
	
	/**
	 * @return
	 */
	public List<String> listAllGroups();
	
	/**
	 * @param groupName
	 * @return
	 */
	public List<GrantedAuthority> listGroupAuthorities(String groupName);
	
	/**
	 * @param group
	 * @param roles
	 */
	public void addRolesToGroup(String group, String[] roles);
	
	/**
	 * Perform authentication for an existing user (performing Loaduserbyusername),
	 * 
	 * @param username Username to authenticate.
	 */
	public void setAuthentication(String username);

}