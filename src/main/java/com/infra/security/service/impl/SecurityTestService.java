/**
 * 
 */
package com.infra.security.service.impl;

import com.cropxapp.farm.model.Farm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class SecurityTestService {

	private static final Logger log = LoggerFactory.getLogger(SecurityTestService.class);

	@PreAuthorize("hasRole('ROLE_ADMIN')")
	public boolean testHasRoleAdmin() {
		log.info("access granted to hasRole('ROLE_ADMIN')");
		return true;
	}
	
	@PreAuthorize("hasRole('ROLE_USER')")
	public boolean testHasRoleUser() {
		log.info("access granted to hasRole('ROLE_USER')");
		return true;
	}
	
	@PreAuthorize("hasRole('ROLE_GROUP')")
	public boolean testHasRoleGroup() {
		log.info("access granted to hasRole('ROLE_GROUP')");
		return true;
	}
	
	@PreAuthorize("hasPermission(#farm, 'administration')")
	public boolean testHasPermissionAdministrationOnFarm(Farm farm) {
		log.info("access granted to hasPermission(#farm, 'administration')");
		return true;
	}
	
	@PreAuthorize("hasPermission(#farm, 'read')")
	public boolean testHasPermissionReadOnFarm(Farm farm) {
		log.info("access granted to hasPermission(#farm, 'read')");
		return true;
	}
}
