package com.infra.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import java.io.Serializable;

public class CustomPermissionEvaluator extends AclPermissionEvaluator {

    private static final Logger log = LoggerFactory.getLogger(CustomPermissionEvaluator.class);
    User user = null;

    @Autowired
    private JdbcUserDetailsManager jdbcUserDetailsManager;

    public CustomPermissionEvaluator(AclService aclService) {
        super(aclService);

    }

    @Override
    public boolean hasPermission(
            Authentication auth, Object targetDomainObject, Object permission) {
        if ((auth == null) || (targetDomainObject == null) || !(permission instanceof String)){
            return false;
        }

        if (!super.hasPermission(auth, targetDomainObject, permission)) {
            log.info("hasPermission1 : {}", auth.getPrincipal());
//            user = jdbcUserDetailsManager.loadUserByUsername(auth.getPrincipal());
            if (user != null) {

            }
        }
        return super.hasPermission(auth, targetDomainObject, permission);
    }

    @Override
    public boolean hasPermission(
            Authentication auth, Serializable targetId, String targetType, Object permission) {
        if ((auth == null) || (targetType == null) || !(permission instanceof String)) {
            return false;
        }

        if (!super.hasPermission(auth, targetId, targetType, permission)) {
            log.info("hasPermission2 : {}", auth.getPrincipal());
        }

        return super.hasPermission(auth, targetId, targetType, permission);
    }
}