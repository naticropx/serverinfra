package com.infra.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;

@Service("userDetailsService")
public class CustomUserDetailsService extends JdbcUserDetailsManager {

    private static final Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);

    @Autowired
    private DataSource dataSource;

    @PostConstruct
    private void initialize() {
        setDataSource(dataSource);
        setEnableGroups(true);
        setEnableAuthorities(true);
    }

    @Override
    @Value("select g.id, g.group_name, ga.authority " +
                "from groups g, group_members gm, group_authorities ga " +
                "where " +
                        "gm.username = ? and " +
                        "g.id = ga.group_id and " +
                        "g.id = gm.group_id")
    public void setGroupAuthoritiesByUsernameQuery(String groupAuthoritiesByUsernameQuery) {
        super.setGroupAuthoritiesByUsernameQuery(groupAuthoritiesByUsernameQuery);
    }
}
