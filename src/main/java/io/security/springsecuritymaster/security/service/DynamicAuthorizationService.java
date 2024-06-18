package io.security.springsecuritymaster.security.service;

import io.security.springsecuritymaster.security.mapper.UrlRoleMapper;

import java.util.Map;

public class DynamicAuthorizationService {
    private final UrlRoleMapper delegatingUrlRoleMapper;

    public DynamicAuthorizationService(UrlRoleMapper delegatingUrlRoleMapper) {
        this.delegatingUrlRoleMapper = delegatingUrlRoleMapper;
    }

    public Map<String, String> getUrlRoleMappings() {
        return delegatingUrlRoleMapper.getUrlRoleMappings();
    }
}
