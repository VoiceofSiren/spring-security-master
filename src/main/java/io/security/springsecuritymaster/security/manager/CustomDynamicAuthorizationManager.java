package io.security.springsecuritymaster.security.manager;

import io.security.springsecuritymaster.security.mapper.MapBasedUrlRoleMapper;
import io.security.springsecuritymaster.security.service.DynamicAuthorizationService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Component("customDynamicAuthorizationManager")
@RequiredArgsConstructor
public class CustomDynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

    private static final AuthorizationDecision DENY = new AuthorizationDecision(false);

    // MvcRequestMatcher의 첫 번째 파라미터를 위한 HandlerMappingIntrospector를 주입
    private final HandlerMappingIntrospector handlerMappingIntrospector;

    // Bean이 생성된 이후에 map() 호출
    @PostConstruct
    public void map() {
        DynamicAuthorizationService dynamicAuthorizationService = new DynamicAuthorizationService(new MapBasedUrlRoleMapper());
        mappings = dynamicAuthorizationService.getUrlRoleMappings()
                .entrySet().stream()
                // entry: String 타입의 key와 String 타입의 value로 이루어져 있음
                .map(entry -> new RequestMatcherEntry<>(
                        new MvcRequestMatcher(handlerMappingIntrospector, entry.getKey()),
                        // value: authorization or expression
                        customAuthorizationManager(entry.getValue())
                ))
                .collect(Collectors.toList());
    }



    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext requestAuthorizationContext) {

        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {

            RequestMatcher matcher = mapping.getRequestMatcher();
            RequestMatcher.MatchResult matchResult = matcher.matcher(requestAuthorizationContext.getRequest());
            if (matchResult.isMatch()) {
                AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
                return manager.check(authentication,
                        new RequestAuthorizationContext(requestAuthorizationContext.getRequest(), matchResult.getVariables()));
            }
        }

        return DENY;
    }

    private AuthorizationManager<RequestAuthorizationContext> customAuthorizationManager(String role) {

        if (role != null) {
            // role이 "ROLE"로 시작하는 경우
            if (role.startsWith("ROLE")) {
                return AuthorityAuthorizationManager.hasAuthority(role);
            // role이 표현식인 경우
            } else {
                return new WebExpressionAuthorizationManager(role);
            }
        }
        return null;
    }

    @Override
    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        AuthorizationManager.super.verify(authentication, object);
    }

}