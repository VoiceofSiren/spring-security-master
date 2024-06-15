package io.security.springsecuritymaster.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.springsecuritymaster.domain.dto.AccountDto;
import io.security.springsecuritymaster.security.token.RestAuthenticationToken;
import io.security.springsecuritymaster.util.WebUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import java.io.IOException;

public class RestAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    // 경로가 "/api/login"이고 요청 방식이 POST에 해당해야 이 필터가 동작하도록 설정하는 생성자
    public RestAuthenticationFilter() {
        super(new AntPathRequestMatcher("/api/login", "POST"));
    }

    // 경로가 "/api/login"이고 요청 방식이 POST에 해당해야 이 필터가 동작하도록 설정하는 생성자
    // Rest DSLs 사용 시 필요 없어짐.
/*    public RestAuthenticationFilter(HttpSecurity http) {
        super(new AntPathRequestMatcher("/api/login", "POST"));

        // 비동기 통신 중 인증 성공 시 인증 상태를 영속화하는 로직
        setSecurityContextRepository(getSecurityContextRepository(http));
    }*/

    // 비동기 통신 시 인증 상태를 영속화하는 로직
    public SecurityContextRepository getSecurityContextRepository(HttpSecurity http) {

        SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);

        if (securityContextRepository == null) {
            securityContextRepository = new DelegatingSecurityContextRepository(
                    new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository()
            );
        }

        return securityContextRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        // POST 방식의 요청이면서 비동기 통신일 경우에만 인증 필터가 동작하도록 설정
        if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
            throw new IllegalArgumentException("Authentication method not supported.");
        }

        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        // AccountDto 객체에 username과 password 값이 있을 때만 인증을 처리하도록 설정
        if (!StringUtils.hasText(accountDto.getUsername()) || !StringUtils.hasText(accountDto.getPassword())) {
            throw new AuthenticationServiceException("Username or password not provided.");
        }

        // 토큰을 생성하여 AuthenticationManager에게 전달
        RestAuthenticationToken restAuthenticationToken = new RestAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
        return getAuthenticationManager().authenticate(restAuthenticationToken);
    }
}
