package io.security.springsecuritymaster.security.provider;

import io.security.springsecuritymaster.domain.dto.AccountContext;
import io.security.springsecuritymaster.security.details.FormAuthenticationDetails;
import io.security.springsecuritymaster.security.exception.SecretException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component("formAuthenticationProvider")
@RequiredArgsConstructor
public class FormAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String loginPw = (String) authentication.getCredentials();

        AccountContext userDetails = (AccountContext) userDetailsService.loadUserByUsername(loginId);

        // 인증 과정 1: 비밀번호 일치 여부 검사
        if (!passwordEncoder.matches(loginPw, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password.");
        }

        // 인증 과정 2: 비밀키의 존재와 일치 여부 검사
        String secretKey = ((FormAuthenticationDetails) authentication.getDetails()).getSecretKey();
        if (secretKey == null || !secretKey.equals("secret")) {
            throw new SecretException("Invalid secret.");
        }

        // 최종 검증 성공 시 인증 토큰 생성
        return new UsernamePasswordAuthenticationToken(userDetails.getAccountDto(), null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 전달된 토큰이 UsernamePasswordAuthenticationToken 타입이면 인증을 수행하겠다는 것을 의미함.
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
