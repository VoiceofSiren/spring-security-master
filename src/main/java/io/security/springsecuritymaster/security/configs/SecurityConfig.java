package io.security.springsecuritymaster.security.configs;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    // private final UserDetailsService userDetailsService;
    private final AuthenticationProvider authenticationProvider;

    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        // 정적 자원 접근 허용
                        .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll()
                        .requestMatchers("/", "/signup").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        // 커스텀 로그인 페이지 설정
                            // login은 기본적으로 POST 요청 -> 요청 시 csrf 토큰이 서버에 전달되어야 함.
                            // Thymeleaf를 이용한 form 태그를 사용 시 자동으로 "_csrf" 이름의 토큰이 생성됨.
                        .loginPage("/login")
                            // 인증 상세 기능: 커스텀 AuthenticationDetailsSource 설정
                            .authenticationDetailsSource(authenticationDetailsSource)
                            .permitAll())
                // 커스텀 UserDetailsService 설정
                /*
                .userDetailsService(userDetailsService)
                */
                // 커스텀 AuthenticationProvider 설정
                // --> 커스텀 UserDetailsService는 SecurityConfig에서필요없게 됨.
                    // AuthenticationFilter -> AuthenticationManager
                    // -> AuthenticationProvider -> UserDetailsService 순으로 진행됨.
                    // 커스텀 AuthenticationProvider 안에서 커스텀 UserDetailsService를 사용하는 방식으로 변경하고자 함.
                .authenticationProvider(authenticationProvider)
        ;
        return http.build();
    }

}
