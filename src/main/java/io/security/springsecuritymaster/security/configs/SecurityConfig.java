package io.security.springsecuritymaster.security.configs;

import io.security.springsecuritymaster.security.handler.FormAccessDeniedHandler;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    // private final UserDetailsService userDetailsService;
    private final AuthenticationProvider authenticationProvider;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

    @Bean
    public SecurityFilterChain formSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                        // 정적 자원 접근 허용
                        .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll()
                        .requestMatchers("/", "/signup", "/login*").permitAll()
                        .requestMatchers("/user").hasAuthority("ROLE_USER")
                        .requestMatchers("/manager").hasAuthority("ROLE_MANAGER")
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated())

                .formLogin(form -> form
                        // 커스텀 로그인 페이지 설정
                            // login은 기본적으로 POST 요청 -> 요청 시 csrf 토큰이 서버에 전달되어야 함.
                            // Thymeleaf를 이용한 form 태그를 사용 시 자동으로 "_csrf" 이름의 토큰이 생성됨.
                        .loginPage("/login").permitAll()
                            // 인증 상세 기능: 커스텀 AuthenticationDetailsSource 설정
                            .authenticationDetailsSource(authenticationDetailsSource)
                            // 인증 성공 시 사용할 커스텀 AuthenticationSuccessHandler 설정
                            .successHandler(authenticationSuccessHandler)
                            // 인증 실패 시 사용할 커스텀 AuthenticationFailureHandler 설정
                            .failureHandler(authenticationFailureHandler))

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

                .exceptionHandling(exception -> exception
                        // 접근 거부 예외 발생 시 커스텀 AccessDeniedHandler 설정
                        .accessDeniedHandler(new FormAccessDeniedHandler("/denied")))
        ;
        return http.build();
    }


    @Bean
    @Order(1)
    public SecurityFilterChain restSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                // "/api"로 시작하는 모든 요청은 여기에서 처리하도록 설정
                .securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth
                        // 정적 자원 접근 허용
                        .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll()
                        .anyRequest().permitAll())
                // (JS 기반의) Rest 방식의 비동기 통신은 클라이언트에서 CSRF 값을 직접 전달해 주어야 한다.
                    // cf) Thymeleaf에서는 자동으로 생성해줌.
                // 잠시 비활성화
                .csrf(AbstractHttpConfigurer::disable)
        ;
        return http.build();
    }

}
