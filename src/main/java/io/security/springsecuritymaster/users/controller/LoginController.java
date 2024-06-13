package io.security.springsecuritymaster.users.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping(value="/login")
    public String login() {
        return "login/login";
    }

    @GetMapping("/signup")
    public String signup() {
        return "login/signup";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();

        // 인증된 상태에서 로그아웃 처리
        if (authentication != null) {
            // 여러 LogoutHandler 구현체들 중에서 Session까지 무효화시키는 SecurityContextLogoutHandler의 logout()을 사용
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        // 로그아웃 시 로그인 페이지로 redirect
        return "redirect:/login";
    }
}