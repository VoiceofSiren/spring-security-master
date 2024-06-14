package io.security.springsecuritymaster.security.handler;

import io.security.springsecuritymaster.security.exception.SecretException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component("formAuthenticationFailureHandler")
public class FormAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "Invalid username or password.";

        if (exception instanceof BadCredentialsException) {
            errorMessage = "Invalid username or password.";
        } else if (exception instanceof UsernameNotFoundException) {
            errorMessage = "User does not exist.";
        } else if (exception instanceof CredentialsExpiredException) {
            errorMessage = "Password expires.";
        } else if (exception instanceof SecretException) {
            errorMessage = "Invalid secret.";
        }

        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);

        super.onAuthenticationFailure(request, response, exception);
    }
}
