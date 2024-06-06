package org.example.demosecurity.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.example.demosecurity.service.JWTService;
import org.example.demosecurity.service.UserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String authToken = request.getHeader("Authorization");

        if(authToken == null || !authToken.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }

        String jwtToken = authToken.substring(7);
        String username = jwtService.extractUsername(jwtToken);

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails fetchedUserDetails = userService.UserDetailsService().loadUserByUsername(username);

            if(jwtService.isTokenValid(jwtToken,fetchedUserDetails)){
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                  UsernamePasswordAuthenticationToken authenticationToken = new
                          UsernamePasswordAuthenticationToken(fetchedUserDetails, null, fetchedUserDetails.getAuthorities()
                );

                  authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                  securityContext.setAuthentication(authenticationToken);
                  SecurityContextHolder.setContext(securityContext);
            }
        }
        filterChain.doFilter(request, response);
    }
}
