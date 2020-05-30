package com.example.springjwtauth.filters;

import com.example.springjwtauth.service.MyUserDetailsService;
import com.example.springjwtauth.util.JsonWebTokenUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private MyUserDetailsService userDetailsService;

    public JwtAuthFilter(MyUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");
        if(nonNull(authorizationHeader)) {

            String jwtToken = getJwtToken(authorizationHeader);
            String userName = JsonWebTokenUtil.validateToken(jwtToken);
            UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtToken(String authorizationHeader) {
        if(isNull(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Invalid Auhorization Header");
        }
        return authorizationHeader.replaceFirst("Bearer ", "").trim();
    }
}
