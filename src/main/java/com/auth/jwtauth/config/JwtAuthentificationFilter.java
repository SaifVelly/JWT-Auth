package com.auth.jwtauth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthentificationFilter extends OncePerRequestFilter {

    // to be implemented later
    private final JwtService jwtService;

    // UserDetailsService is already available in spring security
    private final UserDetailsService userDetailsService;
    // i will provide a bean of type userDetailsService because i want y own implementation
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }
        // 7 because the Bearer + " " contains 7 characters
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt) ;
        //checking if the user is not connected yet
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication()==null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwt, userDetails)){
                // if it is valid we need to update its security context and send the request to the dispatcher Servlet
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // cuz we do not have credentials
                        userDetails.getAuthorities()
                );
                // Giving it more details
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                //updatnig the security holder
                SecurityContextHolder.getContext().setAuthentication(authToken);

            }
        }
        // we need to pass the hand to the filter to be executed
        filterChain.doFilter(request, response);


    }
}
