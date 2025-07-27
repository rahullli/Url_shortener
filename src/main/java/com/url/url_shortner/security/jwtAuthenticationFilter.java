package com.url.url_shortner.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
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
// It will make sure every request will have the JWT auth token in it.
public class jwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private jwtUtils jwtTokenProvider;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
//            Extract the JWT token from the header.
            String jwt = jwtTokenProvider.getJWTTokenFromBearerToken(request);
//            Validate token
            if(jwt != null && jwtTokenProvider.validateToken(jwt)){
                String userName = jwtTokenProvider.getUserNameFromJwtToken(jwt);
//                so here the userDetailsService is from the string security , so I have to create the implementation class
//                for it inorder to return the user data in the format which I have defined.
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
                if(userDetails != null){
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
//            If valid , Get user details
//            Get use Name -> Load User -> Set the auth Context.

        } catch (Exception e) {
            e.printStackTrace();
        }

        filterChain.doFilter(request, response);
    }
}
