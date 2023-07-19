package com.developez.filter;

import com.developez.constants.SecurityConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class JWTTokenGeneratorFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Ottieni l'autenticazione corrente dall'oggetto SecurityContextHolder.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Se l'autenticazione è non null, genera un token JWT.
        if (authentication != null) {
            // Ottieni la chiave segreta per firmare il token JWT.
            SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));

            // Genera un token JWT con le informazioni di autenticazione dell'utente.
            String jwt = Jwts.builder().setIssuer("Eazy Bank").setSubject("JWT Token")
                    .claim("username", authentication.getName())
                    .claim("authorities", populateAuthorities(authentication.getAuthorities()))
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + 30000000))
                    .signWith(key).compact();

            // Imposta il token JWT nell'header della risposta HTTP.
            response.setHeader(SecurityConstants.JWT_HEADER, jwt);
        }

        // Chiama il metodo doFilter della catena di filtri per continuare il processo di richiesta HTTP.
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Controlla se la richiesta HTTP è per la risorsa /user.
        return !request.getServletPath().equals("/user");
    }

    private String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
        // Crea un set di stringhe che contiene le autorizzazioni dell'utente.
        Set<String> authoritiesSet = new HashSet<>();

        // Aggiungi le autorizzazioni dell'utente al set.
        for (GrantedAuthority authority : collection) {
            authoritiesSet.add(authority.getAuthority());
        }

        // Converti il set di stringhe in una stringa separata da virgole.
        return String.join(",", authoritiesSet);
    }
}
