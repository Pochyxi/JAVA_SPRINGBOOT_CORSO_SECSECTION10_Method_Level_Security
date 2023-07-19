package com.developez.filter;

import com.developez.constants.SecurityConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JWTTokenValidatorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Estrae il token JWT dall'header della richiesta
        String jwt = request.getHeader(SecurityConstants.JWT_HEADER);

        if (null != jwt) {
            try {
                // Genera una chiave HMAC utilizzando la chiave JWT
                SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));

                // Crea un parser JWT e lo configura con la chiave HMAC
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();

                // Ottiene il nome utente e l'autorità dai claims del token
                String username = String.valueOf(claims.get("username"));
                String authorities = (String) claims.get("authorities");

                // Crea un oggetto di autenticazione per il nome utente e l'autorità
                Authentication auth = new UsernamePasswordAuthenticationToken(username, null,
                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));

                // Imposta l'oggetto di autenticazione nel contesto di sicurezza
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                // Eccezione generata se il token non è valido
                throw new BadCredentialsException("Invalid Token received!");
            }
        }

        // Passa la richiesta alla prossima catena di filtri
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Determina se il filtro non deve essere eseguito per la richiesta
        return request.getServletPath().equals("/user");
    }
}
