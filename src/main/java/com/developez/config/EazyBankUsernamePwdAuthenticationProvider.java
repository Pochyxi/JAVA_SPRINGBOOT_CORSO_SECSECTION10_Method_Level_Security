package com.developez.config;

import com.developez.model.Authority;
import com.developez.model.Customer;
import com.developez.repository.CustomerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Component
public class EazyBankUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public EazyBankUsernamePwdAuthenticationProvider(CustomerRepository customerRepository, PasswordEncoder passwordEncoder) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Metodo che autentica l'utente
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // Cerca il cliente nel database tramite l'indirizzo email (username)
        List<Customer> customers = customerRepository.findByEmail(username);

        // Verifica se esiste un cliente con l'indirizzo email specificato
        if (customers.size() > 0) {
            // Verifica se la password fornita corrisponde alla password salvata nel database
            if (passwordEncoder.matches(password, customers.get(0).getPwd())) {
                // Restituisce un oggetto UsernamePasswordAuthenticationToken che rappresenta l'utente autenticato
                return new UsernamePasswordAuthenticationToken(username, password, getGrantedAuthorities( customers.get(0).getAuthorities()));
            } else {
                // Se la password non corrisponde, lancia un'eccezione BadCredentialsException
                throw new BadCredentialsException("Invalid password!");
            }
        } else {
            // Se non esiste un cliente con l'indirizzo email specificato, lancia un'eccezione BadCredentialsException
            throw new BadCredentialsException("No user registered with this details!");
        }
    }

    private List<GrantedAuthority> getGrantedAuthorities(Set<Authority> authorities) {
        // Crea una lista di autorizzazioni concesse
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        // Itera attraverso le autorizzazioni
        for (Authority authority : authorities) {
            // Aggiungi l'autorizzazione concessa alla lista
            grantedAuthorities.add(new SimpleGrantedAuthority(authority.getName()));
        }

        // Restituisci la lista di autorizzazioni concesse
        return grantedAuthorities;
    }

    // Verifica se il provider supporta il tipo di autenticazione specificato (UsernamePasswordAuthenticationToken)
    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
