package com.example.ldap;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.ldap.LdapPasswordComparisonAuthenticationManagerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/form.html
        http.formLogin();
        http.logout(
                logout -> logout.logoutRequestMatcher(new AntPathRequestMatcher("/logout")));

        // https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html
        http.authorizeHttpRequests(
                authz -> authz
                        .mvcMatchers("/admin/**").hasRole("ADMIN")
                        .mvcMatchers("/user/**").hasRole("USER")
                        .anyRequest().authenticated());

        return http.build();
    }

    // https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/ldap.html
    @Bean
    public BaseLdapPathContextSource contextSource() {
        return new DefaultSpringSecurityContextSource("ldap://localhost:8389/dc=example,dc=com");
    }

    @Bean
    public LdapAuthoritiesPopulator authorities(BaseLdapPathContextSource contextSource) {
        String groupSearchBase = "ou=groups";

        DefaultLdapAuthoritiesPopulator authorities =
                new DefaultLdapAuthoritiesPopulator(contextSource, groupSearchBase);
        authorities.setGroupSearchFilter("uniqueMember={0}");

        return authorities;
    }

    @Bean
    public AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource,
                                                       LdapAuthoritiesPopulator authorities) {
        LdapPasswordComparisonAuthenticationManagerFactory factory =
                new LdapPasswordComparisonAuthenticationManagerFactory(contextSource, new BCryptPasswordEncoder());

        factory.setUserDnPatterns("uid={0},ou=people");
        factory.setPasswordAttribute("userPassword");
        factory.setLdapAuthoritiesPopulator(authorities);

        return factory.createAuthenticationManager();
    }
}