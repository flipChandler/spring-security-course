package com.amigoscode.springsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.amigoscode.springsecurity.security.UserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

   /* // qlq request tem que estar autenticado pelo httpBasic
    // no way to logout
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }*/

    /*// raiz, index, com css e js são white lists, o resto tem que estar autenticado
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }*/

    /* a ordem dos antMatchers importa - httpBasic
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()                                                   // cross site request forgery     || when disable, spring security is not validating the csrf token given in login
                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    } */

    // form login - by default a session id last 30 minutes
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()                                                   // cross site request forgery     || when disable, spring security is not validating the csrf token given in login
                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                    .loginPage("/login").permitAll()
                    .defaultSuccessUrl("/courses", true)
                    .usernameParameter("username")
                    .passwordParameter("password")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured")          // default 2 weeks | customize to 21 days
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))          // if csrf is enabled, delete this line
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
    }

    // to retrieve user from the database
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails user1 = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name())           // spring interpreta como ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails user2 = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN.name())           // spring interpreta como ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails user3 = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMINTRAINEE.name())           // spring interpreta como ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();
        return new InMemoryUserDetailsManager(user1, user2, user3);
    }
}
