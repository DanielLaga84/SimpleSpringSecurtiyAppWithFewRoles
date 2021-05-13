package com.example.studentsapi.security;

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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.example.studentsapi.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;


    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // every request username and password is send you can not logout that is how it works
        http.
//              csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).disable()// in non browser using we can disable csrf !!! Otherwise we might be attacked. In correct way to generate TOKEN we use :csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).disable()
                csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/", "index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses",true);


    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
                .authorities(STUDENT.getGrantedAuthorities())
//                .roles(ApplicationUserRole.STUDENT.name())
                .build(); //ROLE_STUDENT

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
                .authorities(ADMIN.getGrantedAuthorities())
//                .roles(ApplicationUserRole.ADMIN.name())
                .build(); // ROLE_ADMIN

        UserDetails danielUser = User.builder()
                .username("daniel")
                .password(passwordEncoder.encode("password123"))
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .roles(ApplicationUserRole.ADMINTREINEE.name())
                .build(); // ROLE_ADMINTREINEE

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                danielUser
        );
    }

}
