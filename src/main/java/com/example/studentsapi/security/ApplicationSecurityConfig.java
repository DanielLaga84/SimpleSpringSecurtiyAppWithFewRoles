package com.example.studentsapi.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // every request username and password is send you can not logout that is how it works
        http.
                csrf().disable().
                authorizeRequests()
                .antMatchers("/", "index","/css/*","/js/*")
                .permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name()) //antMatcher to student and gives access to students not admin
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
                .roles(ApplicationUserRole.STUDENT.name()).build(); //ROLE_STUDENT

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
                .roles(ApplicationUserRole.ADMIN.name()).build(); // ROLE_ADMIN

        UserDetails danielUser = User.builder()
                .username("daniel")
                .password(passwordEncoder.encode("password123"))
                .roles(ApplicationUserRole.ADMINTREINEE.name()).build(); // ROLE_ADMINTREINEE

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                danielUser
        );
    }

}
