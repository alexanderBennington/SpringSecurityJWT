package alexander.SpringSecurityJWT.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .csrf(config -> config.disable())
                .authorizeHttpRequests(auth -> 
                    auth
                    .requestMatchers("/hello")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                )
                .sessionManagement(session -> 
                    session
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .httpBasic(withDefaults())
                .build();
    }

    @Bean
    UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("kevin")
                .password("admin")
                .roles()
                .build()
        );
        return manager;
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        //return NoOpPasswordEncoder.getInstance();
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(HttpSecurity httpSecurity, PasswordEncoder passwordEncoder) throws Exception{
        /*return httpSecurity.getSharedObject(AuthenticationManagerBuilder.class)
        .userDetailsService(userDetailsService())
        .passwordEncoder(passwordEncoder)
        .build();*/
        AuthenticationManagerBuilder authenticationManagerBuilder =
                httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder);

        return authenticationManagerBuilder.build();
    }
}
