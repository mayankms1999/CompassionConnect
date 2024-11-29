package CN.CompassionConnect.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;

import CN.CompassionConnect.model.User;
import CN.CompassionConnect.repository.UserRepository;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class DonationSecurityConfig {
    @Autowired
    UserDetailsService userDetailsService;
    @Autowired
    UserRepository userRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
    {
        http
                .csrf().disable()
                .authorizeHttpRequests()
                .antMatchers("/user/register").permitAll()
                .and()
                .rememberMe().userDetailsService(userDetailsService)
                .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .and()
                .logout().deleteCookies("remember-me")
                .and()
        		.oauth2Login()
        		.loginPage("/login")
        		.userInfoEndpoint()
                .userService(oauth2UserService());

        return http.build();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception
    {
        return builder.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        return userRequest -> {
            // Create the default service to load the user
            DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
            OAuth2User oauth2User = delegate.loadUser(userRequest);

            // login should be used instead of email as attribute
            String email = oauth2User.getAttribute("login");

            System.out.println("OAuth2 User: " + email);

            // Load the user from your database
            User user = userRepository.findByUsername(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found for email: " + email));

            // Return the user with the granted authorities
            return new DefaultOAuth2User(user.getAuthorities(), oauth2User.getAttributes(), "login");
        };
    }



}
