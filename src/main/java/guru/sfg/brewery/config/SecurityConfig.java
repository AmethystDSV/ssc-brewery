package guru.sfg.brewery.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ((HttpSecurity) ((HttpSecurity) ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)
                http
                        .authorizeRequests(authorize -> {
                            authorize.antMatchers("/","/webjars/**","/login","/resources/**").permitAll()
                                    .antMatchers("/beers/find","/beers*").permitAll()
                                    .antMatchers(HttpMethod.GET,"/api/v1/beer/**").permitAll()
                                    .mvcMatchers(HttpMethod.GET,"/api/v1/beerUpc/{upc}").permitAll();
                        })
                        .authorizeRequests()
                        .anyRequest())
                .authenticated()
                .and())
                .formLogin()
                .and())
                .httpBasic();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new StandardPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("{SSHA}/WhUKw6Wm7dWv0Mx99I3CnVg2URvHtKtFWpr5w==")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("2d36e9667a9ad2a84c1344537878c59ee81646d59b7c0271aee0fc292a0494530ef3a27120e25335")
                .roles("USER")
                .and()
                .withUser("scott")
                .password("tiger")
                .roles("CUSTOMER");
    }

    /*
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("spring")
                .password("guru")
                .roles("ADMIN")
                .build();
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin,user);
    }
*/
}
