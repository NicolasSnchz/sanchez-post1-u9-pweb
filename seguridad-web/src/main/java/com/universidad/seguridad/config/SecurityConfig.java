package com.universidad.seguridad.config;

import com.universidad.seguridad.security.JwtAuthFilter;
import com.universidad.seguridad.service.UsuarioDetailsService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public DaoAuthenticationProvider authProvider(UsuarioDetailsService uds, PasswordEncoder pe) {
        DaoAuthenticationProvider p = new DaoAuthenticationProvider();
        p.setUserDetailsService(uds);
        p.setPasswordEncoder(pe);
        return p;
    }

    // ApiAuthController necesita un AuthenticationManager y Spring Boot no publica uno como bean:
    // este usa el mismo DaoAuthenticationProvider (UsuarioDetailsService + BCrypt) que el form-login
    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider authProvider) {
        return new ProviderManager(authProvider);
    }

    // JwtAuthFilter es un @Component y Spring Boot registra cualquier Filter como filtro global del
    // servidor. Se desactiva ese registro: el filtro solo debe correr dentro de apiFilterChain
    @Bean
    public FilterRegistrationBean<JwtAuthFilter> jwtAuthFilterSoloEnLaApi(JwtAuthFilter filtro) {
        FilterRegistrationBean<JwtAuthFilter> registro = new FilterRegistrationBean<>(filtro);
        registro.setEnabled(false);
        return registro;
    }

    // Cadena para la API REST, stateless con JWT. @Order(1): se evalua ANTES que webFilterChain
    // (@Order(2)), la mas especifica primero
    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {
        http
            .securityMatcher("/api/**") // esta cadena SOLO aplica a /api/**
            .csrf(csrf -> csrf.disable()) // correcto aqui: no hay cookie de sesion que un atacante
                                          // pueda aprovechar; el token va en un header que un
                                          // formulario cross-site no puede fijar por si solo
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            // Sin esto Spring Security responde 403 a una peticion sin token; la API debe
            // responder 401 (no autenticado) y 403 solo cuando el rol no alcanza, en JSON
            .exceptionHandling(errores -> errores
                .authenticationEntryPoint((peticion, respuesta, ex) ->
                    responderJson(respuesta, HttpServletResponse.SC_UNAUTHORIZED, "Se requiere un token JWT valido"))
                .accessDeniedHandler((peticion, respuesta, ex) ->
                    responderJson(respuesta, HttpServletResponse.SC_FORBIDDEN, "El rol del token no permite este recurso"))
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // Cadena para las vistas Thymeleaf, basada en sesion. @Order(2): la cadena de /api/**
    // (Parte 2) tiene @Order(1) y se evalua primero; esta atiende todo lo demas.
    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/registro", "/error",
                                 "/css/**", "/js/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            );
            // CSRF queda ACTIVO (comportamiento por defecto de Spring Security): esta cadena
            // sirve formularios Thymeleaf con cookie de sesion, el escenario exacto que CSRF protege.
        return http.build();
    }

    private static void responderJson(HttpServletResponse respuesta, int estado, String mensaje) throws IOException {
        respuesta.setStatus(estado);
        respuesta.setContentType(MediaType.APPLICATION_JSON_VALUE);
        respuesta.setCharacterEncoding("UTF-8");
        respuesta.getWriter().write("{\"error\":\"" + mensaje + "\"}");
    }
}
