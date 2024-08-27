---
title:  "Implementing JWT Authentication with Spring Boot"
date:   2024-08-27 02:44:00 -0700
categories: Dev
---
In the world of modern web applications, securing user data and ensuring safe access to applications is more critical than ever. With the increasing number of security threats, robust authentication mechanisms have become an essential component of any web application.

JSON Web Tokens (JWTs) are a popular choice for implementing secure, stateless authentication. They offer a compact and efficient way to transit information between parties, making them ideal for use in modern, API-driven applications.

In this post, we’ll walk through how to implement JWT-based authentication in a Spring Boot application. We’ll cover setting up necessary components, generating and validating JWTs, securing your application’s routes with token-based authentication, and testing these using Postman.

You can see the whole code [here](https://github.com/trpallin/springboot-jwt-auth).

### Project dependencies

First, let’s start by adding the necessary dependencies to your project.

**For Gradle:**
```groovy
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'io.jsonwebtoken:jjwt:0.12.6'
}
```

**For Maven:**
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt</artifactId>
        <version>0.12.6</version>
    </dependency>
</dependencies>
```

### Creating the User Entity

Next, we’ll create a simple user entity with only two fields: email and password.

**User.java**

```java
package com.example.springbootjwtauth.models;

public class User {
    private String email;
    private String password;

    public User(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```

### Creating the UserRepository

We’ll create a UserRepository to manage the user data. For simplicity, we’ll mock the database with a static field named db.

**UserRepository.java**

```java
package com.example.springbootjwtauth.repositories;

import com.example.springbootjwtauth.models.User;
import org.springframework.stereotype.Repository;
import java.util.HashMap;
import java.util.Map;

@Repository
public class UserRepository {
    private static final Map<String, User> db = new HashMap<>();

    public User findByEmail(String email) {
        return db.get(email);
    }

    public void addUser(User user) {
        db.put(user.getEmail(), user);
    }
}
```

### JWT Utility Class

Now, let’s implement the utility class that generates and validates JWT tokens. This is encapsulated in the JwtUtil class.

**JwtUtil.java**

```java
package com.example.springbootjwtauth.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {
    private final Key key;
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 10;

    public JwtUtil() {
        String secret = "a-secret-key-01234567890123456789";
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public static long getExpirationTime() {
        return EXPIRATION_TIME;
    }

    public String generateToken(String email) {
        return generateToken(new HashMap<>(), email);
    }

    public String generateToken(Map<String, Object> extraClaims, String email) {
        return buildToken(extraClaims, email);
    }

    private String buildToken(Map<String, Object> extraClaims, String email) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key)
                .compact();
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Boolean validateToken(String token, String email) {
        final String extractedEmail = extractEmail(token);
        return (extractedEmail.equals(email) && !isTokenExpired(token));
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
```

Explanation:

- Claims are key-value pairs that convey information about the user or any other data you want to include in the token.
- The buildToken() method creates a JWT with claims, issued and expiration dates, and signs it with a secret key.
- The subject is a registered claim in JWTs that identifies the principal (usually the user) to whom the token is issued.

### Implementing JWT Authentication Filter

Next, we introduce the `JwtAuthFilter`, which intercepts incoming requests to check for a valid JWT in the Authorization header. If the token is present and valid, and the SecurityContext is not already authenticated, the filter sets the appropriate authentication token.

**JwtAuthFilter.java**

```java
package com.example.springbootjwtauth.filters;

import com.example.springbootjwtauth.services.CustomUserDetailsService;
import com.example.springbootjwtauth.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;

    public JwtAuthFilter(JwtUtil jwtUtil, CustomUserDetailsService customUserDetailsService) {
        this.jwtUtil = jwtUtil;
        this.customUserDetailsService = customUserDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            username = jwtUtil.extractEmail(jwt);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (jwtUtil.validateToken(jwt, username)) {
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
```

### Custom UserDetailService

The CustomUserDetailService implements Spring Security’s UserDetailsService interface, allowing it to fetch user-specific data during authentication.

**CustomUserDetailsService.java**

```java
package com.example.springbootjwtauth.services;

import com.example.springbootjwtauth.models.User;
import com.example.springbootjwtauth.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .build();
    }
}
```

### Spring Security Configuration

Next, we configure Spring Security in `SecurityConfig.java`, where we set up the authentication and authorization rules for the application.

**SecurityConfig.java**

```java
package com.example.springbootjwtauth.config;

import com.example.springbootjwtauth.filters.JwtAuthFilter;
import com.example.springbootjwtauth.services.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtAuthFilter jwtAuthFilter;
    private final CustomUserDetailsService customUserDetailsService;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter, CustomUserDetailsService customUserDetailsService) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.customUserDetailsService = customUserDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers(
                                        "/auth/login",
                                        "/auth/signup"
                                ).permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );
        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, PasswordEncoder passwordEncoder) throws Exception {
        AuthenticationManagerBuilder authManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder);
        return authManagerBuilder.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

Explanation:

- `@Configuration` and `@EnableWebSecurity`: Indicates that this class is used for Spring Security configuration and enables web security features.
- SecurityFilterChain defines the core HTTP security settings, allowing unauthenticated access to /auth/login and /auth/signup, and requiring authentication for all other requests.
- Integrates JwtAuthFilter before UsernamePasswordAuthenticationFilter to validate JWT tokens in every incoming request.
- Configures the AuthenticationManager with CustomUserDetailsService to handle user authentication requests.

### Creating the Authentication Service

Before implementing the AuthService, we need to define the data transfer objects (DTOs) that will handle the data for user signup and login requests.

**SignUpRequest.java**

```java
package com.example.springbootjwtauth.dtos;

public class SignUpRequest {
    private String email;
    private String password;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```

**LoginRequest.java**

```java
package com.example.springbootjwtauth.dtos;

public class LoginRequest {
    private String email;
    private String password;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```

**LoginResponse.java**

```java
package com.example.springbootjwtauth.dtos;

public class LoginResponse {
    private String token;
    private long expiresIn;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }
}
```

Then create the AuthService to handle user signup and login.

**AuthService.java**

```java
package com.example.springbootjwtauth.services;

import com.example.springbootjwtauth.dtos.LoginRequest;
import com.example.springbootjwtauth.dtos.SignUpRequest;
import com.example.springbootjwtauth.models.User;
import com.example.springbootjwtauth.repositories.UserRepository;
import com.example.springbootjwtauth.utils.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    public User signUpUser(SignUpRequest signUpRequest) {
        if (userRepository.findByEmail(signUpRequest.getEmail()) != null) {
            throw new IllegalArgumentException("The email already exists");
        }
        String encodedPassword = passwordEncoder.encode(signUpRequest.getPassword());
        User user = new User(signUpRequest.getEmail(), encodedPassword);
        userRepository.addUser(user);
        return user;
    }

    public String authenticateUser(LoginRequest loginRequest) {
        User existingUser = userRepository.findByEmail(loginRequest.getEmail());
        if (existingUser != null && isPasswordValid(loginRequest, existingUser)) {
            return jwtUtil.generateToken(loginRequest.getEmail());
        } else {
            throw new IllegalArgumentException("Invalid email or password");
        }
    }

    private boolean isPasswordValid(LoginRequest loginRequest, User existingUser) {
        return passwordEncoder.matches(loginRequest.getPassword(), existingUser.getPassword());
    }
}
```

### Creating the Authentication Controller

Finally, let’s implement the AuthController that exposes the signup and login endpoints.

**AuthController.java**

```java
package com.example.springbootjwtauth.controllers;

import com.example.springbootjwtauth.dtos.LoginRequest;
import com.example.springbootjwtauth.dtos.LoginResponse;
import com.example.springbootjwtauth.dtos.SignUpRequest;
import com.example.springbootjwtauth.models.User;
import com.example.springbootjwtauth.services.AuthService;
import com.example.springbootjwtauth.utils.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    ResponseEntity<User> signUpUser(@RequestBody SignUpRequest signUpRequest) {
        return ResponseEntity.ok(authService.signUpUser(signUpRequest));
    }

    @PostMapping("/login")
    ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        String token = authService.authenticateUser(loginRequest);
        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setExpiresIn(JwtUtil.getExpirationTime());
        return ResponseEntity.ok(response);
    }
}
```

With the AuthController in place, we’ve completed the implementation of JWT-based authentication in our Spring Boot application. Now, all that’s left is to test the functionality to ensure everything works as expected.

### Testing JWT Authentication API with Postman

In this section, we will walk through the process of testing the signup, login, and getUserEmail endpoints using Postman. This will help verify that the JWT authentication flow in your Spring Boot application works as expected.

First, add a UserController as below. It retrieves user information (email) from the token in the request header that our JwtAuthFilter has already saved to SecurityContextHolder.

**UserController.java**

```java
package com.example.springbootjwtauth.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping("/email")
    public ResponseEntity<String> getUserEmail() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String email;
        if (principal instanceof UserDetails) {
            email = ((UserDetails) principal).getUsername();
        } else {
            email = principal.toString();
        }

        return ResponseEntity.ok("Hello, your email is " + email);
    }
}
```

Run the application, and we'll test the functionality of this controller to ensure it returns an error when provided with an invalid token.

### Testing the Signup Endpoint (/auth/signup)

The first step in our JWT authentication flow is to sign up a new user.

1. Open Postman and create a new POST request.
2. Set the URL to http://localhost:8080/auth/signup
3. Set the Request Body to raw and select JSON as the content type. Enter the following JSON payload:

    ```json
    {
        "email": "testuser@example.com",
        "password": "password123"
    }
    ```

    ![img 1](/assets/images/20240826-1.png)

4. Send the Request by clicking the Send button.

Response:

![img 2](/assets/images/20240826-2.png)

We have successfully created a new user, and the response confirms that the user information has been generated as shown above.

### Testing the Login Endpoint (/auth/login)

Next, we’ll test the login endpoint to authenticate the user and receive a JWT token.

1.	Create a new POST request in Postman.
2.	Set the URL to http://localhost:8080/auth/login.
3.	Set the Request Body to raw and select JSON. Use the following JSON payload:

    ```json
    {
        "email": "testuser@example.com",
        "password": "password123"
    }
    ```
    ![img 3](/assets/images/20240826-3.png)

4. Send the Request by clicking the Send button.

Response:

![img 4](/assets/images/20240826-4.png)

We have successfully received a JWT token as shown above.
Our token is:
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlckBleGFtcGxlLmNvbSIsImlhdCI6MTcyNDY3NDM0NCwiZXhwIjoxNzI0NzEwMzQ0fQ._NxQVKadBB0D2QRxEjfv55sfeSdSyN16uMhXG1DNmZY
```

### Testing the Get User Email Endpoint (/user/email)

We’ll test the getUserEmail endpoint, which requires a valid JWT token to access.

1.	Create a new GET request in Postman.
2.	Set the URL to http://localhost:8080/user/email.
3.	Add the Authorization Header:

    In the “Headers” tab, add a new header with the key Authorization and the value “Bearer <your_jwt_token>”. Replace <your_jwt_token> with the token obtained from the login response.

    ![img 5](/assets/images/20240826-5.png)

4.	Send the Request by clicking the Send button.

Response:

![img 6](/assets/images/20240826-6.png)

The server has successfully returned the user's email based on the provided token.

### Testing the Get User Email Endpoint (/user/email) with an Invalid Token

1.	Create a new GET request in Postman.

2.	Set the URL to http://localhost:8080/user/email.

3.	Add the Authorization Header:

    In the “Headers” tab, add a new header with the key Authorization and the value Bearer invalid_token.

    ![img 7](/assets/images/20240826-7.png)

4.	Send the Request by clicking the Send button.

Response:

![img 8](/assets/images/20240826-8.png)

We confirmed that an error is returned when an invalid token is provided.

In this post, we’ve successfully implemented JWT-based authentication in a Spring Boot application. We covered the setup of essential components, the creation of authentication services and filters, and tested the entire flow using Postman. This approach provides a secure, stateless authentication mechanism that is ideal for modern web applications. You can now extend this setup to fit more complex use cases and further secure your application.