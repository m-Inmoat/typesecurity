# TypeScript & Spring Security 実装ガイド

このガイドでは、TypeScriptとSpring Securityを使用したタスク管理アプリケーションの実装方法について詳しく解説します。フロントエンドにはTypeScript/React、バックエンドにはSpring Boot/Spring Securityを使用し、JWT認証によるセキュアなWebアプリケーション開発の基本を学ぶことができます。

## 目次

1. [プロジェクト概要](#プロジェクト概要)
2. [環境セットアップ](#環境セットアップ)
3. [バックエンド実装](#バックエンド実装)
4. [フロントエンド実装](#フロントエンド実装)
5. [統合とテスト](#統合とテスト)
6. [学習ポイント](#学習ポイント)
7. [発展課題](#発展課題)

## プロジェクト概要

このサンプルアプリケーションは、ユーザーがタスクを作成・管理できるシンプルなタスク管理システムです。主な機能は以下の通りです：

- ユーザー登録・ログイン機能
- JWT認証によるセキュアなAPI通信
- ロールベースのアクセス制御（一般ユーザー/管理者）
- タスクのCRUD操作（作成・読取・更新・削除）
- タスクの割り当てと共有

アーキテクチャは「SPAフロントエンド + RESTful APIバックエンド」の構成を採用しています：

```
[クライアント層] TypeScript + React SPA
        ↓ HTTP/REST + JWT
[API層] Spring Boot + Spring Security
        ↓ JPA
[データ層] H2 Database (開発用)
```

## 環境セットアップ

### 必要なソフトウェア

- **Java 17**：バックエンド開発用
- **Node.js & npm**：フロントエンド開発用
- **Git**：バージョン管理用（オプション）
- **IDE**：VS Code, IntelliJ IDEA, Eclipse など

### バックエンド環境セットアップ

1. **Java 17のインストール**

```bash
# Ubuntuの場合
sudo apt update
sudo apt install openjdk-17-jdk

# 確認
java -version
```

2. **プロジェクトディレクトリの作成**

```bash
mkdir -p task-manager/backend
cd task-manager/backend
```

3. **Spring Bootプロジェクトの初期化**

Spring Initializrを使用するか、以下のpom.xmlを作成します：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>3.2.0</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>task-manager</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>task-manager</name>
	<description>Task Manager with Spring Security</description>
	<properties>
		<java.version>17</java.version>
		<jjwt.version>0.11.5</jjwt.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-validation</artifactId>
		</dependency>

		<dependency>
			<groupId>com.h2database</groupId>
			<artifactId>h2</artifactId>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>org.projectlombok</groupId>
			<artifactId>lombok</artifactId>
			<optional>true</optional>
		</dependency>
		
		<!-- JWT Dependencies -->
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-api</artifactId>
			<version>${jjwt.version}</version>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-impl</artifactId>
			<version>${jjwt.version}</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId>
			<version>${jjwt.version}</version>
			<scope>runtime</scope>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-test</artifactId>
			<scope>test</scope>
		</dependency>
	</dependencies>

	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<configuration>
					<excludes>
						<exclude>
							<groupId>org.projectlombok</groupId>
							<artifactId>lombok</artifactId>
						</exclude>
					</excludes>
				</configuration>
			</plugin>
		</plugins>
	</build>
</project>
```

### フロントエンド環境セットアップ

1. **Node.jsとnpmの確認**

```bash
node -v
npm -v
```

2. **プロジェクトディレクトリの作成**

```bash
mkdir -p task-manager/frontend
cd task-manager/frontend
```

3. **Viteを使用したReact+TypeScriptプロジェクトの初期化**

```bash
npm create vite@latest . -- --template react-ts
npm install
```

4. **必要なパッケージのインストール**

```bash
npm install @mui/material @emotion/react @emotion/styled axios react-router-dom react-hook-form @mui/icons-material @mui/x-date-pickers date-fns
```

## バックエンド実装

### 1. アプリケーションプロパティの設定

`src/main/resources/application.properties`ファイルを作成し、以下の内容を追加します：

```properties
spring.datasource.url=jdbc:h2:mem:taskdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=password
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect

spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true

# JWT Configuration
app.jwt.secret=verySecretKeyForJWTSigningThatShouldBeAtLeast256BitsLong
app.jwt.expiration=86400000
app.jwt.header=Authorization
app.jwt.prefix=Bearer 

# CORS Configuration
app.cors.allowed-origins=http://localhost:5173
```

### 2. エンティティの実装

#### User.java

```java
package com.example.taskmanager.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private LocalDateTime updatedAt;
}
```

#### Role.java

```java
package com.example.taskmanager.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;

    public Role(ERole name) {
        this.name = name;
    }

    public enum ERole {
        ROLE_USER,
        ROLE_ADMIN
    }
}
```

#### Task.java

```java
package com.example.taskmanager.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "tasks")
@Data
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class Task {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(length = 1000)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TaskStatus status = TaskStatus.TODO;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TaskPriority priority = TaskPriority.MEDIUM;

    private LocalDate dueDate;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "task_assignees",
            joinColumns = @JoinColumn(name = "task_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id")
    )
    private Set<User> assignees = new HashSet<>();

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    public enum TaskStatus {
        TODO, IN_PROGRESS, DONE
    }

    public enum TaskPriority {
        LOW, MEDIUM, HIGH
    }
}
```

### 3. リポジトリの実装

#### UserRepository.java

```java
package com.example.taskmanager.repository;

import com.example.taskmanager.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}
```

#### RoleRepository.java

```java
package com.example.taskmanager.repository;

import com.example.taskmanager.model.Role;
import com.example.taskmanager.model.Role.ERole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
```

#### TaskRepository.java

```java
package com.example.taskmanager.repository;

import com.example.taskmanager.model.Task;
import com.example.taskmanager.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {
    List<Task> findByOwner(User owner);
    List<Task> findByAssigneesContaining(User assignee);
    List<Task> findByStatus(Task.TaskStatus status);
}
```

### 4. Spring Security設定

#### WebSecurityConfig.java

```java
package com.example.taskmanager.security;

import com.example.taskmanager.security.jwt.AuthEntryPointJwt;
import com.example.taskmanager.security.jwt.AuthTokenFilter;
import com.example.taskmanager.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> 
                auth.requestMatchers("/api/auth/**").permitAll()
                    .requestMatchers("/api/test/**").permitAll()
                    .requestMatchers("/h2-console/**").permitAll()
                    .anyRequest().authenticated()
            );
        
        // Fix for H2 console
        http.headers(headers -> headers.frameOptions(frameOption -> frameOption.sameOrigin()));
        
        http.authenticationProvider(authenticationProvider());
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

### 5. JWT認証の実装

#### JwtUtils.java

```java
package com.example.taskmanager.security.jwt;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.example.taskmanager.security.services.UserDetailsImpl;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${app.jwt.secret}")
  private String jwtSecret;

  @Value("${app.jwt.expiration}")
  private int jwtExpirationMs;

  public String generateJwtToken(Authentication authentication) {
    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

    return Jwts.builder()
        .setSubject((userPrincipal.getUsername()))
        .setIssuedAt(new Date())
        .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
        .signWith(key(), SignatureAlgorithm.HS256)
        .compact();
  }
  
  private Key key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parserBuilder().setSigningKey(key()).build()
               .parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }
}
```

#### AuthTokenFilter.java

```java
package com.example.taskmanager.security.jwt;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.taskmanager.security.services.UserDetailsServiceImpl;

public class AuthTokenFilter extends OncePerRequestFilter {
  @Autowired
  private JwtUtils jwtUtils;

  @Autowired
  private UserDetailsServiceImpl userDetailsService;
  
  @Value("${app.jwt.header}")
  private String headerName;
  
  @Value("${app.jwt.prefix}")
  private String headerPrefix;

  private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    try {
      String jwt = parseJwt(request);
      if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
        String username = jwtUtils.getUserNameFromJwtToken(jwt);

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    } catch (Exception e) {
      logger.error("Cannot set user authentication: {}", e.getMessage());
    }

    filterChain.doFilter(request, response);
  }

  private String parseJwt(HttpServletRequest request) {
    String headerAuth = request.getHeader(headerName);

    if (StringUtils.hasText(headerAuth) && headerAuth.startsWith(headerPrefix)) {
      return headerAuth.substring(headerPrefix.length());
    }

    return null;
  }
}
```

#### AuthEntryPointJwt.java

```java
package com.example.taskmanager.security.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

  private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationException authException) throws IOException, ServletException {
    logger.error("Unauthorized error: {}", authException.getMessage());
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
  }
}
```

### 6. UserDetailsの実装

#### UserDetailsImpl.java

```java
package com.example.taskmanager.security.services;

import com.example.taskmanager.model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private Long id;
    private String username;
    private String email;
    
    @JsonIgnore
    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    public static UserDetailsImpl build(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities);
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

#### UserDetailsServiceImpl.java

```java
package com.example.taskmanager.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.taskmanager.model.User;
import com.example.taskmanager.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  UserRepository userRepository;

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    return UserDetailsImpl.build(user);
  }
}
```

### 7. DTOクラスの実装

#### LoginRequest.java

```java
package com.example.taskmanager.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String password;
}
```

#### SignupRequest.java

```java
package com.example.taskmanager.payload.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignupRequest {
    @NotBlank
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    @NotBlank
    @Size(min = 6, max = 40)
    private String password;
    
    private String[] roles;
}
```

#### JwtResponse.java

```java
package com.example.taskmanager.payload.response;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private Long id;
    private String username;
    private String email;
    private List<String> roles;

    public JwtResponse(String accessToken, Long id, String username, String email, List<String> roles) {
        this.token = accessToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }
}
```

#### MessageResponse.java

```java
package com.example.taskmanager.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class MessageResponse {
    private String message;
}
```

#### TaskRequest.java

```java
package com.example.taskmanager.payload.request;

import com.example.taskmanager.model.Task.TaskPriority;
import com.example.taskmanager.model.Task.TaskStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDate;
import java.util.Set;

@Data
public class TaskRequest {
    @NotBlank
    private String title;
    
    private String description;
    
    @NotNull
    private TaskStatus status;
    
    @NotNull
    private TaskPriority priority;
    
    private LocalDate dueDate;
    
    private Set<Long> assigneeIds;
}
```

### 8. サービス層の実装

#### TaskService.java

```java
package com.example.taskmanager.service;

import com.example.taskmanager.model.Task;
import com.example.taskmanager.model.User;
import com.example.taskmanager.payload.request.TaskRequest;
import com.example.taskmanager.repository.TaskRepository;
import com.example.taskmanager.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class TaskService {

    @Autowired
    private TaskRepository taskRepository;

    @Autowired
    private UserRepository userRepository;

    public List<Task> getAllTasks() {
        return taskRepository.findAll();
    }

    public Task getTaskById(Long id) {
        return taskRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Task not found with id: " + id));
    }

    public List<Task> getTasksByOwner(User owner) {
        return taskRepository.findByOwner(owner);
    }

    public List<Task> getTasksByAssignee(User assignee) {
        return taskRepository.findByAssigneesContaining(assignee);
    }

    @Transactional
    public Task createTask(TaskRequest taskRequest, String ownerUsername) {
        User owner = userRepository.findByUsername(ownerUsername)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + ownerUsername));

        Task task = new Task();
        task.setTitle(taskRequest.getTitle());
        task.setDescription(taskRequest.getDescription());
        task.setStatus(taskRequest.getStatus());
        task.setPriority(taskRequest.getPriority());
        task.setDueDate(taskRequest.getDueDate());
        task.setOwner(owner);

        // Set assignees if provided
        if (taskRequest.getAssigneeIds() != null && !taskRequest.getAssigneeIds().isEmpty()) {
            Set<User> assignees = new HashSet<>();
            for (Long userId : taskRequest.getAssigneeIds()) {
                User user = userRepository.findById(userId)
                        .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
                assignees.add(user);
            }
            task.setAssignees(assignees);
        }

        return taskRepository.save(task);
    }

    @Transactional
    public Task updateTask(Long id, TaskRequest taskRequest) {
        Task task = taskRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Task not found with id: " + id));

        task.setTitle(taskRequest.getTitle());
        task.setDescription(taskRequest.getDescription());
        task.setStatus(taskRequest.getStatus());
        task.setPriority(taskRequest.getPriority());
        task.setDueDate(taskRequest.getDueDate());

        // Update assignees if provided
        if (taskRequest.getAssigneeIds() != null) {
            Set<User> assignees = taskRequest.getAssigneeIds().stream()
                    .map(userId -> userRepository.findById(userId)
                            .orElseThrow(() -> new RuntimeException("User not found with id: " + userId)))
                    .collect(Collectors.toSet());
            task.setAssignees(assignees);
        }

        return taskRepository.save(task);
    }

    public void deleteTask(Long id) {
        if (!taskRepository.existsById(id)) {
            throw new RuntimeException("Task not found with id: " + id);
        }
        taskRepository.deleteById(id);
    }
}
```

### 9. コントローラー層の実装

#### AuthController.java

```java
package com.example.taskmanager.controller;

import com.example.taskmanager.model.Role;
import com.example.taskmanager.model.Role.ERole;
import com.example.taskmanager.model.User;
import com.example.taskmanager.payload.request.LoginRequest;
import com.example.taskmanager.payload.request.SignupRequest;
import com.example.taskmanager.payload.response.JwtResponse;
import com.example.taskmanager.payload.response.MessageResponse;
import com.example.taskmanager.repository.RoleRepository;
import com.example.taskmanager.repository.UserRepository;
import com.example.taskmanager.security.jwt.JwtUtils;
import com.example.taskmanager.security.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                                                 userDetails.getId(), 
                                                 userDetails.getUsername(), 
                                                 userDetails.getEmail(), 
                                                 roles));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(encoder.encode(signUpRequest.getPassword()));

        Set<Role> roles = new HashSet<>();

        // By default, assign ROLE_USER
        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        roles.add(userRole);
        
        // If roles are specified in the request, process them
        if (signUpRequest.getRoles() != null) {
            for (String role : signUpRequest.getRoles()) {
                if ("admin".equals(role)) {
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Admin Role is not found."));
                    roles.add(adminRole);
                }
            }
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
```

#### UserController.java

```java
package com.example.taskmanager.controller;

import com.example.taskmanager.model.User;
import com.example.taskmanager.payload.response.MessageResponse;
import com.example.taskmanager.repository.UserRepository;
import com.example.taskmanager.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    UserRepository userRepository;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        // Get current authenticated user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        // Only allow users to access their own profile, or admins to access any profile
        if (!userDetails.getId().equals(id) && !authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            return ResponseEntity.status(403).body(new MessageResponse("Access denied"));
        }
        
        return userRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        return userRepository.findById(userDetails.getId())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        userRepository.deleteById(id);
        return ResponseEntity.ok(new MessageResponse("User deleted successfully"));
    }
}
```

#### TaskController.java

```java
package com.example.taskmanager.controller;

import com.example.taskmanager.model.Task;
import com.example.taskmanager.model.User;
import com.example.taskmanager.payload.request.TaskRequest;
import com.example.taskmanager.payload.response.MessageResponse;
import com.example.taskmanager.repository.UserRepository;
import com.example.taskmanager.security.services.UserDetailsImpl;
import com.example.taskmanager.service.TaskService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/tasks")
public class TaskController {

    @Autowired
    private TaskService taskService;

    @Autowired
    private UserRepository userRepository;

    @GetMapping
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<Task>> getAllTasks() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        // Admins can see all tasks, users can only see their own or assigned tasks
        if (authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            return ResponseEntity.ok(taskService.getAllTasks());
        } else {
            User user = userRepository.findById(userDetails.getId())
                    .orElseThrow(() -> new RuntimeException("User not found"));
            List<Task> ownedTasks = taskService.getTasksByOwner(user);
            List<Task> assignedTasks = taskService.getTasksByAssignee(user);
            
            // Combine and remove duplicates
            ownedTasks.addAll(assignedTasks);
            return ResponseEntity.ok(ownedTasks.stream().distinct().toList());
        }
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> getTaskById(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        Task task = taskService.getTaskById(id);
        
        // Check if user has access to this task
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean isOwner = task.getOwner().getId().equals(userDetails.getId());
        boolean isAssignee = task.getAssignees().stream()
                .anyMatch(user -> user.getId().equals(userDetails.getId()));
        
        if (isAdmin || isOwner || isAssignee) {
            return ResponseEntity.ok(task);
        } else {
            return ResponseEntity.status(403).body(new MessageResponse("Access denied"));
        }
    }

    @PostMapping
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> createTask(@Valid @RequestBody TaskRequest taskRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        Task task = taskService.createTask(taskRequest, userDetails.getUsername());
        return ResponseEntity.ok(task);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> updateTask(@PathVariable Long id, @Valid @RequestBody TaskRequest taskRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        Task task = taskService.getTaskById(id);
        
        // Check if user has permission to update this task
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean isOwner = task.getOwner().getId().equals(userDetails.getId());
        
        if (isAdmin || isOwner) {
            Task updatedTask = taskService.updateTask(id, taskRequest);
            return ResponseEntity.ok(updatedTask);
        } else {
            return ResponseEntity.status(403).body(new MessageResponse("Access denied"));
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> deleteTask(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        Task task = taskService.getTaskById(id);
        
        // Check if user has permission to delete this task
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean isOwner = task.getOwner().getId().equals(userDetails.getId());
        
        if (isAdmin || isOwner) {
            taskService.deleteTask(id);
            return ResponseEntity.ok(new MessageResponse("Task deleted successfully"));
        } else {
            return ResponseEntity.status(403).body(new MessageResponse("Access denied"));
        }
    }

    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Task>> getTasksByUserId(@PathVariable Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
        
        List<Task> tasks = taskService.getTasksByOwner(user);
        return ResponseEntity.ok(tasks);
    }
}
```

### 10. CORS設定

#### WebConfig.java

```java
package com.example.taskmanager.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("http://localhost:5173")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }
}
```

### 11. データベース初期化

アプリケーション起動時にロールとテストユーザーを作成するためのデータ初期化クラスを作成します：

```java
package com.example.taskmanager.config;

import com.example.taskmanager.model.Role;
import com.example.taskmanager.model.Role.ERole;
import com.example.taskmanager.model.User;
import com.example.taskmanager.repository.RoleRepository;
import com.example.taskmanager.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Initialize roles
        initRoles();
        
        // Create test users
        createTestUsers();
    }

    private void initRoles() {
        if (roleRepository.count() == 0) {
            Role userRole = new Role(ERole.ROLE_USER);
            Role adminRole = new Role(ERole.ROLE_ADMIN);
            
            roleRepository.save(userRole);
            roleRepository.save(adminRole);
        }
    }

    private void createTestUsers() {
        if (userRepository.count() == 0) {
            // Create admin user
            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setEmail("admin@example.com");
            adminUser.setPassword(passwordEncoder.encode("admin123"));
            
            Set<Role> adminRoles = new HashSet<>();
            adminRoles.add(roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Admin Role not found.")));
            adminRoles.add(roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: User Role not found.")));
            
            adminUser.setRoles(adminRoles);
            userRepository.save(adminUser);
            
            // Create regular user
            User regularUser = new User();
            regularUser.setUsername("user");
            regularUser.setEmail("user@example.com");
            regularUser.setPassword(passwordEncoder.encode("user123"));
            
            Set<Role> userRoles = new HashSet<>();
            userRoles.add(roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: User Role not found.")));
            
            regularUser.setRoles(userRoles);
            userRepository.save(regularUser);
        }
    }
}
```

## フロントエンド実装

### 1. TypeScriptインターフェースの定義

`src/interfaces/index.ts`ファイルを作成し、以下の内容を追加します：

```typescript
// src/interfaces/index.ts
export interface User {
  id: number;
  username: string;
  email: string;
  roles: string[];
}

export interface Task {
  id: number;
  title: string;
  description: string;
  status: 'TODO' | 'IN_PROGRESS' | 'DONE';
  priority: 'LOW' | 'MEDIUM' | 'HIGH';
  dueDate: string;
  ownerId: number;
  assigneeIds: number[];
  createdAt: string;
  updatedAt: string;
}

export interface AuthResponse {
  accessToken: string;
  tokenType: string;
  user: User;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

export interface TaskRequest {
  title: string;
  description: string;
  status: string;
  priority: string;
  dueDate: string;
  assigneeIds: number[];
}
```

### 2. APIサービスの実装

#### api.ts

```typescript
// src/services/api.ts
import axios from 'axios';

const API_URL = 'http://localhost:8080/api';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for handling errors
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    
    // Handle token expiration
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        // Attempt to refresh token
        const refreshToken = localStorage.getItem('refreshToken');
        if (refreshToken) {
          const response = await axios.post(`${API_URL}/auth/refresh`, { refreshToken });
          const { accessToken } = response.data;
          
          localStorage.setItem('token', accessToken);
          
          // Retry the original request with new token
          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
          return axios(originalRequest);
        }
      } catch (refreshError) {
        // If refresh fails, redirect to login
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        window.location.href = '/login';
      }
    }
    
    return Promise.reject(error);
  }
);

export default api;
```

#### authService.ts

```typescript
// src/services/authService.ts
import api from './api';
import { AuthResponse, LoginRequest, RegisterRequest, User } from '../interfaces';

export const authService = {
  login: async (credentials: LoginRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/auth/login', credentials);
    localStorage.setItem('token', response.data.accessToken);
    return response.data;
  },
  
  register: async (userData: RegisterRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/auth/register', userData);
    return response.data;
  },
  
  logout: (): void => {
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
  },
  
  getCurrentUser: async (): Promise<User | null> => {
    try {
      const response = await api.get<User>('/users/me');
      return response.data;
    } catch (error) {
      return null;
    }
  },
  
  isAuthenticated: (): boolean => {
    return !!localStorage.getItem('token');
  }
};

export default authService;
```

#### taskService.ts

```typescript
// src/services/taskService.ts
import api from './api';
import { Task, TaskRequest } from '../interfaces';

export const taskService = {
  getAllTasks: async (): Promise<Task[]> => {
    const response = await api.get<Task[]>('/tasks');
    return response.data;
  },
  
  getTaskById: async (id: number): Promise<Task> => {
    const response = await api.get<Task>(`/tasks/${id}`);
    return response.data;
  },
  
  createTask: async (taskData: TaskRequest): Promise<Task> => {
    const response = await api.post<Task>('/tasks', taskData);
    return response.data;
  },
  
  updateTask: async (id: number, taskData: TaskRequest): Promise<Task> => {
    const response = await api.put<Task>(`/tasks/${id}`, taskData);
    return response.data;
  },
  
  deleteTask: async (id: number): Promise<void> => {
    await api.delete(`/tasks/${id}`);
  },
  
  getUserTasks: async (userId: number): Promise<Task[]> => {
    const response = await api.get<Task[]>(`/tasks/user/${userId}`);
    return response.data;
  }
};

export default taskService;
```

### 3. 認証コンテキストの実装

```typescript
// src/contexts/AuthContext.tsx
import React, { createContext, useState, useEffect, ReactNode } from 'react';
import { User } from '../interfaces';
import authService from '../services/authService';

interface AuthContextType {
  currentUser: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextType>({
  currentUser: null,
  loading: true,
  isAuthenticated: false,
  login: async () => {},
  register: async () => {},
  logout: () => {},
});

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadUser = async () => {
      if (authService.isAuthenticated()) {
        try {
          const user = await authService.getCurrentUser();
          setCurrentUser(user);
        } catch (error) {
          console.error('Failed to load user:', error);
          authService.logout();
        }
      }
      setLoading(false);
    };

    loadUser();
  }, []);

  const login = async (username: string, password: string) => {
    setLoading(true);
    try {
      const response = await authService.login({ username, password });
      setCurrentUser(response.user);
    } finally {
      setLoading(false);
    }
  };

  const register = async (username: string, email: string, password: string) => {
    setLoading(true);
    try {
      await authService.register({ username, email, password });
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    authService.logout();
    setCurrentUser(null);
  };

  const value = {
    currentUser,
    loading,
    isAuthenticated: !!currentUser,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  return React.useContext(AuthContext);
};
```

### 4. 認証コンポーネントの実装

#### PrivateRoute.tsx

```typescript
// src/components/common/PrivateRoute.tsx
import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { Box, CircularProgress } from '@mui/material';

interface PrivateRouteProps {
  children: React.ReactNode;
}

const PrivateRoute: React.FC<PrivateRouteProps> = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
      </Box>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }

  return <>{children}</>;
};

export default PrivateRoute;
```

#### LoginForm.tsx

```typescript
// src/components/auth/LoginForm.tsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { Button, TextField, Paper, Typography, Box, Alert } from '@mui/material';
import { useForm, Controller } from 'react-hook-form';

interface LoginFormInputs {
  username: string;
  password: string;
}

const LoginForm: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  
  const { control, handleSubmit, formState: { errors } } = useForm<LoginFormInputs>({
    defaultValues: {
      username: '',
      password: ''
    }
  });

  const onSubmit = async (data: LoginFormInputs) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await login(data.username, data.password);
      navigate('/dashboard');
    } catch (err) {
      setError('ログインに失敗しました。ユーザー名とパスワードを確認してください。');
      console.error('Login error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 400, mx: 'auto', mt: 8 }}>
      <Typography variant="h5" component="h1" gutterBottom align="center">
        ログイン
      </Typography>
      
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      
      <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
        <Controller
          name="username"
          control={control}
          rules={{ required: 'ユーザー名は必須です' }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="username"
              label="ユーザー名"
              autoComplete="username"
              autoFocus
              error={!!errors.username}
              helperText={errors.username?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Controller
          name="password"
          control={control}
          rules={{ required: 'パスワードは必須です' }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="password"
              label="パスワード"
              type="password"
              autoComplete="current-password"
              error={!!errors.password}
              helperText={errors.password?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Button
          type="submit"
          fullWidth
          variant="contained"
          sx={{ mt: 3, mb: 2 }}
          disabled={isLoading}
        >
          {isLoading ? 'ログイン中...' : 'ログイン'}
        </Button>
        
        <Button
          fullWidth
          variant="text"
          onClick={() => navigate('/register')}
          disabled={isLoading}
        >
          アカウント登録はこちら
        </Button>
      </Box>
    </Paper>
  );
};

export default LoginForm;
```

#### RegisterForm.tsx

```typescript
// src/components/auth/RegisterForm.tsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { Button, TextField, Paper, Typography, Box, Alert } from '@mui/material';
import { useForm, Controller } from 'react-hook-form';

interface RegisterFormInputs {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
}

const RegisterForm: React.FC = () => {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  
  const { control, handleSubmit, formState: { errors }, watch } = useForm<RegisterFormInputs>({
    defaultValues: {
      username: '',
      email: '',
      password: '',
      confirmPassword: ''
    }
  });

  const password = watch('password');

  const onSubmit = async (data: RegisterFormInputs) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await register(data.username, data.email, data.password);
      navigate('/login', { state: { message: '登録が完了しました。ログインしてください。' } });
    } catch (err) {
      setError('登録に失敗しました。ユーザー名またはメールアドレスが既に使用されている可能性があります。');
      console.error('Registration error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 400, mx: 'auto', mt: 8 }}>
      <Typography variant="h5" component="h1" gutterBottom align="center">
        アカウント登録
      </Typography>
      
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      
      <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
        <Controller
          name="username"
          control={control}
          rules={{ 
            required: 'ユーザー名は必須です',
            minLength: { value: 3, message: 'ユーザー名は3文字以上必要です' },
            maxLength: { value: 20, message: 'ユーザー名は20文字以下にしてください' }
          }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="username"
              label="ユーザー名"
              autoComplete="username"
              autoFocus
              error={!!errors.username}
              helperText={errors.username?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Controller
          name="email"
          control={control}
          rules={{ 
            required: 'メールアドレスは必須です',
            pattern: { value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i, message: '有効なメールアドレスを入力してください' }
          }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="email"
              label="メールアドレス"
              autoComplete="email"
              error={!!errors.email}
              helperText={errors.email?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Controller
          name="password"
          control={control}
          rules={{ 
            required: 'パスワードは必須です',
            minLength: { value: 6, message: 'パスワードは6文字以上必要です' },
            maxLength: { value: 40, message: 'パスワードは40文字以下にしてください' }
          }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="password"
              label="パスワード"
              type="password"
              autoComplete="new-password"
              error={!!errors.password}
              helperText={errors.password?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Controller
          name="confirmPassword"
          control={control}
          rules={{ 
            required: 'パスワード（確認）は必須です',
            validate: value => value === password || 'パスワードが一致しません'
          }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="confirmPassword"
              label="パスワード（確認）"
              type="password"
              autoComplete="new-password"
              error={!!errors.confirmPassword}
              helperText={errors.confirmPassword?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Button
          type="submit"
          fullWidth
          variant="contained"
          sx={{ mt: 3, mb: 2 }}
          disabled={isLoading}
        >
          {isLoading ? '登録中...' : '登録'}
        </Button>
        
        <Button
          fullWidth
          variant="text"
          onClick={() => navigate('/login')}
          disabled={isLoading}
        >
          既にアカウントをお持ちの方はこちら
        </Button>
      </Box>
    </Paper>
  );
};

export default RegisterForm;
```

### 5. タスク管理コンポーネントの実装

#### TaskList.tsx

```typescript
// src/components/tasks/TaskList.tsx
import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  Paper, 
  List, 
  ListItem, 
  ListItemText, 
  Chip, 
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  CircularProgress
} from '@mui/material';
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { Task } from '../../interfaces';
import taskService from '../../services/taskService';

const TaskList: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [taskToDelete, setTaskToDelete] = useState<Task | null>(null);
  
  const navigate = useNavigate();

  useEffect(() => {
    const fetchTasks = async () => {
      try {
        setLoading(true);
        const data = await taskService.getAllTasks();
        setTasks(data);
        setError(null);
      } catch (err) {
        console.error('Error fetching tasks:', err);
        setError('タスクの取得に失敗しました。');
      } finally {
        setLoading(false);
      }
    };

    fetchTasks();
  }, []);

  const handleAddTask = () => {
    navigate('/tasks/new');
  };

  const handleEditTask = (taskId: number) => {
    navigate(`/tasks/${taskId}/edit`);
  };

  const handleDeleteClick = (task: Task) => {
    setTaskToDelete(task);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    if (!taskToDelete) return;
    
    try {
      await taskService.deleteTask(taskToDelete.id);
      setTasks(tasks.filter(task => task.id !== taskToDelete.id));
      setDeleteDialogOpen(false);
      setTaskToDelete(null);
    } catch (err) {
      console.error('Error deleting task:', err);
      setError('タスクの削除に失敗しました。');
    }
  };

  const handleDeleteCancel = () => {
    setDeleteDialogOpen(false);
    setTaskToDelete(null);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'TODO':
        return 'error';
      case 'IN_PROGRESS':
        return 'warning';
      case 'DONE':
        return 'success';
      default:
        return 'default';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'info';
      default:
        return 'default';
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ maxWidth: 800, mx: 'auto', mt: 4, px: 2 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          タスク一覧
        </Typography>
        <Button 
          variant="contained" 
          startIcon={<AddIcon />}
          onClick={handleAddTask}
        >
          新規タスク
        </Button>
      </Box>

      {error && (
        <Paper sx={{ p: 2, mb: 3, bgcolor: 'error.light', color: 'error.contrastText' }}>
          <Typography>{error}</Typography>
        </Paper>
      )}

      {tasks.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="body1">タスクがありません。新しいタスクを作成してください。</Typography>
        </Paper>
      ) : (
        <Paper elevation={2}>
          <List>
            {tasks.map((task, index) => (
              <React.Fragment key={task.id}>
                <ListItem 
                  alignItems="flex-start"
                  secondaryAction={
                    <Box>
                      <IconButton edge="end" aria-label="edit" onClick={() => handleEditTask(task.id)}>
                        <EditIcon />
                      </IconButton>
                      <IconButton edge="end" aria-label="delete" onClick={() => handleDeleteClick(task)}>
                        <DeleteIcon />
                      </IconButton>
                    </Box>
                  }
                  sx={{ py: 2 }}
                >
                  <ListItemText
                    primary={
                      <Typography variant="h6" component="div">
                        {task.title}
                      </Typography>
                    }
                    secondary={
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="body2" color="text.primary" sx={{ mb: 1 }}>
                          {task.description}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                          <Chip 
                            label={task.status} 
                            size="small" 
                            color={getStatusColor(task.status) as any}
                          />
                          <Chip 
                            label={`優先度: ${task.priority}`} 
                            size="small" 
                            color={getPriorityColor(task.priority) as any}
                          />
                          {task.dueDate && (
                            <Chip 
                              label={`期限: ${task.dueDate}`} 
                              size="small" 
                              variant="outlined"
                            />
                          )}
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
                {index < tasks.length - 1 && <div style={{ borderBottom: '1px solid #eee' }} />}
              </React.Fragment>
            ))}
          </List>
        </Paper>
      )}

      <Dialog
        open={deleteDialogOpen}
        onClose={handleDeleteCancel}
      >
        <DialogTitle>タスクの削除</DialogTitle>
        <DialogContent>
          <Typography>
            「{taskToDelete?.title}」を削除してもよろしいですか？この操作は元に戻せません。
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteCancel}>キャンセル</Button>
          <Button onClick={handleDeleteConfirm} color="error" autoFocus>
            削除
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default TaskList;
```

#### TaskForm.tsx

```typescript
// src/components/tasks/TaskForm.tsx
import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { 
  Box, 
  Typography, 
  Paper, 
  TextField, 
  Button, 
  FormControl, 
  InputLabel, 
  Select, 
  MenuItem, 
  FormHelperText,
  Alert,
  CircularProgress
} from '@mui/material';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { useForm, Controller } from 'react-hook-form';
import { Task, TaskRequest } from '../../interfaces';
import taskService from '../../services/taskService';

interface TaskFormInputs {
  title: string;
  description: string;
  status: 'TODO' | 'IN_PROGRESS' | 'DONE';
  priority: 'LOW' | 'MEDIUM' | 'HIGH';
  dueDate: Date | null;
}

const TaskForm: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const isEditMode = !!id;
  const navigate = useNavigate();
  
  const [loading, setLoading] = useState(isEditMode);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  
  const { control, handleSubmit, reset, formState: { errors } } = useForm<TaskFormInputs>({
    defaultValues: {
      title: '',
      description: '',
      status: 'TODO',
      priority: 'MEDIUM',
      dueDate: null
    }
  });

  useEffect(() => {
    const fetchTask = async () => {
      if (!isEditMode) return;
      
      try {
        setLoading(true);
        const task = await taskService.getTaskById(Number(id));
        
        reset({
          title: task.title,
          description: task.description,
          status: task.status,
          priority: task.priority,
          dueDate: task.dueDate ? new Date(task.dueDate) : null
        });
        
        setError(null);
      } catch (err) {
        console.error('Error fetching task:', err);
        setError('タスクの取得に失敗しました。');
      } finally {
        setLoading(false);
      }
    };

    fetchTask();
  }, [id, isEditMode, reset]);

  const onSubmit = async (data: TaskFormInputs) => {
    setSubmitting(true);
    setError(null);
    
    try {
      const taskData: TaskRequest = {
        title: data.title,
        description: data.description,
        status: data.status,
        priority: data.priority,
        dueDate: data.dueDate ? data.dueDate.toISOString().split('T')[0] : undefined,
        assigneeIds: []
      };
      
      if (isEditMode) {
        await taskService.updateTask(Number(id), taskData);
      } else {
        await taskService.createTask(taskData);
      }
      
      navigate('/tasks');
    } catch (err) {
      console.error('Error saving task:', err);
      setError(`タスクの${isEditMode ? '更新' : '作成'}に失敗しました。`);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ maxWidth: 600, mx: 'auto', mt: 4, px: 2 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        {isEditMode ? 'タスクの編集' : '新規タスク作成'}
      </Typography>
      
      {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}
      
      <Paper elevation={2} sx={{ p: 3 }}>
        <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
          <Controller
            name="title"
            control={control}
            rules={{ required: 'タイトルは必須です' }}
            render={({ field }) => (
              <TextField
                {...field}
                margin="normal"
                required
                fullWidth
                id="title"
                label="タイトル"
                autoFocus
                error={!!errors.title}
                helperText={errors.title?.message}
                disabled={submitting}
              />
            )}
          />
          
          <Controller
            name="description"
            control={control}
            render={({ field }) => (
              <TextField
                {...field}
                margin="normal"
                fullWidth
                id="description"
                label="説明"
                multiline
                rows={4}
                error={!!errors.description}
                helperText={errors.description?.message}
                disabled={submitting}
              />
            )}
          />
          
          <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
            <Controller
              name="status"
              control={control}
              rules={{ required: 'ステータスは必須です' }}
              render={({ field }) => (
                <FormControl fullWidth error={!!errors.status} disabled={submitting}>
                  <InputLabel id="status-label">ステータス</InputLabel>
                  <Select
                    {...field}
                    labelId="status-label"
                    id="status"
                    label="ステータス"
                  >
                    <MenuItem value="TODO">TODO</MenuItem>
                    <MenuItem value="IN_PROGRESS">IN_PROGRESS</MenuItem>
                    <MenuItem value="DONE">DONE</MenuItem>
                  </Select>
                  {errors.status && <FormHelperText>{errors.status.message}</FormHelperText>}
                </FormControl>
              )}
            />
            
            <Controller
              name="priority"
              control={control}
              rules={{ required: '優先度は必須です' }}
              render={({ field }) => (
                <FormControl fullWidth error={!!errors.priority} disabled={submitting}>
                  <InputLabel id="priority-label">優先度</InputLabel>
                  <Select
                    {...field}
                    labelId="priority-label"
                    id="priority"
                    label="優先度"
                  >
                    <MenuItem value="LOW">LOW</MenuItem>
                    <MenuItem value="MEDIUM">MEDIUM</MenuItem>
                    <MenuItem value="HIGH">HIGH</MenuItem>
                  </Select>
                  {errors.priority && <FormHelperText>{errors.priority.message}</FormHelperText>}
                </FormControl>
              )}
            />
          </Box>
          
          <Box sx={{ mt: 2 }}>
            <LocalizationProvider dateAdapter={AdapterDateFns}>
              <Controller
                name="dueDate"
                control={control}
                render={({ field }) => (
                  <DatePicker
                    label="期限日"
                    value={field.value}
                    onChange={(newValue) => field.onChange(newValue)}
                    disabled={submitting}
                    slotProps={{
                      textField: {
                        fullWidth: true,
                        margin: 'normal'
                      }
                    }}
                  />
                )}
              />
            </LocalizationProvider>
          </Box>
          
          <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
            <Button
              type="submit"
              variant="contained"
              disabled={submitting}
              sx={{ flex: 1 }}
            >
              {submitting ? '保存中...' : (isEditMode ? '更新' : '作成')}
            </Button>
            
            <Button
              variant="outlined"
              onClick={() => navigate('/tasks')}
              disabled={submitting}
              sx={{ flex: 1 }}
            >
              キャンセル
            </Button>
          </Box>
        </Box>
      </Paper>
    </Box>
  );
};

export default TaskForm;
```

### 6. レイアウトコンポーネントの実装

```typescript
// src/components/layout/Layout.tsx
import React from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { 
  AppBar, 
  Toolbar, 
  Typography, 
  Button, 
  Box, 
  Container,
  IconButton,
  Menu,
  MenuItem,
  Avatar
} from '@mui/material';
import { AccountCircle } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';

const Layout: React.FC = () => {
  const { currentUser, logout } = useAuth();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);

  const handleMenu = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    logout();
    handleClose();
    navigate('/login');
  };

  return (
    <>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            タスク管理アプリ
          </Typography>
          {currentUser ? (
            <div>
              <IconButton
                size="large"
                aria-label="account of current user"
                aria-controls="menu-appbar"
                aria-haspopup="true"
                onClick={handleMenu}
                color="inherit"
              >
                <AccountCircle />
              </IconButton>
              <Menu
                id="menu-appbar"
                anchorEl={anchorEl}
                anchorOrigin={{
                  vertical: 'top',
                  horizontal: 'right',
                }}
                keepMounted
                transformOrigin={{
                  vertical: 'top',
                  horizontal: 'right',
                }}
                open={Boolean(anchorEl)}
                onClose={handleClose}
              >
                <MenuItem disabled>
                  {currentUser.username}
                </MenuItem>
                <MenuItem onClick={handleLogout}>ログアウト</MenuItem>
              </Menu>
            </div>
          ) : (
            <Button color="inherit" onClick={() => navigate('/login')}>
              ログイン
            </Button>
          )}
        </Toolbar>
      </AppBar>
      <Container component="main" sx={{ mt: 4, mb: 4 }}>
        <Outlet />
      </Container>
    </>
  );
};

export default Layout;
```

### 7. アプリケーションのルーティング設定

```typescript
// src/App.tsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import { AuthProvider } from './contexts/AuthContext';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import LoginForm from './components/auth/LoginForm';
import RegisterForm from './components/auth/RegisterForm';
import TaskList from './components/tasks/TaskList';
import TaskForm from './components/tasks/TaskForm';
import PrivateRoute from './components/common/PrivateRoute';
import Layout from './components/layout/Layout';

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <LocalizationProvider dateAdapter={AdapterDateFns}>
        <AuthProvider>
          <Router>
            <Routes>
              <Route path="/login" element={<LoginForm />} />
              <Route path="/register" element={<RegisterForm />} />
              <Route path="/" element={<Layout />}>
                <Route index element={<Navigate to="/tasks" replace />} />
                <Route 
                  path="/tasks" 
                  element={
                    <PrivateRoute>
                      <TaskList />
                    </PrivateRoute>
                  } 
                />
                <Route 
                  path="/tasks/new" 
                  element={
                    <PrivateRoute>
                      <TaskForm />
                    </PrivateRoute>
                  } 
                />
                <Route 
                  path="/tasks/:id/edit" 
                  element={
                    <PrivateRoute>
                      <TaskForm />
                    </PrivateRoute>
                  } 
                />
              </Route>
            </Routes>
          </Router>
        </AuthProvider>
      </LocalizationProvider>
    </ThemeProvider>
  );
}

export default App;
```

## 統合とテスト

### 1. バックエンドの起動

```bash
cd task-manager/backend
./mvnw spring-boot:run
```

### 2. フロントエンドの起動

```bash
cd task-manager/frontend
npm run dev
```

### 3. 動作確認

1. ブラウザで `http://localhost:5173` にアクセス
2. 登録画面でユーザーを作成
3. ログイン
4. タスクの作成、編集、削除を試す

### 4. 統合テストのポイント

- CORS設定が正しく機能しているか
- JWT認証が正しく機能しているか
- ロールベースのアクセス制御が正しく機能しているか
- タスクのCRUD操作が正しく機能しているか

## 学習ポイント

### TypeScript学習ポイント

1. **型安全なプログラミング**
   - インターフェースを使用したデータモデルの定義
   - 型推論と型アサーションの活用
   - ジェネリクスの使用（例：APIレスポンスの型定義）

2. **Reactとの統合**
   - 関数コンポーネントと型付きprops
   - カスタムフックの型定義
   - コンテキストAPIの型安全な実装

3. **非同期処理**
   - Promise<T>の型定義
   - async/awaitの使用
   - エラーハンドリングの型安全な実装

4. **型安全なフォーム処理**
   - react-hook-formとTypeScriptの統合
   - フォーム入力の検証と型チェック

### Spring Security学習ポイント

1. **認証プロセス**
   - AuthenticationManagerの役割
   - UserDetailsServiceの実装
   - PasswordEncoderの使用

2. **JWT認証**
   - JWTの生成と検証
   - AuthenticationFilterの実装
   - トークンベースの認証フロー

3. **認可と権限制御**
   - ロールベースのアクセス制御（RBAC）
   - @PreAuthorizeアノテーションの使用
   - メソッドレベルのセキュリティ

4. **セキュリティコンテキスト**
   - SecurityContextHolderの使用
   - 認証済みユーザーの情報取得
   - セキュリティコンテキストの伝播

## 発展課題

このサンプルアプリケーションをベースに、以下の機能を追加してみましょう：

1. **パスワードリセット機能**
   - パスワードリセットメールの送信
   - トークンベースのパスワードリセット

2. **ユーザープロファイル管理**
   - プロファイル画像のアップロード
   - ユーザー情報の編集

3. **タスクの共有機能の強化**
   - タスクの共有設定UI
   - 共有ユーザーの検索と選択

4. **通知システム**
   - タスクの期限通知
   - メンション機能

5. **高度な認証機能**
   - 2要素認証
   - ソーシャルログイン連携

これらの発展課題に取り組むことで、TypeScriptとSpring Securityの理解をさらに深めることができます。
