# Spring Security 学習ガイド

このガイドでは、Spring Securityの基本から応用までを体系的に学ぶための情報を提供します。特にRESTful APIのセキュリティ実装やJWT認証に焦点を当て、実際のWebアプリケーション開発におけるSpring Securityの活用方法を解説します。

## 目次

1. [Spring Securityの基本](#spring-securityの基本)
2. [認証と認可](#認証と認可)
3. [Spring Security設定](#spring-security設定)
4. [JWT認証の実装](#jwt認証の実装)
5. [ロールベースのアクセス制御](#ロールベースのアクセス制御)
6. [セキュリティテスト](#セキュリティテスト)
7. [Spring Securityのベストプラクティス](#spring-securityのベストプラクティス)
8. [発展トピック](#発展トピック)
9. [学習リソース](#学習リソース)

## Spring Securityの基本

### Spring Securityとは

Spring Securityは、Javaアプリケーション向けの強力な認証・認可フレームワークです。Spring Frameworkの一部として、包括的なセキュリティ機能を提供し、Webアプリケーション、RESTful API、マイクロサービスなど様々なアプリケーションタイプに対応しています。

### Spring Securityの主な機能

- **認証（Authentication）**: ユーザーが本人であることを確認するプロセス
- **認可（Authorization）**: 認証されたユーザーが特定のリソースにアクセスする権限を持っているかを確認するプロセス
- **保護機能**: CSRF対策、セッション管理、HTTPSの強制など
- **統合機能**: LDAP、OAuth、SAML、JWTなど様々な認証メカニズムとの統合

### Spring Securityのアーキテクチャ

Spring Securityのアーキテクチャは、以下の主要コンポーネントで構成されています：

1. **SecurityContextHolder**: 現在認証されているユーザーの詳細を保持
2. **Authentication**: ユーザーの認証情報を表現するインターフェース
3. **AuthenticationManager**: 認証プロセスを処理するインターフェース
4. **UserDetailsService**: ユーザー情報を取得するためのインターフェース
5. **PasswordEncoder**: パスワードのエンコード・検証を行うインターフェース
6. **SecurityFilterChain**: HTTPリクエストに対するセキュリティフィルタのチェーン

### 開発環境のセットアップ

Spring Securityを使用するには、以下の依存関係をプロジェクトに追加します：

```xml
<!-- Maven -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

または

```groovy
// Gradle
implementation 'org.springframework.boot:spring-boot-starter-security'
```

## 認証と認可

### 認証プロセス

Spring Securityの認証プロセスは以下のステップで行われます：

1. ユーザーがリクエストを送信
2. AuthenticationFilterがリクエストを受け取り、認証情報を抽出
3. AuthenticationManagerに認証を委譲
4. AuthenticationProviderが認証を処理
5. UserDetailsServiceがユーザー情報を取得
6. PasswordEncoderがパスワードを検証
7. 認証成功時、SecurityContextHolderに認証情報が保存される

### UserDetailsServiceの実装

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        
        return UserDetailsImpl.build(user);
    }
}
```

### UserDetailsの実装

```java
public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;
    
    private Long id;
    private String username;
    private String email;
    
    @JsonIgnore
    private String password;
    
    private Collection<? extends GrantedAuthority> authorities;
    
    public UserDetailsImpl(Long id, String username, String email, String password,
                          Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }
    
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
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
    
    // UserDetailsインターフェースの他のメソッドを実装
    // ...
}
```

### パスワードエンコーディング

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

## Spring Security設定

### 基本的なセキュリティ設定

Spring Boot 3.0以降では、WebSecurityConfigurerAdapterが非推奨となり、代わりにSecurityFilterChainを使用します：

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> 
                auth.requestMatchers("/api/auth/**").permitAll()
                    .requestMatchers("/api/test/**").permitAll()
                    .anyRequest().authenticated()
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        
        return http.build();
    }
    
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
```

### CORS設定

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
    configuration.setAllowCredentials(true);
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

### CSRF保護

CSRF（Cross-Site Request Forgery）保護は、Webアプリケーションのセキュリティを強化するために重要です。RESTful APIでは、通常はステートレスな性質からCSRF保護を無効にすることがありますが、必要に応じて有効にできます：

```java
http
    .csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    );
```

## JWT認証の実装

### JWTとは

JWT（JSON Web Token）は、当事者間で情報を安全にJSONオブジェクトとして転送するためのコンパクトで自己完結型の方法です。この情報は、デジタル署名されているため、検証および信頼できます。

### JWT依存関係の追加

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
```

### JWTユーティリティクラス

```java
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

### JWT認証フィルター

```java
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;
    
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    
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
        String headerAuth = request.getHeader("Authorization");
        
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        
        return null;
    }
}
```

### 認証エントリーポイント

```java
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

### JWT認証コントローラー

```java
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
    
    @PostMapping("/signin")
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
    
    @PostMapping("/signup")
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
        User user = new User(signUpRequest.getUsername(),
                            signUpRequest.getEmail(),
                            encoder.encode(signUpRequest.getPassword()));
        
        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();
        
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        
        user.setRoles(roles);
        userRepository.save(user);
        
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
```

## ロールベースのアクセス制御

### ロールの定義

```java
public enum ERole {
    ROLE_USER,
    ROLE_MODERATOR,
    ROLE_ADMIN
}
```

```java
@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;
    
    // getters and setters
}
```

### メソッドレベルのセキュリティ

メソッドレベルのセキュリティを有効にするには、`@EnableMethodSecurity`アノテーションを使用します：

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
    // ...
}
```

そして、コントローラーメソッドに`@PreAuthorize`アノテーションを適用します：

```java
@RestController
@RequestMapping("/api/test")
public class TestController {
    
    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }
    
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }
    
    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }
    
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }
}
```

### カスタム権限評価

より複雑な認可ロジックが必要な場合は、カスタム権限評価を実装できます：

```java
@Component
public class TaskPermissionEvaluator implements PermissionEvaluator {
    
    @Autowired
    private TaskRepository taskRepository;
    
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if ((authentication == null) || (targetDomainObject == null) || !(permission instanceof String)) {
            return false;
        }
        
        Task task = (Task) targetDomainObject;
        String permissionString = (String) permission;
        
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        Long userId = userDetails.getId();
        
        switch (permissionString) {
            case "READ":
                return task.getOwnerId().equals(userId) || task.getAssigneeIds().contains(userId);
            case "WRITE":
                return task.getOwnerId().equals(userId);
            default:
                return false;
        }
    }
    
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if ((authentication == null) || (targetId == null) || !(targetId instanceof Long) || (targetType == null) || !(permission instanceof String)) {
            return false;
        }
        
        if (!targetType.equals("Task")) {
            return false;
        }
        
        Task task = taskRepository.findById((Long) targetId).orElse(null);
        if (task == null) {
            return false;
        }
        
        return hasPermission(authentication, task, permission);
    }
}
```

そして、メソッドで使用します：

```java
@GetMapping("/{id}")
@PreAuthorize("hasPermission(#id, 'Task', 'READ')")
public ResponseEntity<Task> getTask(@PathVariable Long id) {
    // ...
}

@PutMapping("/{id}")
@PreAuthorize("hasPermission(#id, 'Task', 'WRITE')")
public ResponseEntity<Task> updateTask(@PathVariable Long id, @RequestBody Task task) {
    // ...
}
```

## セキュリティテスト

### テスト依存関係の追加

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
</dependency>
```

### コントローラーのテスト

```java
@WebMvcTest(TestController.class)
public class TestControllerTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @MockBean
    private UserDetailsServiceImpl userDetailsService;
    
    @Test
    @WithMockUser(roles = "USER")
    public void testUserAccess() throws Exception {
        mockMvc.perform(get("/api/test/user"))
            .andExpect(status().isOk())
            .andExpect(content().string("User Content."));
    }
    
    @Test
    @WithMockUser(roles = "ADMIN")
    public void testAdminAccess() throws Exception {
        mockMvc.perform(get("/api/test/admin"))
            .andExpect(status().isOk())
            .andExpect(content().string("Admin Board."));
    }
    
    @Test
    @WithAnonymousUser
    public void testAnonymousAccess() throws Exception {
        mockMvc.perform(get("/api/test/user"))
            .andExpect(status().isUnauthorized());
    }
}
```

### JWT認証のテスト

```java
@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Test
    public void testAuthenticationFlow() throws Exception {
        // 1. Register a new user
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername("testuser");
        signupRequest.setEmail("test@example.com");
        signupRequest.setPassword("password123");
        
        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
            .andExpect(status().isOk());
        
        // 2. Login with the new user
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password123");
        
        MvcResult result = mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
            .andExpect(status().isOk())
            .andReturn();
        
        // 3. Extract JWT token from response
        String responseContent = result.getResponse().getContentAsString();
        JwtResponse jwtResponse = objectMapper.readValue(responseContent, JwtResponse.class);
        String token = jwtResponse.getToken();
        
        // 4. Access protected endpoint with JWT token
        mockMvc.perform(get("/api/test/user")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }
}
```

## Spring Securityのベストプラクティス

### セキュアなパスワード管理

1. **強力なパスワードエンコーダーを使用する**：BCryptPasswordEncoderは現在推奨されています。
   ```java
   @Bean
   public PasswordEncoder passwordEncoder() {
       return new BCryptPasswordEncoder(12); // ストレッチング係数を指定
   }
   ```

2. **パスワードポリシーを実装する**：
   ```java
   @Bean
   public PasswordValidator passwordValidator() {
       return new PasswordValidator(Arrays.asList(
           new LengthRule(8, 30),
           new UppercaseCharacterRule(1),
           new DigitCharacterRule(1),
           new SpecialCharacterRule(1)
       ));
   }
   ```

### HTTPS強制

```java
@Configuration
public class HttpsConfig {
    
    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {
            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };
        tomcat.addAdditionalTomcatConnectors(redirectConnector());
        return tomcat;
    }
    
    private Connector redirectConnector() {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("http");
        connector.setPort(8080);
        connector.setSecure(false);
        connector.setRedirectPort(8443);
        return connector;
    }
}
```

### セキュリティヘッダーの設定

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        // ...
        .headers(headers -> headers
            .frameOptions(frameOption -> frameOption.deny())
            .xssProtection(xss -> xss.enable())
            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
        );
    
    return http.build();
}
```

### レート制限の実装

```java
@Component
public class RateLimitFilter extends OncePerRequestFilter {
    
    private final RateLimiter rateLimiter = RateLimiter.create(10.0); // 10 requests per second
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        if (!rateLimiter.tryAcquire()) {
            response.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS);
            response.getWriter().write("Too many requests");
            return;
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### セキュリティ監査

```java
@Configuration
@EnableJpaAuditing
public class AuditConfig {
    
    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return Optional.of("anonymousUser");
            }
            return Optional.of(authentication.getName());
        };
    }
}
```

```java
@Entity
@EntityListeners(AuditingEntityListener.class)
public class AuditableEntity {
    
    @CreatedBy
    private String createdBy;
    
    @CreatedDate
    private Instant createdDate;
    
    @LastModifiedBy
    private String lastModifiedBy;
    
    @LastModifiedDate
    private Instant lastModifiedDate;
    
    // getters and setters
}
```

## 発展トピック

### OAuth 2.0とOpenID Connect

Spring Securityは、OAuth 2.0とOpenID Connectをサポートしています：

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

```java
@Configuration
@EnableWebSecurity
public class OAuth2LoginConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login/oauth2")
                .defaultSuccessUrl("/", true)
            );
        
        return http.build();
    }
}
```

### 多要素認証（MFA）

```java
@Configuration
@EnableWebSecurity
public class MfaSecurityConfig {
    
    @Autowired
    private MfaAuthenticationProvider mfaAuthenticationProvider;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/login", "/mfa/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            );
        
        return http.build();
    }
    
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(mfaAuthenticationProvider);
    }
}
```

### マイクロサービスのセキュリティ

マイクロサービスアーキテクチャでは、以下のようなセキュリティパターンが一般的です：

1. **APIゲートウェイ**：すべてのリクエストを一元管理し、認証・認可を処理
2. **トークンリレー**：サービス間通信でJWTトークンを転送
3. **サービス間認証**：相互TLSやクライアント証明書を使用

```java
@Configuration
@EnableWebSecurity
public class ResourceServerConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        
        return http.build();
    }
    
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }
}
```

### リアクティブセキュリティ

Spring WebFluxを使用するリアクティブアプリケーションでは、以下のようにセキュリティを設定します：

```java
@Configuration
@EnableWebFluxSecurity
public class ReactiveSecurityConfig {
    
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers("/api/auth/**").permitAll()
                .anyExchange().authenticated()
            )
            .httpBasic(withDefaults())
            .build();
    }
    
    @Bean
    public ReactiveUserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build();
        return new MapReactiveUserDetailsService(user);
    }
}
```

## 学習リソース

### 公式ドキュメント

- [Spring Security公式リファレンス](https://docs.spring.io/spring-security/reference/index.html)
- [Spring Security Architecture Guide](https://spring.io/guides/topicals/spring-security-architecture)
- [Spring Boot Security Auto-configuration](https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.security)

### 書籍

- 『Spring Security in Action』 by Laurentiu Spilca
- 『Spring Security - Third Edition』 by Mick Knutson

### オンラインコース

- [Baeldung - Spring Security Course](https://www.baeldung.com/security-spring)
- [Pluralsight - Spring Security Fundamentals](https://www.pluralsight.com/courses/spring-security-fundamentals)
- [Udemy - Spring Security Zero to Master](https://www.udemy.com/course/spring-security-zero-to-master/)

### ブログとチュートリアル

- [Baeldung - Spring Security Series](https://www.baeldung.com/security-spring)
- [Spring.io Guides - Securing a Web Application](https://spring.io/guides/gs/securing-web/)
- [DZone - Spring Security Tutorials](https://dzone.com/articles/spring-security-authentication)

### コミュニティとフォーラム

- [Stack Overflow - Spring Security](https://stackoverflow.com/questions/tagged/spring-security)
- [Spring Community Forums](https://community.spring.io/)
- [Spring Security GitHub](https://github.com/spring-projects/spring-security)

### サンプルプロジェクト

- [Spring Security Samples](https://github.com/spring-projects/spring-security-samples)
- [JWT Authentication with Spring Boot](https://github.com/bezkoder/spring-boot-spring-security-jwt-authentication)
- [OAuth2 Social Login](https://github.com/callicoder/spring-boot-react-oauth2-social-login-demo)
