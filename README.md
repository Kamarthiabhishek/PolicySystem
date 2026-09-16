# PolicySystem — Auth Module

A secure, role-based authentication and user-management backend built for a multi-line insurance platform, using Spring Boot 4, Spring Security, and JWT. This module covers registration, login, token refresh, and admin-controlled role management (Customer / Agent / Admin).

## Features

- **User registration** with server-side validation (unique, case-insensitive email; password policy)
- **JWT-based login** — short-lived access token (HS256, 15 min) + opaque, server-stored refresh token (7 days)
- **Refresh token rotation** — each refresh invalidates the old token and issues a new one, limiting replay risk
- **Role-based access control** — `CUSTOMER`, `AGENT`, `ADMIN` enforced via `@PreAuthorize` at the method level
- **Admin user management** — paginated user listing (with role filter) and role updates, with a guard that blocks the last remaining admin from demoting themselves
- **Centralized error handling** — a `@RestControllerAdvice` global exception handler maps domain exceptions to one consistent JSON error shape
- **Stateless security** — no server-side sessions; CORS configured for a separate frontend origin
- **API documentation** — Swagger / OpenAPI UI generated automatically via springdoc
- **Versioned schema migrations** — Flyway manages the `users` and `refresh_tokens` tables

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 17 |
| Framework | Spring Boot 4 (Web, Security, Data JPA, Validation) |
| Database | PostgreSQL |
| Migrations | Flyway |
| Auth | Spring Security + JJWT (JSON Web Tokens, HS256) |
| Docs | springdoc-openapi (Swagger UI) |
| Build | Maven |
| Testing | JUnit 5, Mockito, Spring Boot Test, H2 (in-memory, for integration tests) |
| Boilerplate | Lombok |

## Architecture

```
com.policysystem.auth
 ├── controller/   AuthController, UserController
 ├── dto/          RegisterRequest, LoginRequest, AuthResponse, RefreshRequest, UserResponse, UpdateRoleRequest
 ├── entity/       User, RefreshToken, Role (enum)
 ├── repository/   UserRepository, RefreshTokenRepository
 ├── service/      AuthService, UserService
 ├── security/     JwtTokenProvider, JwtAuthFilter, SecurityConfig, TokenHasher, UserDetailsServiceImpl
 └── exception/    DuplicateEmailException, InvalidCredentialsException, InvalidTokenException, GlobalExceptionHandler
```

- **Controllers** stay thin — they delegate to services and never build error responses inline.
- **Services** hold business rules (duplicate-email checks, password hashing, self-demotion guard, token rotation).
- **`JwtAuthFilter`** (a `OncePerRequestFilter`) validates the `Authorization: Bearer <token>` header on every request and populates the `SecurityContext`.
- **Refresh tokens** are never stored in plaintext — only a hash (via `TokenHasher`), so a database leak doesn't expose usable tokens.

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Public | Register a new user (always created as `CUSTOMER`) |
| POST | `/api/v1/auth/login` | Public | Log in, receive access + refresh tokens |
| POST | `/api/v1/auth/refresh` | Public (refresh token in body) | Rotate refresh token, issue new access token |
| GET | `/api/v1/users/me` | Any authenticated user | Get the current user's profile |
| GET | `/api/v1/users` | `ADMIN` | Paginated list of users, optional `?role=` filter |
| PATCH | `/api/v1/users/{id}/role` | `ADMIN` | Change a user's role (blocks last-admin self-demotion) |

All errors are returned in a consistent shape:

```json
{
  "timestamp": "2026-08-18T10:15:30Z",
  "status": 400,
  "error": "VALIDATION_ERROR",
  "message": "Validation failed",
  "fieldErrors": [ { "field": "email", "message": "must be a valid, unique email" } ]
}
```

## Getting Started

### Prerequisites

- Java 17+
- Maven 3.9+ (or use the included `mvnw` wrapper)
- PostgreSQL 14+ running locally (or via Docker)

### Setup

1. Create a database and set your credentials via environment variables rather than editing `application.properties` directly:

   ```bash
   export JWT_SECRET=replace-with-a-long-random-secret
   export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/policysystem
   export SPRING_DATASOURCE_USERNAME=postgres
   export SPRING_DATASOURCE_PASSWORD=your-password
   ```

2. Run Flyway migrations automatically on startup, or manually with `./mvnw flyway:migrate`.

3. Start the application:

   ```bash
   ./mvnw spring-boot:run
   ```

4. The API is available at `http://localhost:8080`. Swagger UI is at `http://localhost:8080/swagger-ui.html`.

### Running Tests

```bash
./mvnw test
```

The test suite includes unit tests (service layer: duplicate-email rejection, password hashing, login paths, token expiry, self-demotion guard) and MockMvc integration tests (full register → login → `/me` → refresh flow; 401/403 on missing, invalid, or insufficiently privileged tokens) across 5 test classes.

## Security Notes

- Access tokens are short-lived (15 min) and should be kept in memory on the frontend, not `localStorage`.
- Refresh tokens are opaque UUIDs, stored server-side only as a hash, and rotated on every use.
- Passwords are hashed with BCrypt (strength 10) and never appear in responses or logs.
- **Before deploying or pushing this publicly:** move the database credentials out of `application.properties` and into environment variables or a secrets manager — the checked-in file currently has a local password hardcoded for development convenience.
- RS256 (asymmetric signing) is a natural production upgrade over the current HS256 symmetric secret if multiple services need to verify tokens without sharing the signing key.
