# Auth Module — Build Instructions

Scope: user registration, login, JWT issuance/refresh, and role-based access control (Customer/Agent/Admin) for the Multi-Line Insurance Platform. This is Sprint 1's backend core — see `insurance-app-design-document.md` for how it fits the rest of the system.

---

## 1. Module Scope

**In scope:**
- User registration (email/password)
- Login → access token + refresh token
- Token refresh
- "Get current user" (`/me`)
- Role-based endpoint authorization (Customer / Agent / Admin)
- Admin: list users, change a user's role

**Out of scope (not this module):**
- Email verification / password reset flows
- OAuth/social login
- Account lockout after failed attempts (note as a future hardening item)

---

## 2. Data Model

### `users` table

| Column | Type | Constraints |
|---|---|---|
| id | BIGINT | PK, AUTO_INCREMENT |
| name | VARCHAR(150) | NOT NULL |
| email | VARCHAR(255) | NOT NULL, UNIQUE |
| password_hash | VARCHAR(255) | NOT NULL |
| role | ENUM('CUSTOMER','AGENT','ADMIN') | NOT NULL, DEFAULT 'CUSTOMER' |
| created_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP |

Flyway migration: `V1__create_users_table.sql`.

### Refresh tokens

Store refresh tokens server-side in a `refresh_tokens` table (don't rely solely on client-held long-lived tokens):

| Column | Type | Constraints |
|---|---|---|
| id | BIGINT | PK, AUTO_INCREMENT |
| user_id | BIGINT | NOT NULL, FK → users(id) |
| token_hash | VARCHAR(255) | NOT NULL, UNIQUE — store a hash, never the raw token |
| expires_at | TIMESTAMP | NOT NULL |
| revoked | BOOLEAN | NOT NULL, DEFAULT FALSE |
| created_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP |

This lets logout / "revoke all sessions" actually work, which a stateless-only JWT refresh can't do.

---

## 3. Package Structure

```
com.insuranceapp.auth
 ├── controller/AuthController.java
 ├── controller/UserController.java
 ├── dto/RegisterRequest.java
 ├── dto/LoginRequest.java
 ├── dto/AuthResponse.java
 ├── dto/RefreshRequest.java
 ├── dto/UserResponse.java
 ├── dto/UpdateRoleRequest.java
 ├── entity/User.java
 ├── entity/RefreshToken.java
 ├── entity/Role.java (enum)
 ├── repository/UserRepository.java
 ├── repository/RefreshTokenRepository.java
 ├── service/AuthService.java
 ├── service/UserService.java
 ├── security/JwtTokenProvider.java
 ├── security/JwtAuthFilter.java
 ├── security/SecurityConfig.java
 └── exception/ (DuplicateEmailException, InvalidCredentialsException, InvalidTokenException)
```

---

## 4. Endpoints

### `POST /api/v1/auth/register`
**Auth:** none (public)
**Request:**
```json
{ "name": "Jane Doe", "email": "jane@example.com", "password": "SecurePass1!" }
```
**Response `201`:**
```json
{ "id": 1, "name": "Jane Doe", "email": "jane@example.com", "role": "CUSTOMER" }
```
**Rules:** email unique (case-insensitive), password min 8 chars with at least 1 letter + 1 number, role always defaults to `CUSTOMER` (never accept role from the client here).

### `POST /api/v1/auth/login`
**Auth:** none (public)
**Request:** `{ "email": "...", "password": "..." }`
**Response `200`:**
```json
{
  "accessToken": "eyJ...",
  "refreshToken": "d290f1ee-...",
  "expiresIn": 900,
  "user": { "id": 1, "name": "Jane Doe", "email": "jane@example.com", "role": "CUSTOMER" }
}
```
**Rules:** generic `401 Invalid credentials` for both "no such user" and "wrong password" — never reveal which.

### `POST /api/v1/auth/refresh`
**Auth:** none (refresh token in body)
**Request:** `{ "refreshToken": "..." }`
**Response `200`:** new `accessToken` (+ optionally a rotated `refreshToken`)
**Rules:** reject if token is expired, revoked, or not found (hash lookup). Rotating the refresh token on each use is recommended (invalidate old, issue new) to limit replay risk.

### `GET /api/v1/users/me`
**Auth:** any authenticated role
**Response `200`:** current user's profile (no password hash).

### `GET /api/v1/users` *(Admin only)*
**Auth:** `ADMIN`
**Response:** paginated list of users (`?page=&size=&role=`).

### `PATCH /api/v1/users/{id}/role` *(Admin only)*
**Auth:** `ADMIN`
**Request:** `{ "role": "AGENT" }`
**Rules:** admin cannot demote themselves as the last remaining admin (guard against lockout) — check count of `ADMIN` users before allowing.

---

## 5. JWT Design

- **Algorithm:** HS256 (symmetric secret is fine for this project's scale; note RS256 as the production-grade alternative in the README).
- **Access token claims:** `sub` (user id), `email`, `role`, `iat`, `exp`.
- **Access token expiry:** 15 minutes.
- **Refresh token:** opaque UUID (not a JWT), 7-day expiry, stored hashed server-side as above.
- **Secret:** from environment variable (`JWT_SECRET`), never hardcoded or committed.
- **Header:** `Authorization: Bearer <accessToken>`.

---

## 6. Security Configuration

- `PasswordEncoder`: `BCryptPasswordEncoder` (strength 10).
- `SecurityFilterChain`:
  - Public: `/api/v1/auth/**`, `/swagger-ui/**`, `/v3/api-docs/**`
  - Authenticated: everything else
  - Method-level: `@PreAuthorize("hasRole('ADMIN')")` on admin-only endpoints
- `JwtAuthFilter` (extends `OncePerRequestFilter`): parses `Authorization` header, validates signature + expiry, loads `UserDetails`, sets `SecurityContext`.
- CORS: allow the frontend's dev (`http://localhost:3000`) and deployed origin only; allow credentials if using cookies for refresh token (recommended over localStorage — see section 8).
- CSRF: disabled (stateless JWT API), but note that means the frontend must not rely on cookies for the *access* token without CSRF protection — access token in memory, refresh token as httpOnly cookie is the safer combo.

---

## 7. Error Response Shape (module-wide standard)

```json
{
  "timestamp": "2026-08-18T10:15:30Z",
  "status": 400,
  "error": "VALIDATION_ERROR",
  "message": "Email already registered",
  "fieldErrors": [ { "field": "email", "message": "must be a valid, unique email" } ]
}
```
Handled centrally in `GlobalExceptionHandler` (`@RestControllerAdvice`) — this module should throw domain exceptions (`DuplicateEmailException`, `InvalidCredentialsException`, `InvalidTokenException`) and let the global handler map them to this shape, not build responses inline in controllers.

---

## 8. Frontend Contract Notes

- Store access token in memory (React state/context), **not** `localStorage` (XSS exposure). Refresh token as httpOnly, secure cookie if backend sets it; otherwise memory + refresh-on-load with a `/refresh` call.
- On `401` with an expired access token, frontend should silently call `/refresh` once and retry the original request before forcing logout.
- Role from `user.role` in the login/refresh response drives which dashboard/routes render — don't trust decoded JWT claims on the frontend for anything security-sensitive; they're for UI convenience only.

---

## 9. Testing Requirements

- **Unit (service layer):** registration duplicate-email rejection, password hashing applied, login success/failure paths, token expiry validation, role-change self-demotion guard.
- **Integration (MockMvc):** register → login → access `/me` with token → refresh → access `/me` with new token; 401 on missing/invalid/expired token; 403 on role mismatch for admin endpoints.
- **Security tests:** confirm passwords never appear in any response payload or log line.

---

## 10. Definition of Done

- [ ] `users` + `refresh_tokens` tables created via Flyway migration
- [ ] Register, login, refresh, `/me` endpoints working end-to-end
- [ ] Role-based `@PreAuthorize` enforced on admin endpoints, verified by integration test
- [ ] Global exception handler returns the standard error shape for all auth failures
- [ ] Swagger docs show all endpoints with example payloads
- [ ] No secrets committed; `JWT_SECRET` read from env
- [ ] Unit + integration tests passing
