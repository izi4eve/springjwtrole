# springjwtrole — Java / Spring Boot Boilerplate 

Universal Spring Boot backend starter with authentication, JWT, roles and OAuth2.
**The hardest parts are already done** — drop this into any project and start writing business logic immediately.

---

## What's Already Implemented

This is not a tutorial sample but a **production-ready boilerplate** with real-world functionality:

- Registration via email with confirmation link
- Login / Logout — form-based with session handling
- OAuth2 login — Google (Facebook optional, one line in config)
- JWT authentication — for REST API (`/api/**`), ready for React and mobile clients
- User roles — `ROLE_REGISTERED`, `ROLE_MODERATOR`, `ROLE_ADMIN`
- User dashboard — change password, delete account
- Password recovery — email-based reset flow
- Superuser — configured via properties, auto-created on first launch
- Auto-deletion of unconfirmed accounts — via cron or manually from admin panel
- Admin panel — change user roles, manage accounts
- Multilingual support — English (default) + German
- Custom ErrorController — unified HTTP error handling
- Domain auto-detection — used in confirmation/reset email links

---

## React Frontend

A ready-made React/TypeScript login UI that connects to this backend via JWT:
→ [springjwtrole-front](https://github.com/izi4eve/springjwtrole-front)

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Java 21 |
| Framework | Spring Boot 3.4 |
| Security | Spring Security 6 + JWT (JJWT 0.12) + OAuth2 |
| Templates | Thymeleaf |
| Database | PostgreSQL 16 |
| ORM | Spring Data JPA / Hibernate 6 |
| Mail | Spring Boot Mail |
| Build | Maven |

---

## Quick Start (macOS / zsh)

### 1. Install prerequisites

```zsh
# Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Java 21
brew install openjdk@21
echo 'export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
java -version

# PostgreSQL
brew install postgresql@16
brew services start postgresql@16
```

### 2. Create the database

```zsh
psql postgres
```
```sql
CREATE DATABASE springjwtrole;
CREATE USER springuser WITH PASSWORD 'yourpassword';
GRANT ALL PRIVILEGES ON DATABASE springjwtrole TO springuser;
GRANT ALL ON SCHEMA public TO springuser;
\q
```

### 3. Clone the repository

```zsh
git clone https://github.com/izi4eve/springjwtrole.git
cd springjwtrole
```

### 4. Configure

```zsh
cp app.prop src/main/resources/application.properties
```

Open `src/main/resources/application.properties` and fill in your values.
The file is fully commented — follow the instructions inside.

Key things to set:
- `superuser.email` / `superuser.password` — your admin account
- `spring.datasource.*` — database connection
- `spring.mail.*` — SMTP for confirmation emails
- `app.jwt.secret` — generate with: `openssl rand -base64 32`
- `spring.security.oauth2.client.registration.google.*` — from Google Cloud Console

### 5. Run

**Via IntelliJ IDEA:**
Open the project folder → wait for Maven to load dependencies → run `SpringjwtroleApplication.java`

**Via terminal:**
```zsh
./mvnw spring-boot:run
```

Open: [http://localhost:8080](http://localhost:8080)

### 6. Verify JWT works

```zsh
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"YOUR_ADMIN_EMAIL","password":"YOUR_ADMIN_PASSWORD"}'
```

You should receive `accessToken` and `refreshToken` in the response.

---

## Project Structure

```
src/main/java/com/example/springjwtrole/
├── api/                   # REST controllers (/api/**)
│   └── AuthApiController  # POST /api/auth/login, /api/auth/refresh
├── config/                # SecurityConfig (JWT + Session chains), WebConfig (CORS, locale)
├── controller/            # Thymeleaf controllers (web UI pages)
├── dto/                   # Request/response objects
├── filter/                # LocaleFilter, JwtAuthFilter
├── model/                 # User, Role, ConfirmationToken
├── repository/            # JPA repositories
├── security/              # JwtTokenProvider, JwtAuthFilter
├── service/               # UserService, MailService, OAuth2, cleanup cron
└── util/                  # MessageUtil, LocaleContext
```

---

## Security Architecture

Two independent security filter chains run in parallel:

**Chain 1 — JWT (for `/api/**`)**
- Stateless, no session
- Bearer token required in `Authorization` header
- Used by React frontend and any API client

**Chain 2 — Session (for everything else)**
- Standard Spring Security session via `JSESSIONID` cookie
- Used by Thymeleaf pages, OAuth2 flow, form login

This means you can use both simultaneously — Thymeleaf for SEO pages, React for the app UI.

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | public | Returns `accessToken` + `refreshToken` |
| POST | `/api/auth/refresh` | public | Returns new `refreshToken` |
| GET | `/` | public | Home page (Thymeleaf) |
| GET | `/login` | public | Login page (Thymeleaf + OAuth2) |
| GET | `/register` | public | Registration page |
| GET | `/account` | REGISTERED | User dashboard |
| GET | `/admin/**` | ADMIN | Admin panel |

---

## OAuth2 Setup

### Google

1. Open [Google Cloud Console](https://console.cloud.google.com)
2. APIs & Services → Credentials → Create OAuth 2.0 Client ID
3. Application type: **Web application**
4. Authorized redirect URI: `http://localhost:8080/login/oauth2/code/google`
5. Copy Client ID and Secret to `application.properties`

### Facebook (optional)

1. Open [Facebook Developer Portal](https://developers.facebook.com/apps)
2. Create App → Settings → Basic → copy App ID and Secret
3. Facebook Login → Settings → add redirect URI: `http://localhost:8080/login/oauth2/code/facebook`

---

## Adding Your Own Logic

This project is a starter. To build your app on top:

1. Add REST controllers to `api/` for your business logic
2. Add Thymeleaf controllers to `controller/` for web pages
3. Add models to `model/` and repositories to `repository/`
4. Add new URL rules to `SecurityConfig.java`

Everything auth-related is already wired. You only write what's unique to your product.

---

## Production Checklist

Before deploying, update `application.properties`:

```properties
spring.jpa.show-sql=false
logging.level.org.springframework.web=INFO
logging.level.org.springframework.security=INFO
spring.mail.properties.mail.debug=false
spring.thymeleaf.cache=true
app.cors.origins=https://yourdomain.com
```

---

## Planned

- [ ] Docker + docker-compose
- [ ] Python AI microservice integration
- [ ] Stripe payments module
- [ ] AWS deployment guide

---

## License

For review and educational purposes only.
Practical or commercial use requires author's permission.