# Spring Boot Auth Boilerplate

A complete authentication and authorization system built with **Java + Spring Boot** — a solid foundation for any web project. The hardest parts are already done.

## Features Implemented

This is not a tutorial sample but a **production‑ready boilerplate** with real‑world functionality that would normally take weeks to implement:

- **Registration via email** — with confirmation link  
- **Login / Logout** — standard form + session handling  
- **OAuth2 login** — Google and Facebook (just one line per provider in config)  
- **User roles** — `USER` / `ADMIN`, manageable through an admin panel  
- **User dashboard** — change password, delete account  
- **Password recovery** — email‑based reset  
- **Superuser** — configurable through properties (no database entry)  
- **Auto‑deletion** — unconfirmed accounts removed by cron or manually  
- **Multilingual support** — German (main for SEO) + English  
- **Custom ErrorController** — unified HTTP error handling  
- **Domain auto‑detection** — used in email links  

## Tech Stack

| Component | Technology |
|------------|-------------|
| Language | Java 21 |
| Framework | Spring Boot 3.3.x |
| Security | Spring Security 6 + OAuth2 |
| Templates | Thymeleaf + Thymeleaf Spring Security |
| Database | PostgreSQL |
| ORM | Spring Data JPA / Hibernate |
| Mail | Spring Boot Mail |
| Build Tool | Maven |

***

## Quick Start (macOS M1/M2/M3)

### 1. Install Required Tools

If you already have **Homebrew**, run:

```bash
# Java version manager (lets you switch multiple versions per project)
brew install sdkman

# Or install SDKMAN manually:
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"

# Install Java 21 (LTS)
sdk install java 21.0.3-tem

# Verify installation
java -version
```

**Why SDKMAN?**  
It allows you to keep multiple Java versions on the same machine and switch between them with  
`sdk use java <version>`. Essential when working on several projects.

***

### 2. Install IntelliJ IDEA

```bash
brew install --cask intellij-idea-ce
```

Or download manually: [https://www.jetbrains.com/idea/download](https://www.jetbrains.com/idea/download)  
(Community Edition — free)

***

### 3. Install PostgreSQL

```bash
brew install postgresql@16
brew services start postgresql@16
```

Create a database:

```sql
psql postgres
CREATE DATABASE springjwtrole;
CREATE USER springuser WITH PASSWORD 'yourpassword';
GRANT ALL PRIVILEGES ON DATABASE springjwtrole TO springuser;
\q
```

***

### 4. Clone the Repository

```bash
git clone https://github.com/izi4eve/springjwtrole.git
cd springjwtrole
```

***

### 5. Configure `application.properties`

An example config file `app.prop` is included. Copy it:

```bash
cp app.prop src/main/resources/application.properties
```

Then edit `src/main/resources/application.properties` with your values:

```properties
# Database
spring.datasource.url=jdbc:postgresql://localhost:5432/springjwtrole
spring.datasource.username=springuser
spring.datasource.password=yourpassword

# JPA
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=false

# Mail (example for Gmail)
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=your@gmail.com
spring.mail.password=your_app_password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true

# OAuth2 — Google
spring.security.oauth2.client.registration.google.client-id=YOUR_GOOGLE_CLIENT_ID
spring.security.oauth2.client.registration.google.client-secret=YOUR_GOOGLE_CLIENT_SECRET

# OAuth2 — Facebook
spring.security.oauth2.client.registration.facebook.client-id=YOUR_FACEBOOK_APP_ID
spring.security.oauth2.client.registration.facebook.client-secret=YOUR_FACEBOOK_APP_SECRET

# Superuser
app.superuser.email=admin@yourdomain.com

# Domain for email links
app.domain=http://localhost:8080
```

**Note:** `application.properties` is added to `.gitignore`, so your secrets will never be committed.

***

### 6. Run the Project

**Via IntelliJ IDEA:**
1. Open the project folder: `File → Open → springjwtrole`
2. Maven dependencies will load automatically (may take 1–2 minutes)
3. Find `SpringjwtroleApplication.java` under `src/main/java`
4. Click the green ▶ icon near the `main()` method

**Via terminal:**

```bash
./mvnw spring-boot:run
```

***

### 7. Verify

Open your browser and go to:  
[http://localhost:8080](http://localhost:8080)

***

## Connect Your GitHub Fork

To develop your own version:

```bash
# Fork the repo on GitHub, then clone your fork:
git clone https://github.com/YOUR_USERNAME/springjwtrole.git
cd springjwtrole

# Link the original repository for updates:
git remote add upstream https://github.com/izi4eve/springjwtrole.git
```

**Typical workflow:**
```bash
git add .
git commit -m "feat: describe your change"
git push origin master
```

***

## Get Google OAuth2 Credentials

1. Visit [https://console.cloud.google.com](https://console.cloud.google.com)  
2. Create a new project → *API & Services* → *Credentials* → *Create Credentials* → *OAuth Client ID*  
3. Application type: **Web application**  
4. Authorized redirect URIs:  
   `http://localhost:8080/login/oauth2/code/google`  
5. Copy your **Client ID** and **Client Secret** into `application.properties`

***

## Next Steps (Planned)

- [ ] JWT‑based authentication — for REST APIs (replace sessions with tokens)  
- [ ] REST API controllers — for React/mobile clients  
- [ ] Docker & docker‑compose — for deployment  
- [ ] Python AI service — as a microservice via REST API  
- [ ] AWS deployment — EC2 + RDS  

***

## License

For review and educational purposes only.  
Practical or commercial use requires author’s permission.
