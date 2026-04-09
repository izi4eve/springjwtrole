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

```zsh
# Install Java 21 (LTS)
brew install openjdk@21
echo 'export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Verify installation
java -version
```

***

### 2. Install IntelliJ IDEA

Download manually: [https://www.jetbrains.com/idea/download](https://www.jetbrains.com/idea/download)  
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
GRANT ALL ON SCHEMA public TO springuser;
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

## OAuth2 Login Setup

### Google Sign-in

1. Open [Google Cloud Console](https://console.cloud.google.com/).
2. Select or create a project.
3. Navigate to **APIs & Services → Credentials**.
4. Click **Create Credentials → OAuth 2.0 Client ID**.
5. Choose **Application Type: Web application**.
6. Under **Authorized redirect URIs**, add: http://localhost:8080/login/oauth2/code/google
7. Copy the generated **Client ID** and **Client Secret** into your `application.properties`:

```properties
spring.security.oauth2.client.registration.google.client-id=YOUR_GOOGLE_CLIENT_ID
spring.security.oauth2.client.registration.google.client-secret=YOUR_GOOGLE_CLIENT_SECRET
```

> **Note:** For production, replace `localhost` with your actual domain and add the corresponding redirect URI.

### Facebook Login

1. Go to [Facebook Developer Portal → My Apps](https://developers.facebook.com/apps/).
2. Click **Create App** → **Business** → **Website** (or choose an existing app).
3. In the left menu, go to **Settings → Basic**.
4. Copy:
    - **App ID** to `spring.security.oauth2.client.registration.facebook.client-id`
    - **App Secret** (click **Show** if needed) to `spring.security.oauth2.client.registration.facebook.client-secret`
5. In the **Facebook Login → Settings** section, add the redirect URI: http://localhost:8080/login/oauth2/code/facebook
6. Save changes.

**Optional note in README (up to you):**

> **Note:** Facebook OAuth2 does not require additional payment, but you must comply with Facebook’s app review and usage policies. For most simple projects, this is free.

### Apple Sign in (iCloud)

1. Join the [Apple Developer Program](https://developer.apple.com/programs/) (paid membership required, ~$99/year).
2. Open **App Store Connect** → **Certificates, Identifiers & Profiles** → **Identifiers** → **App IDs**.
3. Register a new **App ID** and enable **Sign in with Apple**.
4. Next, create a **Service ID** with **Sign in with Apple** enabled.
5. Generate a **Private Key** (.p8 file) and store it securely (it is used to construct the JWT‑based `client-secret`).
6. Your `client-id` is the **Service ID**.
7. Configure your `application.properties` as follows:

```properties
spring.security.oauth2.client.registration.apple.client-id=YOUR_APPLE_SERVICE_ID
spring.security.oauth2.client.registration.apple.client-secret=YOUR_APPLE_CLIENT_SECRET_FROM_JWT
spring.security.oauth2.client.registration.apple.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}
spring.security.oauth2.client.registration.apple.scope=openid,email
spring.security.oauth2.client.provider.apple.authorization-uri=https://appleid.apple.com/auth/authorize
spring.security.oauth2.client.provider.apple.token-uri=https://appleid.apple.com/auth/token
spring.security.oauth2.client.provider.apple.user-name-attribute=sub
```

> **Note:** Apple Sign in requires a paid Apple Developer account and is optional. Skip this section if you only want to test Google/Facebook OAuth2 locally.

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
