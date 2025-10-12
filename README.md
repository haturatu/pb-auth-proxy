# Auth Proxy

This is a simple authenticating reverse proxy written in Go. It provides a flexible authentication layer that can be placed in front of any backend web service.

It handles user registration, login, and session management, and proxies authenticated requests to the configured backend. It also includes an administration dashboard for user management.

## Features

- **Authentication**: Provides login, logout, and registration pages.
- **Reverse Proxy**: Proxies authenticated users to a backend service.
- **Admin Dashboard**: A simple UI to manage users (update roles, activate/deactivate, delete).
- **Flexible Database Support**: Works with PostgreSQL, MySQL, and SQLite.
- **Security Hardening**:
    - **Brute-force Protection**: Locks user accounts after a configurable number of failed login attempts.
    - **User Creation Rate Limiting**: Prevents the same IP from creating too many users in a short period.
    - **Configurable Password Policies**: Enforce password strength requirements. See details below.
    - **Secure Session Cookies**: Uses `HttpOnly` secure cookies for session management.
- **Highly Configurable**: Nearly all aspects, including database connections, security policies, and internal URL paths, can be configured via an `.env` file.
- **Structured Logging**: Detailed application and security logs using `slog`.
- **CLI for Admin Creation**: A command-line tool to easily create initial admin users.

### Password Policies

The password strength requirements can be configured by setting the `PASSWORD_POLICY` variable in the `.env` file. The available levels are:

- **`none`**: No requirements. Any password is allowed.
- **`standard`** (Default): A minimum length of 6 characters is required.
- **`enhanced`**: A minimum length of 8 characters is required. The password must contain at least one of each of the following: an uppercase letter, a lowercase letter, a number, and a symbol (e.g., `!@#$%^&*`).
- **`strict`**: A minimum length of 12 characters is required. The password must meet the same complexity requirements as `enhanced` (uppercase, lowercase, number, and symbol).

## Getting Started

### Prerequisites

- Go 1.21 or later
- (Optional) PostgreSQL or MySQL database server.

### Installation

1.  **Clone the repository:**
    ```sh
    git clone <repository-url>
    cd auth-proxy
    ```

2.  **Install dependencies:**
    ```sh
    go mod tidy
    ```

3.  **Build the binaries:**
    ```sh
    go build -o auth-proxy-server ./cmd/server && go build -o admin-cli ./cmd/admin-cli
    ```

### Configuration

Configuration is managed via a `.env` file in the root of the project. Create a file named `.env` and add the necessary variables.

**Example `.env` file:**

```dotenv
# --- Required --- 
# The URL of the backend service you want to protect
TARGET_URL=http://localhost:8081

# A long, random string for securing session cookies
# For production, generate a new key using: openssl rand -base64 45
SESSION_SECRET=my-super-secret-key

# --- Database --- 
# Use ONE of the following options:

# Option 1: PostgreSQL or MySQL (Recommended)
# Example: postgres://user:password@host:port/dbname?sslmode=disable
# Example: mysql://user:password@tcp(host:port)/dbname?charset=utf8mb4&parseTime=true
DATABASE_URL=mysql://test:test@127.0.0.1:3306/auth

# Option 2: SQLite (Default if DATABASE_URL is not set)
# DATABASE_PATH=./auth.db

# --- Security Policies --- 

# Brute-force protection settings
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=10

# User creation rate limit settings
USER_CREATION_RATE_LIMIT_MAX_REQUESTS=5
USER_CREATION_RATE_LIMIT_WINDOW_SECONDS=3600

# Password policy (none, standard, enhanced, strict)
PASSWORD_POLICY=standard

# --- Optional: Path Overrides ---
# Uncomment and change these to avoid URL conflicts with your backend application.
# AUTH_PATH_LOGIN=/login
# AUTH_PATH_REGISTER=/register
# AUTH_PATH_LOGOUT=/logout
# AUTH_PATH_ACCOUNT=/account
# AUTH_PATH_ACCOUNT_PASSWORD=/account/password
# AUTH_PATH_ADMIN=/admin
# AUTH_PATH_ADMIN_USERS_API=/api/admin/users
# AUTH_ASSETS_PATH=/auth-proxy-assets
```

### Database Setup Examples

If you are using PostgreSQL or MySQL, you will need to create a database and a user for the proxy.

#### PostgreSQL

Run these commands in `psql`:

```sql
-- Create a dedicated database
CREATE DATABASE auth_proxy;

-- Create a dedicated user
CREATE USER auth_user WITH PASSWORD 'your_strong_password';

-- Grant privileges on the database to the user
GRANT ALL PRIVILEGES ON DATABASE auth_proxy TO auth_user;
```

Your `DATABASE_URL` in the `.env` file would then be:
`DATABASE_URL=postgres://auth_user:your_strong_password@localhost:5432/auth_proxy?sslmode=disable`

#### MySQL / MariaDB

Run these commands in the MySQL client:

```sql
-- Create a dedicated database
CREATE DATABASE auth_proxy CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create a dedicated user
CREATE USER 'auth_user'@'localhost' IDENTIFIED BY 'your_strong_password';

-- Grant privileges on the database to the user
GRANT ALL PRIVILEGES ON auth_proxy.* TO 'auth_user'@'localhost';

-- Apply the changes
FLUSH PRIVILEGES;
```

Your `DATABASE_URL` in the `.env` file would then be:
`DATABASE_URL=mysql://auth_user:your_strong_password@tcp(127.0.0.1:3306)/auth_proxy?parseTime=true`

## Usage

1.  **Create an Admin User**:

    Before starting the server, create your first admin user using the `admin-cli` tool. Make sure your `.env` file is configured correctly, as the CLI uses it to connect to the database.

    The `--username` and `--password` flags are required.

    *Successful command:*
    ```sh
    ./admin-cli --username <your-admin-username> --password <your-strong-password>
    ```

    *Example of missing flags:*
    ```sh
    $ ./admin-cli 
    time=2025-10-12T04:28:09.014+09:00 level=ERROR msg="Both --username and --password flags are required"
    ```

2.  **Run the Proxy Server**:

    ```sh
    ./auth-proxy-server
    ```

    The server will start on port `:8080` by default.

3.  **Access the Application**:

    - Open your browser and navigate to `http://localhost:8080`.
    - You will be redirected to the login page.
    - Log in with the admin credentials you created.
    - Once authenticated, you will be seamlessly proxied to the `TARGET_URL`.
    - You can access the admin dashboard at `http://localhost:8080/admin` (or your configured path).

## Issuing API Tokens (Bearer Tokens)

In addition to session-based authentication for web browsers, the proxy can issue JWT (JSON Web Tokens) for programmatic API access. These tokens can be used as Bearer Tokens in the `Authorization` header to authenticate requests to protected backend APIs.

To obtain an access token and a refresh token, send a `POST` request to the `/api/auth/token` endpoint with the user's credentials in the JSON body.

**Example using `curl`:**

```sh
curl -X POST -H "Content-Type: application/json" -d '{
  "username": "your-username",
  "password": "your-password"
}' http://localhost:8080/api/auth/token
```

**Successful Response:**

If the credentials are valid, the server will respond with a JSON object containing an `access_token` and a `refresh_token`.

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE2Njc4OTg5ODl9.abcdef123456...",
  "refresh_token": "def456..."
}
```

The `access_token` is a short-lived JWT that should be sent in the `Authorization` header for API requests:

```
Authorization: Bearer <access_token>
```

The `refresh_token` is a long-lived token that can be used to obtain a new access token once the old one expires. To do this, send a `POST` request to the `/auth/refresh` endpoint.

**Note:** The token lifetimes (`ACCESS_TOKEN_DURATION_MINUTES`, `REFRESH_TOKEN_DURATION_DAYS`) can be configured in your `.env` file.

## Configuration Details

| Environment Variable                      | Description                                                                                                                            | Default Value          |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| `TARGET_URL`                              | **(Required)** The URL of the backend service to proxy to.                                                                             | -                      |
| `SESSION_SECRET`                          | **(Required)** A long, random secret key for encrypting session cookies.                                                               | `default-secret-key-for-dev` |
| `DATABASE_URL`                            | The connection string for PostgreSQL or MySQL. If set, this overrides `DATABASE_PATH`.                                                 | -                      |
| `DATABASE_PATH`                           | The file path for the SQLite database. Used only if `DATABASE_URL` is not set.                                                         | `./auth.db`            |
| `MAX_LOGIN_ATTEMPTS`                      | Number of failed login attempts before an account is locked.                                                                           | `5`                    |
| `LOCKOUT_DURATION_MINUTES`                | Duration in minutes for how long an account remains locked.                                                                            | `10`                   |
| `USER_CREATION_RATE_LIMIT_MAX_REQUESTS`   | Max number of user registrations allowed from a single IP within the time window.                                                      | `5`                    |
| `USER_CREATION_RATE_LIMIT_WINDOW_SECONDS` | The time window in seconds for the user creation rate limit.                                                                           | `3600` (1 hour)        |
| `PASSWORD_POLICY`                         | Sets the password strength requirements. See the "Password Policies" section for details.                                        | `standard`             |
| `AUTH_PATH_*`                             | A set of variables to customize the internal URLs for login, admin, etc., to prevent conflicts with the backend. See `.env` example. | Various, e.g., `/login`|
| `AUTH_ASSETS_PATH`                        | The URL path for serving internal static assets (CSS, JS).                                                                             | `/auth-proxy-assets`   |

