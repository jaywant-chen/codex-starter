# Token Demo

Spring Boot 3.4.2 application demonstrating access and refresh token authentication with Spring Security.

## Building

```bash
mvn clean package
```

## Endpoints

* `POST /auth/login` – provide JSON `{ "username": "user", "password": "password" }` to receive `accessToken` and `refreshToken`.
* `POST /auth/refresh` – provide JSON `{ "refreshToken": "<token>" }` to receive a new `accessToken`.
