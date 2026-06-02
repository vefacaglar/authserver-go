# Project Overview — Go OAuth2 / OIDC Auth Server

This document provides a high-level overview of the project architecture for developers coming from a .NET background. It maps Go concepts to their C# equivalents and explains why the codebase is structured the way it is.

---

## Table of Contents

- [Project Structure](#project-structure)
- [.NET to Go Concept Mapping](#net-to-go-concept-mapping)
- [Layered Architecture (Clean Architecture)](#layered-architecture-clean-architecture)
- [Why This Pattern?](#why-this-pattern)
  - [The `internal/` Directory](#the-internal-directory)
  - [Store Interfaces — Repository Pattern](#store-interfaces--repository-pattern)
  - [Memory vs GORM Store — InMemory DbContext](#memory-vs-gorm-store--inmemory-dbcontext)
  - [main.go — Composition Root](#maingo--composition-root)
  - [Handlers — Controller Actions](#handlers--controller-actions)
  - [Clock Interface — TimeProvider](#clock-interface--timeprovider)
  - [context.Context — CancellationToken](#contextcontext--cancellationtoken)
  - [Error Handling — No try/catch](#error-handling--no-trycatch)
  - [Struct Methods — Extension Methods](#struct-methods--extension-methods)
- [Key Differences Table](#key-differences-table)
- [OAuth2 / OIDC Flow Walkthrough](#oauth2--oidc-flow-walkthrough)

---

## Project Structure

```
cmd/authserver/main.go          — Application entry point (composition root)
internal/
  config/                       — Environment-based configuration
  domain/                       — Plain model structs (no HTTP/GORM/JOSE deps)
  store/                        — Store interfaces (ports)
    memory/                     — In-memory implementations (tests)
    gormstore/                  — PostgreSQL implementations (production)
  token/                        — Hashing, PKCE, RSA keys, JWT issuance
  oidc/                         — HTTP handlers (chi-based)
    grants/                     — Auth code, refresh token, client credentials
  session/                      — Encrypted SSO cookie management
  admin/                        — Admin JSON API + SPA (behind auth middleware)
  server/                       — Router wiring, middleware
  clock/                        — Clock interface (SystemClock + FakeClock)
web/
  templates/                    — HTML templates (login, logout, admin)
  static/                       — Admin SPA assets
test/
  integration_test.go           — End-to-end flow tests
```

---

## .NET to Go Concept Mapping

| .NET Concept | Go Equivalent | Where in This Project |
|---|---|---|
| `Program.cs` / `Startup.cs` | `cmd/authserver/main.go` | Application entry, wires everything |
| `namespace` | `package` | Each folder is a package |
| `class` | `struct` | Go has no classes, but you can add methods to structs |
| `interface` | `interface` | Same as C# — drives dependency injection |
| `internal` access modifier | `internal/` folder | Packages under `internal/` cannot be imported from outside the module |
| `appsettings.json` | `internal/config/` + env vars | Go typically reads config from environment variables |
| `DbContext` (EF Core) | `gormstore/` | GORM is Go's equivalent of EF Core |
| `Controller` | `oidc/` handlers | Go has no controllers, just `http.HandlerFunc` |
| Repository pattern | `store/` interfaces | Same as `IRepository<T>` in C# |
| Service layer | `token/` | Business logic lives here |
| Middleware | `server/middleware.go` | Identical to ASP.NET middleware |
| Dependency Injection | Manual constructor injection | Go has no DI container; you wire everything by hand |

---

## Layered Architecture (Clean Architecture)

Think of it like Clean Architecture in .NET:

```
┌─────────────────────────────────────┐
│  Controllers (oidc/)                │  ← HTTP request/response
│  ┌───────────────────────────────┐  │
│  │  Services (token/)            │  │  ← Business logic
│  │  ┌─────────────────────────┐  │  │
│  │  │  Domain Models          │  │  │  ← Entity/DTOs
│  │  │  (domain/)              │  │  │
│  │  └─────────────────────────┘  │  │
│  │  ┌─────────────────────────┐  │  │
│  │  │  Repository Interfaces  │  │  │  ← store/ (IRepository)
│  │  │  ┌───────────────────┐  │  │  │
│  │  │  │ Implementations   │  │  │  │  ← memory/ (test) + gormstore/ (prod)
│  │  │  └───────────────────┘  │  │  │
│  │  └─────────────────────────┘  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

Dependencies point inward: handlers depend on services, services depend on domain + store interfaces, store implementations depend on domain. This is the same dependency rule as Clean Architecture in .NET.

---

## Why This Pattern?

### The `internal/` Directory

In C#, you use `internal class` to restrict access to the same assembly. In Go, packages under `internal/` can only be imported by code within the same module. Since this project is a deployable application (not a library), everything lives under `internal/` — nothing is exposed to external consumers.

### Store Interfaces — Repository Pattern

```csharp
// C#:
public interface IClientRepository {
    Task<Client> FindByClientIdAsync(string clientId);
    Task SaveAsync(Client client);
}
```

```go
// Go:
type ClientStore interface {
    FindByClientID(ctx context.Context, clientID string) (*domain.Client, error)
    Store(ctx context.Context, c *domain.Client) error
}
```

Key differences:
- Go has no `Task<T>`. Instead, you return multiple values: `(result, error)`
- Go has no `async/await`. The `context.Context` parameter serves a similar purpose to `CancellationToken`
- Pointers (`*`) in Go are like reference types in C# (can be nil)

### Memory vs GORM Store — InMemory DbContext

In C#, you use `UseInMemoryDatabase()` for testing. Go does the same:

- `memory/` = In-memory implementation (for tests, uses `map` + `sync.RWMutex`)
- `gormstore/` = PostgreSQL via GORM (for production, similar to EF Core DbContext)

Both implement the same interfaces, so you can swap them freely.

### main.go — Composition Root

In C#, you register services in `Program.cs`:

```csharp
builder.Services.AddScoped<IClientRepository, ClientRepository>();
builder.Services.AddScoped<TokenService>();
```

In Go, you do the same thing manually in `main()`:

```go
clientStore := gormstore.NewClientStore(db)       // = AddScoped
tokenIssuer := token.NewIssuer(keyStore, clock)    // = AddScoped
loginHandler := oidc.NewLoginHandler(userStore, sessionMgr, ...)
```

Go has no DI container. You wire everything by hand in `main()`. This actually follows C#'s "Explicit Dependencies Principle" — all dependencies are visible in the constructor.

### Handlers — Controller Actions

```csharp
// C#:
[HttpGet("/connect/authorize")]
public async Task<IActionResult> Authorize([FromQuery] string client_id, ...) { }
```

```go
// Go:
func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    clientID := r.URL.Query().Get("client_id")  // manual binding
    ...
}
```

Go has no attribute routing. Routes are defined manually with the `chi` router (in `router.go`). There is no model binding — you read query parameters by hand.

### Clock Interface — TimeProvider

This is the same abstraction as `TimeProvider` in ASP.NET 8+:

```go
type Clock interface {
    Now() time.Time
}
```

- **Production**: `SystemClock` (calls `time.Now()`)
- **Tests**: `FakeClock` (you control the time)

Why? To make time-dependent code testable. If you call `time.Now()` directly, you can't control time in tests.

### context.Context — CancellationToken

In Go, every function takes `context.Context` as its first parameter. This serves the same purpose as:

- `CancellationToken` in C# (cancellation signal)
- Request-scoped values (request ID, timeout, etc.)
- It's a Go convention — expected everywhere

### Error Handling — No try/catch

Go has no exceptions. Functions return errors:

```csharp
// C#:
try {
    var client = await repo.FindById(id);
} catch (Exception ex) {
    // handle
}
```

```go
// Go:
client, err := store.FindByClientID(ctx, id)
if err != nil {
    return fmt.Errorf("client not found: %w", err)  // wrap error
}
```

`%w` is like C#'s `throw new Exception("msg", innerException)` — it wraps the original error so you can inspect it later with `errors.Is()` or `errors.As()`.

### Struct Methods — Extension Methods

```csharp
// C#:
public class Client {
    public string ClientId { get; set; }
    public int GetEffectiveLifetime() { ... }
}
```

```go
// Go:
type Client struct {
    ClientID string
}
func (c *Client) EffectiveAccessTokenLifetime() int { ... }
```

In Go, you add methods to structs using a receiver. This is similar to C#'s extension methods.

---

## Key Differences Table

| Topic | C# | Go |
|---|---|---|
| **Null safety** | `null`, `?.`, `??` | Pointer `*T`, explicit nil checks |
| **Generics** | `List<T>`, `Dictionary<K,V>` | `PagedResult[T]` (Go 1.18+) |
| **Concurrency** | `async/await`, `Task` | `goroutine`, `channel`, `sync.Mutex` |
| **Serialization** | `[JsonProperty]` | Struct tags: `` `json:"name"` `` |
| **Dependency Injection** | `IServiceCollection` | Manual constructor wiring |
| **Testing** | xUnit/NUnit | `testing` package, `_test.go` files |
| **ORM** | Entity Framework Core | GORM |
| **HTTP** | ASP.NET Controllers | `http.HandlerFunc` + chi router |
| **Error handling** | `try/catch/finally` | Return `(value, error)`, check with `if err != nil` |
| **Packages** | NuGet + project references | Go modules (`go.mod`) |

---

## OAuth2 / OIDC Flow Walkthrough

Here's what happens when a user authenticates through this server:

```
1.  User hits GET /connect/authorize
2.  → authorize.go handler runs
3.  → Checks session cookie (session/cookie.go)
4.  → No session? → Redirect to /login (oidc/login.go)
5.  → User submits login form → Session created → Cookie set
6.  → Redirect back to /connect/authorize
7.  → Authorization code created (hashed via token/hasher.go)
8.  → Redirect to redirect_uri with code + state
9.  → Client sends POST /connect/token with code + code_verifier
10. → token.go handler runs
11. → PKCE verified (token/pkce.go)
12. → Code marked consumed (single-use via atomic CAS)
13. → Returns access token + ID token + refresh token
```

### Key Security Primitives

- **Authorization codes** are stored as SHA-256 hashes only — the raw code is never persisted
- **MarkConsumed** is an atomic Compare-And-Swap — only the first caller wins (prevents code reuse)
- **PKCE S256** is required by default — `plain` method is rejected
- **Refresh tokens** are rotated on each use — if a consumed token is reused, the entire chain is revoked
- **redirect_uri** must be an exact match — no prefix or wildcard matching

---

## Useful Commands

```bash
go build ./...          # Build all packages
go vet ./...            # Static analysis
go test ./...           # Run all tests
go run ./cmd/authserver # Run the server
gofmt -w .              # Format all Go files
goimports -w .          # Format + organize imports
```
