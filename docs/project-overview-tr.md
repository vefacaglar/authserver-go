# Proje Genel Bakış — Go OAuth2 / OIDC Auth Server

Bu belge, .NET geçmişine sahip geliştiriciler için proje mimarisinin üst düzey bir özetini sunar. Go kavramlarını C# karşılıklarıyla eşleştirir ve kod yapısının neden bu şekilde olduğunu açıklar.

---

## İçindekiler

- [Proje Yapısı](#proje-yapısı)
- [.NET → Go Kavram Eşleştirmesi](#net--go-kavram-eşleştirmesi)
- [Katmanlı Mimari (Clean Architecture)](#katmanlı-mimari-clean-architecture)
- [Neden Bu Pattern?](#neden-bu-pattern)
  - [`internal/` Klasörü](#internal-klasörü)
  - [Store Interface'leri — Repository Pattern](#store-interfaceleri--repository-pattern)
  - [Memory vs GORM Store — InMemory DbContext](#memory-vs-gorm-store--inmemory-dbcontext)
  - [main.go — Composition Root](#maingo--composition-root)
  - [Handler'lar — Controller Action'lar](#handlerlar--controller-actionlar)
  - [Clock Interface — TimeProvider](#clock-interface--timeprovider)
  - [context.Context — CancellationToken](#contextcontext--cancellationtoken)
  - [Error Handling — try/catch Yok](#error-handling--trycatch-yok)
  - [Struct Method'ları — Extension Method'lar](#struct-methodları--extension-methodlar)
- [Temel Farklar Tablosu](#temel-farklar-tablosu)
- [OAuth2 / OIDC Akış Yürüyüşü](#oauth2--oidc-akış-yürüyüşü)

---

## Proje Yapısı

```
cmd/authserver/main.go          — Uygulama giriş noktası (composition root)
internal/
  config/                       — Ortam değişkenlerine dayalı yapılandırma
  domain/                       — Düz model struct'ları (HTTP/GORM/JOSE bağımlılığı yok)
  store/                        — Store interface'leri (portlar)
    memory/                     — In-memory implementasyonlar (test)
    gormstore/                  — PostgreSQL implementasyonları (production)
  token/                        — Hashing, PKCE, RSA keyler, JWT üretimi
  oidc/                         — HTTP handler'lar (chi tabanlı)
    grants/                     — Auth code, refresh token, client credentials
  session/                      — Şifrelenmiş SSO cookie yönetimi
  admin/                        — Admin JSON API + SPA (auth middleware arkasında)
  server/                       — Router bağlantıları, middleware
  clock/                        — Clock interface (SystemClock + FakeClock)
web/
  templates/                    — HTML şablonları (login, logout, admin)
  static/                       — Admin SPA varlıkları
test/
  integration_test.go           — Uçtan uca akış testleri
```

---

## .NET → Go Kavram Eşleştirmesi

| .NET Kavramı | Go Karşılığı | Bu Projedeki Yeri |
|---|---|---|
| `Program.cs` / `Startup.cs` | `cmd/authserver/main.go` | Uygulama buradan başlıyor, her şeyi burada bağlıyor |
| `namespace` | `package` | Her klasör bir package |
| `class` | `struct` | Go'da class yok, ama struct'a method ekleyebilirsiniz |
| `interface` | `interface` | C#'daki ile aynı — dependency injection buradan geliyor |
| `internal` erişim belirleyicisi | `internal/` klasörü | `internal/` altındaki package'lar dışarıdan import edilemez |
| `appsettings.json` | `internal/config/` + env vars | Go'da config genelde environment variable'dan okunur |
| `DbContext` (EF Core) | `gormstore/` | GORM, Go'nun EF Core karşılığıdır |
| `Controller` | `oidc/` handler'ları | Go'da controller yok, sadece `http.HandlerFunc` |
| Repository pattern | `store/` interface'leri | C#'daki `IRepository<T>` ile aynı |
| Service katmanı | `token/` | İş mantığı burada yaşar |
| Middleware | `server/middleware.go` | ASP.NET middleware'in aynısı |
| Dependency Injection | Manuel constructor enjeksiyonu | Go'da DI container yok, elle bağlıyorsunuz |

---

## Katmanlı Mimari (Clean Architecture)

.NET'teki Clean Architecture gibi düşünün:

```
┌─────────────────────────────────────┐
│  Controller'lar (oidc/)             │  ← HTTP istek/yanıtı
│  ┌───────────────────────────────┐  │
│  │  Servisler (token/)           │  │  ← İş mantığı
│  │  ┌─────────────────────────┐  │  │
│  │  │  Domain Modelleri       │  │  │  ← Entity/DTO'lar
│  │  │  (domain/)              │  │  │
│  │  └─────────────────────────┘  │  │
│  │  ┌─────────────────────────┐  │  │
│  │  │  Repository Interface'leri│  │  │  ← store/ (IRepository)
│  │  │  ┌───────────────────┐  │  │  │
│  │  │  │ Implementasyonlar │  │  │  │  ← memory/ (test) + gormstore/ (prod)
│  │  │  └───────────────────┘  │  │  │
│  │  └─────────────────────────┘  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

Bağımlılıklar içeriye doğru işaret eder: handler'lar servislere, servisler domain + store interface'lerine, store implementasyonları domain'e bağımlıdır. Bu, .NET'teki Clean Architecture'ın aynı bağımlılık kuralıdır.

---

## Neden Bu Pattern?

### `internal/` Klasörü

C#'da `internal class` ile aynı assembly içinde erişimi kısıtlarsınız. Go'da `internal/` altındaki package'lar sadece aynı module içindeki kod tarafından import edilebilir. Bu proje deploy edilebilir bir uygulama olduğu (kütüphane değil) için her şey `internal/` altında — dış tüketicilere hiçbir şey açılmıyor.

### Store Interface'leri — Repository Pattern

```csharp
// C#'da:
public interface IClientRepository {
    Task<Client> FindByClientIdAsync(string clientId);
    Task SaveAsync(Client client);
}
```

```go
// Go'da:
type ClientStore interface {
    FindByClientID(ctx context.Context, clientID string) (*domain.Client, error)
    Store(ctx context.Context, c *domain.Client) error
}
```

Önemli farklar:
- Go'da `Task<T>` yok. Bunun yerine birden fazla değer döndürüyorsunuz: `(result, error)`
- Go'da `async/await` yok. `context.Context` parametresi `CancellationToken` ile benzer bir amaca hizmet eder
- Go'da pointer (`*`) C#'daki reference type gibi (nil olabilir)

### Memory vs GORM Store — InMemory DbContext

C#'da test için `UseInMemoryDatabase()` kullanırsınız. Go'da aynısı:

- `memory/` = In-memory implementasyon (testler için, `map` + `sync.RWMutex` kullanır)
- `gormstore/` = GORM ile PostgreSQL (production için, EF Core DbContext'e benzer)

Her ikisi de aynı interface'leri uygular, bu yüzden serbestçe değiştirebilirsiniz.

### main.go — Composition Root

C#'da `Program.cs`'de servislersiniz:

```csharp
builder.Services.AddScoped<IClientRepository, ClientRepository>();
builder.Services.AddScoped<TokenService>();
```

Go'da aynı şeyi `main()` içinde manuel yaparsınız:

```go
clientStore := gormstore.NewClientStore(db)       // = AddScoped
tokenIssuer := token.NewIssuer(keyStore, clock)    // = AddScoped
loginHandler := oidc.NewLoginHandler(userStore, sessionMgr, ...)
```

Go'da DI container yok. Her şeyi `main()`'de elle bağlarsınız. Bu aslında C#'ın "Explicit Dependencies Principle"ini uygular — tüm bağımlılıklar constructor'da görünür.

### Handler'lar — Controller Action'lar

```csharp
// C#'da:
[HttpGet("/connect/authorize")]
public async Task<IActionResult> Authorize([FromQuery] string client_id, ...) { }
```

```go
// Go'da:
func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    clientID := r.URL.Query().Get("client_id")  // manuel binding
    ...
}
```

Go'da attribute routing yok. Rotalar `chi` router ile manuel tanımlanır (`router.go`'da). Model binding yok — query parametrelerini elle okursunuz.

### Clock Interface — TimeProvider

ASP.NET 8+'daki `TimeProvider` abstraction'ı ile aynı:

```go
type Clock interface {
    Now() time.Time
}
```

- **Production**: `SystemClock` (`time.Now()` çağırır)
- **Testler**: `FakeClock` (zamanı siz kontrol edersiniz)

Neden? Zamana bağlı kodu test edilebilir kılmak için. Doğrudan `time.Now()` çağırırsanız testlerde zamanı kontrol edemezsiniz.

### context.Context — CancellationToken

Go'da her fonksiyon ilk parametre olarak `context.Context` alır. Bu, şu amaçlarla kullanılır:

- C#'daki `CancellationToken` gibi (iptal sinyali)
- Request kapsamında değerler taşır (request ID, timeout, vb.)
- Go'nun convention'ıdır — her yerde beklenir

### Error Handling — try/catch Yok

Go'da exception yok. Fonksiyonlar hata döndürür:

```csharp
// C#'da:
try {
    var client = await repo.FindById(id);
} catch (Exception ex) {
    // işle
}
```

```go
// Go'da:
client, err := store.FindByClientID(ctx, id)
if err != nil {
    return fmt.Errorf("istemci bulunamadı: %w", err)  // hata sar
}
```

`%w`, C#'daki `throw new Exception("msg", innerException)` gibidir — orijinal hatayı sarar, böylece daha sonra `errors.Is()` veya `errors.As()` ile inceleyebilirsiniz.

### Struct Method'ları — Extension Method'lar

```csharp
// C#'da:
public class Client {
    public string ClientId { get; set; }
    public int GetEffectiveLifetime() { ... }
}
```

```go
// Go'da:
type Client struct {
    ClientID string
}
func (c *Client) EffectiveAccessTokenLifetime() int { ... }
```

Go'da struct'a method eklemek için receiver kullanırsınız. Bu, C#'daki extension method'lara benzer.

---

## Temel Farklar Tablosu

| Konu | C# | Go |
|---|---|---|
| **Null güvenliği** | `null`, `?.`, `??` | Pointer `*T`, açık nil kontrolleri |
| **Generics** | `List<T>`, `Dictionary<K,V>` | `PagedResult[T]` (Go 1.18+) |
| **Eşzamanlılık** | `async/await`, `Task` | `goroutine`, `channel`, `sync.Mutex` |
| **Serileştirme** | `[JsonProperty]` | Struct tag'leri: `` `json:"name"` `` |
| **Dependency Injection** | `IServiceCollection` | Manuel constructor bağlantı |
| **Test** | xUnit/NUnit | `testing` paketi, `_test.go` dosyaları |
| **ORM** | Entity Framework Core | GORM |
| **HTTP** | ASP.NET Controller'lar | `http.HandlerFunc` + chi router |
| **Hata işleme** | `try/catch/finally` | `(değer, error)` döndürme, `if err != nil` ile kontrol |
| **Paketler** | NuGet + proje referansları | Go modülleri (`go.mod`) |

---

## OAuth2 / OIDC Akış Yürüyüşü

Bir kullanıcı bu sunucu üzerinden kimlik doğruladığında olanlar:

```
1.  Kullanıcı GET /connect/authorize'a gelir
2.  → authorize.go handler çalışır
3.  → Session cookie'yi kontrol eder (session/cookie.go)
4.  → Session yok mu? → /login'e redirect (oidc/login.go)
5.  → Kullanıcı login formunu gönderir → Session oluşturulur → Cookie set edilir
6.  → Tekrar /connect/authorize'a redirect
7.  → Authorization code oluşturulur (token/hasher.go ile hash'lenir)
8.  → redirect_uri'e code + state ile redirect
9.  → Client POST /connect/token'a code + code_verifier gönderir
10. → token.go handler çalışır
11. → PKCE doğrulanır (token/pkce.go)
12. → Code tüketildi olarak işaretlenir (tek kullanımlık, atomic CAS ile)
13. → Access token + ID token + refresh token döner
```

### Temel Güvenlik Primitifleri

- **Authorization code'lar** sadece SHA-256 hash olarak saklanır — ham code asla kalıcı olarak depolanmaz
- **MarkConsumed** atomik bir Compare-And-Swap'dir — sadece ilk çağıran kazanır (code tekrar kullanımını önler)
- **PKCE S256** varsayılan olarak zorunludur — `plain` yöntemi reddedilir
- **Refresh token'lar** her kullanımda rotasyona uğrar — tüketilmiş bir token tekrar kullanılırsa tüm zincir iptal edilir
- **redirect_uri** tam eşleşme olmalıdır — prefix veya wildcard eşleştirmesi yoktur

---

## Faydalı Komutlar

```bash
go build ./...          # Tüm paketleri derle
go vet ./...            # Statik analiz
go test ./...           # Tüm testleri çalıştır
go run ./cmd/authserver # Sunucuyu başlat
gofmt -w .              # Tüm Go dosyalarını biçimlendir
goimports -w .          # Biçimlendir + import'ları düzenle
```
