# Zlecenie: direct-mode Google Drive z refresh tokenem (parytet UX z relay, BEZ popupu)

**Data**: 2026-07-20 · **Autor**: Dariusz Porczyński · **Status**: SPEC do wykonania

## Cel
Tryb „direct" (Flutter czyta Google Drive bez relaya) ma pokazywać `/photos` **od razu po każdym
loginie, bez popupu i bez klikania Connect** — tak jak relay. Dziś direct używa **GIS token model**
(access token ~1h, BEZ refresh tokena), który przy pierwszym grancie **wymusza popup** (blokowany przez
przeglądarkę) i nie odnawia się cicho przy 2.+ loginie (3rd-party cookies). To sufit strukturalny GIS.

**Rozwiązanie**: zgoda przez **REDIRECT** (jak login Dudenest — NIE popup) + **backend trzyma refresh
token** i mintuje access tokeny drive.file na żądanie. Bajty plików nadal lecą **wprost Flutter→Drive**
(direct pozostaje direct); backendowe jest tylko *pozyskanie tokenu*. To świadomy tradeoff (backend
trzyma poświadczenie Google per user — zaakceptowany przez usera 2026-07-20).

---

## 🔴 0. BRAMA — akcja USERA w Google Cloud Console (blokuje wszystko poniżej)
Projekt Google używany przez backend (`GOOGLE_CLIENT_ID`, typ „Web application"; ten sam co login):
1. **Authorized redirect URIs** → dodaj: `https://api.dudenest.com/auth/callback/google/drive`
2. **OAuth consent screen** → dodaj scope `.../auth/drive.file` (non-sensitive → **bez CASA**, bez limitu 100).
3. Nic więcej — `access_type=offline` + `prompt=consent` idą per-request (bez przełącznika w Console).

Bez tego backend dostanie `redirect_uri_mismatch` / brak refresh tokena. **To jedyny krok tylko-usera.**

## 🔴 0b. Nowy sekret (encryption-at-rest refresh tokenów)
- `DUDENEST_DRIVE_TOKEN_ENC_KEY` = 32 losowe bajty base64 (`openssl rand -base64 32`).
- `gh secret set DUDENEST_DRIVE_TOKEN_ENC_KEY --repo dudenest/dudenest-backend`.
- Dodaj do `deploy.yml` env (wzorem `JWT_SECRET`): `DRIVE_TOKEN_ENC_KEY: ${{ secrets.DUDENEST_DRIVE_TOKEN_ENC_KEY }}`.
- **Wartość TYLKO w `~/.AI/credentials/` + GitHub secret — NIGDY w repo/sesji (Rule #20).**

---

## 1. Backend (Go, `dudenest-backend`) — nowe, NIE-łamiące endpointy

### 1a. Storage (CRDB — jest już `sql.Open("postgres", CRDB_DSN)` w `cmd/server/main.go:62`)
Migracja (uruchomić na CRDB backendu):
```sql
CREATE TABLE IF NOT EXISTS google_drive_tokens (
  user_id       STRING PRIMARY KEY,          -- Claims.Sub, np. "google:123"
  refresh_enc   BYTES NOT NULL,              -- AES-256-GCM(refresh_token) (nonce||ciphertext)
  email         STRING NOT NULL,             -- konto Google (do weryfikacji/wyświetlenia)
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
);
```
Nowy pakiet `internal/directauth/store.go` wzorem `internal/relays/sqlstore.go` (`*sql.DB`, driver-agnostic):
`Upsert(ctx, userID, refreshEnc []byte, email)`, `Get(ctx, userID) (refreshEnc []byte, email string, err error)`, `Delete(ctx, userID)`.

### 1b. Kryptografia — `internal/directauth/crypto.go`
AES-256-GCM z `DRIVE_TOKEN_ENC_KEY` (32B po base64-decode). `Encrypt([]byte) []byte` (nonce||ct),
`Decrypt([]byte) []byte`. **Guard startowy**: jeśli feature włączony a klucz pusty/≠32B → `log.Fatalf`
(wzorzec z s313 `requireEnv`, `cmd/server/main.go`).

### 1c. OAuth flow — `internal/directauth/oauth.go` (mirror `internal/auth/oauth.go`)
Reużyj `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` (ten sam klient co login) i wzorzec `startGoogle`/`callbackGoogle`.

- **`GET /auth/google/drive`** (start, wymaga auth usera — patrz niżej):
  - Redirect na `https://accounts.google.com/o/oauth2/v2/auth` z:
    `client_id`, `redirect_uri=https://api.dudenest.com/auth/callback/google/drive`,
    `response_type=code`, `scope=openid email https://www.googleapis.com/auth/drive.file`,
    `access_type=offline`, `prompt=consent` (wymusza refresh token), `include_granted_scopes=true`,
    `state=<signed>`.
  - **Auth w redir.**: redirect nie niesie nagłówka `Authorization`. Klient przekazuje JWT w query
    `?token=<jwt>&return_url=<app>`. Handler **waliduje JWT** (`auth.ValidateJWT`), bierze `claims.Sub`
    i `claims.Email`, pakuje je do `state` (podpisane HMAC — jak `encodeState`, ale z podpisem, by user
    nie podmienił Sub). Odrzuć nie-Google providera (GitHub/Apple nie mają konta Google do drive.file).
- **`GET /auth/callback/google/drive`**:
  - Exchange kodu (`grant_type=authorization_code`, z `client_secret`) → `access_token` + **`refresh_token`**.
  - `userinfo` (`oauth2/v3/userinfo`) → email. **Weryfikacja izolacji**: email Google MUSI == `claims.Email`
    ze `state` (dla providera google) → inaczej 403 (nie pozwól podpiąć cudzego/innego konta pod tego usera).
  - `store.Upsert(sub, Encrypt(refresh_token), email)`. Jeśli Google nie zwrócił `refresh_token` (bo user
    już wcześniej zgadzał bez `prompt=consent`) — `prompt=consent` wymusza go; gdyby jednak brak → zachowaj
    istniejący, nie nadpisuj pustym.
  - Redirect na `return_url` z flagą `?drive=connected`.
- **`GET /api/v1/direct/google/token`** (`requireAuth`): `store.Get(sub)` → refresh w Google
  (`grant_type=refresh_token`) → `{ "access_token": "...", "expires_in": 3599 }`. Gdy brak wpisu → `404
  {"error":"not_connected"}` (Flutter pokazsuje Connect). Gdy refresh 400/`invalid_grant` (odwołany) →
  `store.Delete` + 404 not_connected.
- **`DELETE /api/v1/direct/google/token`** (`requireAuth`): revoke (`https://oauth2.googleapis.com/revoke`)
  + `store.Delete`. Do „Disconnect".

Rejestracja w `cmd/server/main.go` (obok istniejących), gated `if CRDB_DSN != "" && DRIVE_TOKEN_ENC_KEY != ""`.
`/auth/google/drive` + `/auth/callback/google/drive` przez `RegisterRoutes` (bez requireAuth — auth po JWT w query/state).

### 1d. Testy Go (obowiązkowe, `*_test.go`)
- exchange/refresh: `httptest` mock Google token endpoint; asercje na parametry (`access_type=offline`,
  `prompt=consent`, `grant_type=refresh_token`).
- store: mock `*sql.DB` (sqlmock) upsert/get/delete.
- crypto: encrypt→decrypt round-trip + zły klucz → błąd.
- token endpoint: not_connected (404), invalid_grant → delete+404, happy path.
- **Nie łam istniejących**: `/auth/google` login nietknięty; smoke test deploy.yml (`/auth/google`→302) musi przejść.

---

## 2. Flutter (`dudenest`) — zamiana GIS na backend-token

Plik `lib/core/oauth/google_drive_auth_web.dart` (+ stub) — nowa implementacja (zachowaj sygnatury, by
`DirectEngine`/`DirectModeScreen`/`UploadScreen` nie wymagały zmian):
- **`getDriveAccessToken({silent, hint})`** → `GET api.dudenest.com/api/v1/direct/google/token` z nagłówkiem
  `Authorization: Bearer <dudenest JWT z SharedPreferences 'auth_token'>` → zwróć `access_token`. Cache
  ~55 min w pamięci (per bieżący uid — zachowaj wiązanie per-uid). 404 not_connected → rzuć (→ brama Connect).
  **Bez GIS, bez popupu.**
- **`hasValidDriveToken()`** → true jeśli cache ważny; inaczej lekki `HEAD`/GET tokenu (albo po prostu false
  i pozwól `getDriveAccessToken` spróbować — 404 = brama).
- **Connect (brama)** — zamiast popupu GIS: pełnostronicowy **redirect** (jak login):
  `setLocationHref('https://api.dudenest.com/auth/google/drive?token=<jwt>&return_url=<bieżący origin>')`.
  Po powrocie (`?drive=connected`) apka startuje zalogowana, `getDriveAccessToken` dostaje token z backendu
  → `/photos` renderuje od razu, **bez klikania**.
- **`clearDriveToken()`** → wyczyść cache pamięci (token nie żyje już w localStorage; refresh jest w backendzie,
  chroniony per-uid JWT). Opcjonalnie wołać `DELETE /api/v1/direct/google/token` przy „Disconnect", NIE przy
  zwykłym logout (refresh ma przetrwać między sesjami — to jest źródło parytetu z relay).
- **Usuń** skrypt GIS z `web/index.html` + interop GIS (albo zostaw jako martwy fallback — preferencja: usuń).
- `DirectModeScreen._autoConnect`: uprość — `getDriveAccessToken` jest teraz ciche z natury (brak GIS/popupu);
  weryfikacja emaila zbędna (backend gwarantuje konto == user przy connect). Zostaje: token OK → `_connect`;
  404 → brama (redirect).

Testy Flutter: mock HTTP `/direct/google/token` (200 z access_token / 404) → `getDriveAccessToken` zwraca/rzuca;
brama pokazuje przycisk Connect gdy 404.

---

## 3. Bezpieczeństwo / model zagrożeń
- Backend trzyma **refresh token per user, szyfrowany AES-GCM** (`DRIVE_TOKEN_ENC_KEY`). Izolacja: PK=user_id,
  endpoint tokenu gated `requireAuth` (JWT usera) → user X nie dostanie tokenu usera Y.
- Connect weryfikuje **email Google == email Dudenest** (dla providera google) → nie podepniesz cudzego konta.
- Bajty plików **nie przechodzą przez backend** — direct zostaje direct; backend zna tylko *auth*.
- Rotacja `DRIVE_TOKEN_ENC_KEY` = re-encrypt wszystkich wpisów (lub wymuszony re-consent). Udokumentować.

## 4. Deploy / weryfikacja (kolejność!)
1. USER: Google Console (§0) + `DUDENEST_DRIVE_TOKEN_ENC_KEY` (§0b) + wpis w deploy.yml.
2. Migracja CRDB (§1a).
3. Merge backend PR → deploy (smoke `/auth/google`→302 MUSI przejść — login nietknięty).
4. Merge Flutter PR → deploy.
5. USER (runtime, web-only): świeży login → Photos → Connect = **redirect (nie popup)** → zgoda →
   powrót → galeria. Wyloguj + zaloguj → **/photos od razu, ZERO klikania** (parytet z relay). Test w
   2 izolowanych profilach (izolacja kont — dotyka warstwy auth).

## 5. Skąd to wiadomo (kod, nie zgadywanie)
- Wzorzec OAuth redirect+exchange: `internal/auth/oauth.go` (`startGoogle`/`callbackGoogle`).
- JWT/Claims: `internal/auth/jwt.go` (`Claims.Sub/Email/Provider`, `ValidateJWT`).
- DB/store: `internal/relays/sqlstore.go` + `cmd/server/main.go:62` (`sql.Open`, `CRDB_DSN`), `requireAuth`+`WithUserID`.
- Sekrety przez `deploy.yml` env z GitHub secrets (`DUDENEST_*`).
- Flutter direct: `lib/core/oauth/google_drive_auth_web.dart`, `DirectModeScreen`, `google_config.dart`.
