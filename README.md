# new-Web

A Node.js / Express REST API backend for VKM Flower Shop.

---

## Hosting on Vercel

### Prerequisites

- A [Vercel](https://vercel.com) account (free tier works)
- A MySQL database reachable from the internet (e.g. [Aiven](https://aiven.io), [PlanetScale](https://planetscale.com), or [Railway](https://railway.app))

### Steps

1. **Fork / push this repository to GitHub** (if you haven't already).

2. **Import the project into Vercel**
   - Go to <https://vercel.com/new> and click **"Import Git Repository"**.
   - Select your GitHub repository.
   - Leave the **Root Directory** as the repository root (do **not** change it).
   - Vercel will auto-detect the Node.js framework.

3. **Add Environment Variables**
   In the Vercel project dashboard → **Settings → Environment Variables**, add the following (refer to `server/.env.example` for the full list):

   | Variable | Description |
   |---|---|
   | `DB_HOST` | MySQL host (e.g. `mysql.aiven.io`) |
   | `DB_PORT` | MySQL port (default `3306`) |
   | `DB_USER` | MySQL username |
   | `DB_PASSWORD` | MySQL password |
   | `DB_NAME` | Database name (e.g. `vkm_flower_shop`) |
   | `DB_SSL` | Set to `true` if your host requires SSL |
   | `JWT_SECRET` | A long random secret string |
   | `FRONTEND_URL` | Your frontend URL for CORS (e.g. `https://your-app.vercel.app`) |

4. **Deploy**
   Click **Deploy**. Vercel will install dependencies and deploy the API as serverless functions.

5. **Verify**
   Once deployed, visit `https://<your-project>.vercel.app/api/health` — you should see:
   ```json
   { "status": "ok", "timestamp": "..." }
   ```

### How it works

- `vercel.json` at the repository root tells Vercel to route all requests (`/.*`) to `server/index.js`.
- `server/index.js` exports the Express app as the default export (required by `@vercel/node`).
- The server only calls `app.listen()` locally; on Vercel the `VERCEL` environment variable is set automatically, so the listen call is skipped.

### Local Development

```bash
cd server
cp .env.example .env   # fill in your local DB credentials
npm install
npm run dev            # starts with --watch for auto-reload
```

---

## Connecting a Frontend to this Backend

### 1. Set the API base URL

In your frontend project (React, Vue, etc.) create a single constant for the backend URL.

**Vite projects** – add to `.env` (or `.env.local`):

```
VITE_API_URL=http://localhost:3001
```

For production (Vercel), set the same variable in the Vercel dashboard to your deployed backend URL, e.g. `https://your-backend.vercel.app`.

Then reference it in your code:

```js
// src/api.js  (example helper)
const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

export async function apiFetch(path, options = {}) {
  const token = localStorage.getItem('token');
  const res = await fetch(`${BASE_URL}/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Request failed');
  }
  return res.json();
}
```

### 2. Authentication flow

#### Register

```js
const { user, token } = await apiFetch('/register', {
  method: 'POST',
  body: JSON.stringify({ name, email, password, phone, city, area }),
});
localStorage.setItem('token', token);   // persist the JWT
```

#### Login

```js
const { user, token } = await apiFetch('/login', {
  method: 'POST',
  body: JSON.stringify({ email, password }),
});
localStorage.setItem('token', token);
```

All subsequent requests automatically include the `Authorization: Bearer <token>` header via the `apiFetch` helper above.

### 3. API endpoint reference

| Method | Path | Auth required | Description |
|--------|------|---------------|-------------|
| `GET` | `/api/health` | — | Health check |
| `POST` | `/api/register` | — | Create account |
| `POST` | `/api/login` | — | Login → returns JWT |
| `GET` | `/api/products` | — | List all products |
| `POST` | `/api/products` | Admin | Add product |
| `PUT` | `/api/products/:id` | Admin | Update product |
| `DELETE` | `/api/products/:id` | Admin | Delete product |
| `GET` | `/api/orders` | User | List orders |
| `POST` | `/api/orders` | User | Place order |
| `PUT` | `/api/orders/:id/status` | Admin | Update order status |
| `DELETE` | `/api/orders/:id` | Admin | Delete order |
| `GET` | `/api/custom-orders` | User | List custom orders |
| `POST` | `/api/custom-orders` | User | Submit custom order |
| `PUT` | `/api/custom-orders/:id/status` | Admin | Update custom order status |
| `DELETE` | `/api/custom-orders/:id` | Admin | Delete custom order |
| `GET` | `/api/settings/contact` | — | Get admin phone number |
| `PUT` | `/api/settings/contact` | Admin | Update admin phone number |
| `GET` | `/api/users/:id` | Admin | Get user by ID |

All routes also work **without** the `/api` prefix (e.g. `/login` equals `/api/login`).

### 4. Local development – Vite proxy (optional)

If you want to avoid setting `VITE_API_URL` during local development, you can proxy API calls through the Vite dev server. In your frontend's `vite.config.js`:

```js
export default {
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: true,
      },
    },
  },
};
```

With this proxy in place, calls to `/api/...` from the frontend are forwarded to the backend automatically, and no CORS issues arise during local development.

### 5. CORS

The backend already allows:

- `http://localhost:3000` and `http://localhost:5173` / `http://127.0.0.1:5173` (local dev defaults)
- Any `*.vercel.app` origin (Vercel preview / production deployments)
- The URL set in the `FRONTEND_URL` environment variable

If your frontend is hosted on a custom domain, add it to the `FRONTEND_URL` environment variable on your backend deployment.

---

## Android App Integration

### 1. Find your Vercel backend URL

After deploying to Vercel (see the [Hosting on Vercel](#hosting-on-vercel) section above), open your Vercel project dashboard. The URL is shown at the top of the **Overview** tab, e.g.:

```
https://new-web-<your-username>.vercel.app
```

You can verify the backend is reachable by opening this URL in a browser or running:

```
https://new-web-<your-username>.vercel.app/api/health
```

You should see `{"status":"ok","timestamp":"..."}`.

> **No CORS changes are needed for Android.** Native Android apps do not send an `Origin` header, so they are already allowed by the existing server configuration.

---

### 2. Add constants to your Android project

Create `app/src/main/java/<your/package>/network/ApiConstants.kt`:

```kotlin
package com.example.vkmflowershop.network

object ApiConstants {
    // Replace with your actual Vercel deployment URL
    const val BASE_URL = "https://new-web-<your-username>.vercel.app/api/"
}
```

---

### 3. Add Retrofit & OkHttp dependencies

In your `app/build.gradle` (or `build.gradle.kts`):

```kotlin
dependencies {
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-gson:2.11.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
}
```

---

### 4. Create the Retrofit service

`ApiService.kt`:

```kotlin
package com.example.vkmflowershop.network

import retrofit2.Response
import retrofit2.http.*

// --- Request / Response data classes ---

data class RegisterRequest(
    val name: String,
    val email: String,
    val password: String,
    val phone: String,
    val city: String,
    val area: String
)

data class LoginRequest(val email: String, val password: String)

data class AuthResponse(val user: UserDto, val token: String)

data class UserDto(
    val id: String,
    val name: String,
    val email: String,
    val role: String
)

data class Product(
    val id: String,
    val title: String,
    val description: String?,
    val price: Double,
    val durationHours: Int,
    val images: List<String>
)

// --- Retrofit service interface ---

interface ApiService {

    @POST("register")
    suspend fun register(@Body body: RegisterRequest): Response<AuthResponse>

    @POST("login")
    suspend fun login(@Body body: LoginRequest): Response<AuthResponse>

    @GET("products")
    suspend fun getProducts(): Response<List<Product>>

    @GET("orders")
    suspend fun getOrders(@Header("Authorization") token: String): Response<List<Any>>

    @POST("orders")
    suspend fun placeOrder(
        @Header("Authorization") token: String,
        @Body body: Map<String, Any>
    ): Response<Map<String, Any>>
}
```

---

### 5. Build the Retrofit instance

`RetrofitClient.kt`:

```kotlin
package com.example.vkmflowershop.network

import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

object RetrofitClient {

    private val loggingInterceptor = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.BODY   // remove in production
    }

    private val httpClient = OkHttpClient.Builder()
        .addInterceptor(loggingInterceptor)
        .build()

    val apiService: ApiService = Retrofit.Builder()
        .baseUrl(ApiConstants.BASE_URL)
        .client(httpClient)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(ApiService::class.java)
}
```

---

### 6. Usage examples (ViewModel / coroutine)

#### Login

```kotlin
// In a ViewModel (viewModelScope) or a coroutine:
val response = RetrofitClient.apiService.login(LoginRequest("user@example.com", "password123"))
if (response.isSuccessful) {
    val token = response.body()?.token ?: return
    // Save token to SharedPreferences / DataStore
    prefs.edit().putString("jwt_token", token).apply()
} else {
    // Handle error: response.code(), response.errorBody()?.string()
}
```

#### Register

```kotlin
val response = RetrofitClient.apiService.register(
    RegisterRequest(
        name = "John Doe",
        email = "john@example.com",
        password = "secret",
        phone = "9876543210",
        city = "Kanchipuram",
        area = "Main Street"
    )
)
if (response.isSuccessful) {
    val token = response.body()?.token ?: return
    prefs.edit().putString("jwt_token", token).apply()
}
```

#### Authenticated requests

```kotlin
val token = prefs.getString("jwt_token", "") ?: ""
val products = RetrofitClient.apiService.getProducts()          // no auth needed
val orders   = RetrofitClient.apiService.getOrders("Bearer $token")
```

---

### 7. Internet permission

Make sure `AndroidManifest.xml` contains:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

---

### 8. Quick API reference for Android

| Endpoint | Method | Auth | Body / Notes |
|---|---|---|---|
| `/api/health` | GET | — | Health check |
| `/api/register` | POST | — | `{ name, email, password, phone, city, area }` |
| `/api/login` | POST | — | `{ email, password }` → returns `{ user, token }` |
| `/api/products` | GET | — | Returns product list |
| `/api/orders` | GET | Bearer token | Returns order list |
| `/api/orders` | POST | Bearer token | `{ userId, productId, quantity, description }` |
| `/api/custom-orders` | GET | Bearer token | Returns custom-order list |
| `/api/custom-orders` | POST | Bearer token | `{ userId, description, requestedDate, requestedTime, contactName, contactPhone, images }` |
| `/api/settings/contact` | GET | — | Returns `{ phone }` |