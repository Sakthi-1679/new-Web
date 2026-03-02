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