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