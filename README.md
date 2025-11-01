# Click Tracker with Geolocation and Redirect

Track when a user opens a link, capture approximate IP-based location server-side, optionally request precise browser geolocation (with user consent), store to SQLite, and then redirect to the intended destination.

## Features
- Logs each click with timestamp, IP, user agent, referrer, and destination URL
- IP geolocation via `geoip-lite` for approximate location
- Optional precise browser geolocation using the Permissions API (user consent required)
- SQLite storage (`better-sqlite3`)
- Minimal admin listing at `/admin?key=...`

## Quickstart

1) Install dependencies

```bash
cd /home/dhiren/Repositories/Track_hacker
npm install
```

2) Configure environment (copy and edit as needed)

```bash
cp env.example .env
# Then edit .env (PORT, BASE_URL, ADMIN_KEY, REDIRECT_DEFAULT)
```

3) Run the server

```bash
npm run start
# or, for live reload during development
npm run dev
```

4) Use a tracking link

Open your browser to:

```
http://localhost:3000/track?u=https%3A%2F%2Fexample.com
```

- The server immediately logs the click and approximate IP location
- The page asks (via the browser prompt) to allow location to improve accuracy
- The user is redirected shortly regardless of consent

5) View admin listing

```
http://localhost:3000/admin?key=YOUR_ADMIN_KEY
```

## Notes
- The `u` parameter must be an `http` or `https` URL; otherwise, it falls back to `REDIRECT_DEFAULT`.
- The correlation cookie `cid` is `HttpOnly` and used only to relate the precise geolocation POST to the original click.
- Data is stored at `data/clicks.db` (created automatically).
- If running behind a reverse proxy (e.g., Nginx), ensure it sets `X-Forwarded-For` so IP extraction works as expected.

## Privacy
- Precise location is only collected if the user explicitly grants permission in their browser.
- Approximate location from IP is a common analytics practice and is stored with the click.
- Please comply with your local privacy laws and update the UI copy/consent text as appropriate for your use case.

## License
MIT

## Deployment

### Option A: Docker (recommended)

```bash
cd /home/dhiren/Repositories/Track_hacker
cp env.example .env
# Set ADMIN_KEY, BASE_URL (e.g., https://your-domain), REDIRECT_DEFAULT

docker compose up -d --build

# Logs
docker compose logs -f
```

Data persists in `./data` (mounted to `/app/data` in the container).

### Option B: systemd on a Linux server

1) Install Node 20 (e.g., via NodeSource) and nginx + certbot
2) Create `.env` from `env.example`
3) Install deps:

```bash
cd /home/dhiren/Repositories/Track_hacker
npm ci --omit=dev
```

4) systemd service

Copy `deploy/systemd/track-hacker.service` to `/etc/systemd/system/track-hacker.service`, adjust paths/user if needed:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now track-hacker
sudo systemctl status track-hacker
```

5) nginx reverse proxy (HTTP→app, then add TLS via certbot)

Use `deploy/nginx.sample.conf` as a base in `/etc/nginx/sites-available/your.conf` and enable it. Ensure headers `X-Forwarded-For` are set so client IPs are logged. Then run certbot for HTTPS.



# Track_Hacker
