# WiFiSentinel AI

A wireless security dashboard built with Next.js, React, TypeScript, and Tailwind CSS. It visualizes defensive scan results and highlights potentially suspicious access points; it does not scan Wi-Fi networks itself. A backend connection is required for network data.

## Run locally

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Without a reachable backend, the dashboard shows an empty state.

To connect a FastAPI backend, copy `.env.example` to `.env.local`, set `NEXT_PUBLIC_API_URL`, then restart the dev server. API requests are centralized in `src/lib/api.ts`.

Expected endpoints:

- `GET /api/networks`
- `GET /api/networks/{bssid}`
- `POST /api/scan`
- `GET /api/trusted`
- `POST /api/trusted`
