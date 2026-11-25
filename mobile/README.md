# OraSec mobile app

Capacitor 8 + React 19 + Konsta UI app for the OraSec security operations console. Free and open source.
It works with any OraSec server: the first screen asks for the address of the server your organisation runs.
Floating tab bar, app lock (6-digit PIN + Face ID / fingerprint), privacy screen, edge-to-edge insets,
light / dark / branded appearances.

- App id / bundle id: `nz.co.oraflows.orasec` (permanent, same on Android and iOS)
- Version: `package.json` → `scripts/sync-native-version.mjs` writes Android
  `versionName`/`versionCode` and iOS `MARKETING_VERSION`/`CURRENT_PROJECT_VERSION`
  (`MAJOR*10000 + MINOR*100 + PATCH`, so 1.0.0 → 10000).
- Who can use it: OraSec users with organisation-wide access (superuser / staff) on their own server. Anyone can
  open the demo (sample data, nothing is sent anywhere).

## Screens

| Tab | Route | What it shows |
|---|---|---|
| Overview | `/` | posture score, open / known-exploited / likely-exploited, assets exposed, attacks blocked, resolved + MTTR, SLA, criticality, at-risk assets, code, fix first, governance |
| Vulns | `/vulns`, `/vulns/:id` | filter chips (open, critical & high, KEV, EPSS, overdue, mine, resolved), search, finding detail with Note / Assign / Resolve |
| Attacks | `/attacks` | blocked events 24 h – 90 d, timeline, countries, blockers, busiest attackers, latest |
| Risk | `/governance`, `/risks/:id` | risk register + heat map, ISO 27001 progress and automated checks |
| More | `/more` | My work, Assets (`/assets/*`), Code, Data sources, app lock, appearance, privacy, sign out |

## Which server (first screen)

The app does not belong to one server. On the link screen the person enters the address of their OraSec server
(`orasec.example.com`). The app asks that address `GET /api/v2/orasec/mobile/server/` (public, no sign-in, answers
`{"product": "OraSec", …}`), keeps the address on the device and shows it above the link form with a **Change**
button. Changing the server unlinks the device from the old one. Store builds accept https addresses only.
Code: `src/config/serverConfig.ts`, `src/components/ServerStep.tsx`.

A publisher can set build values in `.env.store` (see `.env.store.example`): a default server for an organisation's
own build, the publisher name, the privacy and source links.

## Plugins

On the server every integration is a plugin that an administrator turns on or off (Automation → Plugins). The server
sends the list with `/me/`; the app hides what does not work there: the Attacks tab when no source feeds it, Ask Ora
when the assistant is off, Notifications when phone notifications are off. Data sources lists every plugin with its
state (read only). A server from before plugins existed sends no list and everything is shown.
Code: `src/plugins/pluginState.ts`.

## How a phone signs in (device linking)

There are no passwords in the app. Phones are **linked** instead:

1. On the web: Profile menu → **Mobile app** → *Create a link code* (`XXXXX-XXXXX`, 10 min, single use, stored hashed).
2. In the app: type the code → `POST /api/v2/orasec/mobile/link/` returns a device token `osm_…`
   (only its SHA-256 is stored server-side). The app keeps it in the Keychain / Keystore.
3. Every call sends `Authorization: Bearer osm_…`. Phones can be signed out from the web page or
   in the app (More → Sign out of this phone); tokens expire after 60 days idle.

Server code: `orasec/mobile/` (models, auth decorator with CORS + rate limits, API, web devices
page), migration `0313_orasec_mobile_devices`.

**Behind an access proxy:** if your OraSec console sits behind an access proxy (Cloudflare Access, an identity-aware
proxy, a VPN portal), the app cannot pass it. Let the path `/api/v2/orasec/mobile` through and keep the rest behind
the proxy. The OraSec device token is then the only gate on that path.

## Develop

```bash
npm ci                      # Node 22 or newer
npm run dev                 # browser preview on :5190, proxies /api to $ORASEC_DEV_API or http://localhost:8180
npx tsc --noEmit -p . && npx vitest --run
npm run android:build       # debug APK (cleartext allowed so the emulator reaches http://10.0.2.2:8180)
```

Development builds (`npm run dev`, `cap:sync`, `android:build`) read `.env.development.local` (see
`.env.development.example`): plain http allowed and ready-made test servers under the address field.
Store builds (`android:bundle`, `android:release`, `ios:release`) read `.env.store` and set `STORE_BUILD=1`
(https only, no test servers).

Android System WebView older than 111 shows `public/webview-update.html` instead of a blank screen
(`android.minWebViewVersion` in `capacitor.config.ts`).

Push notifications need your own Firebase project (Android `google-services.json`) and Apple push key; neither is
in this repository. Without them the app builds and runs, and notifications stay off.

