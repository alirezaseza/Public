# KestrelVPN
Android VPN client (Kotlin, Jetpack Compose, sing-box core) that pulls a public subscription, benchmarks servers in short ping-first chunks and connects to the best one.

## Highlights
- Instant connect to the cached best server; first run connects as soon as one good server is found.
- Silent background ranking (skipped when connected, offline or Data Saver is on).
- Iran-direct routing, per-app split tunneling, favorites, usage stats, quick-settings tile, kill-switch on failover.
- Authenticated local probe proxy (see SECURITY.md).
- "Reduce visual effects" mode (automatic on low-RAM devices); fa/en with full RTL.

See `docs/ARCHITECTURE.md` for how the pieces fit together.

## Build
1. `bash scripts/build-libbox.sh` (needs Go; produces `app/libs/libbox.aar`).
2. Copy `local.properties.example` / `keystore.properties.example` and fill them in.
3. `./gradlew testDebugUnitTest assembleDebug`.
4. Set `SubscriptionConfig.DEFAULT_SUBSCRIPTION_URL` to your repo.

## Config repo
The workflow `.github/workflows/collect-configs.yml` runs every 30 minutes: `scripts/collect_configs.py` reads the Telegram channels in `channels.txt`, keeps links posted in the last 25 hours that the app can run and that answer a quick TCP test, and commits them to `sub/all.txt`. Point `SubscriptionConfig.DEFAULT_SUBSCRIPTION_URL` at the raw URL of that file.

## Release checklist
Verify libbox version, test release (minified) build on a real device on Wi-Fi + 2 mobile operators, complete Play's VPN and foreground-service declarations, keep 16 KB page-size compatibility for native libs.

## Status
Statically reviewed and hardened (68+ unit tests written, CI configured), but **not yet compiled or device-tested in the review environment**. Follow `docs/DEVICE_TEST_CHECKLIST.md` before publishing. See `SECURITY.md` for the threat model and known limits.
