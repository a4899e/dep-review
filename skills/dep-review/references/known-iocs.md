# Known live-threat IOCs

Check these before reading anything else. A match is an immediate `fail`.
Add campaigns here as they are published; keep each one's source link.

## CanisterSprawl (npm / PyPI install-time worm)

Package/version blocklist:

- `@automagik/genie` `4.260421.33` through `4.260421.40`
- `pgserve` `1.1.11` through `1.1.14`
- `@fairwords/websocket` `1.0.38` through `1.0.39`
- `@fairwords/loopback-connector-es` `1.4.3` through `1.4.4`
- `@openwebconcept/design-tokens` `1.0.1` through `1.0.3`
- `@openwebconcept/theme-owc` `1.0.1` through `1.0.3`

Strings and files:

- `telemetry.api-monitor.com`
- `cjn37-uyaaa-aaaac-qgnva-cai`, `cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io`
- `dist/env-compat.cjs`, `scripts/check-env.cjs`, `scripts/check-env.js`, `check-env.js`
- `node dist/env-compat.cjs || true`, `node scripts/check-env.cjs || true`
- `pkg-telemetry`, `dist-propagation-report`, `pypi-pth-exfil`
- `Technique: .pth file injection (TeamPCP/LiteLLM method)`
- `X-Session-ID`, `X-Request-Signature`
- `public.pem`
- SHA256 `c19c4574d09e60636425f9555d3b63e8cb5c9d63ceb1c982c35e5a310c97a839`
- SHA256 `834b6e5db5710b9308d0598978a0148a9dc832361f1fa0b7ad4343dcceba2812`
- RSA DER fingerprint `87259b0d1d017ad8b8daa7c177c2d9f0940e457f8dd1ab3abab3681e433ca88e`

```bash
rg -n --hidden -S \
  -e 'telemetry\.api-monitor\.com' \
  -e 'cjn37-uyaaa-aaaac-qgnva-cai' \
  -e 'env-compat\.cjs|check-env\.cjs|check-env\.js' \
  -e 'pkg-telemetry|dist-propagation-report|pypi-pth-exfil' \
  -e 'TeamPCP/LiteLLM|X-Session-ID|X-Request-Signature' \
  -e '87259b0d1d017ad8b8daa7c177c2d9f0940e457f8dd1ab3abab3681e433ca88e' \
  "$WORK/<PKG>-<VER>/"
```

## AI-CLI secret hunting (s1ngularity / Nx, August 2025)

Malicious `nx` releases ran a postinstall that invoked locally installed AI
CLIs with permission bypasses to search the machine for credentials and
wallets. `scan-agent-directives.py` flags this shape under `agent-hijack`:

- `claude --dangerously-skip-permissions`, `gemini --yolo`, `q chat --trust-all-tools`
- prompts that enumerate the filesystem for `.env`, keystores, wallet files
- results written to a file such as `/tmp/inventory.txt` and uploaded to a
  newly created public GitHub repo
