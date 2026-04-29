"""Configuration loader — TOML config + VibeLock secrets."""

# TODO: Settings class
#   - Load defaults.toml + user overlay (deep merge)
#   - Load secrets from secrets.vibe via vibelock-python
#   - Dot-notation access: settings.get("pipeline.batch_size")
#   - Async get_secret(key) for individual secret retrieval
