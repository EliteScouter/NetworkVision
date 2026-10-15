# Contributing

Thanks for helping make NetworkVision better!

## Ground rules

- **Never commit secrets.** No real IPs, API keys, communities, or `.env` files. Tests and fixtures use
  RFC 5737 documentation addresses (`192.0.2.0/24`) and obviously fake values.
- Keep vendor-specific code inside its collector. Everything else only sees the normalized `Snapshot`.
- Run `pytest`, `ruff check app tests` (backend) and `npm run build` (frontend) before opening a PR.

## Adding an integration

1. Create `backend/app/collectors/<vendor>.py` and subclass `Collector` (or `HttpCollector` for REST APIs).
2. Declare `fields` with `FieldSpec`. Mark credentials `secret=True` so they get encrypted and masked.
3. Implement `async def collect(self) -> Snapshot`. Raise `CollectorError` for user-actionable failures.
   Return raw interface counters and NetworkVision computes the rates.
4. Register it in `collectors/registry.py`.
5. Add vendor data the dashboard has no dedicated view for as `Section`s. They render automatically.

The demo collector (`collectors/demo.py`) is a good reference for the full snapshot shape.

## Development setup

See the *Development* section of the README.
