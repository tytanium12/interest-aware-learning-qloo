# Interest-Aware Learning — guarded hosted hackathon release

The hosted entrypoint is `hosted_server.py`. The local development server remains loopback-only. Building and running the offline test suite make no paid Qloo, Tavily, or OpenAI API requests.

## Decision and preflight

- Hosting: Render Free Python web service from this reviewed release repository. Keep the repository private during deployment testing, then make it public for contest judging after completing the release checks.
- Persistence: a separately provisioned Upstash Redis REST database. `EVAL` atomically reserves one global generation allowance **before** any provider calls. Reservations are not refunded (including provider failures). The quota key MUST remain the same across restarts and redeploys. This is a maximum number of billed attempts, **not a dollar guarantee**.
- Safety: `HOSTED_LIVE_ENABLED=0` disables live generation. `HOSTED_PUBLIC_DEMO=0` (default) retains judge-code authentication. `HOSTED_PUBLIC_DEMO=1` opens the learning studio to visitors without a code, but durable Upstash quota, provider credentials, model, and per-request bounds remain mandatory. Public visitors consume the shared allowance; it is not a dollar-denominated cap.
- Hosting charges and third-party usage are NOT pre-authorized by this package. Set an explicit budget and confirm actual quotas before enabling. Render Free can cold-start after idle; check available free-plan usage. Review Upstash terms/free limits when creating the account.

## Setup

1. Run `python -B -m unittest discover -s tests -p 'test*.py' -q` against this repository and confirm that all tests pass.
2. Review the source, README, license, hosting configuration, and credential-handling instructions. Do not commit API keys or private environment files.
3. Deploy the application from this release repository; keep it private while staging and make it public only after a successful hosted live test and a final security review.
4. Create an Upstash Redis database with REST credentials. Keep both its REST URL and token secret. Choose a quota key unique to this deployment that is not reset or changed mid-judging.
5. Create a Render Free Web Service from the new public repo. Blueprint `render.yaml` is included. `HOSTED_LIVE_ENABLED` initially stays `0`. The service should display its limited judge landing page and `/health` even before live credentials are configured.
6. Configure Render environment variables using `.env.example` as a list of names, not as a literal secrets file. Render injects `RENDER_EXTERNAL_URL` and `PORT`. Provide `HOSTED_JUDGE_CODE` (random 16+ characters) and `HOSTED_COOKIE_SECRET` (independent random 32+ characters). Set `QLOO_API_KEY`, `OPENAI_API_KEY`, and an authorized `OPENAI_MODEL` through secret environment variables.
7. **Tavily adapter requires a key FILE.** Upload the Tavily key as a Render Secret File at `/etc/secrets/tavily_api_key`; set `TAVILY_API_KEY_FILE` to that absolute path. Do not set direct key and key-file override for Qloo or OpenAI simultaneously. Do not copy vault paths from Windows.
8. After service is healthy and provider balances/permissions have been verified, set `HOSTED_LIVE_ENABLED=1` as an explicitly approved release action. Perform ONE small live judge-access test with a public source and inspect Qloo, Tavily, and OpenAI provenance. The test will consume one allowance. If any part fails, revert `HOSTED_LIVE_ENABLED=0` while diagnosing.
9. For direct judge access, set `HOSTED_PUBLIC_DEMO=1` on Render and redeploy. Check that an incognito browser opens the studio without a login, `/judge-access` returns 404, and the same global Upstash quota remains in place. Restore the previous login mode by setting `HOSTED_PUBLIC_DEMO=0`.
10. Submit before October 30, 2026 at 11:45 p.m. EDT (8:45 p.m. PDT). Keep the public demo accessible through the official November 5 judging period; monitor service and quota daily.

## Required proof before submission

- Public repo is appropriately licensed, secret-free, contains necessary application files and deployment instructions, and public history has been reviewed.
- Hosted `/health` returns `{"status":"ok","service":"interest-aware-learning"}`.
- Public visitors can reach the studio without a cookie. Invalid origins and inputs are rejected before quota reservation; valid requests reserve quota before provider calls. With public demo off, judge-code authentication still applies.
- A real hosted lesson is generated, with research references when accepted; no fabricated Qloo affinity scores.
- Restart/redeploy does NOT restore spent generations. Quota outage refuses requests, and `HOSTED_LIVE_ENABLED=0` stops live usage.
- Verify which Render service has been deployed and the source commit; inspect sanitized logs; confirm no raw source text, personal data, or credentials are logged.

## Financial guardrails

The global allowance defaults to 200 generation **attempts** (the validated configuration ceiling is 500). Each attempt may use bounded Qloo/Tavily/OpenAI transport/retries under existing per-request limits. Upstash counters are atomic and durable across web restarts, and fail closed on missing/invalid responses. A transient quota response failure may still consume an allowance. This does not create a strict USD spending cap across providers. Also set provider-specific billing caps/alerts where supported; do not mistake an alert for a hard cap. Reserve sufficient allowances for judges after the one live test. Changing `HOSTED_QUOTA_KEY` resets the counter; **do not rotate it during judging**.

## Emergency disable

In the Render environment set `HOSTED_LIVE_ENABLED=0` and redeploy. This disables the generation endpoint regardless of other environment settings. To preserve browser access to the landing page and `/health`, leave the service running. Independently revoke provider keys if compromise is suspected. Do not delete the Redis quota key or reuse keys from unrelated deployments.
