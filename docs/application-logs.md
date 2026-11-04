# Shared application logs

Authserver writes structured diagnostics to stdout and can export the same
events to the Typesense collection `application_logs_v1`. Another API can write
to the same collection with its own `service` value, such as
`vefacaglar-site-api`, using the [collection schema](../deploy/application_logs_v1.json).

| Field | Meaning |
| --- | --- |
| `timestamp` | UTC Unix time in milliseconds |
| `service` | Stable service name. Authserver uses `authserver-go`. |
| `environment` | Deployment environment, such as `development` or `production` |
| `level` | `info`, `warning`, `error`, or `critical` |
| `event` | Stable snake_case identifier, such as `login_failed` |
| `message` | Developer-authored description of the operation or failure |
| `request_id`, `http_method`, `http_route`, `http_status` | Optional HTTP metadata. Use the server-generated ID and the matched route template. |
| `response_code`, `response_message` | Optional application response code and developer-authored public description |
| `error_type`, `error_code` | Optional cause type and stable reason, such as `deadline_exceeded` or `sqlstate_23505` |
| `source`, `stack` | Optional code location and panic frames without argument values |

Go emits these through `slog.InfoContext`, `WarnContext`, `ErrorContext` and
`Log(ctx, errlog.LevelCritical, ...)`. Give exported info records an explicit
`event` attribute. Authserver reserves critical for future use. Warnings include
login rejections such as invalid credentials, invalid CSRF, locked accounts,
malformed JSON and rate limits. A login backend failure records the failed
operation and the safe cause. An HTTP 5xx also has a status event, which can be
correlated with a more specific error by `request_id`. The same ID is returned
in the `X-Request-Id` response header. Other requests do not generate access logs.

Keep request and response bodies, raw URLs and query strings, headers, IP
addresses, user identifiers, credentials, tokens, and raw exception messages
out of this collection. Use fixed event messages and response descriptions.
Any frontend consumer needs a separate, collection-scoped read credential
and must keep it on an operator-only server.

## Provision and enable

Create the collection once using an administrative key. Use a separate
collection-scoped credential with only `documents:create` for each writer.
[Typesense API key scopes](https://typesense.org/docs/30.1/api/api-keys.html)

```sh
curl --fail-with-body -X POST "$TYPESENSE_URL/collections" \
  -H "X-TYPESENSE-API-KEY: $TYPESENSE_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @deploy/application_logs_v1.json

curl --fail-with-body -X POST "$TYPESENSE_URL/keys" \
  -H "X-TYPESENSE-API-KEY: $TYPESENSE_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"description":"Authserver log writer","actions":["documents:create"],"collections":["application_logs_v1"]}'
```

Set `AUTH_LOG_TYPESENSE_URL` to the Typesense base URL reachable by the
authserver process. Use HTTPS for a remote endpoint. Set
`AUTH_LOG_TYPESENSE_API_KEY` to the returned write key. For production, supply
both entries through the GitHub Actions `AUTH_ENV` secret and redeploy. Docker
Compose sets `AUTH_LOG_ENVIRONMENT=production`. The local default is
`development`.

To inspect recent login failures, use a private read key with
`documents:search` on the collection:

```sh
curl --fail-with-body --get "$TYPESENSE_URL/collections/application_logs_v1/documents/search" \
  -H "X-TYPESENSE-API-KEY: $TYPESENSE_READ_KEY" \
  --data-urlencode 'q=*' \
  --data-urlencode 'query_by=message' \
  --data-urlencode 'filter_by=service:=authserver-go && event:=login_failed' \
  --data-urlencode 'sort_by=timestamp:desc'
```

Export runs on a bounded background queue. If delivery fails or the queue
fills, the event remains available in stdout logs. Export does not retry
failed writes. Collection retention is managed by the operator.
