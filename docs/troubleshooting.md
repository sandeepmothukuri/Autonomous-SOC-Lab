# Troubleshooting

## docker compose config fails

Run `docker compose config` and read the error. Most commonly:

* Missing values in `.env` — ensure every `<GENERATE_*>` placeholder is
  replaced.
* A stale container on the `soc-net` subnet with a fixed IP — run
  `docker compose down` and try again.

## OpenSearch exits with "max virtual memory areas vm.max_map_count"

On Linux, increase `vm.max_map_count` (required by OpenSearch):

```bash
sudo sysctl -w vm.max_map_count=262144
```

For persistence, add `vm.max_map_count=262144` to `/etc/sysctl.conf`.

## StackStorm doesn't fire webhooks

1. Check that the pack is registered:
   `docker exec soc-stackstorm st2ctl status`
2. Re-run `bash scripts/setup-stackstorm.sh`.
3. Verify the `elastalert` webhook exists:
   `docker exec soc-stackstorm st2 webhook list`.
4. Check StackStorm logs: `docker logs soc-stackstorm --tail 200`.

## ElastAlert shows "No mapping found"

Wait for the `logs-*` index to exist after Vector ingests events,
then restart ElastAlert: `docker compose restart elastalert2`.
If no events are in the index yet, append synthetic events with
`python scripts/generate-events.py --scenario all`.

## IRIS returns 401

The workflow uses `{{ st2kv.system.iris_token }}`. Populate it:

```bash
docker exec soc-stackstorm st2 key set iris_token "your-iris-api-token"
```

In simulation mode cases may not be created; the workflow logs the
IRIS failure and still emits a completion message.

## Velociraptor API unreachable

`http://velociraptor:8889` is only reachable from within the Docker
network. The default workflow falls back to "simulation" logging when
the call fails. For `active` mode set `velociraptor_token` in
StackStorm's datastore.

## MISP doesn't start on first boot

MISP takes 30-90 seconds to initialize. Run
`bash scripts/health-check.sh` and wait for the MISP check to pass.
Check logs with `docker logs soc-misp --tail 200`.

## Caldera agent ports are exposed

Ports 7010/7012 are Caldera agent contact channels. They bind to
127.0.0.1 by default; never set `CALDERA_BIND_ADDRESS=0.0.0.0` on an
untrusted network.

## No alerts firing

1. Confirm Vector is running: `docker compose ps vector`.
2. Confirm events are in the index:
   `curl http://localhost:9200/logs-*/_count`.
3. Check ElastAlert logs: `docker logs soc-elastalert --tail 200`.
4. Verify `event.severity` and `event.type` match what the rule
   expects (see `docs/detection-engineering.md`).
