# Argus

**One hub, one MCP server and one CLI over every router, access point and VPN in a home network.**

Most homes run three or four networking devices from three or four vendors, and every one of them
has its own admin page, its own login, its own vocabulary and its own idea of what a "band" is. The
answers you actually want, *what is broadcasting right now*, *is anything open*, *is my traffic
going through the tunnel*, are spread across all of them, so nobody ever checks.

Argus puts one driver in front of each device, exposes every capability three ways, and answers
those questions in one call.

```
┌──────────┐   ┌──────────┐   ┌──────────┐
│   MCP    │   │   Hub    │   │   CLI    │      three faces
└────┬─────┘   └────┬─────┘   └────┬─────┘
     └──────────────┼──────────────┘
              registry.invoke()                 one dispatch path
                    │
     ┌──────────────┼──────────────┬───────────────┐
  gateway          ap             plug            vpn        pluggable drivers
  (SOAP-ish)     (SOAP +        (ubus            (REST +
                  form POST)     JSON-RPC)        CLI)
```

Named for Argus Panoptes, the herdsman of a hundred eyes who never closed more than half of them at
once. When he was killed, his eyes were set into the peacock's tail. The watching turned into
something you could look at. That is the whole design: the devices were always reporting, but
nothing was ever looking.

---

## Why this exists

There is no shortage of software for *one* of these things. Every vendor ships an app. OpenWrt has
LuCI. Tailscale has an admin console. Grafana can graph any of it.

There appears to be nothing that aggregates **consumer router admin interfaces across vendors** into
one surface. A survey of 31 sources turned up zero projects doing it. Plenty of single-vendor
libraries, plenty of homelab dashboards that link out to each device's own web UI, nothing that
reads and writes them through a shared interface. Argus is an attempt at that missing layer.

---

## What you get

| | |
|---|---|
| **Read everything at once** | `argus overview` probes every device in parallel and reports what each one says it is. |
| **One security verdict** | `argus posture` reads gateway, access points and VPN together and answers *am I exposed right now*, with the reasons. |
| **Agent access** | 4 meta tools plus one MCP tool per capability, generated from the drivers. Adding a device to the config adds its tools. |
| **A local web hub** | Device cards, live state, the posture panel, and a runner for any capability. Loopback-bound. |
| **Guards that hold** | A band or SSID named in `guard` is refused by the core before the driver is called, no matter which face the call came from. |

### Included drivers

- **`devolo-dlan`**: devolo powerline adapters (firmware 6.x, OpenWrt + ubus underneath). Live radio
  state, air scan, client list, SSID rename, guest-network control.
- **`netgear-nighthawk`**: NETGEAR RAX / R series. SOAP for reads and radio toggles; the web UI's
  `apply.cgi` form for what SOAP refuses.
- **`telekom-speedport`**: Telekom Speedport (Sercomm firmware). Status, arbitrary `/data` pages,
  and a discovery capability that reports which pages a given firmware actually answers.
- **`tailscale`**: tailnet device list, exit-node inventory, route approval, policy-file read, and
  exit-node switching (see the note below, since the REST API cannot do it, and that surprises people).

---

## Quickstart

```bash
git clone <this repo> argus && cd argus && npm install
cp .env.example .env                       # fill in hosts and passwords
cp argus.config.example.json argus.config.json
node bin/argus.mjs doctor                  # config loads? drivers resolve? no device contacted
node bin/argus.mjs overview                # now actually talk to them
node bin/argus.mjs posture
node bin/argus.mjs hub                     # http://127.0.0.1:4380
```

Register the MCP server with any MCP client:

```bash
claude mcp add argus -- node /absolute/path/to/argus/bin/argus-mcp.mjs
```

### CLI

```
argus overview                      every device, does it answer, what is it
argus posture [--json]              the security verdict
argus caps [--kind=write]           every capability reference
argus run <ref> '{"json":true}'     invoke one   (add --confirm to apply a write)
argus hub                           serve the web surface
argus doctor                        config check, nothing contacted
```

---

## Configuration

Two files, and only one of them is ever shareable.

**`.env`** holds every address and credential. Never committed, never logged, never returned by a
capability.

**`argus.config.json`** describes the devices, referencing secrets as `${VAR}`:

```json
{
  "devices": [
    { "id": "ap", "driver": "netgear-nighthawk", "role": "ap",
      "host": "${AP_HOST}", "password": "${AP_PASSWORD}",
      "guard": { "bands": ["5g1"], "ssids": [] } }
  ],
  "policy": { "confirmWrites": true, "allowRestart": false, "hubBind": "127.0.0.1", "hubPort": 4380 }
}
```

A `${VAR}` that is unset makes `argus doctor` fail loudly, rather than letting a device quietly drop
out of the picture.

### `guard`, the rule every home network turns out to need

There is always one radio you must not interrupt. A VR headset's dedicated band, a printer that will
never be re-paired, an IoT SSID full of devices that choke on a rename. Name the band or the SSID in
`guard` and every write capability refuses it in the core, before any driver runs:

```
GUARDED: ap: band "5g1" is guarded in this config and will not be written
```

---

## Security model

- **Loopback by default.** The hub holds admin credentials for every device you list. If you move it
  off `127.0.0.1`, put something that authenticates in front of it.
- **Secrets never come back out.** The core strips values under secret-shaped keys on every return
  path. Where a comparison is genuinely needed, *is the 5 GHz key the same as the 2.4 GHz key?*, it
  returns a sha256 fingerprint and a length instead of the value.
- **Writes are confirmed twice.** `confirmWrites` makes every state-changing capability refuse
  without an explicit `confirm: true`, and most write capabilities additionally default to
  `dryRun: true`, so the first call reports a plan.
- **Restarts are not registered at all** unless `policy.allowRestart` is on. A capability that does
  not exist cannot be called by mistake.

---

## Writing a driver

A driver is one file. It declares what config it needs and returns a list of capabilities:

```js
import { z } from 'zod'
import { defineDriver, defineCapability } from 'argus-hub/driver'

export default defineDriver({
  type: 'my-router',
  title: 'My Router (AC1200)',
  vendor: 'Acme',
  requires: ['host', 'password'],

  create(device) {
    return {
      async probe() { return { ok: true, identity: { model: 'AC1200' } } },
      capabilities: [
        defineCapability({
          name: 'wifi.read',
          title: 'Read wireless state',
          kind: 'read',                    // read | diagnose | write | restart
          input: z.object({}),
          run: async () => ({ ssid: '…' }),
        }),
      ],
    }
  },
})
```

Point a device at it with `"driver": "./drivers/my-router.mjs"` and it appears in the CLI, the hub
and the MCP tool list at once. There is nothing else to register.

`kind` is the entire permission model. The driver never decides what is risky. It says what a
capability *is*, and the core decides what that costs.

---

## Known limits, stated plainly

- **NETGEAR 5 GHz SSIDs cannot be renamed** on firmware V1.0.19.172. Every `Set5G*SSID` and
  `Set5G*WLANWPAPSKByPassphrase` answers SOAP code 402, and the web UI's `apply.cgi` answers a
  400 with an identical 382-byte body to a faithfully reconstructed form POST. Referer, URL shape,
  body size, field count, content type and the ~70 hidden mirror fields have each been eliminated
  with a control run. The eliminations are documented in
  [`wlan-form.mjs`](src/drivers/netgear-nighthawk/wlan-form.mjs) so the next person does not repeat
  them. Reading the form works; writing it does not.
- **Tailscale's REST API cannot change which exit node a client uses.** It can approve a device *as*
  an exit node, which is a different thing that shares a name. Remote switching requires either the
  client's own web interface on port `5252`, which needs the device tagged, the client started with
  `tailscale set --webclient`, and a tailnet policy granting `canEdit: exitNodes`, or SSH plus
  `tailscale set --exit-node`. Both paths are implemented; the API one is not, because it does not
  exist.
- **Speedport page names vary by firmware.** Only `Login` and `Status` are assumed. Run
  `gateway.pages.discover` to find the rest on your box.

---

## Licence

Apache 2.0. See `LICENSE` and `NOTICE`.
