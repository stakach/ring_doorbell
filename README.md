# ring_doorbell

A Crystal client for Ring doorbells:

- **Real-time ding events** — someone pressed the doorbell — delivered via
  Google FCM push (the same mechanism the official Ring app uses)
- **Device status** — name, kind, online/offline
- **Battery level** — on-demand via the device health endpoint

Ring has no local API; everything goes through the Ring cloud. Real-time
events are *push*, not polling: the library performs a one-time registration
as a push receiver (GCM check-in → Firebase installation → FCM registration,
a Crystal port of [`@eneris/push-receiver`](https://github.com/eneris/push-receiver))
and then holds a persistent connection to `mtalk.google.com:5228`, speaking
Google's MCS protocol with WebPush (`aesgcm`) payload decryption. Dings
arrive within a second or two of the button press.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  ring_doorbell:
    github: stakach/ring_doorbell
```

Then run `shards install`.

## Setup (one time)

Ring logins need email + password + a 2FA code. Run the interactive init to
obtain and persist a refresh token:

```bash
crystal run examples/init.cr -- data/ring.token
```

The token file is JSON holding the refresh token, a stable hardware id, the
FCM push credentials (created on first listen) and recently seen push ids.
Guard it like a password.

## Usage

```crystal
require "ring_doorbell"

client = RingDoorbell::Client.new(token_file: "data/ring.token")

# ----- status / battery (REST) -----
client.doorbells.each do |bell|
  puts "#{bell.name} (#{bell.kind}) online=#{bell.online?} battery=#{bell.battery_level}%"
end
client.battery_level(doorbell_id) # freshest reading, from the health endpoint

# ----- real-time events (FCM push) -----
client.on_ding do |event|
  puts "DING! #{event.device_name} at #{event.created_at}"
end
client.on_motion { |event| puts "motion at #{event.device_name}" }

client.listen # registers push credentials on first run, then connects
sleep         # events arrive on a background fiber

client.stop
```

Notes:

- Callbacks run on the push connection's read fiber — keep them quick, or
  `spawn` long-running work.
- The listener reconnects automatically (with backoff) and deduplicates
  re-delivered messages, including across restarts.
- Notifications replayed in the first seconds after connecting are dropped —
  a doorbell must not ring for stale events.
- Intercom buzz events are treated as dings.
- `on_event` sees every recognised push, including kinds not mapped to
  ding/motion (inspect `event.raw`).

## Examples

| Example | Purpose |
|---------|---------|
| `examples/init.cr` | Interactive login (email/password/2FA) → token file |
| `examples/devices.cr` | Dump raw + parsed device list (debugging unusual hardware) |
| `examples/listen.cr` | Live ding/motion printer (`LOG_LEVEL=debug` for protocol logs) |

## Development

- `crystal spec` — the entire protocol stack is covered against in-process
  fakes (OAuth + clients_api + Google registration endpoints over HTTP, and a
  real MCS server over TCP with genuinely encrypted pushes). No network, no
  credentials needed.
- `crystal tool format` / `./bin/ameba` — format and lint.

Protocol notes live in `tasks/todo.md` (field numbers, constants and the
quirks of Google's checkin/MCS endpoints, verified against
`@eneris/push-receiver` 4.3.1 and `ring-client-api`).

## Contributing

1. Fork it (<https://github.com/stakach/ring_doorbell/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Stephen von Takach](https://github.com/stakach) - creator and maintainer
