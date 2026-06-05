# ring_doorbell — implementation progress

Plan: `/home/steve/.claude/plans/sleepy-juggling-spring.md`
Protocol reference: `/home/steve/.claude/plans/sleepy-juggling-spring-agent-a968618cd98bac4a5.md`
push-receiver 4.3.1 source: `/tmp/push-receiver-ref/package/dist/`

## Tasks

- [x] 1. Scaffold: shard.yml deps (openssl_ext, protobuf, ameba), error.cr,
      state_file.cr, module file, CLAUDE.md, shards install, build green
- [x] 2. fcm/protos.cr (protobuf.cr `contract_of "proto2"` DSL) + round-trip spec
- [x] 3. fcm/ece.cr — HKDF (RFC 5869 vectors) + WebPush aesgcm decrypt + specs
- [x] 4. fcm/frame_parser.cr — MCS framing state machine + split-boundary spec
- [x] 5. auth.cr / rest.cr / device.cr / event.cr + fake_ring + specs
- [x] 6. LIVE: examples/init.cr + examples/devices.cr against real account
      (user checkpoint — find the audio-only doorbell, battery level)
- [x] 7. fcm/messages.cr / connection.cr / listener.cr + fake_mcs + specs
- [x] 8. fcm/registration.cr (checkin → c2dm → FIS → FCM) + fake-google specs
- [x] 9. client.cr + integration spec + examples/listen.cr + README
- [x] 10. LIVE: real doorbell ding test; format + ameba + full spec run

## Live findings (real account + hardware, 2026-06-05)

- The user's "audio-only doorbell" is a **Ring Intercom** (`intercom_handset_audio`,
  "Front Entrance", id 475457200), in the `other` array of ring_devices — the
  flattened `DeviceList#doorbells` picks it up.
- `ring_devices` reports `battery_life: "62"` (string) AND an embedded
  `health.battery_percentage: 62` (integer); but `GET /doorbots/{id}/health`
  returns `battery_percentage: "62"` (STRING!) and `battery_voltage: 3876.0`
  (millivolts as float). `Health` numeric fields are normalised accordingly.
- Intercoms subscribe with the standard `doorbots/{id}/subscribe` endpoint
  (verified in ring-client-api ring-intercom.ts and live — 2xx response).
- Full push pipeline worked first try against real Google: checkin → c2dm
  register → FIS → FCM registration; MCS login to mtalk.google.com accepted
  (LoginResponse; server immediately sends an IqStanza, tag 7 — ignorable).
- A REAL button press arrived and decrypted: category
  `com.ring.pn.live-event.intercom`, **subtype `button_press`** (not "ding"),
  device name/id present. Latency ≈ 1s from press to callback.
- Answering/unlocking from the app produces a v1-style push (`data.gcmData`
  with action `com.ring.push.INTERCOM_UNLOCK_FROM_APP`, no android_config) —
  classified as `Other`, surfaced via on_event only.

## Protocol facts verified from push-receiver 4.3.1 source (not just research)

- Ring passes only `{firebase, credentials, debug}` to PushReceiver → defaults apply:
  bundleId `receiver.push.com`, chromeVersion `94.0.4606.51` (login id
  `chrome-94.0.4606.51`; checkin still uses `63.0.3234.0`), vapidKey '' →
  c2dm `sender` = `BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4`
  and FCM `web.applicationPubKey` is OMITTED; heartbeat 5min; persistentIds [].
- MCS frames: `[tag][varint len][proto]`, version byte 0x29 prepended only before
  LoginRequest; server's first reply also has a version byte (>=41 or 38 accepted).
- No IqStanza acks are sent for data messages (push-receiver just logs them).
- Heartbeat: any inbound message resets the timers; ping carries
  last_stream_id_received only when it changed; missing ack for 2× interval →
  reconnect. streamId counts INBOUND handled messages.
- Reconnect backoff: min(retry_count, 15) seconds; persistent_ids sent in login,
  cleared on LoginResponse.
- LoginRequest field numbers: id=1 domain=2 user=3 resource=4 auth_token=5
  device_id=6 ("android-<hex androidId>") setting=8 (new_vc=1)
  received_persistent_id=10 adaptive_heartbeat=12 heartbeat_stat=13
  (ip="" timeout=true interval_ms) use_rmq2=14 auth_service=16 (2) network_type=17 (1)
- Checkin: AndroidCheckinRequest{checkin=4{cell_operator=6 sim_operator=7 roaming=8
  user_number=9 type=12 (3=CHROME_BROWSER) chrome_build=13{platform=1 (2=MAC)
  chrome_version=2 ("63.0.3234.0") channel=3 (1=STABLE)} last_checkin_msec=1 (0)}
  fragment=20 (0) logging_id=7 time_zone=12 user_serial_number=22 version=14 (3)
  id=2/security_token=13 when re-checking-in}; response android_id=7 fixed64,
  security_token=8 fixed64. POST application/x-protobuf.
- FIS fid: 17 random bytes, fid[0] = 0b01110000 + (fid[0] % 0b00010000), sent as
  PLAIN base64 (with padding, not urlsafe). headers x-goog-api-key +
  x-firebase-client = base64({"heartbeats":[],"version":2}). body {appId,
  authVersion:"FIS_v2", fid, sdkVersion:"w:0.6.6"} → authToken.token.
- FCM registration: POST fcmregistrations.googleapis.com/v1/projects/ring-17770/
  registrations, headers x-goog-api-key + x-goog-firebase-installations-auth;
  body web:{auth:<b64url authSecret>, endpoint:"https://fcm.googleapis.com/fcm/send/
  <gcmToken>", p256dh:<b64url 65B uncompressed pubkey>} → {token}.
- c2dm/register3: form-encoded app=org.chromium.linux, X-subtype=wp:receiver.push.com#<uuid>,
  device=<androidId>, sender=<default vapid>; Authorization: AidLogin id:token;
  response `token=<gcm token>`; retry up to 5 on body containing "Error".
- Decrypt: appData keys `encryption` (salt=) + `crypto-key` (dh=), http_ece aesgcm
  with authSecret; keys stored b64url. Decrypt failures are silently dropped
  (future messages decrypt fine) but persistent_id NOT recorded in that case
  (push-receiver returns before pushing the id — replicate).
- Decrypted plaintext = FCM message JSON; `.data` hash values are themselves JSON
  strings (parse each; on parse failure keep raw string). v2 Ring notification keys:
  android_config (category com.ring.pn.live-event.ding/.motion/.intercom),
  data.device.{id,kind,name}, data.event.ding.{id,created_at,subtype}.
  Big ding ids: parse leniently (keep as string on Int64 overflow).
- ring-client-api ignores notifications in the first 2s after connect (startup
  duplicates) — worth replicating as an option.
- Ring REST: PATCH clients_api/device registers push token (metadata
  {api_version, device_model, pn_dict_version:"2.0.0", pn_service:"fcm"},
  os:"android"); POST doorbots/{id}/subscribe needed per camera (re-run periodically).

## Review

All ten steps complete (2026-06-05):

- **77 specs, 0 failures** — the full stack is covered against in-process
  fakes: OAuth/2FA, REST (devices/health/push registration/subscribe, 401
  retry, refresh rotation), protobuf round-trips, RFC 5869 HKDF vectors,
  aesgcm encrypt/decrypt + tamper rejection, MCS framing at every split
  boundary, listener login/dedup/heartbeats/reconnect/replay-grace, the
  four-step Google registration, and a Client end-to-end (login → register →
  subscribe → encrypted push → on_ding).
- `crystal tool format --check` and `./bin/ameba` clean (34 files).
- **Live-verified end to end** on the real account: device discovery +
  battery (REST), push registration against real Google endpoints, MCS login
  to mtalk.google.com, and a real button press delivered + decrypted to the
  `on_ding` callback in ~1s. App-unlock pushes (v1 format) classified as
  Other without issues.

Not yet done: git commit/push (awaiting user instruction; no remote set).

## Lessons / corrections

- Ring type variance is worse than documented: the SAME field
  (`battery_percentage`) is an integer in one payload and a string in
  another. Never declare Ring numeric fields as `Int32?` — parse `JSON::Any`
  leniently (the first live `/health` call crashed on this).
- Model spec fakes on REAL responses once observed: fake_ring now serves
  `/health` battery as a string because the live endpoint does.
