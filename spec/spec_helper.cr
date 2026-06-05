require "spec"
require "../src/ring_doorbell"
require "./support/fake_ring"
require "./support/fake_mcs"

# Polls the block until it returns truthy, failing the spec on timeout.
def wait_until(timeout : Time::Span = 2.seconds, message : String = "condition not met in time", &)
  deadline = Time.instant + timeout
  until yield
    fail message if Time.instant > deadline
    sleep 10.milliseconds
  end
end

# Generates a complete, self-consistent set of push credentials for specs.
def spec_fcm_credentials : RingDoorbell::FCM::Credentials
  key = OpenSSL::PKey::EC.generate("P-256")
  RingDoorbell::FCM::Credentials.new(
    android_id: "5752962939",
    security_token: "1234509876",
    gcm_token: "spec-gcm-token",
    fcm_token: "spec-fcm-token",
    private_key: RingDoorbell::FCM::Credentials.encode(key.private_key_bytes),
    public_key: RingDoorbell::FCM::Credentials.encode(key.public_key_bytes),
    auth_secret: RingDoorbell::FCM::Credentials.encode(Random::Secure.random_bytes(16)),
  )
end

# A valid Ring v2 ding push, as the FCM data fields (each value is a JSON
# document serialised to a string, mirroring real payloads).
def spec_ding_data(device_id = 123_456, category = "com.ring.pn.live-event.ding") : Hash(String, String)
  {
    "android_config" => {category: category}.to_json,
    "data"           => {
      device: {id: device_id, kind: "doorbell_v3", name: "Front Door"},
      event:  {ding: {id: "7654321234567890123", created_at: "2026-06-05T10:00:00Z", subtype: "ding"}},
    }.to_json,
    "analytics" => {server_id: "com.ring.pns"}.to_json,
  }
end

# The decrypted FCM plaintext wrapping those data fields.
def spec_ding_plaintext(device_id = 123_456, category = "com.ring.pn.live-event.ding") : String
  {from: "876313859327", priority: "high", data: spec_ding_data(device_id, category)}.to_json
end
