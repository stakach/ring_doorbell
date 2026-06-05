require "../spec_helper"

private def build_listener(credentials, fake : FakeMCS, *,
                           persistent_ids = [] of String,
                           heartbeat = 30.seconds,
                           grace = 0.seconds) : RingDoorbell::FCM::Listener
  RingDoorbell::FCM::Listener.new(credentials, persistent_ids,
    host: "127.0.0.1", port: fake.port, tls: false,
    heartbeat_interval: heartbeat,
    login_timeout: 2.seconds,
    startup_grace: grace)
end

describe RingDoorbell::FCM::Listener do
  it "logs in and receives a decrypted notification end to end" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake)
      received = [] of JSON::Any
      connected = false
      listener.on_connected { connected = true }
      listener.on_notification { |json| received << json }
      listener.start
      begin
        wait_until { connected }

        login = fake.login_requests.first
        login.user.should eq(credentials.android_id)
        login.auth_token.should eq(credentials.security_token)

        fake.push(spec_ding_plaintext)
        wait_until { received.size == 1 }
        received.first.dig("data", "android_config").as_s.should contain("live-event.ding")
      ensure
        listener.stop
      end
    end
  end

  it "deduplicates messages by persistent id" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake)
      received = 0
      connected = false
      listener.on_connected { connected = true }
      listener.on_notification { received += 1 }
      listener.start
      begin
        wait_until { connected }
        fake.push(spec_ding_plaintext, persistent_id: "dup-1")
        wait_until { received == 1 }
        fake.push(spec_ding_plaintext, persistent_id: "dup-1")
        fake.push(spec_ding_plaintext, persistent_id: "fresh-2")
        wait_until { received == 2 }
        sleep 50.milliseconds
        received.should eq(2)
      ensure
        listener.stop
      end
    end
  end

  it "ignores ids already seen before starting (restart dedup)" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake, persistent_ids: ["old-1"])
      received = 0
      connected = false
      listener.on_connected { connected = true }
      listener.on_notification { received += 1 }
      listener.start
      begin
        wait_until { connected }
        # the login request replayed the stored ids to the server
        fake.login_requests.first.received_persistent_id.should eq(["old-1"])

        fake.push(spec_ding_plaintext, persistent_id: "old-1")
        fake.push(spec_ding_plaintext, persistent_id: "new-1")
        wait_until { received == 1 }
        sleep 50.milliseconds
        received.should eq(1)
      ensure
        listener.stop
      end
    end
  end

  it "reports persistent ids for persistence and clears them after login" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake, persistent_ids: ["old-1"])
      updates = [] of Array(String)
      connected = false
      listener.on_connected { connected = true }
      listener.on_persistent_ids { |ids| updates << ids }
      listener.start
      begin
        wait_until { connected }
        updates.last.should be_empty # delivered with login, then cleared

        fake.push(spec_ding_plaintext, persistent_id: "msg-9")
        wait_until { updates.last == ["msg-9"] }
      ensure
        listener.stop
      end
    end
  end

  it "answers server heartbeat pings" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake)
      connected = false
      listener.on_connected { connected = true }
      listener.start
      begin
        wait_until { connected }
        fake.send_ping
        wait_until { fake.heartbeat_acks.size == 1 }
      ensure
        listener.stop
      end
    end
  end

  it "sends heartbeat pings after the configured silence" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake, heartbeat: 80.milliseconds)
      connected = false
      listener.on_connected { connected = true }
      listener.start
      begin
        wait_until { connected }
        wait_until { !fake.heartbeat_pings.empty? }
      ensure
        listener.stop
      end
    end
  end

  it "reconnects when the server drops the connection" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake)
      connections = 0
      received = 0
      listener.on_connected { connections += 1 }
      listener.on_notification { received += 1 }
      listener.start
      begin
        wait_until { connections == 1 }
        fake.drop_clients
        wait_until(5.seconds) { connections == 2 }

        # still receives pushes after the reconnect
        fake.push(spec_ding_plaintext)
        wait_until { received == 1 }
      ensure
        listener.stop
      end
    end
  end

  it "reconnects when the server requests a close" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake)
      connections = 0
      listener.on_connected { connections += 1 }
      listener.start
      begin
        wait_until { connections == 1 }
        fake.send_close
        wait_until(5.seconds) { connections == 2 }
      ensure
        listener.stop
      end
    end
  end

  it "drops undecryptable pushes without crashing" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake)
      received = 0
      connected = false
      listener.on_connected { connected = true }
      listener.on_notification { received += 1 }
      listener.start
      begin
        wait_until { connected }

        # garbage ciphertext with valid-looking crypto headers
        fake.push_message(RingDoorbell::FCM::DataMessageStanza.new(
          id: "bad-1",
          app_data: [
            RingDoorbell::FCM::AppData.new(key: "encryption", value: "salt=#{RingDoorbell::FCM::Credentials.encode(Random::Secure.random_bytes(16))}"),
            RingDoorbell::FCM::AppData.new(key: "crypto-key", value: "dh=#{RingDoorbell::FCM::Credentials.encode(OpenSSL::PKey::EC.generate("P-256").public_key_bytes)}"),
          ],
          persistent_id: "bad-1",
          raw_data: Random::Secure.random_bytes(48),
        ))
        # ... followed by a good push: the listener must still be alive
        fake.push(spec_ding_plaintext)
        wait_until { received == 1 }
        received.should eq(1)
      ensure
        listener.stop
      end
    end
  end

  it "drops pushes whose sent timestamp is older than stale_after" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake)
      received = 0
      connected = false
      listener.on_connected { connected = true }
      listener.on_notification { received += 1 }
      listener.start
      begin
        wait_until { connected }
        fake.push(spec_ding_plaintext, sent: Time.utc - 5.minutes)
        sleep 100.milliseconds
        received.should eq(0)

        # a fresh one still gets through
        fake.push(spec_ding_plaintext)
        wait_until { received == 1 }
      ensure
        listener.stop
      end
    end
  end

  it "delivers recent pushes even right after connecting (reconnect gap)" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      # huge grace window: only the sent timestamp may save the message
      listener = build_listener(credentials, fake, grace: 10.seconds)
      received = 0
      connected = false
      listener.on_connected { connected = true }
      listener.on_notification { received += 1 }
      listener.start
      begin
        wait_until { connected }
        # a press that happened seconds ago (e.g. while reconnecting) must ring
        fake.push(spec_ding_plaintext, sent: Time.utc - 2.seconds)
        wait_until { received == 1 }
      ensure
        listener.stop
      end
    end
  end

  it "falls back to the startup grace for pushes without a timestamp" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake, grace: 10.seconds)
      received = 0
      connected = false
      listener.on_connected { connected = true }
      listener.on_notification { received += 1 }
      listener.start
      begin
        wait_until { connected }
        fake.push(spec_ding_plaintext, sent: nil)
        sleep 100.milliseconds
        received.should eq(0)
      ensure
        listener.stop
      end
    end
  end

  it "resets the reconnect backoff after each successful session" do
    credentials = spec_fcm_credentials
    with_fake_mcs(credentials) do |fake|
      listener = build_listener(credentials, fake)
      connections = 0
      listener.on_connected { connections += 1 }
      listener.start
      begin
        wait_until { connections == 1 }

        # each drop follows a logged-in session, so every reconnect delay
        # must be the base 1s — without the reset the third would take 3s+
        3.times do |round|
          fake.drop_clients
          wait_until(2.seconds, "reconnect #{round + 2} took longer than the base delay") do
            connections == round + 2
          end
        end
      ensure
        listener.stop
      end
    end
  end
end
