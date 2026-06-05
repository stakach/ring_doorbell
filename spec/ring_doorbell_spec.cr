require "./spec_helper"

private def with_client(fake : FakeRing, mcs : FakeMCS, token_file : String, &)
  client = RingDoorbell::Client.new(
    token_file: token_file,
    oauth_url: fake.oauth_url,
    rest_base: fake.rest_base,
    mcs_host: "127.0.0.1",
    mcs_port: mcs.port,
    mcs_tls: false,
    checkin_url: fake.checkin_url,
    register_url: fake.register_url,
    fis_base: fake.fis_base,
    fcm_base: fake.fcm_base,
    startup_grace: 0.seconds,
    login_timeout: 2.seconds,
  )
  begin
    yield client
  ensure
    client.stop
  end
end

private def spec_token_file(name : String) : String
  path = File.join(Dir.tempdir, "ring_doorbell_spec_#{name}_#{Process.pid}.json")
  File.delete?(path)
  path
end

describe RingDoorbell::Client do
  it "logs in (with 2FA), persists state and reads devices + battery" do
    with_fake_ring do |fake|
      fake.require_2fa = true
      token_file = spec_token_file("login")
      mcs = FakeMCS.new(spec_fcm_credentials)
      mcs.start
      begin
        with_client(fake, mcs, token_file) do |client|
          client.authenticated?.should be_false

          expect_raises(RingDoorbell::TwoFactorRequired) do
            client.login(fake.email, fake.password)
          end
          client.login(fake.email, fake.password, fake.two_fa_code)
          client.authenticated?.should be_true

          bells = client.doorbells
          bells.size.should eq(1)
          bells.first.name.should eq("Front Door")
          client.doorbell(111_222).should_not be_nil
          client.battery_level(111_222).should eq(81)

          # state persisted
          state = RingDoorbell::StateFile.load(token_file)
          state.refresh_token.should_not be_nil
          state.hardware_id.should_not be_empty
        end

        # a new client picks the state straight up
        with_client(fake, mcs, token_file) do |client|
          client.authenticated?.should be_true
          client.doorbells.size.should eq(1)
        end
      ensure
        mcs.stop
        File.delete?(token_file)
      end
    end
  end

  it "delivers dings end to end: register, subscribe, push, callback" do
    with_fake_ring do |fake|
      token_file = spec_token_file("e2e")
      mcs = FakeMCS.new(spec_fcm_credentials)
      mcs.start
      begin
        with_client(fake, mcs, token_file) do |client|
          client.login(fake.email, fake.password)

          dings = [] of RingDoorbell::DingEvent
          motions = [] of RingDoorbell::DingEvent
          events = [] of RingDoorbell::DingEvent
          client.on_ding { |event| dings << event }
          client.on_motion { |event| motions << event }
          client.on_event { |event| events << event }

          client.listen
          client.listening?.should be_true

          # registration ran and was persisted
          state = RingDoorbell::StateFile.load(token_file)
          credentials = state.fcm || fail "expected push credentials to be persisted"
          credentials.fcm_token.should eq("fake-fcm-token")

          # Ring was told about the push token and the doorbell subscribed
          fake.requests_to("/clients_api/session").size.should eq(1)
          push_registration = JSON.parse(fake.requests_to("/clients_api/device").first.body)
          push_registration.dig("device", "push_notification_token").should eq("fake-fcm-token")
          fake.requests_to("/clients_api/doorbots/111222/subscribe").size.should eq(1)

          # push a ding encrypted for the freshly registered keys
          mcs.credentials = credentials
          wait_until { mcs.client_count == 1 }
          mcs.push(spec_ding_plaintext)

          wait_until { dings.size == 1 }
          dings.first.device_name.should eq("Front Door")
          dings.first.ding?.should be_true
          events.size.should eq(1)
          motions.should be_empty

          # then a motion event routes to on_motion only
          mcs.push(spec_ding_plaintext(category: "com.ring.pn.live-event.motion"))
          wait_until { motions.size == 1 }
          dings.size.should eq(1)
          events.size.should eq(2)

          # received message ids are persisted for restart dedup
          wait_until { RingDoorbell::StateFile.load(token_file).persistent_ids.size == 2 }
        end
      ensure
        mcs.stop
        File.delete?(token_file)
      end
    end
  end

  it "reuses persisted push credentials on later runs (checkin only)" do
    with_fake_ring do |fake|
      token_file = spec_token_file("reuse")
      mcs = FakeMCS.new(spec_fcm_credentials)
      mcs.start
      begin
        with_client(fake, mcs, token_file) do |client|
          client.login(fake.email, fake.password)
          client.listen
          wait_until { mcs.client_count == 1 }
        end
        registrations = fake.requests_to("/google/c2dm/register3").size
        checkins = fake.checkin_count

        with_client(fake, mcs, token_file) do |client|
          client.listen
          wait_until { mcs.client_count == 1 }
        end
        # no re-registration, but a fresh keep-alive checkin
        fake.requests_to("/google/c2dm/register3").size.should eq(registrations)
        fake.checkin_count.should eq(checkins + 1)
      ensure
        mcs.stop
        File.delete?(token_file)
      end
    end
  end

  it "refuses to listen when not authenticated" do
    with_fake_ring do |fake|
      token_file = spec_token_file("noauth")
      mcs = FakeMCS.new(spec_fcm_credentials)
      mcs.start
      begin
        with_client(fake, mcs, token_file) do |client|
          expect_raises(RingDoorbell::AuthError, /not authenticated/) { client.listen }
        end
      ensure
        mcs.stop
        File.delete?(token_file)
      end
    end
  end
end
