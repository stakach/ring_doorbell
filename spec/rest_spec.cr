require "./spec_helper"

private def build_rest(fake : FakeRing) : RingDoorbell::REST
  fake.seed_refresh_token("refresh-0")
  auth = RingDoorbell::Auth.new("hw-1", oauth_url: fake.oauth_url)
  RingDoorbell::REST.new(auth, "hw-1", refresh_token: "refresh-0", base_url: fake.rest_base)
end

describe RingDoorbell::REST do
  it "fetches and parses the device list" do
    with_fake_ring do |fake|
      rest = build_rest(fake)
      devices = rest.devices
      bells = devices.doorbells
      bells.size.should eq(1)
      bells.first.id.should eq(111_222)
      bells.first.name.should eq("Front Door")
      bells.first.online?.should be_true
      bells.first.battery_level.should eq(71)

      request = fake.requests_to("/clients_api/ring_devices").first
      request.headers["Authorization"].should eq("Bearer access-1")
      request.headers["hardware_id"].should eq("hw-1")
    end
  end

  it "reads battery from the health endpoint" do
    with_fake_ring do |fake|
      fake.health_battery = 64
      rest = build_rest(fake)
      rest.device_health(111_222).try(&.battery_percentage).should eq(64)
    end
  end

  it "creates a session with the documented body" do
    with_fake_ring do |fake|
      rest = build_rest(fake)
      rest.session
      body = JSON.parse(fake.requests_to("/clients_api/session").first.body)
      body.dig("device", "hardware_id").should eq("hw-1")
      body.dig("device", "os").should eq("android")
      body.dig("device", "metadata", "api_version").should eq(11)
    end
  end

  it "registers the push token via PATCH /device" do
    with_fake_ring do |fake|
      rest = build_rest(fake)
      rest.register_push("fcm-token-xyz")
      request = fake.requests_to("/clients_api/device").first
      request.method.should eq("PATCH")
      body = JSON.parse(request.body)
      body.dig("device", "push_notification_token").should eq("fcm-token-xyz")
      body.dig("device", "metadata", "pn_service").should eq("fcm")
      body.dig("device", "metadata", "pn_dict_version").should eq("2.0.0")
    end
  end

  it "subscribes doorbells to ding events" do
    with_fake_ring do |fake|
      rest = build_rest(fake)
      rest.subscribe(111_222)
      fake.requests_to("/clients_api/doorbots/111222/subscribe").size.should eq(1)
    end
  end

  it "refreshes the access token and retries once on a 401" do
    with_fake_ring do |fake|
      rest = build_rest(fake)
      rest.devices # establishes access-1
      fake.revoke_access_tokens!
      rest.devices.doorbells.size.should eq(1) # silently refreshed

      tokens_used = fake.requests_to("/clients_api/ring_devices").map(&.headers["Authorization"])
      tokens_used.should eq(["Bearer access-1", "Bearer access-1", "Bearer access-2"])
    end
  end

  it "reports rotated refresh tokens so they can be persisted" do
    with_fake_ring do |fake|
      rest = build_rest(fake)
      rotated = [] of String
      rest.on_refresh_token { |token| rotated << token }
      rest.devices
      rotated.should eq(["refresh-1"])
    end
  end

  it "raises AuthError when no refresh token is configured" do
    with_fake_ring do |fake|
      auth = RingDoorbell::Auth.new("hw-1", oauth_url: fake.oauth_url)
      rest = RingDoorbell::REST.new(auth, "hw-1", base_url: fake.rest_base)
      expect_raises(RingDoorbell::AuthError, /not authenticated/) { rest.devices }
    end
  end
end
