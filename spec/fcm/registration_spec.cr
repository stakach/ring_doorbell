require "../spec_helper"

private def build_registration(fake : FakeRing, retry_delay = 1.millisecond) : RingDoorbell::FCM::Registration
  RingDoorbell::FCM::Registration.new(
    api_key: RingDoorbell::Client::RING_FIREBASE_API_KEY,
    project_id: RingDoorbell::Client::RING_FIREBASE_PROJECT_ID,
    app_id: RingDoorbell::Client::RING_FIREBASE_APP_ID,
    checkin_url: fake.checkin_url,
    register_url: fake.register_url,
    fis_base: fake.fis_base,
    fcm_base: fake.fcm_base,
    retry_delay: retry_delay,
  )
end

describe RingDoorbell::FCM::Registration do
  it "runs the four-step pipeline and returns usable credentials" do
    with_fake_ring do |fake|
      credentials = build_registration(fake).register

      credentials.android_id.should eq("5752962939")
      credentials.security_token.should eq("1234509876")
      credentials.gcm_token.should eq("fake-gcm-token")
      credentials.fcm_token.should eq("fake-fcm-token")

      # key material is self-consistent: the private key regenerates the
      # registered public key
      credentials.ec_private_key.public_key_bytes.should eq(credentials.public_key_bytes)
      credentials.public_key_bytes.size.should eq(65)
      credentials.auth_secret_bytes.size.should eq(16)
    end
  end

  it "sends the protobuf check-in as a chrome browser device" do
    with_fake_ring do |fake|
      build_registration(fake).register
      request = fake.requests_to("/google/checkin").first
      request.headers["Content-Type"].should eq("application/x-protobuf")
      parsed = RingDoorbell::FCM::AndroidCheckinRequest.from_protobuf(IO::Memory.new(request.body.to_slice))
      parsed.version.should eq(3)
      parsed.checkin.try(&.type).should eq(3) # chrome browser
      parsed.checkin.try(&.chrome_build).try(&.chrome_version).should eq("63.0.3234.0")
    end
  end

  it "registers with GCM using the AidLogin identity and chromium app" do
    with_fake_ring do |fake|
      build_registration(fake).register
      request = fake.requests_to("/google/c2dm/register3").first
      request.headers["Authorization"].should eq("AidLogin 5752962939:1234509876")
      params = URI::Params.parse(request.body)
      params["app"].should eq("org.chromium.linux")
      params["device"].should eq("5752962939")
      params["X-subtype"].should start_with("wp:receiver.push.com#")
      params["sender"].should eq(RingDoorbell::FCM::Registration::DEFAULT_VAPID_KEY)
    end
  end

  it "retries GCM registration on transient errors" do
    with_fake_ring do |fake|
      fake.gcm_register_failures = 2
      credentials = build_registration(fake).register
      credentials.gcm_token.should eq("fake-gcm-token")
      fake.requests_to("/google/c2dm/register3").size.should eq(3)
    end
  end

  it "registers the web push keys with FCM" do
    with_fake_ring do |fake|
      build_registration(fake).register
      request = fake.requests_to("/google/fcm/projects/ring-17770/registrations").first
      request.headers["x-goog-api-key"].should eq(RingDoorbell::Client::RING_FIREBASE_API_KEY)
      request.headers["x-goog-firebase-installations-auth"].should eq("fis-auth-token")
      body = JSON.parse(request.body)
      body.dig("web", "endpoint").as_s.should eq("https://fcm.googleapis.com/fcm/send/fake-gcm-token")
      # the default (non-VAPID) key must NOT be sent as applicationPubKey
      body.dig?("web", "applicationPubKey").should be_nil
    end
  end

  it "sends a valid firebase installation request" do
    with_fake_ring do |fake|
      build_registration(fake).register
      request = fake.requests_to("/google/fis/projects/ring-17770/installations").first
      request.headers["x-goog-api-key"].should eq(RingDoorbell::Client::RING_FIREBASE_API_KEY)
      body = JSON.parse(request.body)
      body["authVersion"].should eq("FIS_v2")
      body["sdkVersion"].should eq("w:0.6.6")
      fid = Base64.decode(body["fid"].as_s)
      fid.size.should eq(17)
      (fid[0] >> 4).should eq(0b0111) # constant FID header
    end
  end

  it "re-runs check-in for existing credentials" do
    with_fake_ring do |fake|
      registration = build_registration(fake)
      credentials = registration.register
      before = fake.checkin_count
      registration.checkin(credentials)
      fake.checkin_count.should eq(before + 1)
    end
  end
end
