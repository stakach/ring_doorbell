require "../spec_helper"

private alias FCM = RingDoorbell::FCM

private def round_trip(message : T) : T forall T
  T.from_protobuf(message.to_protobuf)
end

describe RingDoorbell::FCM do
  it "round-trips a login request with settings and persistent ids" do
    login = FCM::Messages.login_request("5752962939", "1234509876", ["id-1", "id-2"], 5.minutes)
    parsed = round_trip(login)

    parsed.id.should eq("chrome-94.0.4606.51")
    parsed.domain.should eq("mcs.android.com")
    parsed.user.should eq("5752962939")
    parsed.resource.should eq("5752962939")
    parsed.auth_token.should eq("1234509876")
    parsed.device_id.should eq("android-#{5752962939_u64.to_s(16)}")
    parsed.setting.try(&.map { |setting| {setting.name, setting.value} }).should eq([{"new_vc", "1"}])
    parsed.received_persistent_id.should eq(["id-1", "id-2"])
    parsed.adaptive_heartbeat.should be_false
    parsed.heartbeat_stat.try(&.interval_ms).should eq(300_000)
    parsed.use_rmq2.should be_true
    parsed.auth_service.should eq(2)
    parsed.network_type.should eq(1)
  end

  it "round-trips fixed64 check-in identity fields" do
    response = FCM::AndroidCheckinResponse.new(
      stats_ok: true,
      android_id: 5_752_962_939_u64,
      security_token: 18_446_744_073_709_551_615_u64, # max u64
    )
    parsed = round_trip(response)
    parsed.android_id.should eq(5_752_962_939_u64)
    parsed.security_token.should eq(UInt64::MAX)
  end

  it "round-trips a check-in request with the nested chrome build" do
    request = FCM::AndroidCheckinRequest.new(
      checkin: FCM::AndroidCheckinProto.new(
        type: FCM::AndroidCheckinProto::DEVICE_CHROME_BROWSER,
        chrome_build: FCM::ChromeBuildProto.new(
          platform: FCM::ChromeBuildProto::PLATFORM_MAC,
          chrome_version: "63.0.3234.0",
          channel: FCM::ChromeBuildProto::CHANNEL_STABLE,
        ),
      ),
      time_zone: "Europe/Prague",
      version: 3,
    )
    parsed = round_trip(request)
    parsed.version.should eq(3)
    parsed.time_zone.should eq("Europe/Prague")
    checkin = parsed.checkin || fail "expected a checkin payload"
    checkin.type.should eq(3)
    checkin.chrome_build.try(&.chrome_version).should eq("63.0.3234.0")
  end

  it "round-trips a data message with app data and binary payload" do
    payload = Bytes[0x00, 0x01, 0xFE, 0xFF]
    message = FCM::DataMessageStanza.new(
      id: "m-1",
      from: "876313859327",
      category: "com.ring.android",
      app_data: [
        FCM::AppData.new(key: "encryption", value: "salt=AAAA"),
        FCM::AppData.new(key: "crypto-key", value: "dh=BBBB"),
      ],
      persistent_id: "p-1",
      raw_data: payload,
    )
    parsed = round_trip(message)
    parsed.from.should eq("876313859327")
    parsed.persistent_id.should eq("p-1")
    parsed.raw_data.should eq(payload)
    parsed.app_data_hash.should eq({"encryption" => "salt=AAAA", "crypto-key" => "dh=BBBB"})
  end

  it "extracts crypto parameters from app data headers" do
    salt = Bytes[1, 2, 3, 4]
    dh = Bytes[9, 8, 7, 6, 5]
    message = FCM::DataMessageStanza.new(app_data: [
      FCM::AppData.new(key: "encryption", value: "salt=#{FCM::Credentials.encode(salt)}"),
      FCM::AppData.new(key: "crypto-key", value: "dh=#{FCM::Credentials.encode(dh)}; p256ecdsa=ignored"),
    ])
    message.crypto_salt.should eq(salt)
    message.crypto_dh.should eq(dh)
  end

  it "returns nil crypto parameters when headers are missing" do
    message = FCM::DataMessageStanza.new(app_data: [
      FCM::AppData.new(key: "other", value: "value"),
    ])
    message.crypto_salt.should be_nil
    message.crypto_dh.should be_nil
  end

  it "skips unknown fields when decoding" do
    # A rich DataMessageStanza decoded as a message that only knows a couple
    # of its field numbers must not raise.
    message = FCM::DataMessageStanza.new(
      id: "m-1", from: "f", category: "c",
      persistent_id: "p-1", stream_id: 7,
      raw_data: Bytes[1, 2, 3],
    )
    parsed = FCM::HeartbeatPing.from_protobuf(message.to_protobuf)
    parsed.should be_a(FCM::HeartbeatPing)
  end
end
