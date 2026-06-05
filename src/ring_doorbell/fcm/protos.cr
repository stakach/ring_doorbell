module RingDoorbell::FCM
  # Protocol buffer messages for Google's device check-in and MCS push
  # protocols. Field numbers mirror Chromium's `checkin.proto` / `mcs.proto`
  # (via `@eneris/push-receiver` 4.3.1) — only the fields this library sets or
  # reads are declared; unknown fields are skipped by the decoder.
  #
  # Enum-typed fields are declared as `:int32` (identical wire encoding) with
  # the constants defined alongside.

  # `AndroidCheckinProto.chrome_build`
  struct ChromeBuildProto
    include Protobuf::Message

    # Platform: 1 win, 2 mac, 3 linux, 4 cros, 5 ios
    PLATFORM_MAC = 2
    # Channel: 1 stable, 2 beta, 3 dev, 4 canary
    CHANNEL_STABLE = 1

    contract_of "proto2" do
      optional :platform, :int32, 1
      optional :chrome_version, :string, 2
      optional :channel, :int32, 3
    end
  end

  # The `checkin` payload of an `AndroidCheckinRequest`.
  struct AndroidCheckinProto
    include Protobuf::Message

    # DeviceType: 1 android, 2 ios, 3 chrome browser, 4 chrome os
    DEVICE_CHROME_BROWSER = 3

    contract_of "proto2" do
      optional :last_checkin_msec, :int64, 1
      optional :cell_operator, :string, 6
      optional :sim_operator, :string, 7
      optional :roaming, :string, 8
      optional :user_number, :int32, 9
      optional :type, :int32, 12
      optional :chrome_build, ChromeBuildProto, 13
    end
  end

  # POSTed to `android.clients.google.com/checkin` as `application/x-protobuf`.
  struct AndroidCheckinRequest
    include Protobuf::Message

    contract_of "proto2" do
      optional :id, :int64, 2
      optional :checkin, AndroidCheckinProto, 4
      optional :logging_id, :int64, 7
      optional :time_zone, :string, 12
      optional :security_token, :fixed64, 13
      optional :version, :int32, 14
      optional :fragment, :int32, 20
      optional :user_serial_number, :int32, 22
    end
  end

  # Check-in response; the device identity used for everything that follows.
  struct AndroidCheckinResponse
    include Protobuf::Message

    contract_of "proto2" do
      optional :stats_ok, :bool, 1
      optional :android_id, :fixed64, 7
      optional :security_token, :fixed64, 8
    end
  end

  # name/value pair used in MCS login messages.
  struct Setting
    include Protobuf::Message

    contract_of "proto2" do
      optional :name, :string, 1
      optional :value, :string, 2
    end
  end

  # Client heartbeat configuration sent with the login request.
  struct HeartbeatStat
    include Protobuf::Message

    contract_of "proto2" do
      optional :ip, :string, 1
      optional :timeout, :bool, 2
      optional :interval_ms, :int32, 3
    end
  end

  # MCS tag 0 — also sent by the server; reply with a `HeartbeatAck`.
  struct HeartbeatPing
    include Protobuf::Message

    contract_of "proto2" do
      optional :stream_id, :int32, 1
      optional :last_stream_id_received, :int32, 2
      optional :status, :int64, 3
    end
  end

  # MCS tag 1.
  struct HeartbeatAck
    include Protobuf::Message

    contract_of "proto2" do
      optional :stream_id, :int32, 1
      optional :last_stream_id_received, :int32, 2
      optional :status, :int64, 3
    end
  end

  # MCS tag 2 — first frame sent after connecting (prefixed with the MCS
  # version byte).
  struct LoginRequest
    include Protobuf::Message

    AUTH_SERVICE_ANDROID_ID = 2

    contract_of "proto2" do
      optional :id, :string, 1
      optional :domain, :string, 2
      optional :user, :string, 3
      optional :resource, :string, 4
      optional :auth_token, :string, 5
      optional :device_id, :string, 6
      optional :setting, Setting, 8, repeated: true
      optional :received_persistent_id, :string, 10, repeated: true
      optional :adaptive_heartbeat, :bool, 12
      optional :heartbeat_stat, HeartbeatStat, 13
      optional :use_rmq2, :bool, 14
      optional :auth_service, :int32, 16
      optional :network_type, :int32, 17
    end
  end

  # MCS tag 3 — successful login handshake.
  struct LoginResponse
    include Protobuf::Message

    contract_of "proto2" do
      optional :id, :string, 1
      optional :jid, :string, 2
      optional :stream_id, :int32, 5
      optional :last_stream_id_received, :int32, 6
      optional :server_timestamp, :int64, 8
    end
  end

  # MCS tag 4 — server requested the connection be closed.
  struct Close
    include Protobuf::Message

    contract_of "proto2" do
      optional :unused, :int32, 1
    end
  end

  # MCS tag 7 — request/response stanza (logged only; no reply required).
  struct IqStanza
    include Protobuf::Message

    contract_of "proto2" do
      optional :rmq_id, :int64, 1
      optional :type, :int32, 2
      optional :id, :string, 3
      optional :persistent_id, :string, 8
      optional :stream_id, :int32, 9
      optional :last_stream_id_received, :int32, 10
      optional :status, :int64, 12
    end
  end

  # key/value pair carried by a `DataMessageStanza` — holds the WebPush
  # crypto headers (`encryption`, `crypto-key`) among others.
  struct AppData
    include Protobuf::Message

    contract_of "proto2" do
      optional :key, :string, 1
      optional :value, :string, 2
    end
  end

  # MCS tag 8 — an actual push notification. `raw_data` is the WebPush
  # (aesgcm) encrypted payload.
  struct DataMessageStanza
    include Protobuf::Message

    contract_of "proto2" do
      optional :id, :string, 2
      optional :from, :string, 3
      optional :to, :string, 4
      optional :category, :string, 5
      optional :token, :string, 6
      optional :app_data, AppData, 7, repeated: true
      optional :from_trusted_server, :bool, 8
      optional :persistent_id, :string, 9
      optional :stream_id, :int32, 10
      optional :last_stream_id_received, :int32, 11
      optional :reg_id, :string, 13
      optional :device_user_id, :int64, 16
      optional :ttl, :int32, 17
      optional :sent, :int64, 18
      optional :queued, :int32, 19
      optional :status, :int64, 20
      optional :raw_data, :bytes, 21
      optional :immediate_ack, :bool, 24
    end
  end

  # MCS tag 10 — stream-level error from the server.
  struct StreamErrorStanza
    include Protobuf::Message

    contract_of "proto2" do
      optional :type, :string, 1
      optional :text, :string, 2
    end
  end
end
