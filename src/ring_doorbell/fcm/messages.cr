module RingDoorbell::FCM
  # MCS message tags (the byte preceding each frame).
  module Tag
    HEARTBEAT_PING =  0_u8
    HEARTBEAT_ACK  =  1_u8
    LOGIN_REQUEST  =  2_u8
    LOGIN_RESPONSE =  3_u8
    CLOSE          =  4_u8
    IQ_STANZA      =  7_u8
    DATA_MESSAGE   =  8_u8
    STREAM_ERROR   = 10_u8
  end

  # Builders and framing helpers for the MCS messages we exchange.
  module Messages
    extend self

    # Matches the Chrome version push-receiver registers with.
    CHROME_VERSION = "94.0.4606.51"
    MCS_DOMAIN     = "mcs.android.com"

    def login_request(android_id : String, security_token : String,
                      persistent_ids : Array(String),
                      heartbeat_interval : Time::Span) : LoginRequest
      LoginRequest.new(
        id: "chrome-#{CHROME_VERSION}",
        domain: MCS_DOMAIN,
        user: android_id,
        resource: android_id,
        auth_token: security_token,
        device_id: "android-#{android_id.to_u64.to_s(16)}",
        setting: [Setting.new(name: "new_vc", value: "1")],
        received_persistent_id: persistent_ids,
        adaptive_heartbeat: false,
        heartbeat_stat: HeartbeatStat.new(
          ip: "",
          timeout: true,
          interval_ms: heartbeat_interval.total_milliseconds.to_i,
        ),
        use_rmq2: true,
        auth_service: LoginRequest::AUTH_SERVICE_ANDROID_ID,
        network_type: 1,
      )
    end

    # Serialize a message into a wire frame: `[version?][tag][varint len][payload]`.
    # The MCS version byte is only sent in front of the very first frame.
    def frame(tag : UInt8, message : Protobuf::Message, include_version : Bool = false) : Bytes
      payload = message.to_protobuf.to_slice
      io = IO::Memory.new
      io.write_byte(FrameParser::MCS_VERSION) if include_version
      io.write_byte(tag)
      write_varint(io, payload.size)
      io.write(payload)
      io.to_slice
    end

    def write_varint(io : IO, value : Int32) : Nil
      remaining = value.to_u32
      loop do
        byte = (remaining & 0x7F).to_u8
        remaining >>= 7
        if remaining.zero?
          io.write_byte(byte)
          break
        end
        io.write_byte(byte | 0x80)
      end
    end
  end

  struct DataMessageStanza
    # The string key/value pairs sent alongside the encrypted payload.
    def app_data_hash : Hash(String, String)
      hash = {} of String => String
      app_data.try &.each do |entry|
        key = entry.key
        value = entry.value
        hash[key] = value if key && value
      end
      hash
    end

    # The record salt from the `encryption` header (`salt=<base64url>`).
    def crypto_salt : Bytes?
      header_param("encryption", "salt")
    end

    # The sender's ephemeral public key from `crypto-key` (`dh=<base64url>`).
    def crypto_dh : Bytes?
      header_param("crypto-key", "dh")
    end

    # Parses `key=value; key2=value2` style header values.
    private def header_param(header : String, param : String) : Bytes?
      value = app_data_hash[header]?
      return nil unless value
      value.split(';').each do |part|
        name, _, data = part.strip.partition('=')
        return Credentials.decode(data) if name.strip == param && !data.empty?
      end
      nil
    end
  end
end
