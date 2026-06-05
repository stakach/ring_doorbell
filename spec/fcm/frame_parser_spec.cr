require "../spec_helper"

private alias FCM = RingDoorbell::FCM

# A representative wire exchange: version-prefixed login response, a
# heartbeat ping (empty payload) and a data message large enough for a
# multi-byte varint size.
private def sample_stream : {Bytes, Array({UInt8, Int32})}
  io = IO::Memory.new
  frames = [] of {UInt8, Int32}

  login = FCM::Messages.frame(FCM::Tag::LOGIN_RESPONSE,
    FCM::LoginResponse.new(id: "session-1"), include_version: true)
  io.write(login)
  frames << {FCM::Tag::LOGIN_RESPONSE, login.size - 2 - 1} # version + tag + 1-byte size

  ping = FCM::Messages.frame(FCM::Tag::HEARTBEAT_PING, FCM::HeartbeatPing.new)
  io.write(ping)
  frames << {FCM::Tag::HEARTBEAT_PING, ping.size - 2}

  big = FCM::Messages.frame(FCM::Tag::DATA_MESSAGE,
    FCM::DataMessageStanza.new(id: "m", raw_data: Bytes.new(300, 0xAB_u8)))
  io.write(big)
  # 300+ byte payload → 2 byte varint size
  frames << {FCM::Tag::DATA_MESSAGE, big.size - 3}

  {io.to_slice, frames}
end

private def parse_with_chunks(bytes : Bytes, chunk_size : Int32) : Array({UInt8, Int32})
  received = [] of {UInt8, Int32}
  parser = FCM::FrameParser.new { |tag, payload| received << {tag, payload.size} }
  offset = 0
  while offset < bytes.size
    size = {chunk_size, bytes.size - offset}.min
    parser.push(bytes[offset, size])
    offset += size
  end
  received
end

describe RingDoorbell::FCM::FrameParser do
  it "parses a complete stream fed at once" do
    bytes, expected = sample_stream
    parse_with_chunks(bytes, bytes.size).should eq(expected)
  end

  it "parses identically when fed a byte at a time" do
    bytes, expected = sample_stream
    parse_with_chunks(bytes, 1).should eq(expected)
  end

  it "parses identically across every chunk size" do
    bytes, expected = sample_stream
    (2..17).each do |chunk_size|
      parse_with_chunks(bytes, chunk_size).should eq(expected)
    end
  end

  it "decodes payloads intact" do
    message = FCM::DataMessageStanza.new(id: "m-1", persistent_id: "p-1", raw_data: Bytes[1, 2, 3])
    bytes = IO::Memory.new
    bytes.write(FCM::Messages.frame(FCM::Tag::LOGIN_RESPONSE, FCM::LoginResponse.new, include_version: true))
    bytes.write(FCM::Messages.frame(FCM::Tag::DATA_MESSAGE, message))

    payloads = [] of {UInt8, Bytes}
    parser = FCM::FrameParser.new { |tag, payload| payloads << {tag, payload} }
    parser.push(bytes.to_slice)

    payloads.size.should eq(2)
    parsed = FCM::DataMessageStanza.from_protobuf(IO::Memory.new(payloads[1][1]))
    parsed.persistent_id.should eq("p-1")
    parsed.raw_data.should eq(Bytes[1, 2, 3])
  end

  it "accepts the legacy version byte (38)" do
    parser = FCM::FrameParser.new { |_tag, _payload| }
    frame = FCM::Messages.frame(FCM::Tag::LOGIN_RESPONSE, FCM::LoginResponse.new)
    bytes = IO::Memory.new
    bytes.write_byte(38_u8)
    bytes.write(frame)
    parser.push(bytes.to_slice) # must not raise
  end

  it "rejects unsupported protocol versions" do
    parser = FCM::FrameParser.new { |_tag, _payload| }
    expect_raises(RingDoorbell::ProtocolError, /version/) do
      parser.push(Bytes[7_u8, FCM::Tag::LOGIN_RESPONSE, 0_u8])
    end
  end

  it "rejects oversize varint length prefixes" do
    parser = FCM::FrameParser.new { |_tag, _payload| }
    expect_raises(RingDoorbell::ProtocolError, /varint/) do
      parser.push(Bytes[41_u8, 8_u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])
    end
  end
end
