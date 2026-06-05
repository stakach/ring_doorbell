module RingDoorbell::FCM
  # Incremental parser for the MCS wire framing:
  #
  # ```text
  # [version byte, first frame from each side only]
  # [tag byte][varint payload size][protobuf payload]
  # ```
  #
  # Bytes are fed in as they arrive from the socket (`#push`); complete
  # frames are yielded to the callback as `(tag, payload)`. Frames may be
  # split at any byte boundary across reads.
  class FrameParser
    MCS_VERSION = 41_u8
    # Some Google servers still answer with protocol version 38.
    MIN_LEGACY_VERSION = 38_u8
    MAX_VARINT_BYTES   =     5

    enum State
      Version
      Tag
      Size
      Body
    end

    getter state : State = State::Version

    def initialize(&@on_frame : (UInt8, Bytes) -> Nil)
      @buffer = IO::Memory.new
      @tag = 0_u8
      @size = 0
    end

    # Feed bytes from the socket, emitting any frames they complete.
    def push(data : Bytes) : Nil
      # Append to whatever partial data we are holding.
      @buffer.pos = @buffer.size
      @buffer.write(data)
      process
    end

    private def process : Nil
      loop do
        bytes = @buffer.to_slice
        case @state
        in .version?
          return if bytes.empty?
          version = bytes[0]
          if version < MIN_LEGACY_VERSION
            raise ProtocolError.new("unsupported MCS version: #{version}")
          end
          consume(1)
          @state = State::Tag
        in .tag?
          return if bytes.empty?
          @tag = bytes[0]
          consume(1)
          @state = State::Size
        in .size?
          size, consumed = read_varint(bytes)
          return unless consumed.positive? # incomplete varint — wait for more
          consume(consumed)
          @size = size
          @state = State::Body
        in .body?
          return if bytes.size < @size
          payload = Bytes.new(@size)
          bytes[0, @size].copy_to(payload)
          consume(@size)
          @state = State::Tag
          @on_frame.call(@tag, payload)
        end
      end
    end

    # Decodes a varint32 from the head of *bytes*. Returns `{value, bytes
    # consumed}`, with 0 consumed when the varint is incomplete.
    private def read_varint(bytes : Bytes) : {Int32, Int32}
      value = 0_i64
      shift = 0
      bytes.each_with_index do |byte, index|
        raise ProtocolError.new("varint size field too long") if index >= MAX_VARINT_BYTES
        value |= (byte & 0x7F).to_i64 << shift
        if (byte & 0x80).zero?
          raise ProtocolError.new("frame size out of range: #{value}") if value > Int32::MAX
          return {value.to_i32, index + 1}
        end
        shift += 7
      end
      raise ProtocolError.new("varint size field too long") if bytes.size >= MAX_VARINT_BYTES
      {0, 0}
    end

    # Drop *count* bytes from the front of the buffer.
    private def consume(count : Int32) : Nil
      remaining = @buffer.to_slice[count..]
      @buffer = IO::Memory.new
      @buffer.write(remaining)
    end
  end
end
