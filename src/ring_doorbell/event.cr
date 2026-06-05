module RingDoorbell
  enum EventKind
    # The doorbell button was pressed.
    Ding
    # Motion detected.
    Motion
    # An intercom buzz (treated as a ding).
    Intercom
    # Anything else Ring pushes.
    Other
  end

  # A real-time event extracted from a Ring push notification (v2 format).
  struct DingEvent
    CATEGORY_DING     = "com.ring.pn.live-event.ding"
    CATEGORY_MOTION   = "com.ring.pn.live-event.motion"
    CATEGORY_INTERCOM = "com.ring.pn.live-event.intercom"

    getter kind : EventKind
    getter device_id : Int64?
    getter device_name : String?
    getter device_kind : String?
    getter event_id : String?
    getter created_at : String?
    getter subtype : String?
    # The full (decoded) notification for anything not surfaced above.
    getter raw : JSON::Any

    def initialize(@kind, @raw, *, @device_id = nil, @device_name = nil,
                   @device_kind = nil, @event_id = nil, @created_at = nil,
                   @subtype = nil)
    end

    # Someone is at the door (button press or intercom buzz).
    def ding? : Bool
      kind.ding? || kind.intercom?
    end

    def motion? : Bool
      kind.motion?
    end

    # Builds an event from a decrypted FCM push. Returns `nil` when the push
    # is not a Ring notification (no `data` envelope).
    #
    # The decrypted payload is an FCM message whose `data` values are each
    # themselves JSON documents (or plain strings).
    def self.from_push(notification : JSON::Any) : DingEvent?
      fields = notification["data"]?.try(&.as_h?)
      return nil unless fields

      decoded = JSON::Any.new(fields.transform_values { |value| parse_field(value) })
      category = decoded.dig?("android_config", "category").try(&.as_s?)
      kind = case category
             when CATEGORY_DING     then EventKind::Ding
             when CATEGORY_MOTION   then EventKind::Motion
             when CATEGORY_INTERCOM then EventKind::Intercom
             else                        EventKind::Other
             end

      device = decoded.dig?("data", "device")
      ding = decoded.dig?("data", "event", "ding")

      new(
        kind, decoded,
        device_id: device.try(&.dig?("id")).try(&.as_i64?),
        device_name: device.try(&.dig?("name")).try(&.as_s?),
        device_kind: device.try(&.dig?("kind")).try(&.as_s?),
        event_id: ding.try(&.dig?("id")).try { |id| id.as_s? || id.raw.to_s },
        created_at: ding.try(&.dig?("created_at")).try(&.as_s?),
        subtype: ding.try(&.dig?("subtype")).try(&.as_s?),
      )
    end

    # Each data value is usually a JSON document serialised to a string.
    private def self.parse_field(value : JSON::Any) : JSON::Any
      text = value.as_s?
      return value unless text
      JSON.parse(text)
    rescue JSON::ParseException
      value
    end
  end
end
