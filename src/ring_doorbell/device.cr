module RingDoorbell
  # Connection state reported alongside each device.
  struct Alerts
    include JSON::Serializable

    getter connection : String?
  end

  # Detailed device health (also embedded in `ring_devices` for some models;
  # authoritative via `GET /doorbots/{id}/health`).
  #
  # NOTE: Ring reports the same field as a number in one payload and a string
  # in another (`battery_percentage` is an integer inside `ring_devices` but
  # a string from `/health` on a real Intercom) — all numeric fields are
  # normalised.
  struct Health
    include JSON::Serializable

    @[JSON::Field(key: "battery_percentage")]
    getter battery_percentage_raw : JSON::Any?
    @[JSON::Field(key: "second_battery_percentage")]
    getter second_battery_percentage_raw : JSON::Any?
    @[JSON::Field(key: "battery_voltage")]
    getter battery_voltage_raw : JSON::Any?
    getter battery_present : Bool?
    getter connected : Bool?
    getter firmware_version : String?

    def battery_percentage : Int32?
      Health.percentage(battery_percentage_raw)
    end

    def second_battery_percentage : Int32?
      Health.percentage(second_battery_percentage_raw)
    end

    def battery_voltage : Float64?
      raw = battery_voltage_raw
      return nil unless raw
      raw.as_f? || raw.as_i64?.try(&.to_f) || raw.as_s?.try(&.to_f?)
    end

    # Normalises a number | numeric-string | null battery percentage.
    # :nodoc:
    def self.percentage(raw : JSON::Any?) : Int32?
      return nil unless raw
      value = raw.as_i64? || raw.as_s?.try(&.to_i64?)
      return nil unless value
      # Hardwired models report a voltage-style figure, not a percentage.
      return nil unless 0 <= value <= 100
      value.to_i32
    end
  end

  # A doorbell (or doorbell-like device) as returned by `GET /ring_devices`.
  struct Doorbell
    include JSON::Serializable

    getter id : Int64
    getter kind : String?
    getter description : String?
    getter location_id : String?
    getter firmware_version : String?

    # Ring reports battery as a number, a numeric string or null depending
    # on model/state — normalised by `#battery_level`.
    @[JSON::Field(key: "battery_life")]
    getter battery_life_raw : JSON::Any?
    @[JSON::Field(key: "battery_life_2")]
    getter battery_life_2_raw : JSON::Any?

    # True while on external power / charging.
    getter external_connection : Bool?

    getter alerts : Alerts?
    getter health : Health?

    # The user-assigned device name.
    def name : String?
      description
    end

    def online? : Bool
      alerts.try(&.connection) == "online"
    end

    # Battery percentage (0-100) when the device reports one.
    def battery_level : Int32?
      health.try(&.battery_percentage) ||
        Health.percentage(battery_life_raw) ||
        Health.percentage(battery_life_2_raw)
    end
  end

  # Wraps `GET /doorbots/{id}/health`.
  struct HealthResponse
    include JSON::Serializable

    getter device_health : Health?
  end

  # The full device list for the account.
  struct DeviceList
    include JSON::Serializable

    getter doorbots : Array(Doorbell) = [] of Doorbell
    getter authorized_doorbots : Array(Doorbell) = [] of Doorbell
    getter chimes : Array(Doorbell) = [] of Doorbell
    getter stickup_cams : Array(Doorbell) = [] of Doorbell
    getter other : Array(Doorbell) = [] of Doorbell

    # Every device that can plausibly ring: owned doorbells, doorbells shared
    # with this account, and the `other` bucket (where Ring places intercoms
    # and less common models such as audio-only units).
    def doorbells : Array(Doorbell)
      seen = Set(Int64).new
      (doorbots + authorized_doorbots + other).select { |device| seen.add?(device.id) }
    end
  end
end
