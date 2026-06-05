module RingDoorbell
  # Everything the client persists between runs, stored as a single JSON file
  # (the `token_file`):
  #
  # - the Ring OAuth refresh token (written by the first login, rotated by
  #   Ring on refresh)
  # - a stable hardware id identifying this client install to Ring
  # - the FCM push-receiver credentials (created once, reused forever)
  # - the ids of recently received push messages (server-side dedup/resume)
  #
  # The short-lived access token is intentionally not persisted.
  class StateFile
    include JSON::Serializable

    property refresh_token : String?
    property hardware_id : String = UUID.random.to_s
    property fcm : FCM::Credentials?
    property persistent_ids : Array(String) = [] of String

    def initialize
    end

    # Loads the state from *path*, returning a fresh state when the file does
    # not exist yet.
    def self.load(path : String) : StateFile
      return new unless File.exists?(path)
      from_json(File.read(path))
    rescue ex : JSON::ParseException
      raise Error.new("state file #{path} exists but could not be parsed: #{ex.message}")
    end

    # Limit how many push message ids we replay to the server on reconnect.
    MAX_PERSISTENT_IDS = 100

    def save(path : String) : Nil
      @persistent_ids = @persistent_ids.last(MAX_PERSISTENT_IDS)
      directory = File.dirname(path)
      Dir.mkdir_p(directory) unless directory.empty? || Dir.exists?(directory)
      File.write(path, to_pretty_json)
    end
  end
end
