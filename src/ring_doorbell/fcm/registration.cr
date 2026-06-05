module RingDoorbell::FCM
  # One-time push-receiver registration — performs the four Google API calls
  # that turn "nothing" into a working push identity (`Credentials`):
  #
  # 1. GCM check-in        → android_id + security_token (device identity)
  # 2. GCM registration    → gcm_token
  # 3. Firebase installation (FIS) → short-lived installation auth token
  # 4. FCM registration    → fcm_token (handed to Ring, pushes arrive for it)
  #
  # Mirrors `@eneris/push-receiver` 4.3.1 byte-for-byte, registering as a
  # Chrome browser instance.
  class Registration
    Log = RingDoorbell::Log.for("fcm.registration")

    CHECKIN_URL  = "https://android.clients.google.com/checkin"
    REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
    FIS_BASE     = "https://firebaseinstallations.googleapis.com/v1"
    FCM_BASE     = "https://fcmregistrations.googleapis.com/v1"
    FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send/"

    # Chrome's default application server key, used when the sender (Ring)
    # does not use VAPID.
    DEFAULT_VAPID_KEY = "BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4"

    BUNDLE_ID              = "receiver.push.com"
    GCM_APP                = "org.chromium.linux"
    CHECKIN_CHROME_VERSION = "63.0.3234.0"
    CHECKIN_TIME_ZONE      = "Europe/Prague"
    FIS_AUTH_VERSION       = "FIS_v2"
    FIS_SDK_VERSION        = "w:0.6.6"

    GCM_REGISTER_ATTEMPTS = 5

    def initialize(*, @api_key : String, @project_id : String, @app_id : String,
                   @checkin_url : String = CHECKIN_URL,
                   @register_url : String = REGISTER_URL,
                   @fis_base : String = FIS_BASE,
                   @fcm_base : String = FCM_BASE,
                   @retry_delay : Time::Span = 1.second)
    end

    # Runs the full pipeline and returns the persistent push credentials.
    def register : Credentials
      private_key = OpenSSL::PKey::EC.generate("P-256")
      public_key = private_key.public_key_bytes
      auth_secret = Random::Secure.random_bytes(16)

      android_id, security_token = checkin
      Log.debug { "checked in as android device #{android_id}" }
      gcm_token = gcm_register(android_id, security_token)
      Log.debug { "GCM registration complete" }
      installation_auth = fis_install
      fcm_token = fcm_register(gcm_token, installation_auth, public_key, auth_secret)
      Log.debug { "FCM registration complete" }

      Credentials.new(
        android_id: android_id,
        security_token: security_token,
        gcm_token: gcm_token,
        fcm_token: fcm_token,
        private_key: Credentials.encode(private_key.private_key_bytes),
        public_key: Credentials.encode(public_key),
        auth_secret: Credentials.encode(auth_secret),
      )
    end

    # Re-runs the device check-in for existing credentials — Google expects a
    # periodic check-in to keep the android_id alive (push-receiver does this
    # on every connect).
    def checkin(credentials : Credentials) : Nil
      checkin(android_id: credentials.android_id.to_i64,
        security_token: credentials.security_token.to_u64)
    end

    private def checkin(android_id : Int64? = nil, security_token : UInt64? = nil) : {String, String}
      request = AndroidCheckinRequest.new(
        id: android_id,
        checkin: AndroidCheckinProto.new(
          last_checkin_msec: 0_i64,
          cell_operator: "",
          sim_operator: "",
          roaming: "",
          user_number: 0,
          type: AndroidCheckinProto::DEVICE_CHROME_BROWSER,
          chrome_build: ChromeBuildProto.new(
            platform: ChromeBuildProto::PLATFORM_MAC,
            chrome_version: CHECKIN_CHROME_VERSION,
            channel: ChromeBuildProto::CHANNEL_STABLE,
          ),
        ),
        logging_id: 0_i64,
        time_zone: CHECKIN_TIME_ZONE,
        security_token: security_token,
        version: 3,
        fragment: 0,
        user_serial_number: 0,
      )

      response = HTTP::Client.post(@checkin_url,
        headers: HTTP::Headers{"Content-Type" => "application/x-protobuf"},
        body: request.to_protobuf.to_slice)
      ensure_success(response, "GCM check-in")

      parsed = AndroidCheckinResponse.from_protobuf(IO::Memory.new(response.body.to_slice))
      new_android_id = parsed.android_id || raise ResponseError.new("check-in response missing android_id")
      new_security_token = parsed.security_token || raise ResponseError.new("check-in response missing security_token")
      {new_android_id.to_s, new_security_token.to_s}
    end

    private def gcm_register(android_id : String, security_token : String) : String
      subtype = "wp:#{BUNDLE_ID}##{UUID.random}"
      body = URI::Params.build do |form|
        form.add "app", GCM_APP
        form.add "X-subtype", subtype
        form.add "device", android_id
        form.add "sender", DEFAULT_VAPID_KEY
      end
      headers = HTTP::Headers{
        "Authorization" => "AidLogin #{android_id}:#{security_token}",
        "Content-Type"  => "application/x-www-form-urlencoded",
      }

      GCM_REGISTER_ATTEMPTS.times do |attempt|
        response = HTTP::Client.post(@register_url, headers: headers, body: body)
        ensure_success(response, "GCM registration")
        if response.body.includes?("Error")
          Log.warn { "GCM registration failed (#{response.body.strip}), attempt #{attempt + 1}/#{GCM_REGISTER_ATTEMPTS}" }
          sleep @retry_delay
          next
        end
        token = response.body.partition("token=").last.strip
        raise ResponseError.new("GCM registration returned no token: #{response.body.strip}") if token.empty?
        return token
      end
      raise ResponseError.new("GCM registration failed after #{GCM_REGISTER_ATTEMPTS} attempts")
    end

    private def fis_install : String
      response = HTTP::Client.post("#{@fis_base}/projects/#{@project_id}/installations",
        headers: HTTP::Headers{
          "Content-Type"      => "application/json",
          "x-goog-api-key"    => @api_key,
          "x-firebase-client" => Base64.strict_encode(%({"heartbeats":[],"version":2})),
        },
        body: {
          appId:       @app_id,
          authVersion: FIS_AUTH_VERSION,
          fid:         generate_fid,
          sdkVersion:  FIS_SDK_VERSION,
        }.to_json)
      ensure_success(response, "Firebase installation")

      json = JSON.parse(response.body)
      json.dig("authToken", "token").as_s
    rescue KeyError | TypeCastError
      raise ResponseError.new("Firebase installation response missing authToken")
    end

    private def fcm_register(gcm_token : String, installation_auth : String,
                             public_key : Bytes, auth_secret : Bytes) : String
      response = HTTP::Client.post("#{@fcm_base}/projects/#{@project_id}/registrations",
        headers: HTTP::Headers{
          "Content-Type"                       => "application/json",
          "x-goog-api-key"                     => @api_key,
          "x-goog-firebase-installations-auth" => installation_auth,
        },
        body: {
          web: {
            # applicationPubKey is omitted — Ring pushes through the default
            # (non-VAPID) Chrome key; including it makes registration fail.
            auth:     Credentials.encode(auth_secret),
            endpoint: FCM_ENDPOINT + gcm_token,
            p256dh:   Credentials.encode(public_key),
          },
        }.to_json)
      ensure_success(response, "FCM registration")

      json = JSON.parse(response.body)
      if error = json["error"]?
        raise ResponseError.new("FCM registration failed: #{error["message"]? || error}")
      end
      json["token"].as_s
    rescue KeyError | TypeCastError
      raise ResponseError.new("FCM registration response missing token")
    end

    # A Firebase installation id: 17 random bytes with the constant 0b0111
    # header in the first nibble, plain base64 encoded.
    private def generate_fid : String
      fid = Random::Secure.random_bytes(17)
      fid[0] = 0b0111_0000_u8 + (fid[0] % 0b0001_0000)
      Base64.strict_encode(fid)
    end

    private def ensure_success(response : HTTP::Client::Response, action : String) : Nil
      return if response.success?
      raise ResponseError.new("#{action} failed: HTTP #{response.status_code} #{response.body[0, 200].strip}")
    end
  end
end
