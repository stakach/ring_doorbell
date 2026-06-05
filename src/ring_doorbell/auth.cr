module RingDoorbell
  # Ring's OAuth endpoint: password logins (with 2FA) and refresh-token
  # grants. Stateless — token caching/rotation lives in `REST`.
  class Auth
    Log = RingDoorbell::Log.for("auth")

    OAUTH_URL  = "https://oauth.ring.com/oauth/token"
    CLIENT_ID  = "ring_official_android"
    USER_AGENT = "android:com.ringapp"

    # Refresh this long before the server-side expiry.
    EXPIRY_MARGIN = 60.seconds

    # An issued access token. Ring rotates the refresh token on every grant —
    # always persist the latest one.
    record TokenSet,
      access_token : String,
      refresh_token : String,
      expires_at : Time do
      def expired? : Bool
        Time.utc >= expires_at
      end
    end

    private struct TokenResponse
      include JSON::Serializable

      getter access_token : String
      getter refresh_token : String
      getter expires_in : Int32 = 3600
    end

    private struct TwoFactorResponse
      include JSON::Serializable

      getter phone : String?
      getter tsv_state : String?
    end

    def initialize(@hardware_id : String, *, @oauth_url : String = OAUTH_URL)
    end

    # Email + password login. Ring almost always responds with
    # `TwoFactorRequired` first — prompt for the code and call again with it.
    def password_grant(email : String, password : String, code : String? = nil) : TokenSet
      grant({
        "grant_type" => "password",
        "username"   => email,
        "password"   => password,
        "client_id"  => CLIENT_ID,
        "scope"      => "client",
      }, code)
    end

    def refresh_grant(refresh_token : String) : TokenSet
      grant({
        "grant_type"    => "refresh_token",
        "refresh_token" => refresh_token,
        "client_id"     => CLIENT_ID,
        "scope"         => "client",
      })
    end

    private def grant(body : Hash(String, String), code : String? = nil) : TokenSet
      headers = HTTP::Headers{
        "Content-Type" => "application/json",
        "Accept"       => "application/json",
        "User-Agent"   => USER_AGENT,
        "2fa-support"  => "true",
        "2fa-code"     => code || "",
        "hardware_id"  => @hardware_id,
      }
      response = HTTP::Client.post(@oauth_url, headers: headers, body: body.to_json)

      case response.status_code
      when 200, 201
        token = TokenResponse.from_json(response.body)
        TokenSet.new(
          access_token: token.access_token,
          refresh_token: token.refresh_token,
          expires_at: Time.utc + token.expires_in.seconds - EXPIRY_MARGIN,
        )
      when 412
        info = begin
          TwoFactorResponse.from_json(response.body)
        rescue JSON::ParseException
          TwoFactorResponse.from_json("{}")
        end
        raise TwoFactorRequired.new(
          "Ring sent a verification code (#{info.tsv_state || "2fa"}#{info.phone.try { |phone| " to #{phone}" }}) — retry with it",
          info.phone, info.tsv_state,
        )
      when 400, 401, 403
        raise AuthError.new("authentication failed: #{error_description(response)}")
      else
        raise ResponseError.new("unexpected response from oauth endpoint: HTTP #{response.status_code}")
      end
    rescue ex : IO::Error | Socket::Error | OpenSSL::Error
      raise ConnectionError.new("could not reach #{@oauth_url}: #{ex.message}", cause: ex)
    rescue ex : JSON::ParseException
      raise ResponseError.new("could not parse oauth response: #{ex.message}", cause: ex)
    end

    private def error_description(response : HTTP::Client::Response) : String
      json = JSON.parse(response.body)
      (json["error_description"]? || json["error"]? || response.status_code).to_s
    rescue JSON::ParseException
      "HTTP #{response.status_code}"
    end
  end
end
