# One-time interactive setup: log in to Ring (email + password + 2FA) and
# persist the refresh token to the token file. Everything else (push
# registration) happens automatically on first listen.
#
#   crystal run examples/init.cr -- [token_file]
#
# Default token file: data/ring.token
require "../src/ring_doorbell"

token_file = ARGV[0]? || "data/ring.token"
client = RingDoorbell::Client.new(token_file: token_file)

if client.authenticated?
  puts "#{token_file} already holds a login — continuing will replace it."
end

print "Email: "
email = gets.try(&.strip)
abort "email required" if email.nil? || email.empty?

print "Password: "
password = STDIN.tty? ? STDIN.noecho { gets.try(&.strip) } : gets.try(&.strip)
puts
abort "password required" if password.nil? || password.empty?

begin
  client.login(email, password)
rescue ex : RingDoorbell::TwoFactorRequired
  puts ex.message
  print "2FA code: "
  code = gets.try(&.strip)
  abort "2FA code required" if code.nil? || code.empty?
  client.login(email, password, code)
end

puts "Logged in — token saved to #{token_file}"
puts
puts "Devices on this account:"
client.doorbells.each do |bell|
  battery = bell.battery_level.try { |level| "#{level}%" } || "n/a"
  status = bell.online? ? "online" : "offline"
  puts "  ##{bell.id} #{bell.name} (#{bell.kind}) — #{status}, battery #{battery}"
end
