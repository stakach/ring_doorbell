# Dumps the raw `ring_devices` payload plus a parsed summary — useful for
# checking which array an unusual device (e.g. an audio-only doorbell)
# appears in and what its battery fields look like.
#
#   crystal run examples/devices.cr -- [token_file]
require "../src/ring_doorbell"

token_file = ARGV[0]? || "data/ring.token"
client = RingDoorbell::Client.new(token_file: token_file)
abort "not authenticated — run examples/init.cr first" unless client.authenticated?

puts "===== raw /clients_api/ring_devices ====="
puts client.raw_devices.to_pretty_json
puts
puts "===== parsed doorbells ====="
client.doorbells.each do |bell|
  battery = client.battery_level(bell.id).try { |level| "#{level}%" } || "n/a"
  status = bell.online? ? "online" : "offline"
  puts "##{bell.id} #{bell.name} (#{bell.kind}) — #{status}, battery #{battery} (health endpoint)"
end
