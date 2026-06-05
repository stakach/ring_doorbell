require "./spec_helper"

private def doorbell(json : String) : RingDoorbell::Doorbell
  RingDoorbell::Doorbell.from_json(json)
end

describe RingDoorbell::Doorbell do
  describe "#battery_level" do
    it "parses a numeric battery_life" do
      doorbell(%({"id": 1, "battery_life": 84})).battery_level.should eq(84)
    end

    it "parses a string battery_life" do
      doorbell(%({"id": 1, "battery_life": "71"})).battery_level.should eq(71)
    end

    it "ignores voltage-style values from hardwired models" do
      doorbell(%({"id": 1, "battery_life": 4003})).battery_level.should be_nil
    end

    it "handles a null battery_life" do
      doorbell(%({"id": 1, "battery_life": null})).battery_level.should be_nil
    end

    it "prefers health.battery_percentage when present" do
      bell = doorbell(%({"id": 1, "battery_life": "20", "health": {"battery_percentage": 55}}))
      bell.battery_level.should eq(55)
    end

    it "handles string battery percentages in health (real /health responses)" do
      health = RingDoorbell::HealthResponse.from_json(
        %({"device_health": {"battery_percentage": "62", "battery_voltage": 3876.0}})
      ).device_health
      health.try(&.battery_percentage).should eq(62)
      health.try(&.battery_voltage).should eq(3876.0)
    end

    it "falls back to battery_life_2 (second battery)" do
      bell = doorbell(%({"id": 1, "battery_life": null, "battery_life_2": 33}))
      bell.battery_level.should eq(33)
    end
  end

  describe "#online?" do
    it "is true when alerts.connection is online" do
      doorbell(%({"id": 1, "alerts": {"connection": "online"}})).online?.should be_true
    end

    it "is false when offline or unreported" do
      doorbell(%({"id": 1, "alerts": {"connection": "offline"}})).online?.should be_false
      doorbell(%({"id": 1})).online?.should be_false
    end
  end
end

describe RingDoorbell::DeviceList do
  it "collects doorbells from every plausible array" do
    list = RingDoorbell::DeviceList.from_json({
      doorbots:            [{id: 1, description: "Owned"}],
      authorized_doorbots: [{id: 2, description: "Shared"}],
      chimes:              [{id: 3, description: "Chime"}],
      stickup_cams:        [{id: 4, description: "Cam"}],
      other:               [{id: 5, description: "Audio Doorbell"}],
    }.to_json)

    list.doorbells.map(&.id).should eq([1_i64, 2_i64, 5_i64])
    list.chimes.first.id.should eq(3)
    list.stickup_cams.first.id.should eq(4)
  end

  it "dedups devices appearing in multiple arrays" do
    list = RingDoorbell::DeviceList.from_json({
      doorbots:            [{id: 7, description: "Front"}],
      authorized_doorbots: [{id: 7, description: "Front"}],
    }.to_json)
    list.doorbells.size.should eq(1)
  end

  it "tolerates missing arrays" do
    RingDoorbell::DeviceList.from_json("{}").doorbells.should be_empty
  end
end
