require "logstash/devutils/rspec/spec_helper"

describe "LogStash::Inputs::EventLog", :windows => true do

  before(:all) do
    require 'logstash/inputs/eventlog'
  end

  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "logfile" => "Application", "interval" => 10000, "sincedb_path" => "C:/ProgramData/Logstash/eventlog-Application.sincedb", "sincedb_write_interval" => 15, "start_position" => "end" } }
  end
end
