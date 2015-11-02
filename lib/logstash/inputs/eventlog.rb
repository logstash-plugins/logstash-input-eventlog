# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/timestamp"
require "win32/eventlog"
require "stud/interval"

# This input will pull events from a http://msdn.microsoft.com/en-us/library/windows/desktop/bb309026%28v=vs.85%29.aspx[Windows Event Log].
# Note that Windows Event Logs are stored on disk in a binary format and are only accessible from the Win32 API.
# This means Losgtash needs to be running as an agent on Windows servers where you wish to collect logs 
# from, and will not be accesible across the network.
#
# To collect Events from the System Event Log, use a config like:
# [source,ruby]
#     input {
#       eventlog {
#         type  => 'Win32-EventLog'
#         logfile  => 'System'
#       }
#     }
class LogStash::Inputs::EventLog < LogStash::Inputs::Base

  config_name "eventlog"

  default :codec, "plain"

  # Event Log Name
  # System and Security may require that privileges are given to the user running logstash.
  # see more at: https://social.technet.microsoft.com/forums/windowsserver/en-US/d2f813db-6142-4b5b-8d86-253ebb740473/easy-way-to-read-security-log
  config :logfile, :validate => :string, :validate => [ "Application", "Security", "System" ], :default => "Application"

  # How frequently should tail check for new event logs in ms (default: 1 second)
  config :interval, :validate => :number, :default => 1000

  public
  def register

    # wrap specified logfiles in suitable OR statements
    @hostname = Socket.gethostname
    @logger.info("Opening eventlog #{@logfile}")

    begin
      @eventlog = Win32::EventLog.open(@logfile)
    rescue SystemCallError => e
      if e.errno == 1314 # ERROR_PRIVILEGE_NOT_HELD
        @logger.fatal("No privilege held to open logfile", :logfile => @logfile)
      end
      raise
    end
  end # def register

  public
  def run(queue)

    @logger.debug("Tailing Windows Event Log '#{@logfile}'")

    old_total = @eventlog.total_records()
    flags     = Win32::EventLog::FORWARDS_READ | Win32::EventLog::SEEK_READ
    rec_num   = @eventlog.read_last_event.record_number

    while !stop?
      new_total = @eventlog.total_records()
      if new_total != old_total
        rec_num = @eventlog.oldest_record_number() if @eventlog.full?
        @eventlog.read(flags, rec_num).each { |log| e = process(log); decorate(e); queue << e }
        old_total = new_total
        rec_num   = @eventlog.read_last_event.record_number + 1
      end
      Stud.stoppable_sleep(@interval/1000.0) { stop? }
    end
  end

  private
  def process(log)

    LogStash::Event.new(
      "host"             => @hostname,
      "Logfile"          => @logfile,
      "message"          => log["description"].strip,
      "Category"         => log["category"],
      "ComputerName"     => log["computer"],
      "EventIdentifier"  => log["event_id"],
      "EventType"        => log["event_type"],
      "RecordNumber"     => log["record_number"],
      "SourceName"       => log["source"],
      "TimeGenerated"    => log["time_generated"],
      "TimeWritten"      => log["time_written"],
      "Type"             => log["event_type"],
      "User"             => log["user"],
      "InsertionStrings" => log["string_inserts"]
    )
  end # def run

end # class LogStash::Inputs::EventLog

