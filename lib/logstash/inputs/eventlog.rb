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
#         sincedb_path  => 'C:/ProgramData/Logstash/eventlog-System.sincedb'
#       }
#     }
class LogStash::Inputs::EventLog < LogStash::Inputs::Base

  config_name "eventlog"

  default :codec, "plain"

  # Event Log Name
  # System and Security may require that privileges are given to the user running logstash.
  # see more at: https://social.technet.microsoft.com/forums/windowsserver/en-US/d2f813db-6142-4b5b-8d86-253ebb740473/easy-way-to-read-security-log
  config :logfile, :validate => :string, :default => [ "Application" ]

  # How frequently should tail check for new event logs in ms (default: 1 second)
  config :interval, :validate => :number, :default => 1000

  # Where to write the sincedb database (keeps track of the current
  # position of monitored event logs).
  config :sincedb_path, :validate => :string

  # How often (in seconds) to write a since database with the current position of
  # monitored event logs.
  config :sincedb_write_interval, :validate => :number, :default => 15

  # Choose where Logstash starts initially reading eventlog: at the beginning or
  # at the end. The default behavior treats eventlog like live streams and thus
  # starts at the end. If you have old data you want to import, set this
  # to 'beginning'
  #
  # This option only modifies "first contact" situations where an eventlog is new
  # and not seen before. If an eventlog has already been seen before, this option
  # has no effect.
  config :start_position, :validate => [ "beginning", "end"], :default => "end"

  @@log_class_prefix = "InputEventLog"

  public
  def register

    # wrap specified logfiles in suitable OR statements
    @hostname = Socket.gethostname
    @log_prefix = "[#{@@log_class_prefix}:#{@logfile}]"
    @logger.info("#{@log_prefix}register: Registering input eventlog://#{@hostname}/#{@logfile}")

    begin
      @eventlog = Win32::EventLog.open(@logfile)
    rescue SystemCallError => e
      if e.errno == 1314 # ERROR_PRIVILEGE_NOT_HELD
        @logger.fatal("No privilege held to open logfile", :logfile => @logfile)
      end
      raise
    end
    @sincedb = {}
    @sincedb_last_write = Time.now.to_i
    @sincedb_write_pending = true
    @sincedb_writing = false
    @eventlog_item = nil
    @queue = nil

    @working = true
    @can_exit = false
    @in_teardown = false

    _sincedb_open
  end # def register

  public
  def run(queue)
    @queue = queue
    begin
      rec_num = 0
      old_total = 0
      flags     = Win32::EventLog::FORWARDS_READ | Win32::EventLog::SEEK_READ

      if(@sincedb[@logfile] != nil && @sincedb[@logfile].to_i > @eventlog.oldest_record_number)
        rec_num = @sincedb[@logfile].to_i
        @logger.debug("#{@log_prefix}run: Starting #{@logfile} at rec #{rec_num.to_s}")
      elsif(@start_position == "end")
        rec_num = @eventlog.read_last_event.record_number
        @logger.debug("#{@log_prefix}run: Start #{@logfile} from the ending at rec #{rec_num.to_s}")
      else
        @logger.debug("#{@log_prefix}run: Start #{@logfile} from the beginning")
        @eventlog.read{ |eventlog_item|
          @eventlog_item = eventlog_item
          send_logstash_event()
          rec_num = @eventlog_item.record_number
        }
      end

      @logger.debug("#{@log_prefix}run: Tailing Windows Event Log '#{@logfile}'")
      while !stop?
        if old_total != @eventlog.total_records()
          @working = true
          @eventlog.read(flags, rec_num){ |eventlog_item|
            @eventlog_item = eventlog_item
            if( @eventlog_item.record_number > rec_num )
              send_logstash_event()
            end
            old_total = @eventlog.total_records()
            rec_num = @eventlog_item.record_number
          }
        end
        @working = false
        Stud.stoppable_sleep(@interval/1000.0) { stop? }
      end # while
    rescue LogStash::ShutdownSignal
      @logger.debug("#{@log_prefix}run: Shutdown requested")
      @working = false
    rescue Exception => ex
      @logger.error("#{@log_prefix}run: Windows Event Log error: #{ex}\n#{ex.backtrace}")
      sleep 1
      retry
    end # rescue
    @can_exit = true
  end # run

  private
  def send_logstash_event()
    timestamp = @eventlog_item.time_generated

    e = LogStash::Event.new(
      "host" => @hostname,
      "path" => @logfile,
      "type" => @type,
      "@timestamp" => timestamp
    )

    e["Category"] = @eventlog_item.category
    e["ComputerName"] = @eventlog_item.computer
    e["Data"] = @eventlog_item.data.nil? ? nil : @eventlog_item.data.each_byte.map { |b| b.to_s(16) }.join
    #HEXA  @eventlog_item.data.each_byte.map { |b| b.to_s(16) }.join
    #ASCII @eventlog_item.data
    #UTF-8 @eventlog_item.data.force_encoding('utf-8')
    e["Description"] = @eventlog_item.description.nil? ? nil : @eventlog_item.description.encode('utf-8')
    e["EventId"] = @eventlog_item.event_id
    e["EventIdentifier"] = @eventlog_item.event_id
    e["EventCode"] = e["EventId"]
    e["EventType"] = @eventlog_item.event_type
    e["Logfile"] = @logfile
    e["InsertionStrings"] = nil
    e["InsertionStrings"] = @eventlog_item.string_inserts.map{ |monostring|
      monostring.nil? ? nil : monostring.encode('utf-8')
    }
    e["Message"] = e["Description"].nil? ? e["InsertionStrings"] : e["Description"]
    e["message"] = e["Message"]
    e["RecordNumber"] = @eventlog_item.record_number
    e["SourceName"] = @eventlog_item.source
    e["TimeGenerated"] = @eventlog_item.time_generated
    e["TimeWritten"] = @eventlog_item.time_written
    e["Type"] = @eventlog_item.event_type
    e["User"] = @eventlog_item.user

    decorate(e)
    @queue << e

    @sincedb[@logfile] = @eventlog_item.record_number
    _sincedb_write

    e = nil
    timestamp = nil
  end # send_logstash_event

  private
  def sincedb_write(reason=nil)
    @logger.debug("#{@log_prefix}sincedb_write: Caller requested sincedb write (#{reason})")
    _sincedb_write(true)  # since this is an external request, force the write
  end

  private
  def _sincedb_open
    path = @sincedb_path
    begin
      db = File.open(path)
    rescue
      @logger.debug? && @logger.debug("#{@log_prefix}_sincedb_open: Error opening #{path}: #{$!}")
      return
    end

    @logger.debug? && @logger.debug("#{@log_prefix}_sincedb_open: Reading from #{path}")
    db.each do |line|
      eventlogname, recordnumber = line.split(" ", 2)
      @logger.debug? && @logger.debug("#{@log_prefix}_sincedb_open: Setting #{eventlogname} to #{recordnumber.to_i}")
      @sincedb[eventlogname] = recordnumber.to_i
    end
    db.close
  end # def _sincedb_open

  private
  def _sincedb_write(sincedb_force_write=false)

    # This routine will only write out sincedb if enough time has passed based on @sincedb_write_interval
    # If it hasn't and we were asked to write, then we are pending a write.

    # if we were called with force == true, then we have to write sincedb and bypass a time check 
    # ie. external caller calling the public sincedb_write method

    if(@sincedb_writing)
      @logger.warn? && @logger.warn("#{@log_prefix}_sincedb_write: Already writing")
      return
    end

    @sincedb_writing = true

    if (!sincedb_force_write)
       now = Time.now.to_i
       delta = now - @sincedb_last_write

       # we will have to flush out the sincedb file after the interval expires.  So, we will try again later.
       if delta < @sincedb_write_interval
         @sincedb_write_pending = true
         @sincedb_writing = false
         return
       end
    end

    @logger.debug? && @logger.debug("#{@log_prefix}_sincedb_write: Writing sincedb (delta since last write = #{delta})")

    path = @sincedb_path
    tmp = "#{path}.new"
    begin
      db = File.open(tmp, "w")
    rescue => e
      @logger.warn? && @logger.warn("#{@log_prefix}_sincedb_write: Failed: #{tmp}: #{e}")
      @sincedb_writing = false
      return
    end

    @sincedb.each do |eventlogname, recordnumber|
      db.puts([eventlogname, recordnumber].flatten.join(" "))
    end
    db.close

    begin
      File.rename(tmp, path)
    rescue => e
      @logger.warn? && @logger.warn("#{@log_prefix}_sincedb_write: Rename/sync failed: #{tmp} -> #{path}: #{e}")
    end

    @sincedb_last_write = now
    @sincedb_write_pending = false
    @sincedb_writing = false

    GC.start
  end # def _sincedb_write

  def stop
    if @in_teardown == false
        @in_teardown = true
        @logger.debug("#{@log_prefix}teardown: Stop running")
        #wait end working
        @logger.debug("#{@log_prefix}teardown: Wait end working")
        while @working == true
            sleep 1
        end
        sincedb_write("Shutdown requested")
        @logger.debug("#{@log_prefix}teardown: Wait to be able exit")
        while @can_exit == false
            sleep 1
        end
        @eventlog.close
    else
      @logger.warn("#{@log_prefix}teardown: Already requested")
    end
    return
  end # def stop

end # class LogStash::Inputs::EventLog