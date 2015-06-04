module Windows
  module Constants
    private

    EVENTLOG_SEQUENTIAL_READ = 0x0001
    EVENTLOG_SEEK_READ       = 0x0002
    EVENTLOG_FORWARDS_READ   = 0x0004
    EVENTLOG_BACKWARDS_READ  = 0x0008

    EVENTLOG_SUCCESS          = 0x0000
    EVENTLOG_ERROR_TYPE       = 0x0001
    EVENTLOG_WARNING_TYPE     = 0x0002
    EVENTLOG_INFORMATION_TYPE = 0x0004
    EVENTLOG_AUDIT_SUCCESS    = 0x0008
    EVENTLOG_AUDIT_FAILURE    = 0x0010

    EVENTLOG_FULL_INFO = 0

    ERROR_SUCCESS = 0
    ERROR_INSUFFICIENT_BUFFER = 122

    BUFFER_SIZE = 1024 * 64
    MAX_SIZE    = 512

    BASE_KEY = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\"

    DONT_RESOLVE_DLL_REFERENCES = 0x00000001
    LOAD_LIBRARY_AS_DATAFILE    = 0x00000002

    FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
    FORMAT_MESSAGE_FROM_HMODULE   = 0x00000800
    FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
  end
end