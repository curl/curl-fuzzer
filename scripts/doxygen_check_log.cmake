# Fail the build if the Doxygen warning log has any contents.
# Invoked from the doxygen-check custom target; WARN_LOG points to the log
# doxygen was told to write via WARN_LOGFILE.

if(NOT DEFINED WARN_LOG)
    message(FATAL_ERROR "WARN_LOG not set")
endif()

if(NOT EXISTS "${WARN_LOG}")
    # doxygen writes the file only when there were warnings; its absence
    # means clean run.
    return()
endif()

file(SIZE "${WARN_LOG}" log_size)
if(log_size EQUAL 0)
    return()
endif()

file(READ "${WARN_LOG}" log_contents)
message("${log_contents}")
message(FATAL_ERROR "Doxygen emitted warnings — see above.")
