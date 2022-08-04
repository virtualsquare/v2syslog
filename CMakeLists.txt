cmake_minimum_required(VERSION 3.12)
project(v2syslog
		VERSION 0.0.1
		DESCRIPTION "syslog for virtualsquare"
		HOMEPAGE_URL "https://github.com/virtualsquare/v2syslog"
		LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckSymbolExists)

set(LIBS_REQUIRED ioth iothconf stropt)
set(HEADERS_REQUIRED ioth.h iothconf.h stropt.h strcase.h)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

add_definitions(-D_GNU_SOURCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# ck deps

add_library(libv2syslog SHARED v2syslog.c)
target_link_libraries(libv2syslog ioth)
set_target_properties(libv2syslog PROPERTIES
		OUTPUT_NAME "v2syslog"
		VERSION ${PROJECT_VERSION}
		SOVERSION ${PROJECT_VERSION_MAJOR})

add_library(libv2syslog-static STATIC v2syslog.c)
set_target_properties(libv2syslog-static
		PROPERTIES OUTPUT_NAME v2syslog)

configure_file(v2syslog.pc.in v2syslog.pc @ONLY)

install(TARGETS libv2syslog
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS libv2syslog-static
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES v2syslog.h
		DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/v2syslog.pc
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

add_executable(v2syslogd v2syslogd.c logset.c syslog_names.c readconf.c fdprintf.c selflog.c)
target_link_libraries(v2syslogd libv2syslog stropt iothconf)

install(TARGETS v2syslogd
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
