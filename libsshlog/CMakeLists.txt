

option(BUILD_TESTS "Build test programs" OFF)
option(USE_RINGBUF "Use more efficient Ringbuf for BPF comms, requires recent kernel" OFF)


CPMAddPackage("gh:ibireme/yyjson#0.6.0")
CPMAddPackage("gh:SergiusTheBest/plog#1.1.9")

CPMAddPackage(
  NAME pfs
  GIT_REPOSITORY https://github.com/dtrugman/pfs.git
  VERSION 0.6.0
  DOWNLOAD_ONLY YES
)
if(pfs_ADDED)
  # Bypass default cmake file and compile ourselves to include -fPIC option on static lib

  file(GLOB_RECURSE pfs_sources ${pfs_SOURCE_DIR}/src/*.cpp)
  add_library(pfs STATIC ${pfs_sources})
  set_property(TARGET pfs PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(pfs SYSTEM PUBLIC $<BUILD_INTERFACE:${pfs_SOURCE_DIR}/include>)
endif()

# Build libbpf via Makefile
set (CMAKE_CXX_STANDARD 17)
#set_property(TARGET sshlog PROPERTY CXX_STANDARD 11)
# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    CPPFLAGS=-fPIC
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
    set (X86 TRUE)
else ()
    set (X86 FALSE)
endif ()

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)

if (X86)
  message("-- BPF Using x86 vmlinux.h file")
  set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/bpf/vmlinux/x86/vmlinux.h)
else()
  message("-- BPF Using arm64 vmlinux.h file")
  set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/bpf/vmlinux/arm64/vmlinux.h)
endif()

if (USE_RINGBUF)
  # These define values are carried over in the FindBpfObject.cmake file which calls into clang
  # TODO: Can't seem to figure out how to make this a list of defines that work with FindBpfObject add_custom_command
  message("-- More efficient Ring Buffer enabled")
  set(DEFINE_BPF_USE_RINGBUF -DSSHTRACE_USE_RINGBUF)
endif()
if (CMAKE_BUILD_TYPE STREQUAL "DEBUG" OR CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "debug")
  message("-- Debug log output for BPF enabled.  Available via: cat /sys/kernel/debug/tracing/trace_pipe")
  set(DEFINE_BPF_DEBUG_LOG -D SSHTRACE_DEBUG )
endif()

find_package(BpfObject REQUIRED)

CPMAddPackage(
    NAME tclap
    GITHUB_REPOSITORY mirror/tclap
    GIT_TAG v1.2.5
    DOWNLOAD_ONLY YES
)
if(tclap_ADDED)
    add_library(tclap INTERFACE IMPORTED)
    target_include_directories(
        tclap SYSTEM INTERFACE ${tclap_SOURCE_DIR}/include
    )
endif()


if(USE_RINGBUF)
  set(BPF_EXTRA_DEFINES -D SSHTRACE_USE_RINGBUF )
endif()

bpf_object(sshtrace bpf/sshtrace.bpf.c)
add_dependencies(sshtrace_skel libbpf-build bpftool-build)

set(sshlog_SRC
  sshlog.cpp
  sshtrace_wrapper.cpp
  event_serializer.cpp
  failed_login_watcher.cpp
  proc_parsers/pts_parser.cpp
  proc_parsers/existing_connections.cpp
)
add_library(sshlog SHARED
  ${sshlog_SRC}
)

target_link_libraries(sshlog 
  sshtrace_skel 
  ${LIBBPF_LIBRARIES}
  yyjson
  pfs
  plog
  pthread
  elf
  z
)
target_include_directories(sshlog PRIVATE "${pfs_SOURCE_DIR}/include")


add_executable(sshlog_cli 
  sshlog_cli.cpp
)
target_link_libraries(sshlog_cli
  sshlog
  tclap
)
# Add include directories for PFS library

if(USE_RINGBUF)
  target_compile_definitions(sshlog PUBLIC SSHTRACE_USE_RINGBUF)
endif()

set_target_properties(sshlog PROPERTIES SOVERSION 1)
install (TARGETS sshlog   DESTINATION    ${CMAKE_INSTALL_PREFIX}/lib)