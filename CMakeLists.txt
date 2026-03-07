cmake_minimum_required(VERSION 3.20)

project(pwn_helper VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IDA_SDK_ROOT "" CACHE PATH "Path to ida-sdk root (contains src/include and src/lib)")
if(IDA_SDK_ROOT STREQUAL "")
  if(DEFINED ENV{IDA_SDK_ROOT} AND NOT "$ENV{IDA_SDK_ROOT}" STREQUAL "")
    set(IDA_SDK_ROOT "$ENV{IDA_SDK_ROOT}")
  elseif(DEFINED ENV{IDASDK} AND NOT "$ENV{IDASDK}" STREQUAL "")
    set(IDA_SDK_ROOT "$ENV{IDASDK}")
  endif()
endif()

if(IDA_SDK_ROOT STREQUAL "")
  message(FATAL_ERROR "IDA SDK path is not set. Pass -DIDA_SDK_ROOT=/path/to/ida-sdk-main")
endif()

if(EXISTS "${IDA_SDK_ROOT}/src/include/ida.hpp")
  set(IDA_SDK_SRC "${IDA_SDK_ROOT}/src")
elseif(EXISTS "${IDA_SDK_ROOT}/include/ida.hpp")
  set(IDA_SDK_SRC "${IDA_SDK_ROOT}")
else()
  message(FATAL_ERROR "Cannot find ida.hpp under ${IDA_SDK_ROOT}. Expected src/include/ida.hpp or include/ida.hpp")
endif()

set(IDA_INCLUDE_DIR "${IDA_SDK_SRC}/include")
set(IDA_LIB_BASE "${IDA_SDK_SRC}/lib")

if(WIN32)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(IDA_LIB_DIR "${IDA_LIB_BASE}/x64_win_vc_64")
    set(IDA_LIBS
      "${IDA_LIB_DIR}/ida.lib"
      "${IDA_LIB_DIR}/idalib.lib"
    )
  else()
    message(FATAL_ERROR "This project currently supports only x64 Windows builds.")
  endif()
elseif(APPLE)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
    set(IDA_LIB_DIR "${IDA_LIB_BASE}/arm64_mac_clang_64")
  else()
    set(IDA_LIB_DIR "${IDA_LIB_BASE}/x64_mac_clang_64")
  endif()
  set(IDA_LIBS
    "${IDA_LIB_DIR}/libida.dylib"
    "${IDA_LIB_DIR}/libidalib.dylib"
  )
elseif(UNIX)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(IDA_LIB_DIR "${IDA_LIB_BASE}/x64_linux_gcc_64")
    set(IDA_LIBS
      "${IDA_LIB_DIR}/libida.so"
      "${IDA_LIB_DIR}/libidalib.so"
    )
  else()
    message(FATAL_ERROR "This project currently supports only x64 Linux builds.")
  endif()
else()
  message(FATAL_ERROR "Unsupported platform")
endif()

foreach(_lib IN LISTS IDA_LIBS)
  if(NOT EXISTS "${_lib}")
    message(FATAL_ERROR "Required IDA library not found: ${_lib}")
  endif()
endforeach()

add_library(pwn_helper MODULE
  Test1/main.cpp
  Test1/AdvancedPwnDetectors.hpp
  Test1/FormatStringDetector.hpp
  Test1/IDetector.hpp
  Test1/PatchEngine.hpp
  Test1/ScannerEngine.hpp
  Test1/StackDetector.hpp
  Test1/VulnData.hpp
)

target_include_directories(pwn_helper SYSTEM PRIVATE
  "${IDA_INCLUDE_DIR}"
)

target_include_directories(pwn_helper PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/Test1"
)

target_link_libraries(pwn_helper PRIVATE ${IDA_LIBS})

if(MSVC)
  target_compile_options(pwn_helper PRIVATE /utf-8 /W3 /EHsc)
  target_compile_definitions(pwn_helper PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

set_target_properties(pwn_helper PROPERTIES
  PREFIX ""
  OUTPUT_NAME "pwn_helper"
)

if(DEFINED ENV{IDA_PLUGIN_DIR} AND NOT "$ENV{IDA_PLUGIN_DIR}" STREQUAL "")
  install(TARGETS pwn_helper DESTINATION "$ENV{IDA_PLUGIN_DIR}")
endif()

message(STATUS "IDA include dir: ${IDA_INCLUDE_DIR}")
message(STATUS "IDA lib dir: ${IDA_LIB_DIR}")
