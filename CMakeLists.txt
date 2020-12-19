cmake_minimum_required(VERSION 3.16.3)
project(mod_authg_jwt)

#
# Apache related environment
#
find_program(APXS apxs2 DOC "Apache extension")
if(NOT APXS)
    message(FATAL_ERROR "'apxs2' can't be found. Make sure that apache dev package is installed")
endif()

execute_process(COMMAND ${APXS} -q exp_includedir OUTPUT_VARIABLE APACHE_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${APXS} -q APR_INCLUDEDIR OUTPUT_VARIABLE APR_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)

include_directories(${APACHE_INCLUDE_DIR} ${APR_INCLUDE_DIR})

#
# Flags
#
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wall -Werror -pedantic")

#
# Projects
#
add_subdirectory(src)
