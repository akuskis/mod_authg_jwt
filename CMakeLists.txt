cmake_minimum_required(VERSION 3.16.3)
project(mod_authg_jwt)

#
# Apache related environment
#
include(cmake/FindApache.cmake)

#
# Flags
#
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wall -pedantic -Werror")

#
# Projects
#
add_subdirectory(src)
add_subdirectory(third_party)
