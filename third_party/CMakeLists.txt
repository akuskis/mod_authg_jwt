add_subdirectory(jwt-cpp)

add_library(RapidJSON INTERFACE)
target_include_directories(RapidJSON INTERFACE rapidjson/include)
