add_library(cppcodec INTERFACE)
target_include_directories(cppcodec SYSTEM INTERFACE cppcodec)

# import manually because original CMakeFile of 'jwt-cpp' miss "SYSTEM" flag
add_library(jwt-cpp INTERFACE)
target_include_directories(jwt-cpp SYSTEM INTERFACE jwt-cpp/include)

add_library(RapidJSON INTERFACE)
target_include_directories(RapidJSON SYSTEM INTERFACE rapidjson/include)
