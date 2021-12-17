set(SOURCES Configuration.c mod_authg_jwt.cpp AuthServer.cpp)

    add_library(${PROJECT_NAME} SHARED ${SOURCES})
        target_link_libraries(${PROJECT_NAME} jwt-cpp curl RapidJSON cppcodec)
