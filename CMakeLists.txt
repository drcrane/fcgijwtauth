cmake_minimum_required(VERSION 3.24)

project(auth LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBFCGI REQUIRED fcgi)
pkg_check_modules(LIBSQLITE3 REQUIRED sqlite3)
pkg_check_modules(LIBCURL REQUIRED libcurl)
pkg_check_modules(LIBOPENSSL REQUIRED openssl)

set(JWT_BUILD_EXAMPLES OFF)
add_subdirectory(subprojects/jwt-cpp)

add_library(JWKSVerifier STATIC
    src/JWKSVerifierStore.cpp
	src/HTTPUtils.cpp
)
target_link_libraries(JWKSVerifier PRIVATE ${LIBFCGI_LIBRARIES} ${LIBCURL_LIBRARIES} ${LIBSQLITE3_LIBRARIES} jwt-cpp)

#add_library(${PROJECT_NAME} STATIC
#   src/urlcache.cpp
#	src/jwksstore.cpp
#)
#target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBFCGI_LIBRARIES} ${LIBCURL_LIBRARIES} ${LIBSQLITE3_LIBRARIES} jwt-cpp)

#find_package(jwt-cpp REQUIRED)

add_executable(${PROJECT_NAME}main appsrc/auth.cpp)
target_link_libraries(${PROJECT_NAME}main PRIVATE ${LIBFCGI_LIBRARIES} ${LIBCURL_LIBRARIES} ${LIBSQLITE3_LIBRARIES} jwt-cpp JWKSVerifier)

add_executable(${PROJECT_NAME}mainnospawn appsrc/authnospawn.cpp)
target_link_libraries(${PROJECT_NAME}mainnospawn PRIVATE ${LIBFCGI_LIBRARIES} ${LIBCURL_LIBRARIES} ${LIBSQLITE3_LIBRARIES} jwt-cpp JWKSVerifier)

add_executable(jwks_creator appsrc/jwks_creator.cpp)
target_link_libraries(jwks_creator PRIVATE ${LIBOPENSSL_LIBRARIES} jwt-cpp)

add_executable(jwt_creator appsrc/jwt_creator.cpp)
target_link_libraries(jwt_creator PRIVATE ${LIBOPENSSL_LIBRARIES} jwt-cpp JWKSVerifier)

add_executable(simplestream appsrc/simplestream.c)
target_link_libraries(simplestream PRIVATE ${LIBFCGI_LIBRARIES})

add_subdirectory(testsrc)

