enable_testing()

set(EXECUTABLES
    jwt_tests
	jwksverifier_tests
	httputils_tests
)

foreach(EXECUTABLE ${EXECUTABLES})
    set(SOURCE_FILE ${EXECUTABLE}.cpp)
    add_executable(${EXECUTABLE} ${SOURCE_FILE})
	target_link_libraries(${EXECUTABLE} PRIVATE ${OPENSSL_LIBRARIES} ${LIBCURL_LIBRARIES} ${LIBSQLITE3_LIBRARIES} jwt-cpp JWKSVerifier)
endforeach()

