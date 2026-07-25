set(TEST_SUITES grammar_loader stream_validator tcp_reassembler reporter)

foreach(suite ${TEST_SUITES})
    add_executable(test_${suite} test_${suite}.cpp)
    target_link_libraries(test_${suite} PRIVATE pcapgrammar_lib GTest::gtest_main)
    add_test(NAME ${suite} COMMAND test_${suite})
endforeach()
