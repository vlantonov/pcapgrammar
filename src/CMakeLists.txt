set(LIB_SOURCES
    GrammarLoader.cpp
    PcapReader.cpp
    TcpReassembler.cpp
    FlowTracker.cpp
    StreamValidator.cpp
    Reporter.cpp
)

add_library(pcapgrammar_lib STATIC ${LIB_SOURCES})
target_include_directories(pcapgrammar_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(PCAPGRAMMAR_USE_CONAN)
    target_link_libraries(pcapgrammar_lib PRIVATE yaml-cpp::yaml-cpp)
    target_link_libraries(pcapgrammar_lib PRIVATE libpcap::libpcap)
else()
    target_link_libraries(pcapgrammar_lib PRIVATE yaml-cpp)
    target_include_directories(pcapgrammar_lib PRIVATE ${LIBPCAP_INCLUDE_DIRS})
    target_link_libraries(pcapgrammar_lib PRIVATE ${LIBPCAP_LIBRARIES})
endif()

add_executable(pcapgrammar main.cpp)
target_link_libraries(pcapgrammar PRIVATE pcapgrammar_lib)
