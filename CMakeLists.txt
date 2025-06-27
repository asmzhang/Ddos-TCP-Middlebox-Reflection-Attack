cmake_minimum_required(VERSION 3.12)
project(TCP-Middlebox-Attack)

# 平台检测与配置
if(WIN32)
    find_package(Wpcap REQUIRED)
    add_definitions(-D_WIN32_WINNT=0x0600)
    add_executable(mra_win mra_win.c)
    target_link_libraries(mra_win Wpcap::Packet Ws2_32)
elseif(UNIX)
    find_package(PCAP REQUIRED)
    find_package(Threads REQUIRED)
    add_executable(mra_linux mra_linux.c)
    target_include_directories(mra_linux PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(mra_linux ${PCAP_LIBRARIES} pthread)
endif()

# 编译选项设置
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Wall -Wextra")

# 安装后清理指令
install(CODE "message(\"编译完成，使用./mra_linux运行程序\")")