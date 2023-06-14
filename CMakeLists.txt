cmake_minimum_required(VERSION 3.20)
project(uk_bpf_helper C)

set(CMAKE_C_STANDARD 11)

add_library(uk_bpf_helper SHARED
        uk_bpf_helper_utils.c uk_bpf_helper_utils.h uk_bpf_helper_typedef.h
        helper_function_list.c helper_function_list.h
        helper_group_list.c helper_group_list.h)

add_executable(test_helper_function_list test_helper_function_list.c)
target_link_libraries(test_helper_function_list uk_bpf_helper)

add_executable(test_helper_group_list test_helper_group_list.cpp)
target_link_libraries(test_helper_group_list uk_bpf_helper)

add_executable(test_bpf_helper_utils test_helper_signature_marshal.cpp)
target_link_libraries(test_bpf_helper_utils uk_bpf_helper)

