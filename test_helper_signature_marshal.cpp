extern "C" {
#include "uk_bpf_helper_utils.h"
}

#include <cstdlib>
#include <string>
#include <cassert>
#include <iostream>
#include <sstream>

std::string buffer;

static void append_result(const char *result) {
    buffer += result;
}

void assert_empty_list() {
    buffer.clear();

    HelperFunctionList *list = helper_function_list_init();

    marshall_bpf_helper_definitions(list, append_result);
    assert(buffer.empty());

    helper_function_list_destroy(list);
}

void assert_empty_arg_list() {
    buffer.clear();

    HelperFunctionList *list = helper_function_list_init();
    helper_function_list_emplace_back(list, 0, "test", nullptr,
                                      UK_EBPF_RETURN_TYPE_INTEGER, 0, nullptr);

    marshall_bpf_helper_definitions(list, append_result);
    assert("test()->" + std::to_string(UK_EBPF_RETURN_TYPE_INTEGER) == buffer);

    helper_function_list_destroy(list);
}

void assert_many_args() {
    buffer.clear();

    HelperFunctionList *list = helper_function_list_init();

    uk_ebpf_argument_type_t arg_types[] = {
            UK_EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
            UK_EBPF_ARGUMENT_TYPE_CONST_SIZE,
            UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO};
    helper_function_list_emplace_back(list, 0, "test", nullptr,
                                      UK_EBPF_RETURN_TYPE_UNSUPPORTED, 3,
                                      arg_types);

    marshall_bpf_helper_definitions(list, append_result);
    std::stringstream stream;
    stream << std::hex << UK_EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL;

    assert("test(" + stream.str() + ","
           + std::to_string(UK_EBPF_ARGUMENT_TYPE_CONST_SIZE) + ","
           + std::to_string(UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO)
           + ")->" + std::to_string(UK_EBPF_RETURN_TYPE_UNSUPPORTED)
           == buffer);

    helper_function_list_destroy(list);
}

void assert_many_functions() {
    buffer.clear();

    HelperFunctionList *list = helper_function_list_init();
    helper_function_list_emplace_back(list, 0, "test", nullptr,
                                      UK_EBPF_RETURN_TYPE_INTEGER, 0, nullptr);

    uk_ebpf_argument_type_t arg_types[] = {
            UK_EBPF_ARGUMENT_TYPE_ANYTHING,
            UK_EBPF_ARGUMENT_TYPE_CONST_SIZE,
            UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO};
    helper_function_list_emplace_back(list, 0, "test2", nullptr,
                                      UK_EBPF_RETURN_TYPE_UNSUPPORTED, 3,
                                      arg_types);

    marshall_bpf_helper_definitions(list, append_result);
    assert("test()->" + std::to_string(UK_EBPF_RETURN_TYPE_INTEGER) + ";"
           + "test2(" + std::to_string(UK_EBPF_ARGUMENT_TYPE_ANYTHING)
           + "," + std::to_string(UK_EBPF_ARGUMENT_TYPE_CONST_SIZE) + ","
           + std::to_string(UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO)
           + ")->" + std::to_string(UK_EBPF_RETURN_TYPE_UNSUPPORTED)
           == buffer);

    helper_function_list_destroy(list);
}

void assert_unmarshal_empty() {
    assert_empty_list();

    auto *result = unmarshall_bpf_helper_definitions(buffer.c_str());

    assert(result != nullptr);
    helper_function_list_destroy(result);

    auto *result2 = unmarshall_bpf_helper_definitions("test()->a");
    assert(result2 != nullptr);
    assert(result2->m_head->m_function_signature.m_return_type == (uk_ebpf_return_type_t) 10);
}

void assert_unmarshal_empty_arg_list() {
    assert_empty_arg_list();

    auto *result = unmarshall_bpf_helper_definitions(buffer.c_str());

    assert(result != nullptr);
    assert(result->m_length == 1);
    assert(
            strcmp(result->m_tail->m_function_signature.m_function_name, "test")
            == 0);
    assert(result->m_tail->m_function_signature.m_return_type
           == UK_EBPF_RETURN_TYPE_INTEGER);
    assert(result->m_tail->m_function_signature.m_num_args == 0);

    helper_function_list_destroy(result);
}

void assert_unmarshal_many_args_list() {
    assert_many_args();

    auto *result = unmarshall_bpf_helper_definitions(buffer.c_str());

    assert(result != nullptr);
    assert(result->m_length == 1);
    assert(
            strcmp(result->m_tail->m_function_signature.m_function_name, "test")
            == 0);
    assert(result->m_tail->m_function_signature.m_return_type
           == UK_EBPF_RETURN_TYPE_UNSUPPORTED);
    assert(result->m_tail->m_function_signature.m_num_args == 3);
    assert(result->m_tail->m_function_signature.m_arg_types[0]
           == UK_EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL);
    assert(result->m_tail->m_function_signature.m_arg_types[1]
           == UK_EBPF_ARGUMENT_TYPE_CONST_SIZE);
    assert(result->m_tail->m_function_signature.m_arg_types[2]
           == UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO);

    helper_function_list_destroy(result);
}

void assert_unmarshal_many_functions_list() {
    assert_many_functions();

    auto *result = unmarshall_bpf_helper_definitions(buffer.c_str());

    assert(result != nullptr);
    assert(result->m_length == 2);

    assert(
            strcmp(result->m_head->m_function_signature.m_function_name, "test")
            == 0);
    assert(result->m_head->m_function_signature.m_return_type
           == UK_EBPF_RETURN_TYPE_INTEGER);
    assert(result->m_head->m_function_signature.m_num_args == 0);

    assert(strcmp(result->m_tail->m_function_signature.m_function_name,
                  "test2")
           == 0);
    assert(result->m_tail->m_function_signature.m_return_type
           == UK_EBPF_RETURN_TYPE_UNSUPPORTED);
    assert(result->m_tail->m_function_signature.m_num_args == 3);
    assert(result->m_tail->m_function_signature.m_arg_types[0]
           == UK_EBPF_ARGUMENT_TYPE_ANYTHING);
    assert(result->m_tail->m_function_signature.m_arg_types[1]
           == UK_EBPF_ARGUMENT_TYPE_CONST_SIZE);
    assert(result->m_tail->m_function_signature.m_arg_types[2]
           == UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO);

    helper_function_list_destroy(result);
}

void assert_reject_null_input() {
    buffer.clear();
    assert(unmarshall_bpf_helper_definitions(nullptr) == nullptr);
}

void assert_reject_empty_function_name() {
    buffer.clear();
    buffer.append("test()->0;()->1");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_unexpected_eof() {
    buffer.clear();
    buffer.append("test()->0;test2()->");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->0;test2()-");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->0;test2()");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->0;test2(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->0;test2");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->0;");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_broken_syntax() {
    buffer.clear();
    buffer.append("test()-0;test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test)->0;test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test((->0;test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test)(->0;test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()-->0;test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->>0;test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("t-est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("t>est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("t)est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("t;est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("t,est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()>-0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()>0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_invalid_return_type() {
    buffer.clear();
    buffer.append("test)->");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test)->x");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test)->xxx");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->+");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->A");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->x");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()-");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()->;test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_invalid_arg_type() {
    buffer.clear();
    buffer.append("test(,)->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test(0,)->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test(,0)->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test(abc,xxx)->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append(
            "test(fffffffffffffffff)->0"); // overflow, not a valid uint64_t
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

int main() {
    assert_empty_list();
    assert_empty_arg_list();
    assert_many_args();
    assert_many_functions();

    assert_unmarshal_empty();
    assert_unmarshal_empty_arg_list();
    assert_unmarshal_many_args_list();
    assert_unmarshal_many_functions_list();

    assert_reject_null_input();
    assert_reject_empty_function_name();
    assert_reject_unexpected_eof();
    assert_reject_broken_syntax();
    assert_reject_invalid_return_type();
    assert_reject_invalid_arg_type();

    exit(EXIT_SUCCESS);
}