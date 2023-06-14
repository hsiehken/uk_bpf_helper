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

    auto *list = helper_function_list_init();
    auto *result = helper_function_list_emplace_back(list, 1, "test", nullptr,
                                                     UK_EBPF_RETURN_TYPE_INTEGER, 0, nullptr);

    assert(list->m_tail == result);

    marshall_bpf_helper_definitions(list, append_result);
    assert("1:test()->" + std::to_string(UK_EBPF_RETURN_TYPE_INTEGER) == buffer);

    helper_function_list_destroy(list);
}

void assert_many_args() {
    buffer.clear();

    HelperFunctionList *list = helper_function_list_init();

    uk_ebpf_argument_type_t arg_types[] = {
            UK_EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
            UK_EBPF_ARGUMENT_TYPE_CONST_SIZE,
            UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO};
    helper_function_list_emplace_back(list, 1, "test", nullptr,
                                      UK_EBPF_RETURN_TYPE_UNSUPPORTED, 3,
                                      arg_types);

    marshall_bpf_helper_definitions(list, append_result);
    std::stringstream stream;
    stream << std::hex << UK_EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL;

    assert("1:test(" + stream.str() + ","
           + std::to_string(UK_EBPF_ARGUMENT_TYPE_CONST_SIZE) + ","
           + std::to_string(UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO)
           + ")->" + std::to_string(UK_EBPF_RETURN_TYPE_UNSUPPORTED)
           == buffer);

    helper_function_list_destroy(list);
}

void assert_many_functions() {
    buffer.clear();

    HelperFunctionList *list = helper_function_list_init();
    helper_function_list_emplace_back(list, 1, "test", nullptr,
                                      UK_EBPF_RETURN_TYPE_INTEGER, 0, nullptr);

    uk_ebpf_argument_type_t arg_types[] = {
            UK_EBPF_ARGUMENT_TYPE_ANYTHING,
            UK_EBPF_ARGUMENT_TYPE_CONST_SIZE,
            UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO};
    helper_function_list_emplace_back(list, 2, "test2", nullptr,
                                      UK_EBPF_RETURN_TYPE_UNSUPPORTED, 3,
                                      arg_types);

    marshall_bpf_helper_definitions(list, append_result);
    assert("1:test()->" + std::to_string(UK_EBPF_RETURN_TYPE_INTEGER) + ";"
           + "2:test2(" + std::to_string(UK_EBPF_ARGUMENT_TYPE_ANYTHING)
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
}

void assert_unmarshal_hex_ret_type() {
    auto *result2 = unmarshall_bpf_helper_definitions("1:test()->a");
    assert(result2 != nullptr);
    assert(result2->m_head->m_function_signature.m_return_type == (uk_ebpf_return_type_t) 10);
    assert(result2->m_head->m_index == 1);

    helper_function_list_destroy(result2);
}

void assert_unmarshal_empty_arg_list() {
    assert_empty_arg_list();

    auto *result = unmarshall_bpf_helper_definitions(buffer.c_str());

    assert(result != nullptr);
    assert(result->m_length == 1);
    assert(result->m_tail->m_index == 1);
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
    assert(result->m_tail->m_index == 1);
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

    assert(result->m_head->m_index == 1);
    assert(
            strcmp(result->m_head->m_function_signature.m_function_name, "test")
            == 0);
    assert(result->m_head->m_function_signature.m_return_type
           == UK_EBPF_RETURN_TYPE_INTEGER);
    assert(result->m_head->m_function_signature.m_num_args == 0);

    assert(result->m_tail->m_index == 2);
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
    buffer.append("1:test()->0;2:()->1");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_empty_index() {
    buffer.clear();
    buffer.append("1:test()->0;:()->1");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_unexpected_eof() {
    buffer.clear();
    buffer.append("0:test()->0;1:test2()->");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->0;1:test2()-");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->0;1:test2()");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->0;1:test2(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->0;1:test2");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->0;1:");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->0;");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_broken_syntax() {
    buffer.clear();
    buffer.append("0:test()-0;1:test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test)->0;1:test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test((->0;1:test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test)(->0;1:test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()-->0;0:test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->>0;0:test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:t-est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:t>est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:t)est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:t:est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);


    buffer.clear();
    buffer.append("0:t;est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:t,est(");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()>-0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()>0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0test()>0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0;test()>0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append(":test()>0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append(";test()>0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("test()>0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_invalid_return_type() {
    buffer.clear();
    buffer.append("0:test)->");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test)->x");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test)->xxx");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->+");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->A");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->x");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()-");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test()->;0:test2()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_invalid_arg_type() {
    buffer.clear();
    buffer.append("0:test(,)->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test(0,)->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test(,0)->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test(abc,xxx)->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append(
            "0:test(fffffffffffffffff)->0"); // overflow, not a valid uint64_t
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("0:test->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_reject_invalid_index() {
    buffer.clear();
    buffer.append("x:test()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("aaaaaaaaa:test()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);

    buffer.clear();
    buffer.append("A:test()->0");
    assert(unmarshall_bpf_helper_definitions(buffer.c_str()) == nullptr);
}

void assert_empty_group_list() {
    buffer.clear();

    auto *list = helper_group_list_init();

    marshall_bpf_helper_groups(list, append_result);
    assert(buffer.empty());

    helper_group_destroy(list);
}

void assert_null_group_list() {
    buffer.clear();

    marshall_bpf_helper_groups(nullptr, append_result);
    assert(buffer.empty());
}

void assert_group_list_w_one_element() {
    buffer.clear();

    auto *list = helper_group_list_init();

    UK_UBPF_INDEX_t indexes[] = {1, 2, 3};
    helper_group_list_emplace_back(list, "test", 3,  indexes);

    marshall_bpf_helper_groups(list, append_result);
    assert("test:1,2,3" == buffer);

    helper_group_destroy(list);
}

void assert_group_list_w_multi_element() {
    buffer.clear();

    auto *list = helper_group_list_init();

    UK_UBPF_INDEX_t indexes[] = {1, 2, 3};
    helper_group_list_emplace_back(list, "test", 3, indexes);

    UK_UBPF_INDEX_t indexes2[] = {4, 5, 6};
    helper_group_list_emplace_back(list, "test2", 3, indexes2);

    marshall_bpf_helper_groups(list, append_result);
    assert("test:1,2,3;test2:4,5,6" == buffer);

    helper_group_destroy(list);
}


void assert_unmarshal_empty_group() {
    assert_empty_group_list();

    auto *list = unmarshall_bpf_helper_groups(buffer.c_str());
    assert(list != nullptr);

    assert(list->m_length == 0);
    assert(list->m_head == nullptr);
    assert(list->m_tail == nullptr);

    helper_group_destroy(list);
}


void assert_unmarshal_group_null() {
    auto *list = unmarshall_bpf_helper_groups(nullptr);
    assert(list == nullptr);
}

void assert_unmarshal_group_w_one() {
    assert_group_list_w_one_element();

    auto *list = unmarshall_bpf_helper_groups(buffer.c_str());
    assert(list != nullptr);
    assert(list->m_head != nullptr);
    assert(list->m_tail != nullptr);
    assert(list->m_head == list->m_tail);

    assert(list->m_tail->m_next == nullptr);
    assert(list->m_tail->m_length == 3);
    assert(strcmp(list->m_tail->m_group_name, "test") == 0);
    for (size_t index = 0; index < list->m_tail->m_length; index++) {
        assert(list->m_tail->m_helper_indexes[index] == index + 1);
    }

    helper_group_destroy(list);
}

void assert_unmarshal_group_w_multi() {
    assert_group_list_w_multi_element();

    auto *list = unmarshall_bpf_helper_groups(buffer.c_str());
    assert(list != nullptr);
    assert(list->m_head != nullptr);
    assert(list->m_tail != nullptr);
    assert(list->m_head != list->m_tail);

    assert(list->m_head->m_next == list->m_tail);
    assert(list->m_head->m_length == 3);
    assert(strcmp(list->m_head->m_group_name, "test") == 0);
    for (size_t index = 0; index < list->m_head->m_length; index++) {
        assert(list->m_head->m_helper_indexes[index] == index + 1);
    }

    assert(list->m_tail->m_next == nullptr);
    assert(list->m_tail->m_length == 3);
    assert(strcmp(list->m_tail->m_group_name, "test2") == 0);
    for (size_t index = 0; index < list->m_tail->m_length; index++) {
        assert(list->m_tail->m_helper_indexes[index] == index + 4);
    }

    helper_group_destroy(list);
}

void assert_unmarshal_accept_empty_group() {
    auto *list = unmarshall_bpf_helper_groups("test:");
    assert(list != nullptr);
    assert(list->m_head != nullptr);
    assert(list->m_tail != nullptr);
    assert(list->m_length == 1);

    assert(list->m_head->m_next == nullptr);
    assert(list->m_head->m_length == 0);
    assert(strcmp(list->m_head->m_group_name, "test") == 0);
    assert(list->m_head->m_helper_indexes == nullptr);

    auto *list2 = unmarshall_bpf_helper_groups("test:;test2:");
    assert(list2 != nullptr);
    assert(list2->m_head != nullptr);
    assert(list2->m_tail != nullptr);
    assert(list2->m_length == 2);

    assert(list2->m_head->m_next == list2->m_tail);
    assert(list2->m_head->m_length == 0);
    assert(strcmp(list2->m_head->m_group_name, "test") == 0);
    assert(list2->m_head->m_helper_indexes == nullptr);

    assert(list2->m_tail->m_next == nullptr);
    assert(list2->m_tail->m_length == 0);
    assert(strcmp(list2->m_tail->m_group_name, "test2") == 0);
    assert(list2->m_tail->m_helper_indexes == nullptr);

    auto *list3 = unmarshall_bpf_helper_groups("test:1,2,3;test2:");
    assert(list3 != nullptr);
    assert(list3->m_head != nullptr);
    assert(list3->m_tail != nullptr);
    assert(list3->m_length == 2);

    assert(list3->m_head->m_next == list3->m_tail);
    assert(list3->m_head->m_length == 3);
    assert(strcmp(list3->m_head->m_group_name, "test") == 0);
    assert(list3->m_head->m_helper_indexes != nullptr);
    assert(list3->m_head->m_helper_indexes[0] == 1);
    assert(list3->m_head->m_helper_indexes[1] == 2);
    assert(list3->m_head->m_helper_indexes[2] == 3);

    assert(list3->m_tail->m_next == nullptr);
    assert(list3->m_tail->m_length == 0);
    assert(strcmp(list3->m_tail->m_group_name, "test2") == 0);
    assert(list3->m_tail->m_helper_indexes == nullptr);

    auto *list4 = unmarshall_bpf_helper_groups("test:;test2:4,5,6");
    assert(list4 != nullptr);
    assert(list4->m_head != nullptr);
    assert(list4->m_tail != nullptr);
    assert(list4->m_length == 2);

    assert(list4->m_head->m_next == list4->m_tail);
    assert(list4->m_head->m_length == 0);
    assert(strcmp(list4->m_head->m_group_name, "test") == 0);
    assert(list4->m_head->m_helper_indexes == nullptr);

    assert(list4->m_tail->m_next == nullptr);
    assert(list4->m_tail->m_length == 3);
    assert(strcmp(list4->m_tail->m_group_name, "test2") == 0);
    assert(list4->m_tail->m_helper_indexes != nullptr);
    assert(list4->m_tail->m_helper_indexes[0] == 4);
    assert(list4->m_tail->m_helper_indexes[1] == 5);
    assert(list4->m_tail->m_helper_indexes[2] == 6);

    helper_group_destroy(list);
    helper_group_destroy(list2);
    helper_group_destroy(list3);
    helper_group_destroy(list4);
}

void assert_unmarshal_group_name_w_slash() {
    auto *list = unmarshall_bpf_helper_groups("test/:1,2,3");
    assert(list != nullptr);
    assert(list->m_head != nullptr);
    assert(list->m_tail != nullptr);
    assert(list->m_head == list->m_tail);

    assert(list->m_tail->m_next == nullptr);
    assert(list->m_tail->m_length == 3);
    assert(strcmp(list->m_tail->m_group_name, "test/") == 0);
    for (size_t index = 0; index < list->m_tail->m_length; index++) {
        assert(list->m_tail->m_helper_indexes[index] == index + 1);
    }

    helper_group_destroy(list);
}

void assert_unmarshal_group_reject_empty_group_name() {
    auto *list = unmarshall_bpf_helper_groups("test/:1,2,3;:4,5,6");
    assert(list == nullptr);

    auto *list2 = unmarshall_bpf_helper_groups("test/:1,2,3;:");
    assert(list2 == nullptr);
}

void assert_unmarshal_group_reject_empty_helper_index() {
    auto *list = unmarshall_bpf_helper_groups("test:1,2,3;test2:,");
    assert(list == nullptr);

    auto *list2 = unmarshall_bpf_helper_groups("test:1,2,;test2:,");
    assert(list2 == nullptr);

    auto *list3 = unmarshall_bpf_helper_groups("test:1,,3;test2:,");
    assert(list3 == nullptr);
}

void assert_unmarshal_group_reject_invalid_group_name() {
    auto *list = unmarshall_bpf_helper_groups("test::1,2,3");
    assert(list == nullptr);

    list = unmarshall_bpf_helper_groups(":test::1,2,3");
    assert(list == nullptr);

    list = unmarshall_bpf_helper_groups(":");
    assert(list == nullptr);

    list = unmarshall_bpf_helper_groups("test,:1,2,3");
    assert(list == nullptr);

    list = unmarshall_bpf_helper_groups(",test:1,2,3");
    assert(list == nullptr);

    list = unmarshall_bpf_helper_groups("test;test2:1,2,3");
    assert(list == nullptr);
}

void assert_unmarshal_group_reject_invalid_EOF() {
    auto *list = unmarshall_bpf_helper_groups("test:1,2,3;");
    assert(list == nullptr);

    list = unmarshall_bpf_helper_groups("test");
    assert(list == nullptr);
}

void assert_unmarshal_group_reject_invalid_helper_index() {
    auto *list = unmarshall_bpf_helper_groups("test:1,x,3");
    assert(list == nullptr);

    list = unmarshall_bpf_helper_groups("test:1,aaaaaaaa,3");
    assert(list != nullptr);
    helper_group_destroy(list);

    list = unmarshall_bpf_helper_groups("test:1,aaaaaaaaa,3");
    assert(list == nullptr);
}


int main() {
    assert_empty_list();
    assert_empty_arg_list();
    assert_many_args();
    assert_many_functions();
    assert_reject_empty_index();
    assert_unmarshal_empty();
    assert_unmarshal_hex_ret_type();
    assert_unmarshal_empty_arg_list();
    assert_unmarshal_many_args_list();
    assert_unmarshal_many_functions_list();

    assert_reject_null_input();
    assert_reject_empty_function_name();
    assert_reject_unexpected_eof();
    assert_reject_broken_syntax();
    assert_reject_invalid_return_type();
    assert_reject_invalid_arg_type();
    assert_reject_invalid_index();

    // helper group list tests
    assert_empty_group_list();
    assert_null_group_list();
    assert_group_list_w_one_element();
    assert_group_list_w_multi_element();

    assert_unmarshal_empty_group();
    assert_unmarshal_group_null();
    assert_unmarshal_group_w_one();
    assert_unmarshal_group_w_multi();
    assert_unmarshal_group_name_w_slash();
    assert_unmarshal_accept_empty_group();

    assert_unmarshal_group_reject_empty_group_name();
    assert_unmarshal_group_reject_empty_helper_index();
    assert_unmarshal_group_reject_invalid_group_name();
    assert_unmarshal_group_reject_invalid_EOF();
    assert_unmarshal_group_reject_invalid_helper_index();

    exit(EXIT_SUCCESS);
}