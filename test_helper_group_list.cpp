#include <cstdlib>
#include <cassert>

extern "C" {
#include "helper_group_list.h"
}


void assert_create_empty_list() {
    HelperGroupList *list = helper_group_list_init();
    assert(list != nullptr);
    assert(list->m_length == 0);
    assert(list->m_head == nullptr);
    assert(list->m_tail == nullptr);
    helper_group_destroy(list);
}

void assert_create_list() {
    HelperGroupList *list = helper_group_list_init();
    assert(list != nullptr);
    assert(list->m_length == 0);
    assert(list->m_head == nullptr);
    assert(list->m_tail == nullptr);

    UK_UBPF_INDEX_t indexes[] = {1, 2};
    auto *entry = helper_group_list_emplace_back(list, "group1", 2, indexes);

    assert(list->m_length == 1);
    assert(list->m_head == entry);
    assert(list->m_tail == entry);

    assert(entry->m_next == nullptr);
    assert(entry->m_length == 2);
    assert(strcmp(entry->m_group_name, "group1") == 0);
    assert(entry->m_helper_indexes[0] == 1);
    assert(entry->m_helper_indexes[1] == 2);

    helper_group_destroy(list);
}

void assert_create_multiple_list() {
    HelperGroupList *list = helper_group_list_init();
    assert(list != nullptr);
    assert(list->m_length == 0);
    assert(list->m_head == nullptr);
    assert(list->m_tail == nullptr);

    UK_UBPF_INDEX_t indexes[] = {1, 2};
    auto *entry = helper_group_list_emplace_back(list, "group1/12/", 2, indexes);

    assert(list->m_length == 1);
    assert(list->m_head == entry);
    assert(list->m_tail == entry);

    assert(entry->m_next == nullptr);
    assert(entry->m_length == 2);
    assert(strcmp(entry->m_group_name, "group1/12/") == 0);
    assert(entry->m_helper_indexes[0] == 1);
    assert(entry->m_helper_indexes[1] == 2);

    UK_UBPF_INDEX_t indexes2[] = {3, 4};
    auto *entry2 = helper_group_list_emplace_back(list, "group2/34/", 2, indexes2);

    assert(list->m_length == 2);
    assert(list->m_head == entry);
    assert(list->m_tail == entry2);

    assert(entry->m_next == entry2);
    assert(entry->m_length == 2);
    assert(strcmp(entry->m_group_name, "group1/12/") == 0);
    assert(entry->m_helper_indexes[0] == 1);
    assert(entry->m_helper_indexes[1] == 2);

    assert(entry2->m_next == nullptr);
    assert(entry2->m_length == 2);
    assert(strcmp(entry2->m_group_name, "group2/34/") == 0);
    assert(entry2->m_helper_indexes[0] == 3);
    assert(entry2->m_helper_indexes[1] == 4);


    helper_group_destroy(list);
}


int main() {
    assert_create_empty_list();
    assert_create_list();
    assert_create_multiple_list();

    exit(EXIT_SUCCESS);
}