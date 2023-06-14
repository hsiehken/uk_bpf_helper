#ifndef USHELL_TERMINAL_HELPER_GROUP_LIST_H
#define USHELL_TERMINAL_HELPER_GROUP_LIST_H

#include "helper_function_list.h"

#include <stdint.h>
#include <string.h>

typedef struct HelperGroupListEntry HelperGroupListEntry;
typedef struct HelperGroupListEntry {
    HelperGroupListEntry *m_next;

    size_t m_length;

    char *m_group_name;
    UK_UBPF_INDEX_t *m_helper_indexes;
} HelperGroupListEntry;

/**
 * An linked list of helper function information.
 */
typedef struct HelperGroupList {
    size_t m_length;
    HelperGroupListEntry *m_head;
    HelperGroupListEntry *m_tail;
} HelperGroupList;

HelperGroupList *helper_group_list_init();

HelperGroupListEntry *helper_group_list_emplace_back(HelperGroupList *self, const char *group_name,
                                                     size_t helper_index_number,
                                                     const UK_UBPF_INDEX_t helper_indexes[]);

void helper_group_destroy(HelperGroupList *self);

#endif //USHELL_TERMINAL_HELPER_GROUP_LIST_H
