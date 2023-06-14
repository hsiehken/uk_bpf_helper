#include "helper_group_list.h"

#include <stdlib.h>

HelperGroupList *helper_group_list_init() {
    HelperGroupList *list = malloc(sizeof(HelperGroupList));
    if (list == NULL) {
        return NULL;
    }

    list->m_length = 0;
    list->m_head = NULL;
    list->m_tail = NULL;

    return list;
}


HelperGroupListEntry *helper_group_list_emplace_back(HelperGroupList *self, const char *group_name,
                                                     const size_t helper_index_number,
                                                     const UK_UBPF_INDEX_t helper_indexes[]) {
    HelperGroupListEntry *entry = malloc(sizeof(HelperGroupListEntry) +
                                         strlen(group_name) + 1 +
                                         helper_index_number * sizeof(UK_UBPF_INDEX_t));

    if (entry == NULL) {
        return NULL;
    }

    entry->m_next = NULL;
    entry->m_length = helper_index_number;

    entry->m_group_name = (char *) ((size_t)entry + sizeof(HelperGroupListEntry));
    strncpy(entry->m_group_name, group_name, strlen(group_name) + 1);

    entry->m_helper_indexes =
            helper_index_number > 0 ? (UK_UBPF_INDEX_t *) ((size_t)entry->m_group_name + strlen(group_name) + 1) : NULL;

    if (helper_indexes != NULL) {
        for (size_t index = 0; index < helper_index_number; index++) {
            entry->m_helper_indexes[index] = helper_indexes[index];
        }
    }

    // push back the entry to self
    if (self->m_length == 0) {
        self->m_head = entry;
        self->m_tail = entry;
    } else {
        self->m_tail->m_next = entry;
        self->m_tail = entry;
    }

    self->m_length++;

    return entry;
}

void helper_group_destroy(HelperGroupList *self) {
    for (HelperGroupListEntry *entry = self->m_head; entry != NULL;) {
        HelperGroupListEntry *next = entry->m_next;

        free(entry);
        entry = next;
    }

    self->m_length = 0;
    self->m_head = NULL;
    self->m_tail = NULL;

    free(self);
}