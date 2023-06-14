#include "prog_type_list.h"

#include <stdlib.h>

BpfProgTypeList *bpf_prog_type_list_init() {
    BpfProgTypeList *list = malloc(sizeof(BpfProgTypeList));
    if (list == NULL) {
        return NULL;
    }

    list->m_length = 0;
    list->m_head = NULL;
    list->m_tail = NULL;

    return list;
}


BpfProgType *bpf_prog_type_list_emplace_back(BpfProgTypeList *self, const char *prog_type_name,
                                             size_t helper_index_number,
                                             const UK_UBPF_INDEX_t helper_indexes[]) {
    BpfProgType *entry = malloc(sizeof(BpfProgType) +
                                strlen(prog_type_name) + 1 +
                                           helper_index_number * sizeof(UK_UBPF_INDEX_t));

    if (entry == NULL) {
        return NULL;
    }

    entry->m_next = NULL;
    entry->m_length = helper_index_number;

    entry->m_prog_type_name = (char *) ((size_t) entry + sizeof(BpfProgType));
    strncpy(entry->m_prog_type_name, prog_type_name, strlen(prog_type_name) + 1);

    entry->m_allowed_helper_indexes =
            helper_index_number > 0 ? (UK_UBPF_INDEX_t *) ((size_t) entry->m_prog_type_name + strlen(prog_type_name) + 1)
                                    : NULL;

    if (helper_indexes != NULL) {
        for (size_t index = 0; index < helper_index_number; index++) {
            entry->m_allowed_helper_indexes[index] = helper_indexes[index];
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

void bpf_prog_type_list_destroy(BpfProgTypeList *self) {
    for (BpfProgType *entry = self->m_head; entry != NULL;) {
        BpfProgType *next = entry->m_next;

        free(entry);
        entry = next;
    }

    self->m_length = 0;
    self->m_head = NULL;
    self->m_tail = NULL;

    free(self);
}