#ifndef USHELL_TERMINAL_PROG_TYPE_LIST_H
#define USHELL_TERMINAL_PROG_TYPE_LIST_H

#include "helper_function_list.h"

#include <stdint.h>
#include <string.h>

typedef struct BpfProgType BpfProgType;
typedef struct BpfProgType {
    BpfProgType *m_next;

    size_t m_length;

    char *m_prog_type_name;
    UK_UBPF_INDEX_t *m_allowed_helper_indexes;
} BpfProgType;

/**
 * An linked list of BPF prog_type information.
 */
typedef struct BpfProgTypeList {
    size_t m_length;
    BpfProgType *m_head;
    BpfProgType *m_tail;
} BpfProgTypeList;

BpfProgTypeList *bpf_prog_type_list_init();

BpfProgType *bpf_prog_type_list_emplace_back(BpfProgTypeList *self, const char *prog_type_name,
                                             size_t helper_index_number,
                                             const UK_UBPF_INDEX_t helper_indexes[]);

void bpf_prog_type_list_destroy(BpfProgTypeList *self);

#endif //USHELL_TERMINAL_PROG_TYPE_LIST_H
