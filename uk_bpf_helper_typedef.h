//
// Adapted from PREVAIL:
// https://github.com/vbpf/ebpf-verifier/blob/0e572203afadee1e7fe109f169702e8f7ceea5e8/src/ebpf_base.h
//

#ifndef UK_BPF_HELPER_TYPEDEF_H
#define UK_BPF_HELPER_TYPEDEF_H

typedef enum uk_ebpf_return_type {
	UK_EBPF_RETURN_TYPE_INTEGER = 0,
	UK_EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
	UK_EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED,
	UK_EBPF_RETURN_TYPE_UNSUPPORTED,
} uk_ebpf_return_type_t;

typedef enum uk_ebpf_argument_type {
	UK_EBPF_ARGUMENT_TYPE_DONTCARE = 0,
    UK_EBPF_ARGUMENT_TYPE_ANYTHING, // All values are valid, e.g., 64-bit
				     // flags.
	UK_EBPF_ARGUMENT_TYPE_CONST_SIZE,
	UK_EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
	UK_EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
	UK_EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
	UK_EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS,
	UK_EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
	UK_EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE,
	UK_EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // Memory must have been
						// initialized.
	UK_EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
	UK_EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
	UK_EBPF_ARGUMENT_TYPE_UNSUPPORTED,
} uk_ebpf_argument_type_t;

#endif // UK_BPF_HELPER_TYPEDEF_H
