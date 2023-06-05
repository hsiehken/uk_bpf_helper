#include "helper_function_list.h"

#include <stdlib.h>

HelperFunctionEntry *helper_function_entry_constructor(
    const UK_UBPF_INDEX_t index, const char *function_name,
    const void *function_addr, const ebpf_return_type_t ret_type,
    const UK_EBPF_HELPER_ARG_TYPE_NUM_t arg_type_count,
    const ebpf_argument_type_t arg_types[])
{
	HelperFunctionEntry *entry =
	    malloc(sizeof(HelperFunctionEntry)
		   + arg_type_count * sizeof(ebpf_argument_type_t));
	if (entry == NULL) {
		return NULL;
	}

	entry->m_index = index;
	entry->m_function_addr = function_addr;

	entry->m_function_signature.m_function_name =
	    malloc(strlen(function_name) + 1);
	strncpy(entry->m_function_signature.m_function_name, function_name,
		strlen(function_name) + 1);
	entry->m_function_signature.m_return_type = ret_type;
	entry->m_function_signature.m_num_args = arg_type_count;
	for (int i = 0; i < arg_type_count; ++i) {
		entry->m_function_signature.m_arg_types[i] = arg_types[i];
	}

	return entry;
}

void helper_function_entry_destructor(HelperFunctionEntry *entry)
{
	free(entry->m_function_signature.m_function_name);
	free(entry);
}

HelperFunctionList *helper_function_list_init()
{
	HelperFunctionList *instance = malloc(sizeof(HelperFunctionList));

	if (instance == NULL) {
		return NULL;
	}

	instance->m_length = 0;
	instance->m_head = NULL;
	instance->m_tail = NULL;

	return instance;
}

bool helper_function_list_emplace_back(
    HelperFunctionList *self, UK_UBPF_INDEX_t index, const char *functionName,
    const void *functionAddr, const ebpf_return_type_t retType,
    const UK_EBPF_HELPER_ARG_TYPE_NUM_t argTypeCount,
    const ebpf_argument_type_t argTypes[])
{

	HelperFunctionEntry *entry = helper_function_entry_constructor(
	    index, functionName, functionAddr, retType, argTypeCount, argTypes);

	if (entry == NULL) {
		return false;
	}

	entry->m_next = NULL;

	if (self->m_length == 0) {
		self->m_head = entry;
	} else {
		self->m_tail->m_next = entry;
	}

	self->m_tail = entry;

	self->m_length++;

	return true;
}

void helper_function_list_remove_elem(HelperFunctionList *self,
				      const char *function_name)
{
	size_t removed_elements = 0;

	HelperFunctionEntry *lastEntry = NULL;
	for (HelperFunctionEntry *entry = self->m_head; entry != NULL;) {
		HelperFunctionEntry *next = entry->m_next;

		if (strncmp(entry->m_function_signature.m_function_name,
			    function_name,
			    UK_EBPF_HELPER_FUNCTION_MAX_NAME_LENGTH)
		    == 0) {

			if (lastEntry == NULL) { // case 1: remove the head
				self->m_head = entry->m_next;
			} else if (entry
				   == self->m_tail) { // case 2: remove the tail
				self->m_tail = lastEntry;
				lastEntry->m_next = NULL;
			} else { // case 3: remove the middle
				lastEntry->m_next = entry->m_next;
			}

			removed_elements++;

			helper_function_entry_destructor(entry);
		} else {
			lastEntry = entry;
		}

		entry = next;
	}

	self->m_length -= removed_elements;
}

void helper_function_list_destroy(HelperFunctionList *self)
{
	for (HelperFunctionEntry *entry = self->m_head; entry != NULL;) {
		HelperFunctionEntry *next = entry->m_next;
		helper_function_entry_destructor(entry);
		entry = next;
	}

	free(self);
}