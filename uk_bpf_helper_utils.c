#include "uk_bpf_helper_utils.h"
#include "helper_function_list.h"

#include <stdlib.h>
#include <stdio.h>

// Adapted from
// https://github.com/bminor/newlib/blob/master/newlib/libc/stdlib/utoa.c
// static: do not export this function
static char *utoa_16(unsigned value, char *str) {
    const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    int i, j;
    unsigned remainder;
    char c;

    /* Convert to string. Digits are in reverse order.  */
    i = 0;
    do {
        remainder = value % 16;
        str[i++] = digits[remainder];
        value = value / 16;
    } while (value != 0);
    str[i] = '\0';

    /* Reverse string.  */
    for (j = 0, i--; j < i; j++, i--) {
        c = str[j];
        str[j] = str[i];
        str[i] = c;
    }

    return str;
}

void marshall_bpf_helper_definitions(HelperFunctionList *instance,
                                     void (*append_result)(const char *)) {
    // for hex number in the 64 bit space, max length of an integer is 16
    char buffer[16 + 1];

    for (HelperFunctionEntry *entry = instance->m_head; entry != NULL;
         entry = entry->m_next) {
        utoa_16(entry->m_index, buffer);
        append_result(buffer);
        append_result(UK_BPF_HELPER_DEFINITION_INDEX_END);

        append_result(entry->m_function_signature.m_function_name);
        append_result(UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_START);
        for (int index = 0;
             index < entry->m_function_signature.m_num_args; index++) {
            utoa_16(entry->m_function_signature.m_arg_types[index],
                    buffer);
            append_result(buffer);
            if (index
                != entry->m_function_signature.m_num_args - 1) {
                append_result(
                        UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_SPLIT);
            }
        }

        append_result(
                UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_END
                UK_BPF_HELPER_DEFINITION_RETURN_TYPE_INDICATOR);
        utoa_16(entry->m_function_signature.m_return_type, buffer);
        append_result(buffer);

        if (entry->m_next != NULL) {
            append_result(UK_BPF_HELPER_DEFINITION_FUNCTION_SPLIT);
        }
    }
}

static bool is_hex_digit(const char input) {
    return (input >= '0' && input <= '9') || (input >= 'a' && input <= 'f');
}

static size_t peek_argument_number(const char *input) {
    size_t result = 0;
    size_t index = 1; // skip the first '('

    for (; input[index] != '\0'
           && input[index] != UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_END[0];
           index++) {
        if (input[index]
            == UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_SPLIT[0]) {
            result++;
        } else if (!is_hex_digit(input[index])) {
            return -1;
        }
    }

    if (index > 1) {
        result++; // add the last argument
    }

    return result;
}


#define STATE_ERROR (-1)
#define STATE_INDEX 0
#define STATE_FUNC_NAME 1
#define STATE_ARG_TYPE 2
#define STATE_RETURN_TYPE 3
#define STATE_END 4

#define STR_LEN(str) (sizeof(str) / sizeof(str[0]) - 1)

/**
 * Note: m_function_addr is not serialized. The information is lost and
 * will be set to NULL when unmarshalling.
 *
 * @param input The helper function definition info provided by UShell.
 */
HelperFunctionList *unmarshall_bpf_helper_definitions(const char *input) {
    if (input == NULL) {
        return NULL;
    }

    const size_t input_length = strlen(input);

    char *buffer = malloc(input_length + 1);
    if (buffer == NULL) {
        return NULL;
    }
    strcpy(buffer, input);

    HelperFunctionList *instance = helper_function_list_init();
    if (instance == NULL) {
        free(buffer);
        return NULL;
    }

    if (input_length == 0) {
        free(buffer);
        return instance;
    }

    size_t buffer_length = input_length;

    int state = STATE_INDEX;
    size_t pointer = 0;
    size_t arg_index = 0;

    unsigned int helper_index = 0;

    for (size_t index = 0; index < buffer_length + 1; index++) {
        switch (state) {  // NOLINT(hicpp-multiway-paths-covered)
            case STATE_ERROR: // error state, destroy the instance and
                // return NULL
                goto escape_for;

            case STATE_INDEX:
                if (buffer[index] == UK_BPF_HELPER_DEFINITION_INDEX_END[0]) {
                    if (pointer == index || index - pointer > 8) {
                        // error, index is empty or too long
                        state = STATE_ERROR;
                        continue;
                    }

                    buffer[index] = '\0';
                    helper_index = strtol(&buffer[pointer], NULL, 16);
                    pointer = index + 1;
                    state = STATE_FUNC_NAME;
                } else if (!is_hex_digit(buffer[index])) {
                    state = STATE_ERROR;
                    continue;
                }

                break;

            case STATE_FUNC_NAME: // init state, expecting function name
                if (buffer[index]
                    == UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_START
                    [0]) {
                    if (pointer
                        == index) { // error, function name is empty
                        state = STATE_ERROR;
                        continue;
                    }

                    // peek number of arguments
                    size_t num_args =
                            peek_argument_number(&buffer[index]);
                    if (num_args == (size_t) -1) {
                        // there are invalid characters in the
                        // argument list
                        state = STATE_ERROR;
                        continue;
                    }

                    uk_ebpf_argument_type_t *dummy_args = calloc(
                            num_args, sizeof(uk_ebpf_argument_type_t));
                    if (dummy_args == NULL) {
                        state = STATE_ERROR;
                        continue;
                    }

                    // create a new entry, put the function name in
                    // it
                    buffer[index] = '\0';

                    if (!helper_function_list_emplace_back(
                            instance, helper_index, &buffer[pointer], NULL, 0,
                            num_args, dummy_args)) {
                        state = STATE_ERROR;
                        continue;
                    }

                    // we must at least have a return type
                    // i.e. at lease )->0 in the given string
                    if (index
                        + STR_LEN(
                                UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_END)
                        + STR_LEN(
                                UK_BPF_HELPER_DEFINITION_RETURN_TYPE_INDICATOR)
                        + 1
                        >= buffer_length) {
                        state = STATE_ERROR;
                        continue;
                    }

                    pointer = index + 1; // skip the '('
                    arg_index = 0;
                    state = STATE_ARG_TYPE;
                } else if (
                        buffer[index] == UK_BPF_HELPER_DEFINITION_INDEX_END[0]
                        || buffer[index]
                           == UK_BPF_HELPER_DEFINITION_FUNCTION_SPLIT[0]
                        || buffer[index]
                           == UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_SPLIT
                           [0]
                        || buffer[index]
                           == UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_END
                           [0]
                        || buffer[index]
                           == UK_BPF_HELPER_DEFINITION_RETURN_TYPE_INDICATOR
                           [0]
                        || buffer[index]
                           == UK_BPF_HELPER_DEFINITION_RETURN_TYPE_INDICATOR
                           [1]) {
                    // invalid character in function name
                    state = STATE_ERROR;
                    continue;
                }

                break;
            case STATE_ARG_TYPE: // read argument type util ')
                if (buffer[index]
                    == UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_SPLIT
                    [0]
                    || buffer[index]
                       == UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_END
                       [0]) {
                    // get pointer -> index - 1 as argument type
                    const char current_token = buffer[index];

                    if (instance->m_tail->m_function_signature
                                .m_num_args
                        > 0) {
                        if (pointer == index) {
                            state = STATE_ERROR;
                            continue;
                        }

                        // max length of argument type is 16
                        // (uint64_t)
                        if (index - pointer > 16) {
                            state = STATE_ERROR;
                            continue;
                        }

                        // given argument type is not empty
                        buffer[index] = '\0';
                        instance->m_tail->m_function_signature
                                .m_arg_types[arg_index] =
                                strtol(&buffer[pointer], NULL, 16);

                        // point to the next character
                        // where a new argument type MAY start
                        pointer = index + 1;
                        arg_index++;
                    }

                    if (current_token
                        == UK_BPF_HELPER_DEFINITION_ARGUMENT_TYPE_END
                        [0]) {
                        // the argument type list is finished
                        // goto return type mode

                        // we must at least still have ->0
                        // in the given string
                        if (index
                            + STR_LEN(
                                    UK_BPF_HELPER_DEFINITION_RETURN_TYPE_INDICATOR)
                            + 1
                            >= buffer_length
                            || buffer[index + 1]
                               != UK_BPF_HELPER_DEFINITION_RETURN_TYPE_INDICATOR
                               [0]
                            || buffer[index + 2]
                               != UK_BPF_HELPER_DEFINITION_RETURN_TYPE_INDICATOR
                               [1]) {
                            state = STATE_ERROR;
                            continue;
                        }

                        state = STATE_RETURN_TYPE;

                        // skip the '->'
                        index += STR_LEN(
                                UK_BPF_HELPER_DEFINITION_RETURN_TYPE_INDICATOR);
                        pointer = index + 1;
                    }
                }

                break;
            case STATE_RETURN_TYPE:
                if (buffer[index]
                    == UK_BPF_HELPER_DEFINITION_FUNCTION_SPLIT[0]
                    || buffer[index] == '\0') {
                    if (pointer == index) {
                        // given return type is empty
                        state = STATE_ERROR;
                        continue;
                    }

                    // get pointer -> index - 1 as return type
                    const char current_token = buffer[index];

                    buffer[index] = '\0';
                    instance->m_tail->m_function_signature
                            .m_return_type =
                            strtol(&buffer[pointer], NULL, 16);

                    pointer = index + 1;

                    // goto next function name
                    if (current_token == '\0') {
                        state = STATE_END;
                    } else {
                        state = STATE_INDEX;
                    }
                } else if (!is_hex_digit(buffer[index])) {
                    // invalid character in return type
                    state = STATE_ERROR;
                    continue;
                }
                break;
            default:
                state = STATE_ERROR;
                continue;
        }
    }

    escape_for:

    free(buffer);

    if (state != STATE_END) {
        helper_function_list_destroy(instance);
        return NULL;
    }

    return instance;
}