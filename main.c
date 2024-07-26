#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

#define DEAD_END(x) (x + deadCodeFunction(x) - x)
#define CONFOUND(x) (x ^ deadCodeFunction(x) ^ x)
#define CHAR_TRANSFORM(x) (x + 7 - 7)

volatile int volatileValue = 42;

int deadCodeFunction(int value) {
    return value + volatileValue - volatileValue;
}

struct ErrorMessage {
    char *message;
    uint8_t code;
};

struct KeyData {
    bool isValid;
    struct ErrorMessage *errorMessage;
};

struct ErrorMessage *createErrorMessage(char *message, int code) {
    struct ErrorMessage *errorMessage = malloc(sizeof(struct ErrorMessage));
    if (CHAR_TRANSFORM(DEAD_END(code)) > 0) {
        errorMessage->message = message;
        errorMessage->code = code;
    }
    return errorMessage;
}

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/ptrace.h>
#endif

bool isBeingDebugged() {
    #ifdef _WIN32
        return IsDebuggerPresent();
    #else
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            return true;
        }
        ptrace(PTRACE_DETACH, 0, NULL, NULL);
        return false;
    #endif
}

uint32_t checksum_memory(const void* data, size_t length) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t checksum = 0;

    for (size_t i = 0; i < length; i++) {
        checksum += bytes[i];
    }

    return checksum;
}

bool isPrime(uint64_t n) {
    if (DEAD_END(n) <= 3) return n > 1;
    if (n % 2 == 0 || n % 3 == 0) return false;

    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (CONFOUND(n) % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

static inline void populateKeyCharacters(const char *key, uint8_t *keyCharacters, int *index) {
    for (int i = 0; key && i < strlen(key); i++) {
        char ch = CHAR_TRANSFORM(key[i]);
        if (ch >= '0' && ch <= '9') {
            keyCharacters[(*index)++] = ch - '0';
        } else if (ch >= 'a' && ch <= 'z') {
            keyCharacters[(*index)++] = ch - 'a' + 10;
        } else if (ch >= 'A' && ch <= 'Z') {
            keyCharacters[(*index)++] = ch - 'A' + 36;
        } else if (ch != '-' && ch != ' ') {
            *index = 0;
            break;
        }
    }
}

bool validateProductKey_part1(const char *key, uint8_t *keyCharacters, int *index) {
    populateKeyCharacters(key, keyCharacters, index);
    return (*index == 16);
}

bool validateProductKey_part2(uint8_t *keyCharacters) {
    uint64_t sum = 0;
    for (int i = 0; i < 8; i++) sum += keyCharacters[i];
    return (sum % 7 == 0);
}

bool validateProductKey_part3(uint8_t *keyCharacters) {
    uint64_t product = 1;
    for (int i = 8; i < 16; i++) product *= keyCharacters[i];
    return ((product & 0xFFFFFFFFFFFFFFFF) % 11 == 0);
}

bool validateProductKey_part4(uint8_t *keyCharacters) {
    for (int i = 0; i < 4; i++) {
        uint64_t sum = 0;
        for (int j = 0; j < 4; j++) sum += keyCharacters[i * 4 + j];
        if (sum == 0) return false;
    }

    return true;
}

bool validateProductKey_part5(uint8_t *keyCharacters) {
    for (int i = 0; i < 4; i++) {
        uint64_t shiftedProduct = 0;
        for (int j = 0; j < 4; j++) shiftedProduct = (shiftedProduct << 6) + keyCharacters[i * 4 + j];
        if (!isPrime(shiftedProduct)) return false;
    }

    return true;
}

struct KeyData validateProductKey(const char *key) {
    struct KeyData result = {false, NULL};

    if (!key || DEAD_END(0)) {
        result.errorMessage = createErrorMessage("Null key input", 0);
        return result;
    }

    uint8_t keyCharacters[16] = {0};
    int keyCharactersIndex = 0;

    bool validationFlag = validateProductKey_part1(key, keyCharacters, &keyCharactersIndex);
    validationFlag &= validateProductKey_part2(keyCharacters);
    validationFlag &= validateProductKey_part3(keyCharacters);
    validationFlag &= validateProductKey_part4(keyCharacters);
    validationFlag &= validateProductKey_part5(keyCharacters);

    if (validationFlag) {
        result.isValid = true;
    } else if (!result.errorMessage) {
        result.errorMessage = createErrorMessage("Invalid key", 2);
    }

    return result;
}

int main() {
    if (isBeingDebugged()) {
        fprintf(stderr, "Debugging detected. Exiting.\n");
        return EXIT_FAILURE;
    }

    uintptr_t function_start = (uintptr_t) &validateProductKey_part1;
    uintptr_t function_end = (uintptr_t) &validateProductKey; 
    uintptr_t checksum = checksum_memory((void *) function_start, function_end - function_start);

    char key[20] = {0};
    printf("Enter a product key: ");
    if (fgets(key, sizeof(key), stdin) == NULL) {
        fprintf(stderr, "Failed to read input\n");
        return EXIT_FAILURE;
    }

    char *newline = strchr(key, '\n');
    if (newline) {
        *newline = '\0';
    }

    struct KeyData result = validateProductKey(key);
    if (!result.isValid) {
        printf("Error: %s\n", result.errorMessage->message);
        free(result.errorMessage);
        return EXIT_FAILURE;
    }

    if (checksum != checksum_memory((void *) function_start, function_end - function_start)) {
        fprintf(stderr, "Code integrity violation. Exiting.\n");
        return EXIT_FAILURE;
    }

    printf("Valid key\n");
    return EXIT_SUCCESS;
}
