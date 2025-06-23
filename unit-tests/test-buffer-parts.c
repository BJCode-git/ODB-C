#include <newutils.h>
#define _XOPEN_SOURCE_EXTENDED 1
#include <stdlib.h>

/*
uint8_t test_is_page_aligned(const void *addr) {
    return ((uintptr_t) addr & (PAGE_SIZE - 1)) == 0;
}

void *test_get_ceil_page(void *addr) {
    if (addr == NULL) return NULL;
    uintptr_t a = (uintptr_t) addr;
    return (void *) ((a + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
}

void *test_get_floor_page(void *addr) {
    if (addr == NULL) return NULL;
    uintptr_t a = (uintptr_t) addr;
    return (void *) (a & ~(PAGE_SIZE - 1));
}
*/

// Fonction de test
void test_buffer_parts(size_t total_size) {
    printf("=== Test avec buffer total_size = %zu bytes ===\n", total_size);

    void *raw_buffer = malloc(total_size);
    if (!raw_buffer) {
        perror("malloc");
        return;
    }

    ODB_Local_Buffer buf = {
        .buffer = raw_buffer,
        .head_size = total_size,
        .body_size = 0,
        .tail_size = 0
    };

    get_buffer_parts(&buf);

    printf("Adresse buffer : %p\n", raw_buffer);
    printf("Head size      : %zu bytes\n", buf.head_size);
    printf("Body address   : %p\n", buf.body);
    printf("Body size      : %zu bytes\n", buf.body_size);
    printf("Tail address   : %p\n", buf.tail);
    printf("Tail size      : %zu bytes\n", buf.tail_size);
    printf("--------------------------------------------\n");

    free(raw_buffer);
}

void test_aligned_buffer_parts(size_t total_size) {
	printf("=== Test avec buffer total_size = %zu bytes ===\n", total_size);

	void *raw_buffer = valloc(total_size);
	if (!raw_buffer) {
		perror("malloc");
		return;
	}

	ODB_Local_Buffer buf = {
		.buffer = raw_buffer,
		.body = NULL,
		.tail = NULL,
		.head_size = 0,
		.body_size = total_size,
		.tail_size = 0
	};

	get_buffer_parts(&buf);

	printf("Adresse buffer : %p\n", raw_buffer);
	printf("Head size      : %zu bytes\n", buf.head_size);
	printf("Body address   : %p\n", buf.body);
	printf("Body size      : %zu bytes\n", buf.body_size);
	printf("Tail address   : %p\n", buf.tail);
	printf("Tail size      : %zu bytes\n", buf.tail_size);
	printf("--------------------------------------------\n");

	free(raw_buffer);
}

int main() {
	// Test avec buffer non aligné
	printf("Test sans buffer aligné\n\n");
    test_buffer_parts(0);
    test_buffer_parts(1);
    test_buffer_parts(2048);
    test_buffer_parts(PAGE_SIZE-1);
    test_buffer_parts(8000);   // test partiellement aligné
    test_buffer_parts(16384);  // multiple exact de 4k
    test_buffer_parts(135152); // multiple exact de 64k
    test_buffer_parts(270304);

	printf("Test avec buffer aligné\n\n");
    test_aligned_buffer_parts(0);
    test_aligned_buffer_parts(1);
	test_aligned_buffer_parts(8000);   // test partiellement aligné
	test_aligned_buffer_parts(16384);  // multiple exact de 4k
    test_aligned_buffer_parts(135152); // multiple exact de 64k
    test_aligned_buffer_parts(270304); // multiple exact de 256k

    return 0;
}
