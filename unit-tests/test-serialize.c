#include <newutils.h>

void print_odb_desc(const ODB_Desc *desc) {
    printf("magic_number: %u\n", desc->magic_number);
    printf("real: %u\n", desc->real);
    printf("fd: %zu\n", desc->fd);
    printf("source_addr: %s:%u\n", inet_ntoa(desc->source_addr.sin_addr), ntohs(desc->source_addr.sin_port));
    printf("head_size: %zu\n", desc->head_size);
    printf("body_size: %zu\n", desc->body_size);
    printf("tail_size: %zu\n", desc->tail_size);
    printf("crc: %u\n", desc->crc);
}

int main() {
    ODB_Desc desc = {
        .magic_number = ODB_MAGIC_NUMBER,
        .real = 1,
        .fd = 0,
        .source_addr.sin_addr.s_addr = inet_addr("127.0.0.1"),
        .source_addr.sin_port = htons(59342),
        .head_size = 0,
        .body_size = 487,
        .tail_size = 0,
        .crc = 0xFF
    };

    printf("Avant sérialisation :\n");
    print_odb_desc(&desc);

    // Sérialisation en place
    serialize_odb_desc_inplace(&desc);

	printf("Après sérialisation :\n");
    print_odb_desc(&desc);

    // Désérialisation en place
    deserialize_odb_desc_inplace(&desc);

    printf("\nAprès désérialisation :\n");
    print_odb_desc(&desc);

    return 0;
}