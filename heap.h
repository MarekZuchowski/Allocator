#ifndef ALLOCATOR_HEAP_H
#define ALLOCATOR_HEAP_H

struct block_t {
    struct block_t* next;
    struct block_t* prev;
    size_t size;
    uint16_t checksum;
};

struct memory_manager_t {
    uint8_t* heap_head;
    uint8_t* heap_tail;
    struct block_t* first_memory_block;
};

enum pointer_type_t
{
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};

int heap_setup(void);
void heap_clean(void);
void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void* memblock, size_t size);
void  heap_free(void* memblock);
void heap_combine(struct block_t* block);
size_t heap_get_largest_used_block_size(void);
enum pointer_type_t get_pointer_type(const void* const pointer);
int heap_validate(void);
uint16_t heap_checksum(void* block);
void* heap_malloc_aligned(size_t count);
void* heap_calloc_aligned(size_t number, size_t size);
void* heap_realloc_aligned(void* memblock, size_t size);

#endif
