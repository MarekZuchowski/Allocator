#include <stdio.h>
#include <memory.h>
#include <stdint.h>
#include "heap.h"

#define FENCES_SIZE 8
#define PAGE_SIZE 4096
#define BLOCK_STRUCT_SIZE 32
#define BLOCK_STRUCT_N_FENCES_SIZE 40
#define CHECKSUM_FIELD_BYTE 24
#define USED_ON_PAGE(ptr) ((intptr_t)ptr & (intptr_t)(PAGE_SIZE - 1))

struct memory_manager_t memory_manager = {NULL, NULL, NULL};

int heap_setup(void) {
    void* ptr = custom_sbrk(PAGE_SIZE);
    if(ptr == (void*)-1)
        return -1;

    memory_manager.heap_head = (uint8_t*)ptr;
    memory_manager.heap_tail = (uint8_t*)ptr + PAGE_SIZE;
    memory_manager.first_memory_block = NULL;

    return 0;
}

void heap_clean(void) {
    custom_sbrk(-custom_sbrk_get_reserved_memory());
    memory_manager.heap_head = NULL;
    memory_manager.heap_tail = NULL;
    memory_manager.first_memory_block = NULL;
}

void* heap_malloc(size_t size) {
    if(heap_validate() || size == 0)
        return NULL;

    if(memory_manager.first_memory_block == NULL) {
        if(size + BLOCK_STRUCT_SIZE + FENCES_SIZE * 2 > custom_sbrk_get_reserved_memory()) {
            size_t bytes_to_add = (BLOCK_STRUCT_SIZE + FENCES_SIZE * 2 + size) / PAGE_SIZE * PAGE_SIZE;
            if(custom_sbrk(bytes_to_add) == (void*)-1)
                return NULL;
            memory_manager.heap_tail += bytes_to_add;
        }
        memory_manager.first_memory_block = (struct block_t*)(memory_manager.heap_head);
        memory_manager.first_memory_block->prev = NULL;
        memory_manager.first_memory_block->next = NULL;
        memory_manager.first_memory_block->size = size;
        memory_manager.first_memory_block->checksum = heap_checksum(memory_manager.first_memory_block);
        memset((uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_SIZE, '#', FENCES_SIZE);
        memset((uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

        return (uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_N_FENCES_SIZE;
    }

    struct block_t* new_block = NULL;

    if((uint8_t*)memory_manager.heap_head != (uint8_t*)memory_manager.first_memory_block) {
        int available_memory = (int)((uint8_t*)memory_manager.first_memory_block - (uint8_t*)memory_manager.heap_head - BLOCK_STRUCT_SIZE - FENCES_SIZE * 2);
        if((int)size <= available_memory) {
            new_block = (struct block_t*)memory_manager.heap_head;
            new_block->next = memory_manager.first_memory_block;
            new_block->next->prev = new_block;
            new_block->next->checksum = heap_checksum(new_block->next);
            new_block->prev = NULL;
            memory_manager.first_memory_block = new_block;
            new_block->size = size;
            new_block->checksum = heap_checksum(new_block);
            memset((uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_SIZE, '#', FENCES_SIZE);
            memset((uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

            return (uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_N_FENCES_SIZE;
        }
    }

    struct block_t* current_block;
    for(current_block = memory_manager.first_memory_block; current_block->next != NULL; current_block = current_block->next) {
        int available_memory = (int)((uint8_t*)current_block->next - (uint8_t*)current_block - BLOCK_STRUCT_SIZE - FENCES_SIZE * 2 - current_block->size - BLOCK_STRUCT_SIZE - FENCES_SIZE * 2);
        if((int)size <= available_memory) {
            new_block = (struct block_t *) ((uint8_t *) current_block + BLOCK_STRUCT_SIZE + FENCES_SIZE * 2 +current_block->size);
            new_block->prev = current_block;
            new_block->next = current_block->next;
            current_block->next = new_block;
            new_block->next->prev = new_block;
            current_block->checksum = heap_checksum(current_block);
            new_block->next->checksum = heap_checksum(new_block->next);

            new_block->size = size;
            new_block->checksum = heap_checksum(new_block);
            memset((uint8_t *) new_block + BLOCK_STRUCT_SIZE, '#', FENCES_SIZE);
            memset((uint8_t *) new_block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

            return (uint8_t *)new_block + BLOCK_STRUCT_N_FENCES_SIZE;
        }
    }

    if(new_block == NULL) {
        size_t remaining_memory = custom_sbrk_get_reserved_memory() - (((uint8_t*)current_block + BLOCK_STRUCT_SIZE + current_block->size + FENCES_SIZE * 2) - (uint8_t*)memory_manager.heap_head);
        if(size + BLOCK_STRUCT_SIZE + FENCES_SIZE * 2 > remaining_memory) {
            size_t bytes_to_add = (BLOCK_STRUCT_SIZE + FENCES_SIZE * 2 + size) / PAGE_SIZE * PAGE_SIZE;
            if(size + BLOCK_STRUCT_SIZE + FENCES_SIZE * 2 - bytes_to_add > remaining_memory)
                bytes_to_add += PAGE_SIZE;
            if(custom_sbrk(bytes_to_add) == (void*)-1)
                return NULL;
            memory_manager.heap_tail += bytes_to_add;
        }
        new_block = (struct block_t*)((uint8_t*)current_block + BLOCK_STRUCT_SIZE + current_block->size + FENCES_SIZE * 2);
        new_block->prev = current_block;
        new_block->next = NULL;
        current_block->next = new_block;
        current_block->checksum = heap_checksum(current_block);
    }

    new_block->size = size;
    new_block->checksum = heap_checksum(new_block);
    memset((uint8_t*)new_block + BLOCK_STRUCT_SIZE, '#', FENCES_SIZE);
    memset((uint8_t*)new_block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

    return (uint8_t*)new_block + BLOCK_STRUCT_N_FENCES_SIZE;
}

void* heap_calloc(size_t number, size_t size) {
    if(number == 0 || size==0)
        return NULL;
    void* memblock = heap_malloc(number * size);
    if(memblock != NULL)
        memset(memblock, 0, number * size);
    return memblock;
}

void* heap_realloc(void* memblock, size_t size) {
    if(heap_validate())
        return NULL;
    if((memblock != NULL && get_pointer_type(memblock) != pointer_valid) || (memblock == NULL && size == 0))
        return NULL;

    if(memblock != NULL && size == 0) {
        heap_free(memblock);
        return NULL;
    }

    if(memblock == NULL && size != 0) {
        return heap_malloc(size);
    }

    struct block_t* block = (struct block_t*)((uint8_t*)memblock - BLOCK_STRUCT_N_FENCES_SIZE);

    if(size == block->size)
        return memblock;

    if(size < block->size) {
        block->size = size;
        block->checksum = heap_checksum(block);
        memset((uint8_t*)block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

        return memblock;
    }

    if(block->next == NULL) {
        size_t available_memory = memory_manager.heap_tail - ((uint8_t*)block + BLOCK_STRUCT_SIZE + FENCES_SIZE * 2);
        if(size > available_memory) {
            size_t bytes_to_add = size/PAGE_SIZE * PAGE_SIZE;
            if(size - bytes_to_add > available_memory)
                bytes_to_add += PAGE_SIZE;
            if(custom_sbrk(bytes_to_add) == (void*)-1) {
                return NULL;
            }
            memory_manager.heap_tail += bytes_to_add;
        }
        block->size = size;
        block->checksum = heap_checksum(block);
        memset((uint8_t*)block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);
        return memblock;
    }

    size_t available_memory = (uint8_t*)block->next - ((uint8_t*)block + BLOCK_STRUCT_SIZE + FENCES_SIZE * 2);
    if(size <= available_memory) {
        block->size = size;
        block->checksum = heap_checksum(block);
        memset((uint8_t*)block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

        return memblock;
    }

    void* new_memblock = heap_malloc(size);
    if(new_memblock == NULL)
        return NULL;

    memmove(new_memblock, (uint8_t*)block + BLOCK_STRUCT_N_FENCES_SIZE, block->size);
    heap_free(memblock);

    return new_memblock;
}

void heap_free(void* memblock) {
    if(get_pointer_type(memblock) != pointer_valid)
        return;

    struct block_t* block = (struct block_t*)((uint8_t*)memblock - BLOCK_STRUCT_N_FENCES_SIZE);

    if(block->next == NULL) {
        if(block->prev == NULL)
            memory_manager.first_memory_block = NULL;
        else {
            block->prev->next = NULL;
            block->prev->checksum = heap_checksum(block->prev);
        }
    }
    else {
        if(block->prev == NULL) {
            block->next->prev = NULL;
            block->next->checksum = heap_checksum(block->next);
            memory_manager.first_memory_block = block->next;
        }
        else {
            block->prev->next = block->next;
            block->next->prev = block->prev;
            block->prev->checksum = heap_checksum(block->prev);
            block->next->checksum = heap_checksum(block->next);
        }
    }
}

size_t heap_get_largest_used_block_size(void) {
    if(memory_manager.heap_head==NULL || memory_manager.first_memory_block==NULL || heap_validate())
        return 0;

    size_t size = 0;
    for(const struct block_t* current = memory_manager.first_memory_block; current!=NULL; current = current->next)
        if(current->size > size)
            size = current->size;

    return size;
}

enum pointer_type_t get_pointer_type(const void* const pointer) {
    if(pointer == NULL)
        return pointer_null;
    if(heap_validate())
        return pointer_heap_corrupted;

    uint8_t* ptr = (uint8_t*)pointer;
    if(ptr < memory_manager.heap_head || ptr >= memory_manager.heap_tail)
        return pointer_unallocated;

    struct block_t* current = memory_manager.first_memory_block;
    while(current != NULL) {
        if(ptr >= (uint8_t*)current && ptr < (uint8_t*)current + BLOCK_STRUCT_SIZE)
            return pointer_control_block;
        if (ptr==(uint8_t *)current + BLOCK_STRUCT_N_FENCES_SIZE)
            return pointer_valid;
        if(ptr >= (uint8_t *)current + BLOCK_STRUCT_N_FENCES_SIZE + 1 && ptr < (uint8_t *)current + BLOCK_STRUCT_N_FENCES_SIZE + current->size)
            return pointer_inside_data_block;
        if((ptr >= (uint8_t*)current + BLOCK_STRUCT_SIZE && ptr < (uint8_t*)current + BLOCK_STRUCT_N_FENCES_SIZE) || (ptr >= (uint8_t*)current + BLOCK_STRUCT_N_FENCES_SIZE + current->size && ptr < (uint8_t*)current + BLOCK_STRUCT_N_FENCES_SIZE + current->size + FENCES_SIZE))
            return pointer_inside_fences;
        if(current->next == NULL) {
            if(ptr >= (uint8_t*)current + BLOCK_STRUCT_SIZE + current->size + FENCES_SIZE * 2 && ptr < memory_manager.heap_tail)
                return pointer_unallocated;
        }
        else {
            if(ptr >= (uint8_t*)current + BLOCK_STRUCT_SIZE + current->size + FENCES_SIZE * 2 && ptr < (uint8_t*)current->next)
                return pointer_unallocated;
        }
        current = current->next;
    }

    return pointer_unallocated;
}

int heap_validate(void) {
    if(memory_manager.heap_head == NULL)
        return 2;

    if(memory_manager.first_memory_block != NULL) {
        char fences[8] = "########";
        for(struct block_t* current = memory_manager.first_memory_block; current != NULL; current = current->next) {
            if(current->checksum != heap_checksum(current))
                return 3;
            if(memcmp(fences, (uint8_t *) current + BLOCK_STRUCT_SIZE, FENCES_SIZE) != 0 || memcmp(fences, (uint8_t *) current + BLOCK_STRUCT_N_FENCES_SIZE + current->size, FENCES_SIZE) != 0)
                return 1;
        }
    }

    return 0;
}

uint16_t heap_checksum(void* block) {
    uint16_t checksum = 0;

    for(int i = 0; i < BLOCK_STRUCT_SIZE; i++) {
        if(i == CHECKSUM_FIELD_BYTE || i == CHECKSUM_FIELD_BYTE + 1)
            continue;

        checksum += *((uint8_t*)block + i);
    }

    return checksum;
}

void* heap_malloc_aligned(size_t size) {
    if(heap_validate() || size == 0)
        return NULL;

    if(memory_manager.first_memory_block == NULL) {
        if(memory_manager.heap_head + PAGE_SIZE + size + FENCES_SIZE > memory_manager.heap_tail) {
            size_t bytes_to_add = (PAGE_SIZE + size + FENCES_SIZE) / PAGE_SIZE * PAGE_SIZE;
            if(custom_sbrk(bytes_to_add) == (void*)-1)
                return NULL;
            memory_manager.heap_tail += bytes_to_add;
        }
        memory_manager.first_memory_block = (struct block_t*)(memory_manager.heap_head + PAGE_SIZE - BLOCK_STRUCT_N_FENCES_SIZE);
        memory_manager.first_memory_block->prev = NULL;
        memory_manager.first_memory_block->next = NULL;
        memory_manager.first_memory_block->size = size;
        memory_manager.first_memory_block->checksum = heap_checksum(memory_manager.first_memory_block);
        memset((uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_SIZE, '#', FENCES_SIZE);
        memset((uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

        return (uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_N_FENCES_SIZE;
    }

    struct block_t* new_block = NULL;

    if((uint8_t*)memory_manager.heap_head != (uint8_t*)memory_manager.first_memory_block) {
        int available_memory = (int)((uint8_t*)memory_manager.first_memory_block - (uint8_t*)memory_manager.heap_head - PAGE_SIZE - size - FENCES_SIZE);
        if((int)size <= available_memory) {
            new_block = (struct block_t*)(memory_manager.heap_head + PAGE_SIZE - BLOCK_STRUCT_N_FENCES_SIZE);
            new_block->next = memory_manager.first_memory_block;
            new_block->next->prev = new_block;
            new_block->next->checksum = heap_checksum(new_block->next);
            new_block->prev = NULL;
            memory_manager.first_memory_block = new_block;
            new_block->size = size;
            new_block->checksum = heap_checksum(new_block);
            memset((uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_SIZE, '#', FENCES_SIZE);
            memset((uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

            return (uint8_t*)memory_manager.first_memory_block + BLOCK_STRUCT_N_FENCES_SIZE;
        }
    }

    struct block_t* current_block;
    for(current_block = memory_manager.first_memory_block; current_block->next != NULL; current_block = current_block->next) {
        uint8_t pages_needed = 0;
        if(PAGE_SIZE - USED_ON_PAGE((uint8_t*)current_block + BLOCK_STRUCT_SIZE + current_block->size + FENCES_SIZE * 2) < BLOCK_STRUCT_N_FENCES_SIZE)
        pages_needed++;
        pages_needed++;
        uint8_t* new_memblock = (uint8_t*)current_block + BLOCK_STRUCT_SIZE + current_block->size + FENCES_SIZE * 2 - USED_ON_PAGE((uint8_t*)current_block + BLOCK_STRUCT_SIZE + current_block->size + FENCES_SIZE * 2)  + PAGE_SIZE * pages_needed ;
        if(new_memblock + size + FENCES_SIZE <= (uint8_t*)current_block->next) {
            new_block = (struct block_t *)(new_memblock - BLOCK_STRUCT_N_FENCES_SIZE);
            new_block->prev = current_block;
            new_block->next = current_block->next;
            current_block->next = new_block;
            new_block->next->prev = new_block;
            current_block->checksum = heap_checksum(current_block);
            new_block->next->checksum = heap_checksum(new_block->next);

            new_block->size = size;
            new_block->checksum = heap_checksum(new_block);
            memset((uint8_t *) new_block + BLOCK_STRUCT_SIZE, '#', FENCES_SIZE);
            memset((uint8_t *) new_block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);
            return (uint8_t *)new_block + BLOCK_STRUCT_N_FENCES_SIZE;
        }
    }

    if(new_block == NULL) {
        uint8_t pages_needed = 0;
        if(PAGE_SIZE - USED_ON_PAGE((uint8_t*)current_block + BLOCK_STRUCT_SIZE + current_block->size + FENCES_SIZE * 2) < BLOCK_STRUCT_N_FENCES_SIZE)
        pages_needed++;
        pages_needed++;
        size_t bytes_to_add = ((size + FENCES_SIZE) / PAGE_SIZE + pages_needed)* PAGE_SIZE;
        if(custom_sbrk(bytes_to_add) == (void*)-1)
            return NULL;
        memory_manager.heap_tail += bytes_to_add;

        new_block = (struct block_t *)((uint8_t *)current_block + BLOCK_STRUCT_SIZE + current_block->size + FENCES_SIZE * 2 - USED_ON_PAGE((uint8_t*)current_block + BLOCK_STRUCT_SIZE + current_block->size + FENCES_SIZE * 2 ) + PAGE_SIZE * pages_needed - BLOCK_STRUCT_N_FENCES_SIZE);
        new_block->prev = current_block;
        new_block->next = NULL;
        current_block->next = new_block;
        current_block->checksum = heap_checksum(current_block);
    }

    new_block->size = size;
    new_block->checksum = heap_checksum(new_block);
    memset((uint8_t*)new_block + BLOCK_STRUCT_SIZE, '#', FENCES_SIZE);
    memset((uint8_t*)new_block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

    return (uint8_t*)new_block + BLOCK_STRUCT_N_FENCES_SIZE;
}

void* heap_calloc_aligned(size_t number, size_t size) {
    if(number == 0 || size == 0)
        return NULL;
    void* memblock = heap_malloc_aligned(number * size);
    if(memblock != NULL)
        memset(memblock, 0, number * size);
    return memblock;
}

void* heap_realloc_aligned(void* memblock, size_t size) {
    if(heap_validate())
        return NULL;
    if((memblock != NULL && get_pointer_type(memblock) != pointer_valid) || (memblock == NULL && size == 0))
        return NULL;

    if(memblock != NULL && size == 0) {
        heap_free(memblock);
        return NULL;
    }

    if(memblock == NULL && size != 0) {
        return heap_malloc_aligned(size);
    }

    struct block_t* block = (struct block_t*)((uint8_t*)memblock - BLOCK_STRUCT_N_FENCES_SIZE);

    if(size == block->size)
        return memblock;

    if(size < block->size) {
        block->size = size;
        block->checksum = heap_checksum(block);
        memset((uint8_t*)block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

        return memblock;
    }

    if(block->next == NULL) {
        size_t available_memory = memory_manager.heap_tail - ((uint8_t*)block + BLOCK_STRUCT_SIZE + FENCES_SIZE * 2);
        if(size > available_memory) {
            size_t bytes_to_add = size/PAGE_SIZE * PAGE_SIZE;
            if(size - bytes_to_add > available_memory)
                bytes_to_add += PAGE_SIZE;
            if(custom_sbrk(bytes_to_add) == (void*)-1) {
                return NULL;
            }
            memory_manager.heap_tail += bytes_to_add;
        }
        block->size = size;
        block->checksum = heap_checksum(block);
        memset((uint8_t*)block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);
        return memblock;
    }

    size_t available_memory = (uint8_t*)block->next - ((uint8_t*)block + BLOCK_STRUCT_SIZE + FENCES_SIZE * 2);
    if(size <= available_memory) {
        block->size = size;
        block->checksum = heap_checksum(block);
        memset((uint8_t*)block + BLOCK_STRUCT_N_FENCES_SIZE + size, '#', FENCES_SIZE);

        return memblock;
    }

    void* new_memblock = heap_malloc_aligned(size);
    if(new_memblock == NULL)
        return NULL;

    memmove(new_memblock, (uint8_t*)block + BLOCK_STRUCT_N_FENCES_SIZE, block->size);
    heap_free(memblock);

    return new_memblock;
}