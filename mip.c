/*
*
*    == [ Memory Injection Pervention ] ==
*
* @author: Algo1337
* @since: 12/19/2024
*
*       == [ Flexibility ] ==
* Since this is for sensitive information protection, We only made support for (char/char *)
*
*       == [ HEAP MEMORY INFOMATION FOR MIP ]
* Since this library avoids memory allocation, You must unlock the memory, update it manually, 
* then update the size on MIP then relock if needed
*
*       == [ STACK MEMORY INFORMATION FOR MIP ]
* To avoid locking other memory, fill buffers up with enough data for a memory page. 4096. Use CHAR_MAX_BUFF_SIZE
*
* Note that even tho this is watching and comparing cached memory, app will only exit if memory has been modified.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CHAR_MAX_BUFF_SIZE  4096

typedef enum Memory_T {
    STACK_MEMORY    = 0x02935382,
    HEAP_MEMORY     = 0x04802413
} Memory_T;

typedef struct Memory {
    Memory_T    *Type;
    void        *Pointer;
    void        *Memsz;
    void        *Copy;
    int         Locked;

    void        *Base;
} Memory;

typedef struct MIP {
    Memory      **Pointers;
    long        PointerCount;

    int         Debug;
} MIP;

int LockToggle(Memory *mem) { 
    if(!mem)
        return 0;

    void *aligned_ptr = (void *)((uintptr_t)mem->Pointer & ~(sysconf(_SC_PAGESIZE) - 1));
    size_t aligned_size = mem->Memsz + ((uintptr_t)mem->Pointer - (uintptr_t)aligned_ptr);

    /* Unlock memory */
    if(mem->Locked) {
        if(munlock(aligned_ptr, aligned_size) != 0 || mprotect(aligned_ptr, aligned_size, PROT_READ | PROT_WRITE) != 0) {
            printf("[ x ] Unable to unlock memory....!\n");
            return 0;
        }

        mem->Locked = 0;
        return 1;
    }

    /* Lock memory */
    if(mlock(aligned_ptr, aligned_size) != 0 || mprotect(aligned_ptr, mem->Memsz, PROT_READ) != 0) {
        (void)(mem->Base->Debug ? printf("[ x ] Unable to lock memory....!\n") : 0);
        return 0;
    }
    
    mem->Locked = 1;
    return mem->Locked;
}

Memory NewPointer(Memory_T *t, char *p, long sz) {
    Memory *new_mem = (Memory *)malloc(sizeof(Memory));
    *new_mem = (Memory){
        .Type        = t,
        .Pointer     = (p ? p : (t == HEAP_MEMORY ? malloc(1)) : NULL),
        .Memset      = sz
    };

    if(t == STACK_MEMORY)
        printf("[ x ] Warning, MIP does not create stack variables for you, You must create it and assign the stack pointer....!\n");

    mem->Copy = strdup(p);
    return new_mem;
}

int UpdateMemory(Memory *mem, void *update, long new_sz) {
    if(!mem || !update)
        return 0;

    if(mem->Pointer)
        free(mem->Pointer);

    mem->Pointer = update;
    mem->Copy = strdup(update);
    return 1;
}

int AddMemory(MIP *m, Memory *new_mem) {
    if(!m || !new_mem)
        return 0;

    new_mem->Locked = 0;
    new_mem->Base = m;

    m->Pointers[m->PointerCount] = (Memory *)malloc(sizeof(Memory));
    *m->Pointers[m->PointerCount] = new_mem;
    m->PointerCount++;
    m->Pointers = (Memory **)realloc(m->Pointers, sizeof(Memory *) * (m->PointerCount + 1));

    return 1;
}

void WatchMemories(MIP *m) {
    if(!m)
        return 0;

    if(m->PointerCount < 1)
        return 0;

    while(m->PointerCount != 0) {
        int i = 0;
        while(i != m->PointerCount) {
            if(!m->Pointers[i])
                break;

            if(!m->Pointers[i]->Locked)
                break;

            // Check if data matches the copy while locked, if not matched, its been injected
            /* Skill issue if developer trys modifying memory without unlocking */
            if(m->Pointers[i]->Locked && strcmp(m->Pointers[i]->Pointer, m->Pointers[i]->Copy)) {
                // memory modified
                printf("[ x ] Memory unintentedly modified");
            }
            i++;
        }
        (void *)(m->Debug ? printf("[ - ] Watching %ld memory blocks.....!\n", m->PointerCount) : 0);
    }
}

MIP *InitMIP(Memory **globals) {
    MIP *mip = (MIP *)malloc(sizeof(MIP));
    *mip = (MIP){
        Pointers = (Memory **)malloc(sizeof(Memory *)),
        PointerCount = 0
    };

    if(globals) {
        (void)(m->Debug ? printf("[ x ] Adding global variables....!\n") : 0);
        for(int i = 0; globals[i] != NULL; i++) {
            if(globals[i])
                break;
            
            AddMemory(mip, globals[i]);
        }
    } else { 
        (void)(m->Debug ? printf("[ x ] No global variables provided....!\n") : 0);
    }

    return mip;
}

int main() {
    char *Test = (char *)malloc(15);
    *Test = "Hello World!";

    MIP *mip = InitMIP(NULL);

    char *BUFF = (char *)malloc(1024);
    AddMemory(mip, NewPointer(HEAP_MEMORY, BUFF));



    /* Since the library handles all memory, functions returning pointers can be passed directly using the NewPointer() function */
    /* Keep in mind: This is not good practice to use elsewhere unless you handle the memory wherever its being passed into ! */
    int add_chk = AddMemory(mip, NewPointer(HEAP_MEMORY, Test));
    if(!add_chk)
        printf("[ x ] Error, Unable to add to MIP's Memory Stack.....!");

    
    return 0;
}