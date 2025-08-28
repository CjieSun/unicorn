#include <unicorn/unicorn.h>
#include <stdio.h>

// Global flag to track if interrupt was called
static int interrupt_called = 0;
static uint32_t interrupt_number = 0;

// Interrupt callback function
static void interrupt_hook(uc_engine *uc, uint32_t intno, void *user_data)
{
    printf("Interrupt hook called with intno: %u\n", intno);
    interrupt_called = 1;
    interrupt_number = intno;
    
    // Stop emulation when interrupt is received
    uc_emu_stop(uc);
}

int main()
{
    uc_engine *uc;
    uc_hook hook;
    uc_err err;
    
    printf("Testing Unicorn IRQ functionality...\n");
    
    // Initialize unicorn engine for ARM
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed to initialize Unicorn engine: %s\n", uc_strerror(err));
        return 1;
    }
    
    // Map memory
    err = uc_mem_map(uc, 0x10000, 0x1000, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("Failed to map memory: %s\n", uc_strerror(err));
        return 1;
    }
    
    // Simple ARM code: NOP instruction (0xe1a00000)
    uint8_t code[] = {0x00, 0x00, 0xa0, 0xe1}; // NOP in ARM little-endian
    err = uc_mem_write(uc, 0x10000, code, sizeof(code));
    if (err != UC_ERR_OK) {
        printf("Failed to write code: %s\n", uc_strerror(err));
        return 1;
    }
    
    // Register interrupt hook
    err = uc_hook_add(uc, &hook, UC_HOOK_INTR, interrupt_hook, NULL, 0, 0);
    if (err != UC_ERR_OK) {
        printf("Failed to register interrupt hook: %s\n", uc_strerror(err));
        return 1;
    }
    
    printf("Triggering interrupt 42...\n");
    
    // Test our new IRQ trigger function
    err = uc_irq_trigger(uc, 42);
    if (err != UC_ERR_OK) {
        printf("Failed to trigger interrupt: %s\n", uc_strerror(err));
        return 1;
    }
    
    // Start emulation - this should be interrupted by our IRQ
    printf("Starting emulation...\n");
    err = uc_emu_start(uc, 0x10000, 0x10004, 0, 1);
    
    // Check if interrupt was called
    if (interrupt_called) {
        printf("SUCCESS: Interrupt was triggered and handled!\n");
        printf("Interrupt number: %u\n", interrupt_number);
        if (interrupt_number == 42) {
            printf("SUCCESS: Correct interrupt number received!\n");
        } else {
            printf("WARNING: Expected interrupt 42 but got %u\n", interrupt_number);
        }
    } else {
        printf("FAILED: Interrupt was not called\n");
    }
    
    // Clean up
    uc_hook_del(uc, hook);
    uc_close(uc);
    
    return interrupt_called ? 0 : 1;
}