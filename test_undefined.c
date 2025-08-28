#include <unicorn/unicorn.h>
#include <stdio.h>
#include <assert.h>

#define OK(statement) do { \
    uc_err __err = statement; \
    if (__err != UC_ERR_OK) { \
        printf("ERROR: %s failed with error %d: %s\n", #statement, __err, uc_strerror(__err)); \
        exit(1); \
    } \
} while(0)

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

// Global variables for IRQ test
static int irq_test_called = 0;
static uint32_t irq_test_intno = 0;

// IRQ test callback function
static void test_arm_irq_hook(uc_engine *uc, uint32_t intno, void *user_data)
{
    printf("=== IRQ hook called with interrupt number: %u ===\n", intno);
    irq_test_called = 1;
    irq_test_intno = intno;
    // Stop emulation when interrupt is received
    uc_emu_stop(uc);
}

int main()
{
    uc_engine *uc;
    uc_hook hook;
    
    // Test with undefined instruction that should trigger an exception
    char undefined_code[] = "\xff\xff\xff\xff"; // Undefined instruction
    
    printf("=== Testing undefined instruction exception ===\n");
    
    // Reset test state
    irq_test_called = 0;
    irq_test_intno = 0;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A15));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, undefined_code, sizeof(undefined_code) - 1));
    
    printf("UC setup complete\n");

    // Register interrupt hook
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_arm_irq_hook, NULL, 0, 0));
    printf("IRQ hook registered\n");

    // Start emulation - should trigger undefined instruction exception
    printf("Starting emulation with undefined instruction...\n");
    uc_err err = uc_emu_start(uc, code_start, code_start + 4, 0, 1);
    printf("Emulation result: %s\n", uc_strerror(err));

    // Check results
    printf("IRQ called: %d, IRQ number: %u\n", irq_test_called, irq_test_intno);

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));

    return 0;
}