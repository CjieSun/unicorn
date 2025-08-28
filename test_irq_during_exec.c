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
static int code_hook_called = 0;

// IRQ test callback function
static void test_irq_hook(uc_engine *uc, uint32_t intno, void *user_data)
{
    printf("=== IRQ hook called with interrupt number: %u ===\n", intno);
    irq_test_called = 1;
    irq_test_intno = intno;
    uc_emu_stop(uc);
}

// Code hook to trigger interrupt during execution
static void code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf("Code hook at 0x%lx, triggering interrupt...\n", address);
    code_hook_called = 1;
    
    // Trigger interrupt 42 during execution
    uc_irq_trigger(uc, 42);
    
    printf("Interrupt triggered from code hook\n");
}

int main()
{
    uc_engine *uc;
    uc_hook irq_hook_handle, code_hook_handle;
    
    // Use multiple NOPs so we have more opportunities to trigger
    char code[] = "\x00\xf0\x20\xe3"  // nop
                  "\x00\xf0\x20\xe3"  // nop  
                  "\x00\xf0\x20\xe3"  // nop
                  "\x00\xf0\x20\xe3"; // nop
    
    printf("=== Testing IRQ trigger during execution ===\n");
    
    // Reset test state
    irq_test_called = 0;
    irq_test_intno = 0;
    code_hook_called = 0;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A15));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    
    printf("UC setup complete\n");

    // Register interrupt hook
    OK(uc_hook_add(uc, &irq_hook_handle, UC_HOOK_INTR, test_irq_hook, NULL, 0, 0));
    printf("IRQ hook registered\n");
    
    // Register code hook to trigger interrupt during execution
    OK(uc_hook_add(uc, &code_hook_handle, UC_HOOK_CODE, code_hook, NULL, code_start, code_start + 4));
    printf("Code hook registered\n");

    // Start emulation - code hook should trigger interrupt
    printf("Starting emulation...\n");
    uc_err err = uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 4);
    printf("Emulation result: %s\n", uc_strerror(err));

    // Check results
    printf("Code hook called: %d\n", code_hook_called);
    printf("IRQ hook called: %d, IRQ number: %u\n", irq_test_called, irq_test_intno);
    
    if (irq_test_called == 1 && irq_test_intno == 42) {
        printf("=== SUCCESS: IRQ triggered during execution! ===\n");
    } else {
        printf("=== FAILED: IRQ not triggered properly ===\n");
    }

    OK(uc_hook_del(uc, irq_hook_handle));
    OK(uc_hook_del(uc, code_hook_handle));
    OK(uc_close(uc));

    return (irq_test_called == 1 && irq_test_intno == 42) ? 0 : 1;
}