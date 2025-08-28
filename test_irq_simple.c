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

#define TEST_CHECK(expr) assert(expr)

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

// Simple test setup
static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size, int cpu)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_ctl_set_cpu_model(*uc, cpu));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

// Global variables for IRQ test
static int irq_test_called = 0;
static uint32_t irq_test_intno = 0;

// IRQ test callback function
static void test_arm_irq_trigger_hook(uc_engine *uc, uint32_t intno, void *user_data)
{
    printf("IRQ hook called with interrupt number: %u\n", intno);
    irq_test_called = 1;
    irq_test_intno = intno;
    // Stop emulation when interrupt is received
    uc_emu_stop(uc);
}

static void test_arm_irq_trigger(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\x00\xf0\x20\xe3"; // nop
    
    printf("Starting IRQ trigger test...\n");
    
    // Reset test state
    irq_test_called = 0;
    irq_test_intno = 0;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    printf("UC setup complete\n");

    // Register interrupt hook
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_arm_irq_trigger_hook, NULL, 0, 0));
    printf("IRQ hook registered\n");

    // Trigger interrupt 42
    printf("Triggering interrupt 42...\n");
    OK(uc_irq_trigger(uc, 42));
    printf("Interrupt triggered\n");

    // Start emulation - should be interrupted immediately
    printf("Starting emulation...\n");
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));
    printf("Emulation finished\n");

    // Verify interrupt was called with correct number
    printf("IRQ called: %d, IRQ number: %u\n", irq_test_called, irq_test_intno);
    TEST_CHECK(irq_test_called == 1);
    TEST_CHECK(irq_test_intno == 42);

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
    printf("Test complete - SUCCESS!\n");
}

int main()
{
    test_arm_irq_trigger();
    return 0;
}