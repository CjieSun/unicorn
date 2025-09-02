# NVIC Interrupt Support for Unicorn ARM Cortex-M

This module provides a "fake NVIC" implementation that adds interrupt support to Unicorn for ARM Cortex-M processors.

## Problem

Unicorn removed QEMU's underlying interrupt support and doesn't have QoM + sysbus to register NVIC, UART, and other peripherals. This makes it impossible to use standard ARM Cortex-M interrupt handling.

## Solution

This implementation provides a fake NVIC using Python that:

1. **Intercepts NVIC register accesses** - Monitors reads/writes to NVIC registers (0xE000E100 ~ 0xE000E4FF)
2. **Maintains interrupt state** - Uses Python arrays to track enabled[], pending[], and priority[] for each interrupt
3. **Supports external interrupt triggering** - Peripherals can trigger interrupts by calling `trigger_irq()`
4. **Provides interrupt injection** - Periodically check for pending interrupts and inject the highest priority one
5. **Simulates exception entry** - Automatically pushes stack frame and jumps to interrupt vector

## Quick Start

```python
from unicorn import *
from unicorn.arm_const import *
from unicorn.working_nvic import create_cortex_m_with_nvic

# Create Cortex-M with NVIC support
uc, nvic = create_cortex_m_with_nvic(max_irqs=32)

# Map memory regions
uc.mem_map(0x08000000, 0x10000, UC_PROT_READ | UC_PROT_EXEC)  # Flash
uc.mem_map(0x20000000, 0x10000, UC_PROT_READ | UC_PROT_WRITE) # RAM

# Configure interrupts
nvic.enable_irq(0)           # Enable Timer interrupt
nvic.set_priority(0, 64)     # Set medium priority
nvic.trigger_irq(0)          # Trigger interrupt

# Set up interrupt handler
def timer_handler(irq_num):
    print(f"Timer interrupt {irq_num} fired!")
    
nvic.add_interrupt_handler(0, timer_handler)

# In your emulation loop, check for interrupts
def instruction_hook(uc, address, size, user_data):
    # Check and inject interrupts
    injected_irq = nvic.check_and_inject_irq()
    if injected_irq is not None:
        print(f"Interrupt {injected_irq} injected!")
        
uc.hook_add(UC_HOOK_CODE, instruction_hook)

# Start emulation
uc.emu_start(start_address, end_address)
```

## API Reference

### WorkingNVIC Class

#### Basic Operations
- `enable_irq(irq_num)` - Enable an interrupt
- `disable_irq(irq_num)` - Disable an interrupt  
- `trigger_irq(irq_num)` - Trigger an interrupt (set pending)
- `clear_irq(irq_num)` - Clear a pending interrupt
- `set_priority(irq_num, priority)` - Set interrupt priority (0-255, lower = higher priority)

#### NVIC Register Access
- `read_nvic_register(address)` - Read NVIC register value
- `write_nvic_register(address, value, size)` - Write to NVIC register

#### Interrupt Management
- `check_and_inject_irq()` - Check for pending interrupts and inject highest priority one
- `add_interrupt_handler(irq_num, handler)` - Add callback for when interrupt is injected
- `get_status_summary()` - Get summary of interrupt states

### NVIC Register Addresses

| Register | Address | Description |
|----------|---------|-------------|
| NVIC_ISER0-7 | 0xE000E100-0xE11C | Interrupt Set-Enable Registers |
| NVIC_ICER0-7 | 0xE000E180-0xE19C | Interrupt Clear-Enable Registers |
| NVIC_ISPR0-7 | 0xE000E200-0xE21C | Interrupt Set-Pending Registers |
| NVIC_ICPR0-7 | 0xE000E280-0xE29C | Interrupt Clear-Pending Registers |
| NVIC_IABR0-7 | 0xE000E300-0xE31C | Interrupt Active Bit Registers |
| NVIC_IPR0-59 | 0xE000E400-0xE4EC | Interrupt Priority Registers |
| SCB_VTOR | 0xE000ED08 | Vector Table Offset Register |

## Examples

See the `examples/` directory for complete demonstrations:

- `comprehensive_nvic_test.py` - Complete functionality test
- `test_working_nvic.py` - Basic functionality test
- `working_nvic_example.py` - Full emulation example

## How It Works

### Exception Injection Process

When `check_and_inject_irq()` is called:

1. **Find highest priority interrupt** - Scan all pending+enabled interrupts
2. **Save CPU context** - Read R0-R3, R12, LR, PC, xPSR registers  
3. **Push stack frame** - Write 8-word frame to stack (decrements SP by 32)
4. **Update IPSR** - Set exception number (IRQ number + 16)
5. **Jump to vector** - Read vector from table at VTOR + (exception_num * 4)
6. **Set EXC_RETURN** - Load LR with return value (0xFFFFFFF9)
7. **Mark active** - Set interrupt as active, clear pending

### Integration Pattern

```python
# Typical usage pattern in emulation loop
def emulation_step(uc, nvic):
    # 1. Execute some instructions
    uc.emu_start(pc, pc + 4, count=1)  # Single step
    
    # 2. Simulate peripheral activity
    if some_timer_expired():
        nvic.trigger_irq(TIMER_IRQ)
        
    if uart_data_available():
        nvic.trigger_irq(UART_IRQ)
    
    # 3. Check and inject interrupts
    injected_irq = nvic.check_and_inject_irq()
    
    # 4. Continue emulation
    return injected_irq
```

## Limitations

- Uses polling-based interrupt checking (call `check_and_inject_irq()` periodically)
- Does not automatically intercept memory-mapped register accesses (use `write_nvic_register()`)
- Exception return handling is simplified
- No support for interrupt nesting or preemption
- PRIMASK, FAULTMASK, and BASEPRI are not implemented

## License

GPLv2 - Same as Unicorn Engine