#!/usr/bin/env python3
"""
Comprehensive example demonstrating working ARM Cortex-M interrupt handling

This example shows how to use the working NVIC implementation to handle interrupts
in ARM Cortex-M emulation. It demonstrates:
- Setting up interrupt handlers and priorities
- Triggering interrupts from peripherals  
- NVIC register manipulation
- Exception entry and exit
- Polling-based interrupt checking

Author: Unicorn Engine Team
License: GPLv2
"""

import struct
import sys
import os

# Add the parent directory to the path so we can import unicorn modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unicorn import *
from unicorn.arm_const import *
from unicorn.working_nvic import WorkingNVIC, create_cortex_m_with_nvic

# Memory layout
FLASH_BASE = 0x08000000
RAM_BASE = 0x20000000
NVIC_BASE = 0xE000E100

# ARM Cortex-M program with proper vector table and interrupt handlers
ARM_CODE = bytes([
    # Vector table (first 8 system + 8 external interrupt vectors)
    0x00, 0x10, 0x00, 0x20,  # 0x00: Initial SP = 0x20001000
    0x31, 0x00, 0x00, 0x08,  # 0x04: Reset handler = 0x08000030 + 1
    0x41, 0x00, 0x00, 0x08,  # 0x08: NMI handler = 0x08000040 + 1
    0x41, 0x00, 0x00, 0x08,  # 0x0C: Hard fault = 0x08000040 + 1
    0x00, 0x00, 0x00, 0x00,  # 0x10: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x14: Reserved  
    0x00, 0x00, 0x00, 0x00,  # 0x18: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x1C: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x20: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x24: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x28: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x2C: Reserved
    
    # External interrupt vectors
    0x49, 0x00, 0x00, 0x08,  # 0x30: IRQ0 (Timer) = 0x08000048 + 1
    0x51, 0x00, 0x00, 0x08,  # 0x34: IRQ1 (UART) = 0x08000050 + 1
    0x59, 0x00, 0x00, 0x08,  # 0x38: IRQ2 (GPIO) = 0x08000058 + 1
    0x41, 0x00, 0x00, 0x08,  # 0x3C: IRQ3 = default handler
    
    # Reset handler at 0x08000040
    0x00, 0x20,              # movs r0, #0      
    0x01, 0x21,              # movs r1, #1      
    0x08, 0x44,              # add  r0, r1      
    0xFE, 0xE7,              # b    .           (infinite loop)
    
    # Default exception/interrupt handler at 0x08000048
    0x02, 0x22,              # movs r2, #2      
    0x10, 0x44,              # add  r0, r2      
    0x70, 0x47,              # bx   lr          (return from interrupt)
    0x00, 0xBF,              # nop              (padding)

    # Timer interrupt handler at 0x08000050
    0x0A, 0x23,              # movs r3, #10     
    0x18, 0x44,              # add  r0, r3      
    0x70, 0x47,              # bx   lr          (return from interrupt)
    0x00, 0xBF,              # nop              (padding)
    
    # UART interrupt handler at 0x08000058  
    0x14, 0x23,              # movs r3, #20     
    0x18, 0x44,              # add  r0, r3      
    0x70, 0x47,              # bx   lr          (return from interrupt)
    0x00, 0xBF,              # nop              (padding)
    
    # GPIO interrupt handler at 0x08000060
    0x1E, 0x23,              # movs r3, #30     
    0x18, 0x44,              # add  r0, r3      
    0x70, 0x47,              # bx   lr          (return from interrupt)
    0x00, 0xBF,              # nop              (padding)
])


def main():
    """Main example function."""
    print("=== Working ARM Cortex-M NVIC Interrupt Example ===\n")
    
    try:
        # Create Cortex-M3 with working NVIC support
        uc, nvic = create_cortex_m_with_nvic(max_irqs=32)
        
        # Map memory regions
        print("[+] Setting up memory regions...")
        uc.mem_map(FLASH_BASE, 1024 * 1024, UC_PROT_READ | UC_PROT_EXEC)  # 1MB Flash
        uc.mem_map(RAM_BASE, 64 * 1024, UC_PROT_READ | UC_PROT_WRITE)      # 64KB RAM
        
        # Write program to flash
        print("[+] Loading program into flash...")
        uc.mem_write(FLASH_BASE, ARM_CODE)
        
        # Set up initial CPU state
        print("[+] Initializing CPU state...")
        initial_sp = 0x20001000
        uc.reg_write(UC_ARM_REG_SP, initial_sp)
        uc.reg_write(UC_ARM_REG_PC, FLASH_BASE + 0x40)  # Reset handler address
        
        # Set vector table base
        nvic.vtor = FLASH_BASE
        nvic.write_nvic_register(0xE000ED08, FLASH_BASE)  # Write to SCB_VTOR
        
        # Configure interrupt priorities  
        print("[+] Configuring interrupt priorities...")
        nvic.set_priority(0, 64)   # Timer interrupt - medium priority
        nvic.set_priority(1, 32)   # UART interrupt - high priority  
        nvic.set_priority(2, 128)  # GPIO interrupt - low priority
        
        # Enable interrupts
        print("[+] Enabling interrupts...")
        nvic.enable_irq(0)         # Enable Timer interrupt
        nvic.enable_irq(1)         # Enable UART interrupt
        nvic.enable_irq(2)         # Enable GPIO interrupt
        
        # Test NVIC register access
        print("[+] Testing NVIC register access...")
        
        # Enable IRQ3 via NVIC_ISER register
        nvic.write_nvic_register(0xE000E100, 0x08)  # Enable IRQ3
        print(f"    IRQ3 enabled via register: {nvic.enabled[3]}")
        
        # Set IRQ4 pending via NVIC_ISPR register  
        nvic.write_nvic_register(0xE000E200, 0x10)  # Set IRQ4 pending
        print(f"    IRQ4 pending via register: {nvic.pending[4]}")
        
        # Add interrupt handlers for logging
        def timer_handler(irq_num):
            print(f"[IRQ] Timer interrupt {irq_num} handler called!")
            
        def uart_handler(irq_num):
            print(f"[IRQ] UART interrupt {irq_num} handler called!")
            
        def gpio_handler(irq_num):
            print(f"[IRQ] GPIO interrupt {irq_num} handler called!")
            
        nvic.add_interrupt_handler(0, timer_handler)
        nvic.add_interrupt_handler(1, uart_handler)
        nvic.add_interrupt_handler(2, gpio_handler)
        
        # Set up instruction tracing with interrupt polling
        instruction_count = 0
        injected_interrupts = []
        
        def trace_instruction(uc, address, size, user_data):
            nonlocal instruction_count, injected_interrupts
            instruction_count += 1
            
            # Get current registers
            pc = uc.reg_read(UC_ARM_REG_PC)
            sp = uc.reg_read(UC_ARM_REG_SP)
            r0 = uc.reg_read(UC_ARM_REG_R0)
            
            print(f"[EXEC] #{instruction_count:3d} PC=0x{pc:08x} SP=0x{sp:08x} R0=0x{r0:08x}")
            
            # Simulate peripheral interrupts at specific instruction counts
            if instruction_count == 3:
                print("[SIM] Timer interrupt triggered by peripheral")
                nvic.trigger_irq(0)
                
            elif instruction_count == 6:  
                print("[SIM] UART data received interrupt")
                nvic.trigger_irq(1)
                
            elif instruction_count == 12:
                print("[SIM] GPIO button press interrupt")
                nvic.trigger_irq(2)
                
            # Check and inject interrupts (key part of the solution)
            injected_irq = nvic.check_and_inject_irq()
            if injected_irq is not None:
                # Interrupt was injected!
                new_pc = uc.reg_read(UC_ARM_REG_PC)
                new_sp = uc.reg_read(UC_ARM_REG_SP)
                injected_interrupts.append(injected_irq)
                print(f"[INT] IRQ{injected_irq} injected! PC: 0x{pc:08x} -> 0x{new_pc:08x}, SP: 0x{sp:08x} -> 0x{new_sp:08x}")
                
            # Stop after reasonable number of instructions
            if instruction_count >= 30:
                print("[+] Stopping emulation after 30 instructions")
                uc.emu_stop()
                
        print("\n[+] Starting emulation with interrupt monitoring...")
        uc.hook_add(UC_HOOK_CODE, trace_instruction)
        
        # Start emulation
        try:
            uc.emu_start(FLASH_BASE + 0x40, FLASH_BASE + len(ARM_CODE), count=100)
        except UcError as e:
            if e.errno != UC_ERR_OK:
                print(f"[!] Emulation stopped: {e}")
        
        # Display final state
        print(f"\n[+] Final CPU state:")
        final_pc = uc.reg_read(UC_ARM_REG_PC)
        final_sp = uc.reg_read(UC_ARM_REG_SP)  
        final_r0 = uc.reg_read(UC_ARM_REG_R0)
        
        print(f"    PC   = 0x{final_pc:08x}")
        print(f"    SP   = 0x{final_sp:08x}")
        print(f"    R0   = 0x{final_r0:08x}")
        
        # Display interrupt summary
        print(f"\n[+] Interrupt Summary:")
        print(f"    Interrupts injected: {injected_interrupts}")
        
        status = nvic.get_status_summary()
        print(f"    Total enabled: {status['enabled_count']}")
        print(f"    Total pending: {status['pending_count']}")  
        print(f"    Total active: {status['active_count']}")
        print(f"    VTOR: {status['vtor']}")
        
        if status['enabled_irqs']:
            print(f"    Enabled IRQs: {status['enabled_irqs']}")
        if status['pending_irqs']:
            print(f"    Pending IRQs: {status['pending_irqs']}")
        if status['active_irqs']:
            print(f"    Active IRQs: {status['active_irqs']}")
            
        # Test reading NVIC registers  
        print(f"\n[+] NVIC Register Values:")
        iser0 = nvic.read_nvic_register(0xE000E100)
        ispr0 = nvic.read_nvic_register(0xE000E200)
        print(f"    NVIC_ISER0 = 0x{iser0:08x}")
        print(f"    NVIC_ISPR0 = 0x{ispr0:08x}")
        
        print("\n[+] Working NVIC interrupt example completed successfully!")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())