#!/usr/bin/env python3
"""
Example demonstrating ARM Cortex-M interrupt handling with fake NVIC

This example shows how to use the fake NVIC implementation to handle interrupts
in ARM Cortex-M emulation. It demonstrates:
- Setting up interrupt handlers
- Triggering interrupts from peripherals
- NVIC register manipulation
- Exception entry and exit

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
from unicorn.nvic import NVIC, create_cortex_m_with_nvic, NVIC_ISER_BASE, NVIC_ISPR_BASE, NVIC_IPR_BASE

# Memory layout
FLASH_BASE = 0x08000000
RAM_BASE = 0x20000000
NVIC_BASE = 0xE000E100

# Simple ARM Cortex-M program
# This program sets up a main loop and timer interrupt handler
ARM_CODE = bytes([
    # Vector table (first 40 entries - enough for external interrupts)
    0x00, 0x10, 0x00, 0x20,  # 0x00: Initial SP = 0x20001000
    0x21, 0x00, 0x00, 0x08,  # 0x04: Reset handler = 0x08000020 + 1 (Thumb)
    0x31, 0x00, 0x00, 0x08,  # 0x08: NMI handler = 0x08000030 + 1  
    0x31, 0x00, 0x00, 0x08,  # 0x0C: Hard fault handler = 0x08000030 + 1
    0x00, 0x00, 0x00, 0x00,  # 0x10: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x14: Reserved  
    0x00, 0x00, 0x00, 0x00,  # 0x18: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x1C: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x20: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x24: Reserved  
    0x00, 0x00, 0x00, 0x00,  # 0x28: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x2C: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x30: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x34: Reserved  
    0x00, 0x00, 0x00, 0x00,  # 0x38: Reserved
    0x00, 0x00, 0x00, 0x00,  # 0x3C: Reserved
    # External interrupt vectors
    0x35, 0x00, 0x00, 0x08,  # 0x40: IRQ0 handler = 0x08000034 + 1
    0x35, 0x00, 0x00, 0x08,  # 0x44: IRQ1 handler = 0x08000034 + 1
    0x35, 0x00, 0x00, 0x08,  # 0x48: IRQ2 handler = 0x08000034 + 1
    0x35, 0x00, 0x00, 0x08,  # 0x4C: IRQ3 handler = 0x08000034 + 1
    
    # Reset handler (address 0x08000050)
    0x00, 0x20,              # movs r0, #0      ; 0x08000050
    0x01, 0x21,              # movs r1, #1      ; 0x08000052
    0x08, 0x44,              # add  r0, r1      ; 0x08000054  
    0xFE, 0xE7,              # b    .           ; 0x08000056 (infinite loop)
    
    # Default exception handler (address 0x08000058) 
    0x10, 0xB5,              # push {r4, lr}    ; 0x08000058
    0x02, 0x22,              # movs r2, #2      ; 0x0800005A
    0x10, 0x44,              # add  r0, r2      ; 0x0800005C
    0x10, 0xBD,              # pop  {r4, pc}    ; 0x0800005E

    # IRQ handler (address 0x08000060)
    0x08, 0xB5,              # push {r3, lr}    ; 0x08000060
    0x05, 0x23,              # movs r3, #5      ; 0x08000062
    0x18, 0x44,              # add  r0, r3      ; 0x08000064
    0x08, 0xBD,              # pop  {r3, pc}    ; 0x08000066
])

def main():
    """Main example function."""
    print("=== ARM Cortex-M NVIC Interrupt Example ===\n")
    
    try:
        # Create Cortex-M3 with NVIC support
        uc, nvic = create_cortex_m_with_nvic("cortex-m3", max_irqs=32)
        
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
        uc.reg_write(UC_ARM_REG_PC, FLASH_BASE + 0x50)  # Reset handler address
        
        # Set vector table base
        nvic.vtor = FLASH_BASE
        
        # Set up interrupt priorities  
        print("[+] Configuring interrupt priorities...")
        nvic.set_priority(0, 64)   # Timer interrupt - medium priority
        nvic.set_priority(1, 32)   # UART interrupt - high priority
        nvic.set_priority(2, 128)  # GPIO interrupt - low priority
        
        # Enable interrupts
        print("[+] Enabling interrupts...")
        nvic.enabled[0] = True     # Enable Timer interrupt
        nvic.enabled[1] = True     # Enable UART interrupt  
        nvic.enabled[2] = True     # Enable GPIO interrupt
        
        # Add interrupt handlers for logging
        def timer_handler(irq_num):
            print(f"[IRQ] Timer interrupt {irq_num} injected!")
            
        def uart_handler(irq_num):
            print(f"[IRQ] UART interrupt {irq_num} injected!")
            
        def gpio_handler(irq_num):
            print(f"[IRQ] GPIO interrupt {irq_num} injected!")
            
        nvic.add_interrupt_handler(0, timer_handler)
        nvic.add_interrupt_handler(1, uart_handler)
        nvic.add_interrupt_handler(2, gpio_handler)
        
        # Set up instruction tracing  
        instruction_count = 0
        
        def trace_instruction(uc, address, size, user_data):
            nonlocal instruction_count
            instruction_count += 1
            
            # Get current registers
            pc = uc.reg_read(UC_ARM_REG_PC)
            sp = uc.reg_read(UC_ARM_REG_SP)
            r0 = uc.reg_read(UC_ARM_REG_R0)
            ipsr = uc.reg_read(UC_ARM_REG_IPSR)
            
            print(f"[EXEC] #{instruction_count:3d} PC=0x{pc:08x} SP=0x{sp:08x} R0=0x{r0:08x} IPSR={ipsr:3d}")
            
            # Trigger some interrupts during execution
            if instruction_count == 5:
                print("[SIM] Simulating timer interrupt...")
                nvic.trigger_irq(0)
                
            elif instruction_count == 10:  
                print("[SIM] Simulating UART data received...")
                nvic.trigger_irq(1)
                
            elif instruction_count == 15:
                print("[SIM] Simulating GPIO button press...")
                nvic.trigger_irq(2)
                
            # Check and inject interrupts
            if nvic.check_and_inject_irq():
                # Interrupt was injected, get new PC
                new_pc = uc.reg_read(UC_ARM_REG_PC)
                new_ipsr = uc.reg_read(UC_ARM_REG_IPSR)
                print(f"[INT] Interrupt injected! New PC=0x{new_pc:08x}, IPSR={new_ipsr}")
                
            # Stop after reasonable number of instructions
            if instruction_count >= 25:
                print("[+] Stopping emulation after 25 instructions")
                uc.emu_stop()
                
        print("[+] Starting emulation with interrupt monitoring...")
        uc.hook_add(UC_HOOK_CODE, trace_instruction)
        
        # Start emulation
        try:
            uc.emu_start(FLASH_BASE + 0x50, FLASH_BASE + len(ARM_CODE), count=100)
        except UcError as e:
            if e.errno != UC_ERR_OK:
                print(f"[!] Emulation error: {e}")
        
        # Display final state
        print("\n[+] Final CPU state:")
        final_pc = uc.reg_read(UC_ARM_REG_PC)
        final_sp = uc.reg_read(UC_ARM_REG_SP)  
        final_r0 = uc.reg_read(UC_ARM_REG_R0)
        final_ipsr = uc.reg_read(UC_ARM_REG_IPSR)
        
        print(f"    PC   = 0x{final_pc:08x}")
        print(f"    SP   = 0x{final_sp:08x}")
        print(f"    R0   = 0x{final_r0:08x}")  
        print(f"    IPSR = {final_ipsr}")
        
        # Display NVIC state
        print("\n[+] Final NVIC state:")
        print("    Interrupt states:")
        for i in range(8):
            enabled = "EN" if nvic.enabled[i] else "DIS"
            pending = "PEND" if nvic.pending[i] else "----"  
            active = "ACT" if nvic.active[i] else "---"
            priority = nvic.priority[i]
            print(f"      IRQ{i:2d}: {enabled:3s} {pending:4s} {active:3s} PRI={priority:3d}")
            
        # Test NVIC register access
        print("\n[+] Testing NVIC register access...")
        
        # Test ISER register (enable interrupt 5)
        test_address = NVIC_ISER_BASE
        print(f"    Writing 0x20 to NVIC_ISER0 (0x{test_address:08x}) to enable IRQ5")
        uc.mem_write(test_address, struct.pack("<I", 0x20))  # Enable IRQ5
        
        # Read it back
        read_value = struct.unpack("<I", uc.mem_read(test_address, 4))[0]
        print(f"    Read back: 0x{read_value:08x}")
        print(f"    IRQ5 enabled: {nvic.enabled[5]}")
        
        # Test ISPR register (trigger interrupt 7)
        test_address = NVIC_ISPR_BASE  
        print(f"    Writing 0x80 to NVIC_ISPR0 (0x{test_address:08x}) to trigger IRQ7")
        uc.mem_write(test_address, struct.pack("<I", 0x80))  # Trigger IRQ7
        
        # Check if pending
        print(f"    IRQ7 pending: {nvic.pending[7]}")
        
        # Test priority register access
        test_address = NVIC_IPR_BASE + 6  # Priority for IRQ6
        print(f"    Writing priority 192 to IRQ6 at address 0x{test_address:08x}")
        uc.mem_write(test_address, bytes([192]))
        
        # Read it back
        read_priority = uc.mem_read(test_address, 1)[0]  
        print(f"    Read back priority: {read_priority}")
        print(f"    IRQ6 priority: {nvic.priority[6]}")
        
        print("\n[+] NVIC interrupt example completed successfully!")
        
        # Cleanup
        nvic.cleanup()
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())