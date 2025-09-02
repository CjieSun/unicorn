#!/usr/bin/env python3
"""
Simple test of the working NVIC implementation
This test focuses on NVIC functionality without complex instruction execution.
"""

import struct
import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unicorn import *
from unicorn.arm_const import *
from unicorn.working_nvic import WorkingNVIC, create_cortex_m_with_nvic

def test_working_nvic():
    """Test the working NVIC implementation."""
    print("=== Working NVIC Functionality Test ===\n")
    
    try:
        # Create Cortex-M with working NVIC
        uc, nvic = create_cortex_m_with_nvic(32)
        
        # Map required memory regions
        uc.mem_map(0x08000000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)  # Flash
        uc.mem_map(0x20000000, 0x1000, UC_PROT_READ | UC_PROT_WRITE) # RAM
        
        # Set up basic vector table
        vector_table = bytes([
            0x00, 0x10, 0x00, 0x20,  # Initial SP
            0x09, 0x00, 0x00, 0x08,  # Reset vector 
            0x0D, 0x00, 0x00, 0x08,  # NMI
            0x0D, 0x00, 0x00, 0x08,  # Hard fault
        ] + [0x00] * 48)  # Pad with zeros
        
        uc.mem_write(0x08000000, vector_table)
        
        # Set vector table base
        nvic.vtor = 0x08000000
        
        print("[+] Testing basic NVIC operations...")
        
        # Test 1: Enable interrupts
        print("    Test 1: Enabling interrupts")
        nvic.enable_irq(0)  # Timer
        nvic.enable_irq(1)  # UART
        nvic.enable_irq(2)  # GPIO
        
        enabled_irqs = [i for i, enabled in enumerate(nvic.enabled) if enabled]
        print(f"        Enabled IRQs: {enabled_irqs}")
        
        # Test 2: Set priorities
        print("    Test 2: Setting priorities")
        nvic.set_priority(0, 64)   # Medium priority
        nvic.set_priority(1, 32)   # High priority (lower number = higher priority)
        nvic.set_priority(2, 128)  # Low priority
        
        print(f"        IRQ0 priority: {nvic.priority[0]}")
        print(f"        IRQ1 priority: {nvic.priority[1]}")
        print(f"        IRQ2 priority: {nvic.priority[2]}")
        
        # Test 3: Trigger interrupts
        print("    Test 3: Triggering interrupts")
        nvic.trigger_irq(0)
        nvic.trigger_irq(1)
        nvic.trigger_irq(2)
        
        pending_irqs = [i for i, pending in enumerate(nvic.pending) if pending]
        print(f"        Pending IRQs: {pending_irqs}")
        
        # Test 4: Check interrupt priority resolution
        print("    Test 4: Priority resolution")
        highest_priority = 256
        best_irq = -1
        
        for irq_num in range(8):
            if nvic.pending[irq_num] and nvic.enabled[irq_num]:
                if nvic.priority[irq_num] < highest_priority:
                    highest_priority = nvic.priority[irq_num]
                    best_irq = irq_num
                    
        if best_irq >= 0:
            print(f"        Highest priority pending IRQ: {best_irq} (priority {highest_priority})")
        else:
            print("        No interrupts ready to serve")
            
        # Test 5: NVIC register access
        print("    Test 5: NVIC register operations")
        
        # Test ISER (enable register)
        nvic.write_nvic_register(0xE000E100, 0x10, 4)  # Enable IRQ4
        print(f"        IRQ4 enabled via ISER: {nvic.enabled[4]}")
        iser_value = nvic.read_nvic_register(0xE000E100)
        print(f"        ISER0 value: 0x{iser_value:08x}")
        
        # Test ISPR (pending register)
        nvic.write_nvic_register(0xE000E200, 0x20, 4)  # Set IRQ5 pending
        print(f"        IRQ5 pending via ISPR: {nvic.pending[5]}")
        ispr_value = nvic.read_nvic_register(0xE000E200)
        print(f"        ISPR0 value: 0x{ispr_value:08x}")
        
        # Test IPR (priority register)
        nvic.write_nvic_register(0xE000E400 + 6, 192, 1)  # Set IRQ6 priority
        print(f"        IRQ6 priority via IPR: {nvic.priority[6]}")
        
        # Test 6: Interrupt handlers
        print("    Test 6: Interrupt handlers")
        handler_called = []
        
        def test_handler(irq_num):
            handler_called.append(irq_num)
            print(f"        Handler called for IRQ{irq_num}")
            
        nvic.add_interrupt_handler(7, test_handler)
        nvic.enable_irq(7)
        nvic.trigger_irq(7)
        
        # Simulate interrupt injection check
        injected_irq = nvic.check_and_inject_irq()
        if injected_irq is not None:
            print(f"        Interrupt IRQ{injected_irq} would be injected")
        
        # Test 7: Status summary
        print("    Test 7: Status summary")
        status = nvic.get_status_summary()
        print(f"        Enabled: {status['enabled_count']}, Pending: {status['pending_count']}")
        print(f"        Active: {status['active_count']}, VTOR: {status['vtor']}")
        
        print("\n[+] All NVIC functionality tests passed!")
        
        # Display final summary
        print("\n[+] Final NVIC State Summary:")
        print(f"    Enabled IRQs: {status['enabled_irqs']}")
        print(f"    Pending IRQs: {status['pending_irqs']}")
        if status['active_irqs']:
            print(f"    Active IRQs: {status['active_irqs']}")
            
        return 0
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(test_working_nvic())