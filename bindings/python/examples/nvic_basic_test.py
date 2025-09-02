#!/usr/bin/env python3
"""
Simple test of NVIC register access functionality
"""

import struct
import sys
import os

# Add the parent directory to the path so we can import unicorn modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unicorn import *
from unicorn.arm_const import *
from unicorn.nvic import NVIC, create_cortex_m_with_nvic, NVIC_ISER_BASE, NVIC_ISPR_BASE, NVIC_IPR_BASE

def test_nvic_basic():
    """Test basic NVIC functionality."""
    print("=== Basic NVIC Test ===\n")
    
    try:
        # Create Cortex-M3 with NVIC support
        uc, nvic = create_cortex_m_with_nvic("cortex-m3", max_irqs=32)
        
        # Map memory regions (but not NVIC region - let the hook handle it)
        print("[+] Setting up memory regions...")
        # Only map memory below NVIC
        if 0xE0000000 > 0x20000000:
            uc.mem_map(0x20000000, 0xBFF00000, UC_PROT_READ | UC_PROT_WRITE)  # RAM region
        # Map memory after NVIC if needed
        
        print("[+] Testing NVIC register access...")
        
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
        
        print("\n[+] Testing interrupt triggering...")
        
        # Enable some interrupts
        nvic.enabled[0] = True
        nvic.enabled[1] = True
        nvic.set_priority(0, 64)
        nvic.set_priority(1, 32)  # Higher priority
        
        # Trigger both
        nvic.trigger_irq(0)
        nvic.trigger_irq(1)
        
        print(f"    IRQ0 pending: {nvic.pending[0]}, priority: {nvic.priority[0]}")
        print(f"    IRQ1 pending: {nvic.pending[1]}, priority: {nvic.priority[1]}")
        
        # Check which one would be served first
        print("    Checking which interrupt would be served...")
        highest_priority = 256
        best_irq = -1
        
        for irq_num in range(8):
            if nvic.pending[irq_num] and nvic.enabled[irq_num]:
                if nvic.priority[irq_num] < highest_priority:
                    highest_priority = nvic.priority[irq_num]
                    best_irq = irq_num
        
        if best_irq >= 0:
            print(f"    IRQ{best_irq} would be served first (priority {highest_priority})")
        else:
            print("    No interrupts to serve")
            
        print("\n[+] NVIC basic test completed successfully!")
        
        # Cleanup
        nvic.cleanup()
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(test_nvic_basic())