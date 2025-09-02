#!/usr/bin/env python3
"""
Simplified NVIC Implementation using mapped memory and read/write hooks

This is a simpler version that uses mapped memory and hooks to intercept accesses.
"""

import struct
from typing import Dict, List, Optional, Callable
from unicorn import *
from unicorn.arm_const import *

# NVIC Register Addresses
NVIC_BASE = 0xE000E100
NVIC_ISER_BASE = 0xE000E100  # Interrupt Set-Enable Registers
NVIC_ICER_BASE = 0xE000E180  # Interrupt Clear-Enable Registers  
NVIC_ISPR_BASE = 0xE000E200  # Interrupt Set-Pending Registers
NVIC_ICPR_BASE = 0xE000E280  # Interrupt Clear-Pending Registers
NVIC_IPR_BASE = 0xE000E400   # Interrupt Priority Registers
SCB_VTOR = 0xE000ED08         # Vector Table Offset Register


class SimpleNVIC:
    """Simple NVIC implementation with hooks."""
    
    def __init__(self, uc: Uc, max_irqs: int = 240):
        self.uc = uc
        self.max_irqs = max_irqs
        self.enabled = [False] * max_irqs
        self.pending = [False] * max_irqs
        self.priority = [0] * max_irqs
        self.vtor = 0x00000000
        self.mem_hook = None
        self.interrupt_handlers: Dict[int, Callable] = {}
        
        # Map NVIC region
        uc.mem_map(NVIC_BASE, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        
        # Install hooks
        self.mem_hook = uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self._mem_hook,
            begin=NVIC_BASE,
            end=NVIC_BASE + 0x1000
        )
        
    def _mem_hook(self, uc, access, address, size, value, user_data):
        """Handle NVIC memory accesses."""
        if access == UC_MEM_WRITE:
            print(f"[NVIC] WRITE 0x{address:08x} = 0x{value:08x}")
            self._handle_write(address, size, value)
        elif access == UC_MEM_READ:
            print(f"[NVIC] READ 0x{address:08x}")
            # Let the read proceed normally, but we can intercept it
            pass
            
    def _handle_write(self, address, size, value):
        """Handle register writes."""
        if NVIC_ISER_BASE <= address < NVIC_ISER_BASE + 32:
            # Enable interrupts
            reg_idx = (address - NVIC_ISER_BASE) // 4
            for bit in range(32):
                if value & (1 << bit):
                    irq_num = reg_idx * 32 + bit
                    if irq_num < self.max_irqs:
                        self.enabled[irq_num] = True
                        print(f"[NVIC] Enabled IRQ{irq_num}")
                        
        elif NVIC_ISPR_BASE <= address < NVIC_ISPR_BASE + 32:
            # Set pending interrupts
            reg_idx = (address - NVIC_ISPR_BASE) // 4
            for bit in range(32):
                if value & (1 << bit):
                    irq_num = reg_idx * 32 + bit
                    if irq_num < self.max_irqs:
                        self.pending[irq_num] = True
                        print(f"[NVIC] Set IRQ{irq_num} pending")
                        
        elif NVIC_IPR_BASE <= address < NVIC_IPR_BASE + 240:
            # Priority registers
            irq_num = address - NVIC_IPR_BASE
            if size == 1 and irq_num < self.max_irqs:
                self.priority[irq_num] = value & 0xFF
                print(f"[NVIC] Set IRQ{irq_num} priority to {value & 0xFF}")
                
    def trigger_irq(self, irq_num):
        """Trigger an interrupt."""
        if 0 <= irq_num < self.max_irqs:
            self.pending[irq_num] = True
            
    def set_priority(self, irq_num, priority):
        """Set interrupt priority."""
        if 0 <= irq_num < self.max_irqs:
            self.priority[irq_num] = priority & 0xFF
            
    def cleanup(self):
        """Cleanup."""
        if self.mem_hook:
            self.uc.hook_del(self.mem_hook)


def test_simple_nvic():
    """Test the simple NVIC implementation."""
    print("=== Simple NVIC Test ===\n")
    
    try:
        # Create Unicorn ARM instance
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        
        # Create NVIC
        nvic = SimpleNVIC(uc, 32)
        
        print("[+] Testing NVIC register writes...")
        
        # Test enabling IRQ5 via ISER
        test_addr = NVIC_ISER_BASE
        print(f"Writing 0x20 to NVIC_ISER0 (0x{test_addr:08x})")
        uc.mem_write(test_addr, struct.pack("<I", 0x20))
        print(f"IRQ5 enabled: {nvic.enabled[5]}")
        
        # Test setting IRQ7 pending via ISPR
        test_addr = NVIC_ISPR_BASE
        print(f"Writing 0x80 to NVIC_ISPR0 (0x{test_addr:08x})")
        uc.mem_write(test_addr, struct.pack("<I", 0x80))
        print(f"IRQ7 pending: {nvic.pending[7]}")
        
        # Test priority setting
        test_addr = NVIC_IPR_BASE + 6
        print(f"Writing priority 192 to IRQ6 (0x{test_addr:08x})")
        uc.mem_write(test_addr, bytes([192]))
        print(f"IRQ6 priority: {nvic.priority[6]}")
        
        print("\n[+] Testing programmatic interface...")
        nvic.trigger_irq(10)
        nvic.set_priority(10, 64)
        print(f"IRQ10 pending: {nvic.pending[10]}, priority: {nvic.priority[10]}")
        
        print("\n[+] Simple NVIC test completed!")
        
        nvic.cleanup()
        return 0
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(test_simple_nvic())