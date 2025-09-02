#!/usr/bin/env python3
"""
Test NVIC memory mapping and hooks with the correct ARM Cortex-M memory layout
"""

import struct
import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unicorn import *
from unicorn.arm_const import *

# ARM Cortex-M Memory Map
FLASH_BASE = 0x08000000
SRAM_BASE = 0x20000000  
PERIPH_BASE = 0x40000000
SYSTEM_BASE = 0xE0000000
NVIC_BASE = 0xE000E100


def test_nvic_memory():
    """Test NVIC memory region mapping."""
    print("=== NVIC Memory Test ===\n")
    
    try:
        # Create ARM Cortex-M instance
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        
        # Map system control space - this includes NVIC
        print("[+] Mapping system control space...")
        try:
            # Try mapping the entire system region
            uc.mem_map(SYSTEM_BASE, 0x100000, UC_PROT_READ | UC_PROT_WRITE)
            print(f"    Mapped 0x{SYSTEM_BASE:08x} - 0x{SYSTEM_BASE + 0x100000:08x}")
        except UcError as e:
            print(f"    Failed to map system region: {e}")
            # Try smaller region around NVIC
            try:
                nvic_page = NVIC_BASE & ~0xFFF  # Align to page boundary
                uc.mem_map(nvic_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
                print(f"    Mapped NVIC page 0x{nvic_page:08x} - 0x{nvic_page + 0x1000:08x}")
            except UcError as e2:
                print(f"    Failed to map NVIC region: {e2}")
                return 1
        
        # Test basic memory access to NVIC registers
        print("[+] Testing NVIC register access...")
        
        # Test NVIC_ISER0 (Interrupt Set-Enable Register 0)
        iser0_addr = 0xE000E100
        print(f"    Testing ISER0 at 0x{iser0_addr:08x}")
        
        try:
            # Write to enable interrupt 5
            uc.mem_write(iser0_addr, struct.pack("<I", 0x20))  # Bit 5 set
            print("    Write successful")
            
            # Read back
            data = uc.mem_read(iser0_addr, 4)
            value = struct.unpack("<I", data)[0]
            print(f"    Read back: 0x{value:08x}")
            
        except UcError as e:
            print(f"    Memory access failed: {e}")
            
        # Test NVIC_ISPR0 (Interrupt Set-Pending Register 0)
        ispr0_addr = 0xE000E200
        print(f"    Testing ISPR0 at 0x{ispr0_addr:08x}")
        
        try:
            uc.mem_write(ispr0_addr, struct.pack("<I", 0x80))  # Bit 7 set
            data = uc.mem_read(ispr0_addr, 4)
            value = struct.unpack("<I", data)[0]
            print(f"    Read back: 0x{value:08x}")
        except UcError as e:
            print(f"    Memory access failed: {e}")
            
        # Test priority register
        ipr_addr = 0xE000E400 + 6  # Priority for IRQ 6
        print(f"    Testing IPR6 at 0x{ipr_addr:08x}")
        
        try:
            uc.mem_write(ipr_addr, bytes([192]))
            data = uc.mem_read(ipr_addr, 1)
            value = data[0]
            print(f"    Read back: {value}")
        except UcError as e:
            print(f"    Memory access failed: {e}")
            
        print("\n[+] NVIC memory test completed!")
        return 0
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(test_nvic_memory())