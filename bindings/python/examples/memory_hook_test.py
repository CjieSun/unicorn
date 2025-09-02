#!/usr/bin/env python3
"""
Test basic memory hook functionality to understand how hooks work
"""

import struct
import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unicorn import *
from unicorn.arm_const import *


def test_memory_hooks():
    """Test basic memory hook functionality."""
    print("=== Memory Hook Test ===\n")
    
    try:
        # Create ARM Cortex-M instance
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        
        # Map a test region
        test_base = 0x40000000  # Peripheral region
        uc.mem_map(test_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        
        # Add memory hook
        def mem_hook(uc, access, address, size, value, user_data):
            access_str = "WRITE" if access == UC_MEM_WRITE else "READ"
            print(f"[HOOK] {access_str} 0x{address:08x} size={size} value=0x{value:08x}")
            
        hook_id = uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, mem_hook,
                             begin=test_base, end=test_base + 0x1000)
        
        print("[+] Testing memory hook...")
        
        # Test write
        print("Writing 0x12345678 to 0x40000100")
        uc.mem_write(test_base + 0x100, struct.pack("<I", 0x12345678))
        
        # Test read
        print("Reading from 0x40000100")
        data = uc.mem_read(test_base + 0x100, 4)
        value = struct.unpack("<I", data)[0]
        print(f"Read value: 0x{value:08x}")
        
        # Clean up
        uc.hook_del(hook_id)
        
        print("\n[+] Memory hook test completed!")
        return 0
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(test_memory_hooks())