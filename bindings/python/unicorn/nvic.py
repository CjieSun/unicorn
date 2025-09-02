#!/usr/bin/env python3
"""
Fake NVIC Implementation for Unicorn ARM Cortex-M Emulation

This module provides interrupt support for ARM Cortex-M processors by implementing
a fake NVIC (Nested Vectored Interrupt Controller) using Unicorn's memory hooks.

Since Unicorn removed QEMU's interrupt support and doesn't have QoM + sysbus to
register NVIC and other peripherals, this implementation uses hooks to intercept
NVIC register accesses and manage interrupt state in Python.

Author: Unicorn Engine Team
License: GPLv2
"""

import struct
from typing import Dict, List, Optional, Callable
from unicorn import *
from unicorn.arm_const import *

# NVIC Register Addresses (ARMv7-M Architecture Reference Manual)
NVIC_BASE = 0xE000E100
NVIC_ISER_BASE = 0xE000E100  # Interrupt Set-Enable Registers
NVIC_ICER_BASE = 0xE000E180  # Interrupt Clear-Enable Registers  
NVIC_ISPR_BASE = 0xE000E200  # Interrupt Set-Pending Registers
NVIC_ICPR_BASE = 0xE000E280  # Interrupt Clear-Pending Registers
NVIC_IABR_BASE = 0xE000E300  # Interrupt Active Bit Registers (read-only)
NVIC_IPR_BASE = 0xE000E400   # Interrupt Priority Registers
NVIC_END = 0xE000E4FF

# System Control Block registers
SCB_BASE = 0xE000ED00
SCB_VTOR = 0xE000ED08  # Vector Table Offset Register


class NVIC:
    """
    Fake NVIC implementation for ARM Cortex-M interrupt handling.
    
    This class provides a complete NVIC emulation by hooking memory accesses
    to NVIC registers and managing interrupt state.
    """
    
    def __init__(self, uc: Uc, max_irqs: int = 240):
        """
        Initialize the fake NVIC.
        
        Args:
            uc: Unicorn engine instance
            max_irqs: Maximum number of external interrupts (default 240)
        """
        self.uc = uc
        self.max_irqs = max_irqs
        
        # Interrupt state arrays
        self.enabled = [False] * max_irqs     # NVIC_ISER/ICER state
        self.pending = [False] * max_irqs     # NVIC_ISPR/ICPR state  
        self.active = [False] * max_irqs      # NVIC_IABR state
        self.priority = [0] * max_irqs        # NVIC_IPR state (0-255)
        
        # Vector table base address (default reset value)
        self.vtor = 0x00000000
        
        # Hook for NVIC register access
        self.mem_hook = None
        self.interrupt_handlers: Dict[int, Callable] = {}
        
        # Install memory hooks
        self._install_hooks()
        
    def _install_hooks(self):
        """Install memory hooks for NVIC and SCB registers."""
        # Use unmapped memory hooks so our handler gets called
        self.mem_hook = self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
            self._nvic_mem_hook_unmapped,
            begin=NVIC_BASE,
            end=SCB_BASE + 0x100  # Cover NVIC and part of SCB
        )
        
    def _nvic_mem_hook_unmapped(self, uc: Uc, access: int, address: int, size: int, value: int, user_data):
        """
        Handle NVIC register memory accesses for unmapped memory.
        
        Args:
            uc: Unicorn engine instance
            access: Access type (UC_MEM_READ_UNMAPPED or UC_MEM_WRITE_UNMAPPED)
            address: Memory address being accessed
            size: Access size in bytes
            value: Value being written (for writes)
            user_data: User data (unused)
            
        Returns:
            True to indicate the access was handled
        """
        # Debug print
        access_str = "WRITE" if access == UC_MEM_WRITE_UNMAPPED else "READ"
        print(f"[NVIC] {access_str} addr=0x{address:08x} size={size} value=0x{value:08x}")
        
        if access == UC_MEM_WRITE_UNMAPPED:
            self._handle_write(address, size, value)
            return True
        elif access == UC_MEM_READ_UNMAPPED:
            # For reads, we need to handle the read and return the value
            read_value = self._handle_read(address, size)
            if read_value is not None:
                print(f"[NVIC] Returning read value: 0x{read_value:08x}")
                # For unmapped memory hooks, we need to set the value in a different way
                # We'll use a temporary mapping to set the value
                try:
                    # Map temporarily, write value, then unmap
                    uc.mem_map(address, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
                    if size == 1:
                        uc.mem_write(address, bytes([read_value & 0xFF]))
                    elif size == 2:
                        uc.mem_write(address, struct.pack("<H", read_value & 0xFFFF))
                    elif size == 4:
                        uc.mem_write(address, struct.pack("<I", read_value & 0xFFFFFFFF))
                except UcError as e:
                    print(f"[NVIC] Error handling read: {e}")
                return True
            return False
            
    def _handle_write(self, address: int, size: int, value: int):
        """Handle NVIC register writes."""
        print(f"[NVIC] Handling write to 0x{address:08x}, value=0x{value:08x}")
        
        if NVIC_ISER_BASE <= address < NVIC_ISER_BASE + 0x80:
            # Interrupt Set-Enable Registers
            reg_offset = (address - NVIC_ISER_BASE) // 4
            print(f"[NVIC] ISER write: reg_offset={reg_offset}")
            self._set_enable_bits(reg_offset * 32, value, True)
            
        elif NVIC_ICER_BASE <= address < NVIC_ICER_BASE + 0x80:
            # Interrupt Clear-Enable Registers  
            reg_offset = (address - NVIC_ICER_BASE) // 4
            print(f"[NVIC] ICER write: reg_offset={reg_offset}")
            self._set_enable_bits(reg_offset * 32, value, False)
            
        elif NVIC_ISPR_BASE <= address < NVIC_ISPR_BASE + 0x80:
            # Interrupt Set-Pending Registers
            reg_offset = (address - NVIC_ISPR_BASE) // 4
            print(f"[NVIC] ISPR write: reg_offset={reg_offset}")
            self._set_pending_bits(reg_offset * 32, value, True)
            
        elif NVIC_ICPR_BASE <= address < NVIC_ICPR_BASE + 0x80:
            # Interrupt Clear-Pending Registers
            reg_offset = (address - NVIC_ICPR_BASE) // 4
            print(f"[NVIC] ICPR write: reg_offset={reg_offset}")
            self._set_pending_bits(reg_offset * 32, value, False)
            
        elif NVIC_IPR_BASE <= address < NVIC_IPR_BASE + 0xF0:
            # Interrupt Priority Registers (4 priorities per 32-bit register)
            reg_offset = address - NVIC_IPR_BASE
            print(f"[NVIC] IPR write: reg_offset={reg_offset}, size={size}")
            if size == 1:
                # Byte access
                irq_num = reg_offset
                if irq_num < self.max_irqs:
                    self.priority[irq_num] = value & 0xFF
                    print(f"[NVIC] Set IRQ{irq_num} priority to {value & 0xFF}")
            elif size == 4:
                # Word access
                base_irq = reg_offset
                for i in range(4):
                    if base_irq + i < self.max_irqs:
                        self.priority[base_irq + i] = (value >> (i * 8)) & 0xFF
                        
        elif address == SCB_VTOR:
            # Vector Table Offset Register
            self.vtor = value & 0xFFFFFF80  # Must be 128-byte aligned
            print(f"[NVIC] Set VTOR to 0x{self.vtor:08x}")
            
    def _handle_read(self, address: int, size: int) -> int:
        """Handle NVIC register reads."""
        if NVIC_ISER_BASE <= address < NVIC_ISER_BASE + 0x80:
            # Interrupt Set-Enable Registers
            reg_offset = (address - NVIC_ISER_BASE) // 4
            return self._get_enable_bits(reg_offset * 32)
            
        elif NVIC_ICER_BASE <= address < NVIC_ICER_BASE + 0x80:
            # Interrupt Clear-Enable Registers (same as ISER)
            reg_offset = (address - NVIC_ICER_BASE) // 4
            return self._get_enable_bits(reg_offset * 32)
            
        elif NVIC_ISPR_BASE <= address < NVIC_ISPR_BASE + 0x80:
            # Interrupt Set-Pending Registers
            reg_offset = (address - NVIC_ISPR_BASE) // 4
            return self._get_pending_bits(reg_offset * 32)
            
        elif NVIC_ICPR_BASE <= address < NVIC_ICPR_BASE + 0x80:
            # Interrupt Clear-Pending Registers (same as ISPR)
            reg_offset = (address - NVIC_ICPR_BASE) // 4
            return self._get_pending_bits(reg_offset * 32)
            
        elif NVIC_IABR_BASE <= address < NVIC_IABR_BASE + 0x80:
            # Interrupt Active Bit Registers (read-only)
            reg_offset = (address - NVIC_IABR_BASE) // 4
            return self._get_active_bits(reg_offset * 32)
            
        elif NVIC_IPR_BASE <= address < NVIC_IPR_BASE + 0xF0:
            # Interrupt Priority Registers
            reg_offset = address - NVIC_IPR_BASE
            if size == 1:
                # Byte access
                irq_num = reg_offset
                if irq_num < self.max_irqs:
                    return self.priority[irq_num]
            elif size == 4:
                # Word access
                base_irq = reg_offset
                value = 0
                for i in range(4):
                    if base_irq + i < self.max_irqs:
                        value |= (self.priority[base_irq + i] << (i * 8))
                return value
                
        elif address == SCB_VTOR:
            # Vector Table Offset Register
            return self.vtor
            
        return 0  # Default return value
        
    def _set_enable_bits(self, base_irq: int, value: int, enable: bool):
        """Set or clear interrupt enable bits."""
        for i in range(32):
            if value & (1 << i):
                irq_num = base_irq + i
                if irq_num < self.max_irqs:
                    self.enabled[irq_num] = enable
                    
    def _set_pending_bits(self, base_irq: int, value: int, pending: bool):
        """Set or clear interrupt pending bits."""
        for i in range(32):
            if value & (1 << i):
                irq_num = base_irq + i
                if irq_num < self.max_irqs:
                    self.pending[irq_num] = pending
                    
    def _get_enable_bits(self, base_irq: int) -> int:
        """Get interrupt enable bits as a 32-bit value."""
        value = 0
        for i in range(32):
            irq_num = base_irq + i
            if irq_num < self.max_irqs and self.enabled[irq_num]:
                value |= (1 << i)
        return value
        
    def _get_pending_bits(self, base_irq: int) -> int:
        """Get interrupt pending bits as a 32-bit value."""
        value = 0
        for i in range(32):
            irq_num = base_irq + i
            if irq_num < self.max_irqs and self.pending[irq_num]:
                value |= (1 << i)
        return value
        
    def _get_active_bits(self, base_irq: int) -> int:
        """Get interrupt active bits as a 32-bit value."""
        value = 0
        for i in range(32):
            irq_num = base_irq + i
            if irq_num < self.max_irqs and self.active[irq_num]:
                value |= (1 << i)
        return value
        
    def trigger_irq(self, irq_num: int):
        """
        Trigger an interrupt by setting its pending bit.
        
        Args:
            irq_num: External interrupt number (0-239)
        """
        if 0 <= irq_num < self.max_irqs:
            self.pending[irq_num] = True
            
    def clear_irq(self, irq_num: int):
        """
        Clear a pending interrupt.
        
        Args:
            irq_num: External interrupt number (0-239)
        """
        if 0 <= irq_num < self.max_irqs:
            self.pending[irq_num] = False
            
    def set_priority(self, irq_num: int, priority: int):
        """
        Set interrupt priority.
        
        Args:
            irq_num: External interrupt number (0-239)  
            priority: Priority value (0-255, lower values = higher priority)
        """
        if 0 <= irq_num < self.max_irqs:
            self.priority[irq_num] = priority & 0xFF
            
    def check_and_inject_irq(self) -> bool:
        """
        Check for pending enabled interrupts and inject the highest priority one.
        
        Returns:
            True if an interrupt was injected, False otherwise
        """
        # Find highest priority pending enabled interrupt
        highest_priority = 256  # Lower values = higher priority
        best_irq = -1
        
        for irq_num in range(self.max_irqs):
            if self.pending[irq_num] and self.enabled[irq_num]:
                if self.priority[irq_num] < highest_priority:
                    highest_priority = self.priority[irq_num]
                    best_irq = irq_num
                    
        if best_irq >= 0:
            self._inject_exception(best_irq)
            return True
            
        return False
        
    def _inject_exception(self, irq_num: int):
        """
        Inject an interrupt exception by simulating Cortex-M exception entry.
        
        Args:
            irq_num: External interrupt number to inject
        """
        try:
            # Get current CPU state
            sp = self.uc.reg_read(UC_ARM_REG_SP)
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            lr = self.uc.reg_read(UC_ARM_REG_LR)
            
            # Read general purpose registers
            r0 = self.uc.reg_read(UC_ARM_REG_R0)
            r1 = self.uc.reg_read(UC_ARM_REG_R1)
            r2 = self.uc.reg_read(UC_ARM_REG_R2)
            r3 = self.uc.reg_read(UC_ARM_REG_R3)
            r12 = self.uc.reg_read(UC_ARM_REG_R12)
            
            # Read xPSR (combine APSR, IPSR, EPSR)
            apsr = self.uc.reg_read(UC_ARM_REG_APSR)
            ipsr = self.uc.reg_read(UC_ARM_REG_IPSR)
            epsr = self.uc.reg_read(UC_ARM_REG_EPSR)
            xpsr = (apsr & 0xF0000000) | (ipsr & 0x1FF) | (epsr & 0x0700FC00)
            xpsr |= 0x01000000  # Set Thumb bit
            
            # Create exception stack frame (8 words = 32 bytes)
            # Stack frame: R0, R1, R2, R3, R12, LR, PC, xPSR
            frame = struct.pack("<8I", r0, r1, r2, r3, r12, lr, pc, xpsr)
            
            # Push frame onto stack
            sp -= 32
            self.uc.mem_write(sp, frame)
            self.uc.reg_write(UC_ARM_REG_SP, sp)
            
            # Set exception number in IPSR (IRQ number + 16 for external interrupts)
            exception_number = irq_num + 16
            self.uc.reg_write(UC_ARM_REG_IPSR, exception_number)
            
            # Read vector from vector table
            vector_address = self.vtor + (exception_number * 4)
            vector_data = self.uc.mem_read(vector_address, 4)
            vector = struct.unpack("<I", vector_data)[0]
            
            # Set PC to ISR address (clear LSB for Thumb mode)
            isr_address = vector & 0xFFFFFFFE
            self.uc.reg_write(UC_ARM_REG_PC, isr_address)
            
            # Set LR to EXC_RETURN value
            # 0xFFFFFFFD = Return to Thread mode, use PSP after return
            # 0xFFFFFFF9 = Return to Thread mode, use MSP after return  
            # 0xFFFFFFF1 = Return to Handler mode, use MSP after return
            exc_return = 0xFFFFFFF9  # Return to Thread mode with MSP
            self.uc.reg_write(UC_ARM_REG_LR, exc_return)
            
            # Mark interrupt as active and clear pending
            self.active[irq_num] = True
            self.pending[irq_num] = False
            
            # Call user interrupt handler if registered
            if irq_num in self.interrupt_handlers:
                self.interrupt_handlers[irq_num](irq_num)
                
        except Exception as e:
            print(f"Error injecting IRQ {irq_num}: {e}")
            
    def add_interrupt_handler(self, irq_num: int, handler: Callable[[int], None]):
        """
        Add a callback function for when an interrupt is injected.
        
        Args:
            irq_num: External interrupt number
            handler: Callback function that takes the IRQ number as parameter
        """
        self.interrupt_handlers[irq_num] = handler
        
    def remove_interrupt_handler(self, irq_num: int):
        """
        Remove interrupt handler callback.
        
        Args:
            irq_num: External interrupt number
        """
        if irq_num in self.interrupt_handlers:
            del self.interrupt_handlers[irq_num]
            
    def cleanup(self):
        """Clean up resources when done."""
        if self.mem_hook:
            self.uc.hook_del(self.mem_hook)
            self.mem_hook = None


def create_cortex_m_with_nvic(cpu_model: str = "cortex-m3", max_irqs: int = 240) -> tuple[Uc, NVIC]:
    """
    Create a Cortex-M Unicorn instance with fake NVIC support.
    
    Args:
        cpu_model: CPU model string (e.g., "cortex-m3", "cortex-m4") 
        max_irqs: Maximum number of external interrupts
        
    Returns:
        Tuple of (Unicorn engine instance, NVIC instance)
    """
    # Create Unicorn instance for ARM Cortex-M
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    
    # Create and attach NVIC
    nvic = NVIC(uc, max_irqs)
    
    return uc, nvic