#!/usr/bin/env python3
"""
Working NVIC Implementation for Unicorn ARM Cortex-M Emulation

This implementation provides interrupt support for ARM Cortex-M processors by:
1. Managing NVIC state in Python
2. Providing methods to trigger interrupts and check interrupt status
3. Implementing exception injection when interrupts are triggered
4. Using periodic polling or manual calls to check and inject interrupts

Since memory hooks in Unicorn have limitations for this use case, this implementation
uses a polling-based approach where the user calls check_and_inject_irq() periodically.

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

# System Control Block registers
SCB_BASE = 0xE000ED00
SCB_VTOR = 0xE000ED08  # Vector Table Offset Register


class WorkingNVIC:
    """
    Working NVIC implementation for ARM Cortex-M interrupt handling.
    
    This class provides NVIC emulation by managing interrupt state and providing
    methods to trigger and inject interrupts.
    """
    
    def __init__(self, uc: Uc, max_irqs: int = 240):
        """
        Initialize the NVIC.
        
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
        
        # Interrupt handlers
        self.interrupt_handlers: Dict[int, Callable] = {}
        
        # Map system control space
        try:
            uc.mem_map(0xE0000000, 0x100000, UC_PROT_READ | UC_PROT_WRITE)
        except UcError:
            pass  # Already mapped
            
    def enable_irq(self, irq_num: int):
        """Enable an interrupt."""
        if 0 <= irq_num < self.max_irqs:
            self.enabled[irq_num] = True
            
    def disable_irq(self, irq_num: int):
        """Disable an interrupt."""
        if 0 <= irq_num < self.max_irqs:
            self.enabled[irq_num] = False
            
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
            
    def read_nvic_register(self, address: int) -> int:
        """
        Read NVIC register value based on internal state.
        
        Args:
            address: Register address
            
        Returns:
            Register value
        """
        if NVIC_ISER_BASE <= address < NVIC_ISER_BASE + 0x80:
            # Interrupt Set-Enable Registers
            reg_offset = (address - NVIC_ISER_BASE) // 4
            return self._get_enable_bits(reg_offset * 32)
            
        elif NVIC_ISPR_BASE <= address < NVIC_ISPR_BASE + 0x80:
            # Interrupt Set-Pending Registers
            reg_offset = (address - NVIC_ISPR_BASE) // 4
            return self._get_pending_bits(reg_offset * 32)
            
        elif NVIC_IABR_BASE <= address < NVIC_IABR_BASE + 0x80:
            # Interrupt Active Bit Registers (read-only)
            reg_offset = (address - NVIC_IABR_BASE) // 4
            return self._get_active_bits(reg_offset * 32)
            
        elif NVIC_IPR_BASE <= address < NVIC_IPR_BASE + 0xF0:
            # Interrupt Priority Registers (byte access)
            irq_num = address - NVIC_IPR_BASE
            if irq_num < self.max_irqs:
                return self.priority[irq_num]
                
        elif address == SCB_VTOR:
            return self.vtor
            
        return 0
        
    def write_nvic_register(self, address: int, value: int, size: int = 4):
        """
        Write NVIC register and update internal state.
        
        Args:
            address: Register address
            value: Value to write
            size: Access size in bytes
        """
        if NVIC_ISER_BASE <= address < NVIC_ISER_BASE + 0x80:
            # Interrupt Set-Enable Registers
            reg_offset = (address - NVIC_ISER_BASE) // 4
            self._set_enable_bits(reg_offset * 32, value, True)
            
        elif NVIC_ICER_BASE <= address < NVIC_ICER_BASE + 0x80:
            # Interrupt Clear-Enable Registers  
            reg_offset = (address - NVIC_ICER_BASE) // 4
            self._set_enable_bits(reg_offset * 32, value, False)
            
        elif NVIC_ISPR_BASE <= address < NVIC_ISPR_BASE + 0x80:
            # Interrupt Set-Pending Registers
            reg_offset = (address - NVIC_ISPR_BASE) // 4
            self._set_pending_bits(reg_offset * 32, value, True)
            
        elif NVIC_ICPR_BASE <= address < NVIC_ICPR_BASE + 0x80:
            # Interrupt Clear-Pending Registers
            reg_offset = (address - NVIC_ICPR_BASE) // 4
            self._set_pending_bits(reg_offset * 32, value, False)
            
        elif NVIC_IPR_BASE <= address < NVIC_IPR_BASE + 0xF0:
            # Interrupt Priority Registers
            irq_num = address - NVIC_IPR_BASE
            if size == 1 and irq_num < self.max_irqs:
                self.priority[irq_num] = value & 0xFF
                
        elif address == SCB_VTOR:
            # Vector Table Offset Register
            self.vtor = value & 0xFFFFFF80  # Must be 128-byte aligned
            
        # Also write to actual memory for consistency
        try:
            if size == 1:
                self.uc.mem_write(address, bytes([value & 0xFF]))
            elif size == 2:
                self.uc.mem_write(address, struct.pack("<H", value & 0xFFFF))
            elif size == 4:
                self.uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))
        except UcError:
            pass  # Ignore if memory write fails
            
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
        
    def check_and_inject_irq(self) -> Optional[int]:
        """
        Check for pending enabled interrupts and inject the highest priority one.
        
        Returns:
            IRQ number that was injected, or None if no interrupt was injected
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
            try:
                self._inject_exception(best_irq)
                return best_irq
            except Exception as e:
                print(f"[NVIC] Error injecting IRQ {best_irq}: {e}")
                
        return None
        
    def _inject_exception(self, irq_num: int):
        """
        Inject an interrupt exception by simulating Cortex-M exception entry.
        
        Args:
            irq_num: External interrupt number to inject
        """
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
        try:
            apsr = self.uc.reg_read(UC_ARM_REG_APSR)
            ipsr = self.uc.reg_read(UC_ARM_REG_IPSR)  
            epsr = self.uc.reg_read(UC_ARM_REG_EPSR)
            xpsr = (apsr & 0xF0000000) | (ipsr & 0x1FF) | (epsr & 0x0700FC00)
        except:
            # Fallback if specific registers don't work
            xpsr = self.uc.reg_read(UC_ARM_REG_CPSR)
            
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
        try:
            self.uc.reg_write(UC_ARM_REG_IPSR, exception_number)
        except:
            pass  # IPSR might not be directly writable
            
        # Read vector from vector table
        vector_address = self.vtor + (exception_number * 4)
        vector_data = self.uc.mem_read(vector_address, 4)
        vector = struct.unpack("<I", vector_data)[0]
        
        # Set PC to ISR address (clear LSB for Thumb mode)
        isr_address = vector & 0xFFFFFFFE
        self.uc.reg_write(UC_ARM_REG_PC, isr_address)
        
        # Set LR to EXC_RETURN value
        # 0xFFFFFFF9 = Return to Thread mode, use MSP after return  
        exc_return = 0xFFFFFFF9
        self.uc.reg_write(UC_ARM_REG_LR, exc_return)
        
        # Mark interrupt as active and clear pending
        self.active[irq_num] = True
        self.pending[irq_num] = False
        
        # Call user interrupt handler if registered
        if irq_num in self.interrupt_handlers:
            try:
                self.interrupt_handlers[irq_num](irq_num)
            except Exception as e:
                print(f"[NVIC] Error in interrupt handler {irq_num}: {e}")
                
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
            
    def get_status_summary(self) -> Dict:
        """Get a summary of current interrupt status."""
        enabled_count = sum(1 for x in self.enabled if x)
        pending_count = sum(1 for x in self.pending if x)
        active_count = sum(1 for x in self.active if x)
        
        return {
            'enabled_count': enabled_count,
            'pending_count': pending_count,
            'active_count': active_count,
            'vtor': f"0x{self.vtor:08x}",
            'enabled_irqs': [i for i, x in enumerate(self.enabled) if x],
            'pending_irqs': [i for i, x in enumerate(self.pending) if x],
            'active_irqs': [i for i, x in enumerate(self.active) if x],
        }


def create_cortex_m_with_nvic(max_irqs: int = 240) -> tuple[Uc, WorkingNVIC]:
    """
    Create a Cortex-M Unicorn instance with working NVIC support.
    
    Args:
        max_irqs: Maximum number of external interrupts
        
    Returns:
        Tuple of (Unicorn engine instance, WorkingNVIC instance)
    """
    # Create Unicorn instance for ARM Cortex-M
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    
    # Create and attach NVIC
    nvic = WorkingNVIC(uc, max_irqs)
    
    return uc, nvic