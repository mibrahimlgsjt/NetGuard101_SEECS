"""
Guard Conditions for State Transitions
Guards ensure transitions only occur when preconditions are met.
"""

from typing import Dict, Any, Callable, Awaitable
from idps.fsm.states import SystemState


class GuardConditions:
    """
    Guard conditions that must be satisfied before transitions can occur.
    Guards enforce business logic constraints.
    """
    
    def __init__(self):
        self._guards: Dict[str, Callable[[Dict[str, Any]], Awaitable[bool]]] = {}
        self._register_default_guards()
    
    def _register_default_guards(self):
        """Register default guard conditions."""
        self.register_guard("check_network_available", self._check_network_available)
        self.register_guard("check_has_data_to_encrypt", self._check_has_data_to_encrypt)
        self.register_guard("check_authenticated", self._check_authenticated)
    
    def register_guard(
        self,
        name: str,
        guard_func: Callable[[Dict[str, Any]], Awaitable[bool]]
    ):
        """Register a new guard condition."""
        self._guards[name] = guard_func
    
    async def check_guard(
        self,
        guard_name: str,
        context: Dict[str, Any]
    ) -> bool:
        """
        Check if a guard condition is satisfied.
        
        Args:
            guard_name: Name of the guard to check
            context: Context dictionary with system state
            
        Returns:
            True if guard passes, False otherwise
        """
        if guard_name not in self._guards:
            # If guard not found, assume it passes (backward compatibility)
            return True
        
        try:
            return await self._guards[guard_name](context)
        except Exception as e:
            # Guard errors should fail the transition
            print(f"Guard '{guard_name}' raised exception: {e}")
            return False
    
    async def _check_network_available(self, context: Dict[str, Any]) -> bool:
        """Check if network is available."""
        network_status = context.get("network_available", False)
        return network_status
    
    async def _check_has_data_to_encrypt(self, context: Dict[str, Any]) -> bool:
        """Check if there is data to encrypt."""
        has_data = context.get("has_data_to_encrypt", False)
        return has_data
    
    async def _check_authenticated(self, context: Dict[str, Any]) -> bool:
        """Check if user is authenticated."""
        is_authenticated = context.get("is_authenticated", False)
        return is_authenticated


# Global guard conditions instance
guard_conditions = GuardConditions()

