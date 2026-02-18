"""
Finite State Machine Module for IDPS
Formal logic engine ensuring the application never enters an undefined state.
"""

from idps.fsm.states import SystemState, StateRegistry, StateMetadata
from idps.fsm.transitions import TransitionRules, TransitionResult, Transition
from idps.fsm.events import Event, EventType, EventProcessor
from idps.fsm.guards import GuardConditions, guard_conditions
from idps.fsm.controller import FSMController, StateTransitionError

__all__ = [
    "SystemState",
    "StateRegistry",
    "StateMetadata",
    "TransitionRules",
    "TransitionResult",
    "Transition",
    "Event",
    "EventType",
    "EventProcessor",
    "GuardConditions",
    "guard_conditions",
    "FSMController",
    "StateTransitionError",
]

