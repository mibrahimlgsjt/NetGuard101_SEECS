# FSM Architecture Documentation

## Overview

The Finite State Machine (FSM) module provides formal correctness guarantees for the IDPS application, ensuring the system **never enters an undefined state**. This is achieved through:

1. **Explicit State Definitions**: All possible states are enumerated
2. **Formal Transition Rules**: Only valid transitions are allowed
3. **Guard Conditions**: Business logic constraints are enforced
4. **Event-Driven Architecture**: State changes are triggered by events
5. **Async Concurrency**: Non-blocking I/O ensures UI responsiveness

## Module Structure

```
idps/fsm/
├── __init__.py          # Module exports
├── states.py            # State definitions and metadata
├── transitions.py       # Transition rules and validation
├── events.py            # Event system and handlers
├── guards.py            # Guard condition system
├── controller.py        # Async FSM controller
├── example_usage.py     # Usage examples
├── visualization.py     # Visualization tools
└── README.md            # Module documentation
```

## State Machine Diagram

```
                    ┌─────────────────┐
                    │ UNAUTHENTICATED │ (Initial State)
                    └────────┬────────┘
                             │ auth_requested
                             ▼
                    ┌─────────────────┐
                    │ AUTHENTICATING  │
                    └────┬────────────┘
                         │ auth_success
                         ▼
                    ┌─────────────────┐
                    │ AUTHORIZED_IDLE │
                    └───┬─────────┬───┘
                        │         │
        sync_requested  │         │ encrypt_requested
                        ▼         ▼
                ┌──────────┐  ┌──────────────┐
                │  SYNCING │  │ENCRYPTING_DATA│
                └────┬─────┘  └──────┬───────┘
                     │               │
                     │ sync_complete │ encrypt_complete
                     └───────┬───────┘
                             ▼
                    ┌─────────────────┐
                    │ AUTHORIZED_IDLE │
                    └─────────────────┘
```

## Core Components

### 1. States (`states.py`)

Defines all possible system states with metadata:

- **UNAUTHENTICATED**: Initial state
- **AUTHENTICATING**: Authentication in progress
- **SYNCING**: Synchronizing with server
- **AUTHORIZED_IDLE**: Authenticated and ready
- **ENCRYPTING_DATA**: Encrypting sensitive data
- **ERROR**: Error state
- **SHUTDOWN**: Terminal state

Each state includes metadata:
- `allows_user_input`: Can user interact?
- `requires_network`: Does this state need network?
- `requires_authentication`: Is auth required?
- `is_terminal`: Is this a final state?

### 2. Transitions (`transitions.py`)

Formal transition rules define valid state changes:

```python
VALID_TRANSITIONS = {
    (UNAUTHENTICATED, AUTHENTICATING, "auth_requested"),
    (AUTHENTICATING, AUTHORIZED_IDLE, "auth_success"),
    (AUTHORIZED_IDLE, SYNCING, "sync_requested"),
    # ... more transitions
}
```

**Key Features**:
- Transition validation
- Guard condition support
- Path finding between states
- Invalid transition rejection

### 3. Events (`events.py`)

Event-driven architecture for triggering transitions:

**Event Types**:
- User events: `USER_CLICK`, `USER_INPUT`, `LOGOUT`
- Auth events: `AUTH_REQUESTED`, `AUTH_SUCCESS`, `AUTH_FAILED`
- Network events: `SYNC_REQUESTED`, `SYNC_COMPLETE`, `SYNC_ERROR`
- Sensor events: `SENSOR_INPUT`, `INTRUSION_DETECTED`
- System events: `SHUTDOWN_REQUESTED`, `ERROR_RECOVERED`

**Event Handlers**:
- `UserEventHandler`: Processes user interactions
- `NetworkEventHandler`: Handles network events
- `AuthenticationEventHandler`: Manages auth flow
- `SensorEventHandler`: Processes sensor inputs

### 4. Guards (`guards.py`)

Guard conditions enforce business logic:

```python
# Example guards
check_network_available()  # Required for sync
check_has_data_to_encrypt()  # Required before encryption
check_authenticated()  # Required for auth operations
```

Guards are checked **before** transitions occur. If a guard fails, the transition is rejected.

### 5. Controller (`controller.py`)

Async FSM controller manages state transitions:

**Key Features**:
- Async event processing (non-blocking)
- Thread-safe state transitions (async locks)
- State history tracking
- Transition callbacks
- State handlers
- Context management

**Usage**:
```python
fsm = FSMController(initial_state=SystemState.UNAUTHENTICATED)
await fsm.start()

event = Event(EventType.AUTH_REQUESTED, source="ui")
await fsm.send_event(event)  # Non-blocking

await fsm.stop()
```

## Formal Correctness Guarantees

### 1. State Validation
- All states are explicitly defined
- Invalid states cannot be created
- State metadata is validated

### 2. Transition Validation
- Only valid transitions are allowed
- Invalid transitions are rejected with clear errors
- Transition rules are mathematically defined

### 3. Guard Enforcement
- Business logic constraints are enforced
- Guards are checked before transitions
- Failed guards prevent invalid state changes

### 4. Atomic Transitions
- State changes are atomic (protected by locks)
- No race conditions
- Consistent state at all times

### 5. History Tracking
- All transitions are logged
- Audit trail for debugging
- State history available for analysis

### 6. No Undefined States
- System cannot enter undefined state
- All states are explicitly handled
- Error states are defined and recoverable

## Concurrency Strategy

The FSM uses Python's `asyncio` for non-blocking I/O:

1. **Event Queue**: Events are queued and processed asynchronously
2. **Async Locks**: State transitions are protected by async locks
3. **Non-blocking Operations**: Long-running operations don't block the UI
4. **Concurrent Processing**: Multiple events can be processed concurrently

**Example**:
```python
# UI thread remains responsive
await fsm.send_event(auth_event)  # Returns immediately
# Event processed in background
```

## Integration Points

### UI Layer
```python
# UI sends events to FSM
button.on_click(lambda: fsm.send_event(Event(EventType.AUTH_REQUESTED)))
```

### Business Logic Layer
```python
# Business logic registers state handlers
fsm.register_state_handler(SystemState.SYNCING, sync_handler)
```

### Network Layer
```python
# Network layer sends events
network.on_sync_complete(lambda: fsm.send_event(Event(EventType.SYNC_COMPLETE)))
```

## Testing

Comprehensive test suite ensures correctness:

- State definition tests
- Transition validation tests
- Guard condition tests
- Event processing tests
- Concurrency tests
- Integration tests

Run tests:
```bash
pytest tests/test_fsm.py -v
```

## Visualization

Generate visual representations:

```python
from idps.fsm.visualization import save_visualization_files
save_visualization_files("docs/fsm")
```

This generates:
- `fsm_graph.dot`: Graphviz diagram
- `states_table.md`: State definitions table
- `transitions_table.md`: Transition rules table

## Academic-Grade Features

✅ **Formal State Definitions**: Explicit enumeration  
✅ **Transition Rules**: Mathematically defined  
✅ **Guard Conditions**: Precondition checking  
✅ **Event System**: Formal event-driven architecture  
✅ **Concurrency Safety**: Async/await with proper locking  
✅ **Audit Trail**: Complete transition history  
✅ **Visualization**: Graph and table representations  
✅ **Comprehensive Testing**: Unit and integration tests  
✅ **Documentation**: Complete API documentation  

## Future Enhancements

- State persistence (save/restore)
- Distributed FSM (multi-instance)
- Performance monitoring
- Advanced guard DSL
- State machine testing framework
- Visual state machine editor

