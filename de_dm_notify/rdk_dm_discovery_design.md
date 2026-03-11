# RDK DM Discovery Extension - Architecture & Design

This document describes the extensions added to the **RDK-USP Discovery Engine** to provide better visibility into the data model synchronization status and improve error robustness.

## 1. Overview
The RDK DM Discovery extension adds a set of control and monitoring parameters under `Device.X_RDK_DMDiscovery.`. It also introduces a "Real Response" error handling mechanism that ensures the USP schema is always consistent with the underlying RBUS state.

### Key Features
*   **Real-time Status Tracking**: Monitor the engine's state (Idle, Syncing, Committing).
*   **Provider Insights**: See exactly which RBUS components are registered and how many parameters they provide.
*   **Fast Deregistration**: Instant schema cleanup when an RBUS provider dies.
*   **Accurate Error Reporting**: Returning USP Error 7005 (Object Not Found) instead of generic internal errors for missing providers.

---

## 2. Architecture Diagram

The system interacts between **usp-pa-vendor-rdk** (the Agent), the **RBUS Bus**, and external **RBUS Providers**.

```mermaid
graph TD
    subgraph USP_Agent [USP PA Agent]
        V[Vendor.c]
        S[Data Model Schema]
        T[Discovery Thread]
        M[Global Status Store]
    end

    subgraph RBUS [RBUS Bus]
        B[RBUS Core]
    end

    subgraph Providers [RBUS Components]
        P1[MassStress Provider]
        P2[WiFi Provider]
    end

    V -- "rbus_getExt" --> B
    B -- "Query" --> Providers
    T -- "rbusElementInfo_get" --> B
    P1 -- "NotifyDML Event" --> B
    B -- "Callback" --> V
    V -- "Deregister/Register" --> S
    V -- "Update" --> M
```

---

## 3. Discovery Flow (TriggerSync)

When the user triggers a synchronization, the follow sequence occurs:

```mermaid
sequenceDiagram
    participant U as UspPA / Controller
    participant V as Vendor.c
    participant G as Status Store
    participant R as RBUS
    participant S as USP Schema

    U->>V: Set Device.X_RDK_DMDiscovery.TriggerSync = true
    V->>G: Set Status = "Syncing"
    V->>R: rbusElementInfo_get("Device.")
    R-->>V: Return all discovered elements
    V->>V: CountUniqueProviders()
    V->>G: Update ProviderCount & List & LastSyncTime
    loop For each new element
        V->>S: USP_REGISTER_GroupedVendorParam...
    end
    V->>G: Set Status = "Idle"
    V-->>U: Success
```

---

## 4. Error Handling: "Real Response" (GET)

This flow explains the fix for the reported "Error 7003" race condition when a provider is killed.

```mermaid
sequenceDiagram
    participant C as Controller
    participant V as Vendor.c (RDK_GetGroup)
    participant R as RBUS
    participant H as Task Handler
    participant S as USP Schema

    C->>V: GET Device.X_RDK_MassStress.Param_1
    V->>R: rbus_getExt()
    R-->>V: Error: RBUS_ERROR_DESTINATION_NOT_FOUND
    Note over V: Detects Provider is gone
    V->>H: dml_register_task_handler(Sync Call)
    H->>S: DATA_MODEL_DeRegisterPath()
    Note over S: Path removed instantly
    V-->>C: USP Error 7005 (Object Not Found)
    Note over C: "Real Response" - Controller knows it's gone.
```

---

## 5. Function Reference

### `CountUniqueProviders(rbusElementInfo_t* elems, ...)`
*   **Purpose**: Scans the list of RBUS elements and extracts unique component namespaces (e.g., `Device.X_RDK_MassStress`).
*   **Action**: Updates the human-readable string `DiscoveredProviders` with element counts for each namespace.

### `RDK_GetGroup(int group_id, kv_vector_t *params)`
*   **Purpose**: Fetches parameter values from RBUS.
*   **New Logic**: If `rbus_getExt` returns a "Destination Not Found" error, it immediately triggers a synchronous deregistration of those paths and returns USP Error **7005**.

### `RDK_SyncDiscovery()`
*   **Purpose**: Performs a full bus scan.
*   **New Logic**: Resets the Provider List to `(none)` if no providers are found, ensuring the UI/parameters remain consistent with the zero count.

### `dml_register_task_handler(void* arg1, void* arg2)`
*   **Purpose**: Handles the actual registration/deregistration in the USP schema.
*   **New Logic**: Now accepts an `is_async` flag. If called synchronously (from a GET failure), it avoids freeing memory that might be on the stack.

---

## 6. Datamodel Summary (New Parameters)

| Parameter | Type | Access | Description |
| :--- | :--- | :--- | :--- |
| `TriggerSync` | Boolean | R/W | Trigger a full RBUS scan. |
| `TriggerCommit` | Boolean | R/W | Manually save discovered DM to flash. |
| `Status` | String | RO | Current state: `Idle`, `Syncing`, `Committing`. |
| `LastSyncTime` | DateTime| RO | ISO-8601 time of last completed sync. |
| `ProviderCount` | Unsigned| RO | Number of unique provider namespaces. |
| `DiscoveredProviders`| String | RO | Comma-separated list with element counts. |
