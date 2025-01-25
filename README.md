# Win-Kernel-CR3Protect

A minimal CR3 protection **proof-of-concept (PoC)** for implementing CR3 protection in the Windows kernel by hooking the `KdpTrap` function.

---

## Implementation Overview

### 1. Hooking the KdpTrap

The driver overwrites a portion of the `KdpTrap` function to redirect execution to our custom handler.

### 2. Checking Process Name

Before handling the CR3 register, the PoC inspects the name of the current process (`cheatengine-x8`). If it matches a target process, the CR3 modification is rejected.

### 3. Handling CR3 Modifications

When a CR3 write instruction (`mov cr3, ...`) is encountered:

1. **Identify** the instruction using its opcode.
2. **Check** the source operand for the new CR3 value.
3. **Decide** whether to allow or override the new CR3 based on the process.
4. **Apply** the final CR3 value to the process.

---

## Limitations

- **Windows Version Compatibility**: Offsets for `KdpTrap` vary by OS build. Update the hooking offset to match your os version.
- **PG**: Might break on future versions of Windows.

---

## Further Reading
https://github.com/SamuelTulach/HookGuard

---

## Disclaimer

This code is provided **as-is** for educational and research purposes. Hooking kernel functions can cause system instability and may violate software license agreements. Use at your own risk.
