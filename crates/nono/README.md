# nono

Capability-based sandboxing library using Landlock (Linux) and Seatbelt (macOS).

## Overview

nono provides OS-enforced process level sandboxing. It allows you to restrict filesystem access, network access, and process execution for your application and its child processes.

## Installation

```toml
[dependencies]
nono = "0.1"
```

## Usage

```rust
use nono::{CapabilitySet, Sandbox};

// Build a capability set
let mut caps = CapabilitySet::new();
caps.allow_read("/path/to/read")?;
caps.allow_write("/path/to/write")?;
caps.allow_execute("/usr/bin/ls")?;

// Apply the sandbox (irreversible)
Sandbox::apply_auto(&caps)?;

// All subsequent operations are restricted to granted capabilities
```

## Features

- **Landlock** (Linux 5.13+) - Filesystem access control
- **Seatbelt** (macOS) - Filesystem and network restrictions
- **Child process inheritance** - All spawned processes inherit restrictions and individual policy may be applied to child processes (tool sandboxing)

## Platform Support

| Platform | Mechanism | Minimum Version |
|----------|-----------|-----------------|
| Linux | Landlock | Kernel 5.13+ |
| macOS | Seatbelt | 10.5+ |

## Documentation

- [API Documentation](https://docs.rs/nono)
- [Project Documentation](https://docs.nono.sh)

## License

Apache-2.0
