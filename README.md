# Win32 Process Monitor

A Windows C++ project for exploring process enumeration and simple behavior-based security monitoring with the Win32 API.

The code is organized in phases: list existing processes, poll for newly observed process IDs, and experiment with rules for suspicious parent-child process relationships.

## Current implementation

- Enumerates Windows processes using `CreateToolhelp32Snapshot` and `Process32First/Process32Next`.
- Displays process details such as PID, parent PID, executable name, thread count, priority information, and executable path when accessible.
- Polls for new PIDs every two seconds.
- Includes a separate rule-engine experiment that checks for scripting or command-line processes associated with common PDF readers or browsers.

## Status and limitations

**This is a learning prototype, not a security product.**

The process-monitoring loop and rule engine are separate in the current source tree. The rule engine is **not wired into `main.cpp`**, and its `ProcessEvent` type still needs to be connected to the monitoring code. As a result, PDF-related alerts should not be considered an operational feature of this published version.

Process access may also be restricted by Windows permissions. The module and thread listing functions are placeholders, not complete inspectors. The source has not been packaged with a reproducible build configuration or automated tests.

## Source files

| File | Responsibility |
| --- | --- |
| `main.cpp` | Initial process snapshot and polling loop |
| `GetProcess.cpp` | Process information retrieval and output |
| `ProcessesMonitor.cpp` | Detection of newly observed process IDs |
| `RuleEngine.cpp` / `RuleEngine.h` | Experimental parent-child process rule logic |
| `headers.h` | Win32 includes and function declarations |

## Environment

- Windows
- A C++ toolchain with Windows SDK / Win32 headers

The `.exe` files in the repository are historical phase builds. Review or compile the source yourself rather than relying on included binaries.

## Next steps

- Define and populate process events with parent process names.
- Integrate the rule engine with the monitoring loop.
- Add a reproducible build configuration and small set of tests.
- Replace placeholder module/thread inspection functions.
