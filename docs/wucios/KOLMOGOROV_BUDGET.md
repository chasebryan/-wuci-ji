# Kolmogorov Budget

Kolmogorov Budget tracks attack surface, size, package count, dependency weight, complexity, and reducibility.

## Categories

- GUI packages
- Browser packages
- Office suites
- Media players
- Default network services
- Listening ports
- Image size
- Package count
- SUID/SGID count
- Kernel module count

## Measured Values

Measured values must come from generated evidence. If no artifact or substrate trial output exists, the value is `NOT_MEASURED`.

## Target Values

Targets are allowed only when clearly labeled as targets. A target is not a measurement.

No WuciOS v2.4 document may claim a specific image size, including 300 MB, unless a generated artifact proves it. Until then, such values must be labeled `TARGET_NOT_MEASURED` or omitted.
