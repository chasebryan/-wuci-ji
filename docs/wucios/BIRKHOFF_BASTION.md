# Birkhoff Bastion

Birkhoff Bastion is the optional operator shell profile. It may contain a minimal window manager candidate such as ratpoison. It must not contaminate Noether Core.

Ratpoison is a candidate only. It requires version and package hash pinning, dependency inventory, no default network service, and component-register acceptance before use.

DWM is a hold candidate. If WuciOS patches or vendors DWM, that C code becomes WuciOS-owned attack surface. DWM must pass a stricter patch audit and show a measurable advantage over ratpoison before acceptance.

Xfce is excluded from Birkhoff Bastion and from Noether Core. If retained at all, it belongs only in the non-authoritative Developer Desktop profile.

Birkhoff Bastion must not enable default network services. Noether Core must build without it.
