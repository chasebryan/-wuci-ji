#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/build/wucios/review"
mkdir -p "$OUT"

write_not_measured() {
  file="$1"
  reason="$2"
  {
    printf 'NOT_MEASURED\n'
    printf 'reason: %s\n' "$reason"
  } >"$OUT/$file"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

collect_packages() {
  if has_cmd xbps-query; then
    xbps-query -l >"$OUT/package-manifest.txt" 2>"$OUT/package-manifest.err" || write_not_measured package-manifest.txt "xbps-query failed"
  elif has_cmd apk; then
    apk info -vv >"$OUT/package-manifest.txt" 2>"$OUT/package-manifest.err" || write_not_measured package-manifest.txt "apk failed"
  elif has_cmd dpkg-query; then
    dpkg-query -W >"$OUT/package-manifest.txt" 2>"$OUT/package-manifest.err" || write_not_measured package-manifest.txt "dpkg-query failed"
  elif has_cmd rpm; then
    rpm -qa >"$OUT/package-manifest.txt" 2>"$OUT/package-manifest.err" || write_not_measured package-manifest.txt "rpm failed"
  elif has_cmd pacman; then
    pacman -Q >"$OUT/package-manifest.txt" 2>"$OUT/package-manifest.err" || write_not_measured package-manifest.txt "pacman failed"
  elif has_cmd nix-store; then
    nix-store -q --requisites /run/current-system >"$OUT/package-manifest.txt" 2>"$OUT/package-manifest.err" || write_not_measured package-manifest.txt "nix-store failed"
  elif has_cmd guix; then
    guix package --list-installed >"$OUT/package-manifest.txt" 2>"$OUT/package-manifest.err" || write_not_measured package-manifest.txt "guix failed"
  elif has_cmd pkg_info; then
    pkg_info >"$OUT/package-manifest.txt" 2>"$OUT/package-manifest.err" || write_not_measured package-manifest.txt "pkg_info failed"
  else
    write_not_measured package-manifest.txt "no supported package manager found"
  fi
  if [ -s "$OUT/package-manifest.txt" ] && ! grep -q '^NOT_MEASURED$' "$OUT/package-manifest.txt"; then
    wc -l <"$OUT/package-manifest.txt" | tr -d ' ' >"$OUT/package-count.txt"
  else
    write_not_measured package-count.txt "package manifest unavailable"
  fi
}

collect_services() {
  : >"$OUT/enabled-services.txt"
  measured=0
  if has_cmd systemctl; then
    systemctl list-unit-files --state=enabled --no-pager >>"$OUT/enabled-services.txt" 2>>"$OUT/enabled-services.err" || true
    measured=1
  fi
  if has_cmd rc-status; then
    rc-status -a >>"$OUT/enabled-services.txt" 2>>"$OUT/enabled-services.err" || true
    measured=1
  fi
  if has_cmd sv && [ -d /var/service ]; then
    sv status /var/service/* >>"$OUT/enabled-services.txt" 2>>"$OUT/enabled-services.err" || true
    measured=1
  fi
  if has_cmd service; then
    service --status-all >>"$OUT/enabled-services.txt" 2>>"$OUT/enabled-services.err" || true
    measured=1
  fi
  if [ "$measured" -eq 0 ]; then
    write_not_measured enabled-services.txt "no supported service manager found"
  fi
}

collect_ports() {
  if has_cmd ss; then
    ss -tulpn >"$OUT/listening-ports.txt" 2>"$OUT/listening-ports.err" || write_not_measured listening-ports.txt "ss failed"
  elif has_cmd netstat; then
    netstat -tulpn >"$OUT/listening-ports.txt" 2>"$OUT/listening-ports.err" || write_not_measured listening-ports.txt "netstat failed"
  else
    write_not_measured listening-ports.txt "ss and netstat unavailable"
  fi
}

collect_suid_sgid() {
  tmp="$OUT/suid-sgid.txt.tmp"
  if has_cmd find; then
    if has_cmd timeout; then
      if timeout 20 find / -xdev -perm /6000 -type f -print >"$tmp" 2>"$OUT/suid-sgid.err"; then
        mv "$tmp" "$OUT/suid-sgid.txt"
      else
        {
          printf 'PARTIAL\n'
          printf 'reason: find / timed out or was blocked; scanned common paths where possible\n'
          find /usr /bin /sbin /lib /lib64 /opt -xdev -perm /6000 -type f -print 2>/dev/null || true
        } >"$OUT/suid-sgid.txt"
        rm -f "$tmp"
      fi
    else
      {
        printf 'PARTIAL\n'
        printf 'reason: timeout unavailable; scanned common paths only\n'
        find /usr /bin /sbin /lib /lib64 /opt -xdev -perm /6000 -type f -print 2>/dev/null || true
      } >"$OUT/suid-sgid.txt"
    fi
  else
    write_not_measured suid-sgid.txt "find unavailable"
  fi
}

collect_modules() {
  if has_cmd lsmod; then
    lsmod >"$OUT/kernel-modules.txt" 2>"$OUT/kernel-modules.err" || write_not_measured kernel-modules.txt "lsmod failed"
  elif [ -r /proc/modules ]; then
    cp /proc/modules "$OUT/kernel-modules.txt"
  else
    write_not_measured kernel-modules.txt "lsmod and /proc/modules unavailable"
  fi
}

collect_os() {
  {
    printf 'uname: '
    uname -a 2>/dev/null || printf 'NOT_MEASURED\n'
    if [ -r /etc/os-release ]; then
      printf '\n/etc/os-release:\n'
      cat /etc/os-release
    else
      printf '\n/etc/os-release: NOT_MEASURED\n'
    fi
  } >"$OUT/os-release.txt"
}

write_surface_report() {
  package_count="NOT_MEASURED"
  if [ -s "$OUT/package-count.txt" ]; then
    package_count="$(head -n 1 "$OUT/package-count.txt")"
  fi
  {
    printf '{\n'
    printf '  "schema": "wucios.surface_report.v1",\n'
    printf '  "source": "host_or_current_environment",\n'
    printf '  "artifact": "NOT_MEASURED",\n'
    printf '  "package_count": "%s",\n' "$package_count"
    printf '  "package_manifest": "%s",\n' "$(test -s "$OUT/package-manifest.txt" && printf 'build/wucios/review/package-manifest.txt' || printf 'NOT_MEASURED')"
    printf '  "enabled_services": "%s",\n' "$(test -s "$OUT/enabled-services.txt" && printf 'build/wucios/review/enabled-services.txt' || printf 'NOT_MEASURED')"
    printf '  "listening_ports": "%s",\n' "$(test -s "$OUT/listening-ports.txt" && printf 'build/wucios/review/listening-ports.txt' || printf 'NOT_MEASURED')"
    printf '  "suid_sgid": "%s",\n' "$(test -s "$OUT/suid-sgid.txt" && printf 'build/wucios/review/suid-sgid.txt' || printf 'NOT_MEASURED')"
    printf '  "kernel_modules": "%s",\n' "$(test -s "$OUT/kernel-modules.txt" && printf 'build/wucios/review/kernel-modules.txt' || printf 'NOT_MEASURED')"
    printf '  "notes": [\n'
    printf '    "This inventory is a local collection surface, not a WuciOS release artifact measurement unless bound to a built image.",\n'
    printf '    "Missing values are written as NOT_MEASURED."\n'
    printf '  ]\n'
    printf '}\n'
  } >"$OUT/surface-report.json"

  {
    printf '# WuciOS Surface Report\n\n'
    printf 'Source: `host_or_current_environment`\n\n'
    printf 'Artifact: `NOT_MEASURED`\n\n'
    printf '| Metric | Value |\n'
    printf '| --- | --- |\n'
    printf '| Package count | `%s` |\n' "$package_count"
    printf '| Package manifest | `build/wucios/review/package-manifest.txt` |\n'
    printf '| Enabled services | `build/wucios/review/enabled-services.txt` |\n'
    printf '| Listening ports | `build/wucios/review/listening-ports.txt` |\n'
    printf '| SUID/SGID | `build/wucios/review/suid-sgid.txt` |\n'
    printf '| Kernel modules | `build/wucios/review/kernel-modules.txt` |\n'
    printf '\nThis inventory is not a release-authoritative WuciOS artifact measurement unless bound to a built image.\n'
  } >"$OUT/surface-report.md"
}

write_hash_manifest() {
  if has_cmd sha256sum; then
    (
      cd "$OUT"
      for file in package-manifest.txt enabled-services.txt listening-ports.txt suid-sgid.txt kernel-modules.txt surface-report.json surface-report.md os-release.txt; do
        if [ -f "$file" ]; then
          sha256sum "$file"
        fi
      done
    ) >"$OUT/hash-manifest.sha256"
  else
    write_not_measured hash-manifest.sha256 "sha256sum unavailable"
  fi
}

collect_packages
collect_services
collect_ports
collect_suid_sgid
collect_modules
collect_os
write_surface_report
write_hash_manifest

printf 'WuciOS surface inventory: generated %s\n' "$OUT"
