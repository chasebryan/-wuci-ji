export type NavigationGuard = () => boolean;

let activeGuard: NavigationGuard | null = null;

export function setNavigationGuard(guard: NavigationGuard): () => void {
  activeGuard = guard;
  return () => {
    if (activeGuard === guard) {
      activeGuard = null;
    }
  };
}

export function clearNavigationGuard(): void {
  activeGuard = null;
}

export function confirmNavigationAway(): boolean {
  return activeGuard?.() ?? true;
}
