export WUCIOS_RELEASE="2.4.0"
export WUCIOS_CODENAME="Noether Forge"
export PYTHONPATH="/usr/local/lib/wucios"

case "${USER:-$(id -un 2>/dev/null)}" in
  wj) PS1='WJ>_ ' ;;
  wj_low) PS1='WJ-low>_ ' ;;
  root) PS1='WJ-root# ' ;;
esac

export PS1
