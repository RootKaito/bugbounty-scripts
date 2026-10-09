#!/usr/bin/env bash
# Prepara uma VM Kali para rodar o toolkit: dependências via apt + go install.
# Idempotente — pode rodar de novo sem duplicar nada.
set -euo pipefail

echo ">>> Atualizando apt e instalando dependências de sistema"
sudo apt-get update -qq
sudo apt-get install -y -qq nmap golang-go python3 python3-pip python3-venv jq git

echo ">>> Instalando dependências Python"
pip3 install --user --break-system-packages -q -r requirements.txt 2>/dev/null \
  || pip3 install --user -q -r requirements.txt

GOBIN="$(go env GOPATH 2>/dev/null)/bin"
[ -z "${GOBIN}" ] && GOBIN="$HOME/go/bin"
mkdir -p "$GOBIN"

if ! grep -q "$GOBIN" <<< "$PATH"; then
  echo "export PATH=\"\$PATH:$GOBIN\"" >> "$HOME/.bashrc"
  export PATH="$PATH:$GOBIN"
  echo ">>> Adicionado $GOBIN ao PATH em ~/.bashrc (abra um novo terminal depois, ou rode: source ~/.bashrc)"
fi

install_go_tool() {
  local bin="$1" pkg="$2"
  if command -v "$bin" >/dev/null 2>&1; then
    echo ">>> $bin já instalado, pulando"
  else
    echo ">>> Instalando $bin"
    go install -v "$pkg"
  fi
}

install_go_tool subfinder   github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go_tool dnsx        github.com/projectdiscovery/dnsx/cmd/dnsx@latest
install_go_tool naabu       github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
install_go_tool katana      github.com/projectdiscovery/katana/cmd/katana@latest
install_go_tool nuclei      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install_go_tool assetfinder github.com/tomnomnom/assetfinder@latest
install_go_tool gau         github.com/lc/gau/v2/cmd/gau@latest
install_go_tool ffuf        github.com/ffuf/ffuf/v2@latest
install_go_tool notify      github.com/projectdiscovery/notify/cmd/notify@latest

# httpx (ProjectDiscovery) colide de nome com o cliente HTTP Python que o
# Kali já traz por padrão em /usr/bin ou ~/.local/bin — por isso instalamos
# e já renomeamos para "pdhttpx", que é o nome que recon.py procura.
if command -v pdhttpx >/dev/null 2>&1; then
  echo ">>> pdhttpx já instalado, pulando"
else
  echo ">>> Instalando httpx (ProjectDiscovery) como pdhttpx"
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  mv "$GOBIN/httpx" "$GOBIN/pdhttpx"
fi

echo ""
echo ">>> amass (opcional, usado só com --deep) não é instalado por padrão"
echo "    porque é lento. Se quiser: go install github.com/owasp-amass/amass/v4/cmd/amass@latest"
echo ""
echo ">>> SecLists (opcional, pro --fuzz/ffuf) não vem por padrão neste script."
echo "    No Kali costuma já estar em /usr/share/seclists (apt install seclists)"
echo ""
echo ">>> Setup concluído. Teste com:"
echo "    cp programs/_template.yaml programs/seu-programa.yaml   # edite o escopo antes"
echo "    python3 recon.py programs/seu-programa.yaml"
