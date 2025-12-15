# 🛡️ Guia Completo: Servidor OpenVPN no Windows

Este guia detalha a implementação de um servidor OpenVPN profissional em ambiente Windows Server.

## ✅ Recursos
- 🚀 **Driver Wintun:** Alta performance.
- 🔒 **Segurança:** AES-256-GCM.
- ⚡ **Split Tunneling:** Internet local fora do túnel.
- 🌐 **NAT/Roteamento (RRAS):** Acesso à LAN corporativa.
- 🤖 **Automação:** Script para gerar clientes.

---

## 📋 1. Pré-requisitos
- **Internet:** IP público fixo ou DDNS (ex: duckdns.org). Se usar DDNS, verifique liberação de portas com o ISP (CGNAT pode bloquear).
- **Servidor:** Windows Server 2016/2019/2022 (IP LAN Fixo, ex: `192.168.0.253`).
- **Cliente:** Windows 10/11.
- **Software:** [OpenVPN Community Edition 2.6.x](https://openvpn.net/community-downloads/).

---

## 🚀 2. Instalação e PKI

No **Servidor** (como Admin):

### 2.1 Instalação
- Desmarque: `OpenVPN GUI`, `TAP-Windows6`.
- Marque: `OpenVPN Service`, `Wintun Drivers`, `EasyRSA 3 Scripts`.

### 2.2 Gerar Chaves (CMD Admin)
### Abra o Prompt de Comando como Administrador e execute:
```cmd
cd "C:\Program Files\OpenVPN\easy-rsa"
EasyRSA-Start.bat
```
No shell EasyRSA:
```bash
easyrsa init-pki
```
```bash
easyrsa build-ca
```
```bash
easyrsa build-server-full server nopass
```
```bash
easyrsa gen-dh
```

---

## ⚙️ 3. Configuração do Servidor
Crie o arquivo: C:\Program Files\OpenVPN\config-auto\server.ovpn

### Importante: Abra os arquivos gerados em C:\Program Files\OpenVPN\easy-rsa\pki\ usando o Bloco de Notas para copiar o conteúdo das chaves (ca.crt, server.cert, server.key, dh.pem) para dentro das tags abaixo.

```bash
port 1194
proto udp
dev tun

# Rede da VPN (Cria uma rede virtual separada da sua LAN)
server 10.8.0.0 255.255.255.0

# Topologia recomendada
topology subnet

# Se você quiser limitar o acesso a apenas 10 usuários simultâneos.
max-clients 10

# CONFIGURAÇÃO CRÍTICA PARA SEU CENÁRIO
# 1. Empurra a rota da sua LAN para o cliente
push "route 192.168.0.0 255.255.255.0"

# 2. Configuração de DNS para resolver "nome-servidor" e AD
# Força o cliente a usar seu servidor AD como DNS para conexões VPN
push "dhcp-option DNS 192.168.0.253"
push "dhcp-option DOMAIN seudominio.local"

# Manter a conexão viva
keepalive 10 120

# Criptografia
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM

# Persistência
persist-key
persist-tun

# Log
# Onde salvar o histórico (Use log-append para não apagar ao reiniciar o serviço)
log-append "C:\\Program Files\\OpenVPN\\log\\server.log"

# Onde salvar o status atual (atualizado a cada 10 segundos)
status "C:\\Program Files\\OpenVPN\\log\\status.log" 10

# Nível de detalhe (3 é padrão, 4 para debug, 5+ gera muito lixo)
verb 3

windows-driver wintun

# Permite que clientes se vejam (opcional)
client-to-client

# --- Certificados ---
<ca>
-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----

-----END PRIVATE KEY-----
</key>
<dh>
-----BEGIN DH PARAMETERS-----

-----END DH PARAMETERS-----
</dh>
```

---

## 🛠️ 4. Roteamento e NAT (RRAS)
Necessário para acessar outros PCs da rede.

- Instalar: **Server Manager > Add Roles > Remote Access > Routing (Ele vai pedir para instalar DirectAccess e VPN, aceite)**.
- Configurar: **Routing and Remote Access > Botão direito no Server > Configure and Enable**.
- Escolha **Custom Configuration** > marque **NAT**.

**Ativar NAT:**
- Vá em **IPv4 > NAT**.
- Botão direito > **New Interface** > Selecione a placa de rede física (Ethernet).
- Marque: **Public interface connected to the Internet** e **Enable NAT**.
- Nota: Isso fará com que todo tráfego vindo da VPN (10.8.0.x) pareça vir do IP 192.168.x.x ao acessar a rede local, garantindo que a resposta volte corretamente.

---

## 🛡️ 5. Liberar Portas
- Firewall do Windows: **Entrada (Inbound) > Porta 1194 UDP > Permitir**.
### Abra o PowerShell como Administrador e execute:
```PowerShell
New-NetFirewallRule -DisplayName "OpenVPN Server" -Direction Inbound -LocalPort 1194 -Protocol UDP -Action Allow
```
- Roteador: **Port Forwarding 1194 UDP para o IP do Servidor (IP_LAN_SERVIDOR)**.

---

## 🤖 6. Automação de Clientes

### 6.1 Script Gerador (PowerShell) — **Substituído pelo novo script inline**
Salve em: `C:\Program Files\OpenVPN\easy-rsa\gerar_cliente_inline.ps1`

```powershell
<#$
.SYNOPSIS
    Gera um arquivo de configuração OpenVPN (.ovpn) com certificados embutidos (Inline).
.DESCRIPTION
    Este script lê os certificados gerados pelo EasyRSA e cria um arquivo .ovpn único
    configurado especificamente para o ambiente Windows Server 2016/2019/2022.
#>

# ==========================================
# 1. CONFIGURAÇÕES (Edite se necessário)
# ==========================================
$VPNClientName = Read-Host "Digite o nome do usuario (ex: usuario1)"
$PublicIP      = "Seu_IP_Publico_Aqui"
$Port          = "1194"
$Protocol      = "udp"

# Caminhos padrão do EasyRSA (conforme tutorial anterior)
$EasyRsaPath   = "C:\\Program Files\\OpenVPN\\easy-rsa\\pki"
$OutputDir     = "$env:USERPROFILE\\Desktop\\VPN_Configs"

# ==========================================
# 2. VERIFICAÇÃO DE ARQUIVOS
# ==========================================
$CaCertPath     = "$EasyRsaPath\\ca.crt"
$ClientCertPath = "$EasyRsaPath\\issued\\$VPNClientName.crt"
$ClientKeyPath  = "$EasyRsaPath\\private\\$VPNClientName.key"

Write-Host "Verificando arquivos para o usuário: $VPNClientName..." -ForegroundColor Cyan

if (-not (Test-Path $ClientCertPath)) {
    Write-Error "ERRO: O certificado para '$VPNClientName' não foi encontrado em: $ClientCertPath"
    Write-Warning "Você rodou o comando 'build-client-full $VPNClientName nopass'?"
    return
}
if (-not (Test-Path $ClientKeyPath)) {
    Write-Error "ERRO: A chave privada não foi encontrada em: $ClientKeyPath"
    return
}

# Cria diretório de saída se não existir
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null }

# ==========================================
# 3. LEITURA DOS CONTEÚDOS
# ==========================================
try {
    $CA   = Get-Content $CaCertPath -Raw
    $Cert = Get-Content $ClientCertPath -Raw
    $Key  = Get-Content $ClientKeyPath -Raw
}
catch {
    Write-Error "Falha ao ler os arquivos de certificado. Verifique as permissões."
    return
}

# Pega apenas o bloco do certificado (caso o easyrsa tenha colocado texto extra)
$CertPattern = "(?ms)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
if ($Cert -match $CertPattern) { $Cert = $Matches[0] }

$KeyPattern = "(?ms)-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----"
if ($Key -match $KeyPattern) { $Key = $Matches[0] }

# ==========================================
# 4. MONTAGEM DO ARQUIVO .OVPN
# ==========================================
$OvpnContent = @"
client
dev tun
proto $Protocol
remote $PublicIP $Port

# --- Configurações de Conexão ---
resolv-retry infinite
nobind
persist-key
persist-tun
explicit-exit-notify  # Avisa o servidor quando desconectar (limpa a sessão mais rápido)

# --- Configurações do Windows/Driver ---
windows-driver wintun
route-delay 5         # Espera 5s para criar rotas (Evita erros de "Network Unreachable")
ip-win32 netsh        # Método mais estável de aplicar IP no Wintun

# --- Segurança e Criptografia (Moderno) ---
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-GCM
auth-nocache

# 1. Adicione esta linha para NÃO mandar toda a internet pela VPN
# (Isso libera a velocidade da sua internet local)
pull-filter ignore "redirect-gateway"

# 3. Ajuste de pacotes (Evita que a conexão "engasgue" ou trave)
mssfix 1400
tun-mtu 1500

# --- Logs ---
verb 3

# Certificados Embutidos
<ca>
$CA
</ca>

<cert>
$Cert
</cert>

<key>
$Key
</key>
"@

# ==========================================
# 5. SALVAR ARQUIVO
# ==========================================
$OutputFile = "$OutputDir\\$VPNClientName.ovpn"
Set-Content -Path $OutputFile -Value $OvpnContent

Write-Host "------------------------------------------------" -ForegroundColor Green
Write-Host "SUCESSO! Arquivo gerado em:" -ForegroundColor Green
Write-Host "$OutputFile" -ForegroundColor Yellow
Write-Host "Envie este arquivo para o computador do cliente." -ForegroundColor Gray
Write-Host "------------------------------------------------"
```

> **Dica:** Você pode definir `$PublicIP` com o seu DDNS (ex.: `seu_subdominio.duckdns.org`) para não depender de IP fixo.

---

## 🏁 7. Uso
- Serviços > **OpenVPNService > Automático > Iniciar**.
- Gerar perfil do cliente (executar no servidor, pasta `easy-rsa`):
```powershell
powershell .\gerar_cliente_inline.ps1
```

---

## 🔧 8. Configuração de Acesso por Nome (Arquivo Hosts)
Como a VPN não propaga nomes NetBIOS automaticamente, para acessar o servidor pelo nome (ex: \\nome-servidor) em vez do IP (\\ip-servidor), siga estes passos no computador do cliente:

Clique no menu Iniciar e digite Bloco de Notas (Notepad).

Clique com o botão direito no ícone do Bloco de Notas e selecione "Executar como administrador" (Isso é obrigatório).

No Bloco de Notas, vá em Arquivo > Abrir.

Navegue até a pasta: C:\Windows\System32\drivers\etc.

No canto inferior direito da janela de abrir, mude de "Documentos de texto (.txt)" para **"Todos os arquivos (.*)"**.

Selecione o arquivo chamado hosts e clique em Abrir.

Vá até o final do arquivo (última linha) e adicione o IP do servidor e o nome desejado. Exemplo:

```bash
192.168.0.253    nome-servidor
```
Clique em Arquivo > Salvar.

Agora o cliente pode acessar digitando `\\nome-servidor` no Explorador de Arquivos.
