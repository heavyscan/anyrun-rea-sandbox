# Relatório Técnico Forense — `suspicious_installer_dropper.sh`

## 1. Resumo Executivo e Veredito
O artefato **`suspicious_installer_dropper.sh`** (família *Executable Script*, voltado para **Linux / POSIX Scripting**) foi submetido ao pipeline completo de engenharia reversa estática (**REA Engine v6.7.0**) e detonação comportamental dinâmica em ambiente isolado.

- **Veredito Final**: **CLEAN / BENIGN** (Threat Score: **25/100**)
- **Assinatura Mágica (`file`)**: `Bourne-Again shell script, ASCII text executable`
- **MIME Type**: `text/x-shellscript`
- **Tamanho Exato**: `428 bytes`
- **Hash SHA-256**: `f997c64334bd692cf5097fa34609d64b3186bcac325856b8d2cdd1d46211047b`

### Justificativa Técnica do Veredito
- Indicadores de rede embutidos: 1 URLs e 1 endereços IP (URLs: https://c2-telemetry.evil-simulation.example/gate.php | IPs: 10.240.0.10).
- **URLs Identificadas para Validação Manual (1)**: `https://c2-telemetry.evil-simulation.example/gate.php`
- **Endereços IP Identificados para Validação Manual (1)**: `10.240.0.10`
- **Chaves de Registro Identificadas (0)**: `Nenhuma chave de registro detectada`

## 2. Análise Estática Profunda (REA Engine)
- **Entropia de Shannon**: `5.0329 bits/byte` — Baixa a moderada (típica de scripts em texto claro, código-fonte ou binários nativos sem compressão/ofuscação).
- **Suspeita de Packer / Criptografia**: `NÃO (Estrutura aberta/padrão)`
- **Workflow REA Acionado**: `capture-process`
- **Ferramentas Executadas**: `rea:static-inspector`

### Capacidades de Sistema e Primitivas Identificadas
- Nenhuma primitiva de API maliciosa ou destrutiva isolada.

### Strings e Comandos Notáveis Extraídos
- `echo "[*] Dropper Installer v2.4 initializing..."`
- `echo "[*] Target C2: https://c2-telemetry.evil-simulation.example/gate.php"`
- `echo "[*] Checking privilege level: uid=1000(sandbox-operator) gid=1000(sandbox-operator)"`
- `echo "[*] Enumerating network interfaces: eth0 UP 10.240.0.10/24"`
- `echo "[*] Attempting simulated persistence check in ~/.config/autostart..."`
- `echo "[+] Installer execution finished."`
- `#!/usr/bin/env bash`
- `sleep 1`

## 3. Comportamento na Detonação Dinâmica e Sessão Visual
- **Vídeo da Detonação Gravado**: `session_recording.mp4` (`1,195,966 bytes (1.14 MB)`)
- **Captura de Tela (Keyframe)**: `session_keyframe.png`
- **Conexões de Rede Externas (C2) — `1 URLs` e `1 IPs externos`**:
  - **URLs**: `https://c2-telemetry.evil-simulation.example/gate.php`
  - **IPs**: `10.240.0.10`
- **Chaves de Registro Monitoradas (`0 chaves`)**: `Nenhuma chave de registro detectada`

## 4. Mapeamento Tático MITRE ATT&CK

| ID Técnica | Tática (Tactic) | Nome da Técnica |
|---|---|---|
| `T1071` | Command and Control | Application Layer Protocol |

## 5. Recomendações de Resposta a Incidentes e Governança Zero Trust
1. **Validação de Homologação (Application Allowlisting)**: Caso `suspicious_installer_dropper.sh` seja uma ferramenta ou script administrativo legítimo da equipe de TI/Suporte, cadastre uma política de permissão baseada exclusivamente no hash **SHA-256 (`f997c64334bd692cf5097fa34609d64b3186bcac325856b8d2cdd1d46211047b`)** no **ThreatLocker Zero Trust Control Plane** para impedir adulterações futuras.
2. **Monitoramento de Sub-Processos (EDR / Sysmon)**: Audite eventos de criação de processos filhos (Event ID 4688 / Sysmon Event ID 1) quando interpretadores (`powershell.exe`, `cmd.exe`, `/bin/bash`) forem invocados com parâmetros de elevação (`-Verb RunAs`) ou bypass (`-ExecutionPolicy Bypass`).
3. **Bloqueio Preventivo (Se Não Reconhecido)**: Caso o artefato não pertença ao catálogo oficial de automação da organização, aplique bloqueio imediato do hash SHA-256 e utilize a regra YARA anexa neste relatório para varredura retroativa nos endpoints.