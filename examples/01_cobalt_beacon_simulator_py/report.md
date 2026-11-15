# 🛡️ Relatório Técnico Forense ANY.RUN + REA

## 1. Resumo Executivo & Veredito
- **Arquivo Analisado**: `cobalt_beacon_simulator.py`
- **Sistema Operacional Alvo**: `Linux / POSIX Scripting`
- **Família do Artefato**: `Executable Script`
- **Veredito Final**: **MALICIOUS** (Threat Score: **70/100**)
- **SHA-256**: `6af86b7c66707dd82d489994b231a7f0328d57d234f75506574d8768c706bbd8`

## 2. Análise Estática via REA (Reverse Engineer Anything)
- **Entropia de Shannon**: `5.4185` bits/byte
- **Ferramentas REA Executadas**: ``
- **Capacidades Detectadas**: `/etc/passwd`

## 3. Comportamento na Detonação Dinâmica & Sessão Gravada
- **Gravação de Vídeo**: `session_recording.mp4` (1204912 bytes)
- **Razões de Pontuação**:
  - Referências diretas a arquivos críticos de credenciais ou persistência SSH.
  - Indicadores de rede embutidos: 1 URLs e 1 endereços IP.
  - Chaves de Registro do Windows associadas a persistência ou configuração de sistema.

## 4. Recomendações Zero Trust
- Bloquear preventivamente o hash SHA-256 `6af86b7c66707dd82d489994b231a7f0328d57d234f75506574d8768c706bbd8` no ThreatLocker Zero Trust Control Plane caso não seja um binário homologado.