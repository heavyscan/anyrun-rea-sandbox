# **Relatório Técnico Forense: Análise de Script Shell Suspicioso (ANY.RUN + REA)**  
**Data:** 2025-04-05  
**Artefato Analisado:** `suspicious_installer_dropper.sh`  
**Plataforma:** ANY.RUN + REA (Reverse Engineer Anything)  
**Tipo de Análise:** Detecção de Malware, Comportamento Dinâmico, Mapeamento MITRE ATT&CK  

---

## 🔍 1. Resumo Executivo e Veredito

### **Veredito Final:**  
✅ **CLEAN / BENIGN**  

### **Explicação do Veredito:**  
Apesar da presença de **indicadores de rede embutidos** (URL e IP de C2), o artefato em análise — um script shell (`.sh`) — **não demonstra comportamento malicioso ativo** durante a execução na sandbox. O script é uma **aplicação de script de shell padrão do Linux**, com estrutura e comportamento típico de scripts de instalação ou configuração.

O **score de ameaça (threat score)** de **25/100** indica um risco **baixo a moderado**, classificado como **"low"**. Esse valor é atribuído principalmente ao fato de que:

- O script **não executa comandos perigosos** (não invoca `system()`, `execve()` com comandos maliciosos, não modifica arquivos de sistema).
- As **strings de saída** são apenas informativas, como "Target C2" e "Installer execution finished", sem tentativas de comunicação real ou execução de payloads.
- O **comportamento de syscalls** é compatível com a execução de um script bash padrão, com acesso a bibliotecas e arquivos de sistema legítimos, mas sem tentativas de escrita, leitura de arquivos sensíveis ou execução de comandos com privilégios elevados.

> ⚠ **Observação crítica:** O fato de o script **contém uma URL de C2 embutida** (embora não seja usada) **não significa que ele seja malicioso**. Muitos scripts legítimos (por exemplo, de automação de instalação) incluem URLs de documentação ou configuração de exemplo. A presença de URLs de C2 **não é, por si só, um sinal de malware**, especialmente se não houver comunicação ativa ou uso de APIs de rede.

---

## 🔬 2. Análise Estática Profunda (REA Engine)

### **Formato e Arquitetura**
- **Tipo de arquivo:** Script de shell (Bourne-Again Shell Script)
- **MIME Type:** `text/x-shellscript`
- **Target OS:** Linux / POSIX
- **Arquitetura de execução:** Script interpretado (bash), não compilado
- **Tamanho:** 428 bytes (aprox. 0.4 KB)

### **Entropia (Entropy)**
- **Valor:** 5.0329  
- **Interpretação:**  
  - Entropia entre **4.7 e 5.6** é considerada **normal para scripts de shell**.  
  - Entropia abaixo de 4.8 indica estrutura previsível (como scripts legítimos).  
  - Entropia acima de 5.6 indica compressão ou criptografia (não aplicável aqui).  
✅ **Conclusão:** O script é **estático, legítimo e não compactado ou criptografado**.

### **Strings Notáveis (Strings de Saída)**
```bash
echo " [*] Target C2: https://c2-telemetry.evil-simulation.example/gate.php"
echo " [+] Installer execution finished."
```
- Essas strings são **informativas**, não maliciosas.
- A URL é **embutida como exemplo** (provavelmente para simulação de C2), **n