# 🔍 App Stack Finder (`app-stack-finder`)

**App Stack Finder** é uma ferramenta CLI robusta, extensível e modular desenvolvida em Python para análise profunda e fingerprinting de tecnologias, frameworks, infraestrutura, bancos de dados, servidores web e versões.

Projetada para funcionar de forma ágil em máquinas locais ou em pipelines automatizadas de **CI/CD** (GitHub Actions, GitLab CI, Jenkins, Azure DevOps).

---

## 🚀 Funcionalidades Principais

1. **Multi-Fontes de Entrada:**
   - 🌐 **URL Web:** Varre requisições HTTP/S, analisa cabeçalhos (`Server`, `X-Powered-By`), WAFs (`Cloudflare`, `AWS WAF`, `Sucuri`), CDNs (`CloudFront`, `Fastly`, `Akamai`), cookies de sessão e assinaturas no DOM/scripts.
   - 💻 **Diretório Local:** Varredura em profundidade via streams/generators ignorando pastas pesadas (`node_modules`, `.git`, `venv`, `target`, etc.).
   - 📦 **Repositório Git Remoto:** Clona via shallow clone (`--depth 1`) repositórios públicos ou privados (HTTPS com Personal Access Token ou SSH com chave privada) e limpa os arquivos temporários após o término.

2. **Detecção e Extração de Versões (Deep Inspection):**
   - **Manifestos Suportados:**
     - **Node.js / JS / TS:** `package.json`, `yarn.lock`, `pnpm-lock.yaml`, `package-lock.json`, `bun.lockb`
     - **Python:** `requirements.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`
     - **Java / Kotlin:** `pom.xml`, `build.gradle`, `build.gradle.kts`
     - **Go:** `go.mod`, `go.sum`
     - **Rust:** `Cargo.toml`, `Cargo.lock`
     - **PHP:** `composer.json`, `composer.lock`
     - **Ruby:** `Gemfile`, `Gemfile.lock`
     - **.NET / C#:** `.csproj`, `.fsproj`, `global.json`
   - **Infraestrutura como Código & Contêineres:**
     - Docker (`Dockerfile`, `Containerfile`, `docker-compose.yml`)
     - Kubernetes (manifestos `yaml` de `Deployment`, `Service`, `StatefulSet`, etc.)
     - Helm (`Chart.yaml`)
     - Terraform & OpenTofu (`*.tf`, `*.tfvars`, detecção de providers AWS, Azure, GCP, Cloudflare)
     - Ansible (`ansible.cfg`, `playbook.yml`, `roles/`)
     - AWS CloudFormation & SAM (`template.yaml`)
     - Serverless Framework (`serverless.yml`) e Pulumi (`Pulumi.yaml`)
     - Plataformas Cloud (`vercel.json`, `netlify.toml`, `fly.toml`, `Procfile`)
   - **CI / CD Pipelines:**
     - GitHub Actions (`.github/workflows/*.yml`)
     - GitLab CI (`.gitlab-ci.yml`)
     - Jenkins (`Jenkinsfile`)
     - CircleCI (`.circleci/config.yml`)
     - Bitbucket Pipelines (`bitbucket-pipelines.yml`)
     - Azure DevOps Pipelines (`azure-pipelines.yml`)

3. **Formatos de Saída e Relatórios:**
   - **Rich Terminal Table:** Interface gráfica visual e colorida no terminal.
   - **JSON Estruturado:** Ideal para ingestão e automação em CI/CD e auditoria de SCA/DevOps.
   - **Markdown:** Perfeito para documentação, PR comments e wikis.

---

## 📐 Arquitetura

O projeto adota os princípios de **Clean Architecture**, **SOLID** e extensibilidade **Open-Closed**:

```text
app_stack_finder/
├── data/                     # Armazenamento local de assinaturas
│   └── technologies.json     # Base de 7.500+ assinaturas (baixada sob demanda)
├── core/
│   ├── models.py             # Modelos de domínio (TechItem, ScanResult, TechCategory)
│   └── interfaces.py         # Contratos e interfaces abstratas (BaseDetector)
├── detectors/                # Módulos plugáveis de detecção
│   ├── base.py               # Utilitários de sanitização de versões e leitura segura
│   ├── manifest_detector.py  # Análise profunda de gerenciadores de dependência
│   ├── infra_detector.py     # Análise de Docker, K8s, Terraform, CI/CD
│   └── header_detector.py    # Fingerprinting HTTP, headers, cookies, WAF/CDN
├── services/
│   ├── git_service.py        # Gestão de clone e limpeza de repositórios remotos
│   ├── scanner_service.py    # Orquestrador central de varreduras
│   ├── rule_repository.py    # Repositório unificado de regras (Singleton & Lazy Loading)
│   └── updater_service.py    # Atualizador e download de assinaturas remotas
├── utils/
│   ├── file_walker.py        # Varredura eficiente por geradores/streams
│   └── reporter.py           # Formatadores de saída (Rich, JSON, Markdown)
└── main.py                   # Ponto de entrada CLI (Click + Rich)
```

---

## 🛠️ Instalação

### Instalação Local em Ambiente Virtual

```bash
# Clone ou acesse o repositório
cd app-stack-finder

# Crie e ative o ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# Instale as dependências e o pacote em modo editável
pip install -e .
```

### 📦 Empacotamento em Executável Standalone (Linux & Windows)

O sistema pode ser compilado em um **executável único e independente** (standalone single-file), funcionando em qualquer máquina **sem exigir a instalação do Python**:

#### No Linux (Binário ELF Standalone):
```bash
# Executa a compilação e testa o executável com --help automaticamente
./build.sh linux

# O binário gerado estará disponível em dist/app-stack-finder
./dist/app-stack-finder --help
./dist/app-stack-finder scan https://exemplo.com
```

#### No Windows (Executável .exe):
```cmd
REM No Windows (CMD ou PowerShell), execute o script batch
build.bat

REM O executável será gerado e validado em dist\app-stack-finder.exe
dist\app-stack-finder.exe --help
dist\app-stack-finder.exe scan C:\caminho\do\projeto
```

#### CI/CD Automático Multiplataforma:
O repositório já inclui o workflow `.github/workflows/build-binaries.yml`, que compila automaticamente os artefatos de **Linux** (`app-stack-finder-linux`) e **Windows** (`app-stack-finder-windows.exe`) no GitHub Actions.

---

## 💻 Guia de Uso da CLI

### 1. Comando Inteligente `scan` (Detecta automaticamente URL, Git ou Pasta)

```bash
# Escanear diretório local
app-stack-finder scan .

# Escanear uma URL Web remota
app-stack-finder scan https://example.com

# Escanear um repositório Git público
app-stack-finder scan https://github.com/fastapi/fastapi.git
```

### 2. Escaneamento Específico de Diretório (`dir`)

```bash
# Varredura simples
app-stack-finder dir /caminho/do/projeto

# Exportando relatório para JSON
app-stack-finder dir . -f json -o relatorio.json

# Exportando para Markdown
app-stack-finder dir . -f md -o relatorio.md

# Limitando a profundidade da busca e excluindo pastas extras
app-stack-finder dir . --max-depth 5 -e temp_folder -e legacy
```

### 3. Escaneamento de URL Web Remota (`url`)

```bash
# Analisa cabeçalhos, cookies, WAF e DOM
app-stack-finder url https://example.com

# Saída em JSON para pipelines
app-stack-finder url https://example.com -f json

# Ignorar certificados SSL inválidos em ambientes de teste
app-stack-finder url https://staging.interno.local -k
```

### 4. Escaneamento de Repositório Git Remoto (`git`)

```bash
# Repositório público via HTTPS
app-stack-finder git https://github.com/psf/requests.git

# Repositório privado com Personal Access Token (PAT)
app-stack-finder git https://github.com/sua-org/repo-privado.git -t ghp_seuToken12345

# Repositório privado via SSH
app-stack-finder git git@github.com:sua-org/repo-privado.git --ssh-key ~/.ssh/id_ed25519 -b main
```

### 5. Atualização de Assinaturas Remotas (`--update-rules`)

O `app-stack-finder` utiliza uma estratégia avançada de **Regras Híbridas (Hybrid Matching)**:
- **Regras Internas Predefinidas:** Nativas do projeto, focadas na detecção profunda de manifestos de código (Node.js, Python, Java, Go, Rust, PHP, Ruby, .NET), infraestrutura (Docker, Kubernetes, Helm, Terraform, Ansible, CI/CD) e frameworks/WAFs corporativos e governamentais (LumisXP, InfraPHP, eproc, JBoss Web, F5 BIG-IP/ASM).
- **Assinaturas Remotas Webanalyze:** Base com mais de **7.500 tecnologias** web (CMS, bibliotecas JavaScript, analítica, servidores web, CDNs, etc.) sincronizada do ecossistema Wappalyzer/Webanalyze.

Para baixar ou atualizar a base de assinaturas remotas:

```bash
# Atualizar a base de assinaturas diretamente
app-stack-finder --update-rules

# Ou através do comando explícito
app-stack-finder update-rules

# Ou atualizar automaticamente antes de executar uma análise
app-stack-finder scan https://example.com --update-rules
```

#### Características do Hybrid Matching & Lazy Loading:
1. **Lazy Loading & Baixo Consumo de Memória:** O carregamento do arquivo `technologies.json` só ocorre quando uma análise de URL/HTTP é efetivamente iniciada. Varreduras de arquivos locais ou repositórios Git não gastam CPU nem memória com o parse das 7.500 regras web.
2. **Pré-Compilação de Regex:** Todas as regras são pré-compiladas no momento do carregamento em estruturas indexadas por tipo de cabeçalho, cookie ou meta tag (`re.compile`), garantindo detecção em frações de segundo.
3. **Resolução de Versões Dinâmicas:** Trata o formato de versões do Wappalyzer (isolando modificadores como `\;version:\1` e ternários `\;version:\1?A:B`).
4. **Fallback Transparente:** Caso o arquivo `technologies.json` ainda não tenha sido baixado, a aplicação opera normalmente com as regras internas predefinidas sem quebrar.

---

## 🔄 Integração em CI / CD

### GitHub Actions

Exemplo de workflow para análise automática de tecnologias a cada push:

```yaml
name: Stack Fingerprint Audit

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  audit-stack:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Código
        uses: actions/checkout@v4

      - name: Configurar Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Instalar App Stack Finder
        run: pip install git+https://github.com/app-stack-finder/app-stack-finder.git

      - name: Executar Auditoria de Stack
        run: |
          app-stack-finder dir . -f json -o stack-report.json
          app-stack-finder dir . -f md -o stack-report.md

      - name: Upload Relatórios
        uses: actions/upload-artifact@v4
        with:
          name: stack-fingerprint-reports
          path: stack-report.*
```

### GitLab CI (`.gitlab-ci.yml`)

```yaml
stages:
  - audit

stack_fingerprint:
  stage: audit
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y git
    - pip install -e .
  script:
    - app-stack-finder dir . -f json -o stack-report.json
  artifacts:
    paths:
      - stack-report.json
    expire_in: 1 week
```

---

## 🧩 Adicionando um Novo Detector (Extensibilidade Open-Closed)

Basta herdar de `BaseDetector` e implementar o método correspondente:

```python
from pathlib import Path
from typing import Iterable, List
from app_stack_finder.core.interfaces import BaseDetector
from app_stack_finder.core.models import TechItem, TechCategory

class CustomDatabaseDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "CustomDatabaseDetector"

    def detect_filesystem(self, root_path: Path, files: Iterable[Path]) -> List[TechItem]:
        items = []
        for file in files:
            if file.name == "custom_db.conf":
                items.append(
                    TechItem(
                        name="CustomDB",
                        category=TechCategory.DATABASES,
                        version="2.0",
                        source=str(file.name),
                        confidence=1.0,
                    )
                )
        return items
```

Registre no `ScannerService`:

```python
scanner = ScannerService()
scanner.register_detector(CustomDatabaseDetector())
result = scanner.scan_directory(".")
```

---

## 🧪 Testes Automatizados

Para rodar toda a suíte de testes unitários e de integração:

```bash
pytest -v
```

---

## 📄 Licença

Distribuído sob a licença **MIT**. Consulte `pyproject.toml` para mais informações.
