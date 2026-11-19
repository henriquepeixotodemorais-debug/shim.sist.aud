from __future__ import annotations
import os
import io
import re 
import openpyxl
import base64
import requests
import streamlit as st
import pandas as pd
from cryptography.fernet import Fernet, InvalidToken
import csv
import copy
import hashlib
import importlib.util
import io
import os
import re
import secrets
import shutil
import tempfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from zipfile import BadZipFile
from openpyxl import load_workbook
from openpyxl.utils.exceptions import InvalidFileException


# ---------------------------------------------------------
# CONFIGURAÇÃO DO TEMA
# ---------------------------------------------------------
st.set_page_config(layout="wide", initial_sidebar_state="expanded")
st.markdown("""
    <style>
        :root { color-scheme: light; }
    </style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# SECRETS E VARIÁVEIS DO GITHUB
# ---------------------------------------------------------
# Use st.secrets no Streamlit Cloud; fallback para variáveis de ambiente
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
GITHUB_USER = st.secrets.get("GITHUB_USER") or os.environ.get("GITHUB_USER")
GITHUB_REPO = st.secrets.get("GITHUB_REPO") or os.environ.get("GITHUB_REPO")
ENCRYPTION_KEY = st.secrets.get("ENCRYPTION_KEY") or os.environ.get("ENCRYPTION_KEY")
SENHA_AUTORIDADES = st.secrets.get("SENHA_AUTORIDADES") or os.environ.get("SENHA_AUTORIDADES")  
SENHA_BASE = st.secrets.get("SENHA_BASE") or os.environ.get("SENHA_BASE")  
SENHA_SECRETARIOS = st.secrets.get("SENHA_SECRETARIOS") or os.environ.get("SENHA_SECRETARIOS")  
# Nome do arquivo no repositório. Usar extensão .enc deixa claro que está cifrado.
GITHUB_FILE = "baseaud.csv.enc"

# Endpoints (API_URL usado para criar/atualizar; RAW_URL opcional para download direto)
API_URL = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/contents/{GITHUB_FILE}" if GITHUB_USER and GITHUB_REPO else None
RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/{GITHUB_FILE}" if GITHUB_USER and GITHUB_REPO else None

# ---------------------------------------------------------
# VALIDAÇÃO INICIAL E FERNET
# ---------------------------------------------------------
missing = []
if not GITHUB_USER:
    missing.append("GITHUB_USER")
if not GITHUB_REPO:
    missing.append("GITHUB_REPO")
if not ENCRYPTION_KEY:
    missing.append("ENCRYPTION_KEY")

if missing:
    st.error(
        "Faltam configurações: " + ", ".join(missing) + ".\n"
        "No Streamlit Cloud adicione ENCRYPTION_KEY, GITHUB_TOKEN, GITHUB_USER e GITHUB_REPO em Secrets."
    )
    st.stop()

# Inicializa Fernet (espera-se chave gerada por Fernet.generate_key().decode())
try:
    fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)
except Exception:
    st.error("Chave de criptografia inválida. Gere com Fernet.generate_key() e cole em ENCRYPTION_KEY (ex.: 'g6K8...==').")
    st.stop()

# ---------------------------------------------------------
# LIMPA CACHE AO DIGITAR QUALQUER SENHA
# ---------------------------------------------------------
password = st.text_input("Insira a chave de acesso", type="password")
if password:
    st.cache_data.clear()

# ---------------------------------------------------------
# COLUNAS ESPERADAS (caso o repositório comece vazio)
# ---------------------------------------------------------
EXPECTED_COLUMNS = [
    "data e horário",
    "sala de audiência",
    "número do processo relacionado",
    "parte a ser ouvida ou tipo de processo",
    "telefone da parte",
    "estado da intimação",
    "link do processo",
    "dimensão da audiência",
    "resumo dos fatos",
]

# ---------------------------------------------------------
# FUNÇÃO PARA CARREGAR CSV DO GITHUB (DESCRIPTOGRAFA NO CACHE)
# ---------------------------------------------------------
@st.cache_data(ttl=60)
def load_csv_from_github():
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

    r = requests.get(API_URL, headers=headers)
    if r.status_code == 404:
        return pd.DataFrame(columns=EXPECTED_COLUMNS)
    if r.status_code != 200:
        st.error(f"Erro ao acessar GitHub API: {r.status_code} {r.text}")
        st.stop()

    payload = r.json()
    content_b64 = payload.get("content", "")
    if not content_b64:
        st.error("Conteúdo vazio no GitHub.")
        st.stop()

    content_b64 = "".join(content_b64.splitlines())
    try:
        raw_bytes = base64.b64decode(content_b64)
    except Exception as e:
        st.error(f"Erro ao decodificar base64: {e}")
        st.stop()

    # tenta descriptografar
    try:
        plain_bytes = fernet.decrypt(raw_bytes)
        text = plain_bytes.decode("utf-8", errors="replace")
    except InvalidToken:
        # fallback: arquivo não cifrado
        text = raw_bytes.decode("utf-8", errors="replace")

    # remove BOM se existir
    if text.startswith("\ufeff"):
        text = text.replace("\ufeff", "", 1)

    # normaliza quebras de linha
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # tenta ler com vírgula
    try:
        df = pd.read_csv(io.StringIO(text), dtype=str, sep=",")
        if df.shape[1] == 1:
            raise ValueError("provavelmente não é vírgula")
    except Exception:
        # tenta ler com ponto e vírgula
        df = pd.read_csv(io.StringIO(text), dtype=str, sep=";")

    # garante colunas esperadas
    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    df = df[EXPECTED_COLUMNS]

    return df.fillna("")


# ---------------------------------------------------------
# FUNÇÃO DE UPLOAD (CIFRA E ENVIA AO GITHUB) COM RETRY E LOG
# ---------------------------------------------------------
def upload_csv_to_github(uploaded_file):
    """
    Cifra os bytes do uploaded_file com Fernet, codifica em base64 e envia ao GitHub.
    Faz checagens: repo acessível, obtém default_branch, busca sha atual (se existir),
    tenta PUT e loga a resposta completa para diagnóstico.
    """
    if not GITHUB_TOKEN:
        st.error("GITHUB_TOKEN não configurado. Não é possível enviar ao GitHub.")
        return

    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    # 1) Verifica se o repo é acessível e obtém branch padrão
    repo_meta = requests.get(f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}", headers=headers)
    if repo_meta.status_code != 200:
        st.error("Repositório inacessível com esse token/owner/repo. Verifique GITHUB_USER, GITHUB_REPO e permissões do token.")
        return

    default_branch = repo_meta.json().get("default_branch", "main")

    # 2) Prepara conteúdo cifrado
    content = uploaded_file.getvalue()  # bytes do CSV
    encrypted = fernet.encrypt(content)
    encoded = base64.b64encode(encrypted).decode()

    # 3) Monta payload usando branch padrão
    api_url = API_URL
    payload = {
        "message": "Atualização automática do CSV (cifrado) via Streamlit",
        "content": encoded,
        "branch": default_branch
    }

    # 4) Tenta obter sha atual (se existir) e inclui no payload para update
    r_get = requests.get(api_url, headers=headers)
    if r_get.status_code == 200:
        sha = r_get.json().get("sha")
        payload["sha"] = sha

    # 5) Envia o arquivo
    put_response = requests.put(api_url, json=payload, headers=headers)

    # 6) Se conflito 409, tenta buscar sha de novo e reenviar
    if put_response.status_code == 409:
        new_r = requests.get(api_url, headers=headers)
        if new_r.status_code == 200:
            payload["sha"] = new_r.json().get("sha")
            put_response = requests.put(api_url, json=payload, headers=headers)

    if put_response.status_code in [200, 201]:
        st.success("CSV cifrado enviado com sucesso ao GitHub! Recarregando...")
        st.cache_data.clear()
        st.rerun()
    else:
        st.error(f"Erro ao enviar arquivo: {put_response.status_code} {put_response.text}")

# ---------------------------------------------------------
# MODO sisbase — UPLOAD DO CSV (CIFRADO)
# ---------------------------------------------------------
if password == SENHA_BASE:
    st.header("🗂 Painel de Administração da Base")
    st.info("Envie um CSV; ele será cifrado localmente e armazenado cifrado no GitHub (arquivo: " + GITHUB_FILE + ").")
    uploaded = st.file_uploader("📤 Enviar novo CSV (será cifrado)", type=["csv"])
    if uploaded:
        upload_csv_to_github(uploaded)
    st.stop()

    # ---------------------------------------------------------
# CARREGAR CSV DO GITHUB (DESCRIPTOGRAFA NO CACHE)
# ---------------------------------------------------------
df = load_csv_from_github()

# ---------------------------------------------------------
# PREPARAÇÃO DOS DADOS (MANTIDA COMO SOLICITADO)
# ---------------------------------------------------------
# Se o DataFrame estiver vazio (projeto começando sem base), mostra instrução
if df.empty:
    st.warning("Nenhuma base encontrada. Entre com a chave 'sisbase' e faça o upload do CSV para iniciar.")
    st.stop()

# df = df.sort_values(["dia", "sala de audiência", "data e horário"])

# ordena globalmente por data/hora e sala
# df = df.sort_values(["sala de audiência"], ascending=True).reset_index(drop=True)
# df = df.sort_values(["dia", "sala de audiência", "data e horário"])
# df = df.sort_values([ "dia", "data e horário","sala de audiência"])

df["data e horário"] = pd.to_datetime(df["data e horário"], dayfirst=True, errors="coerce") 
# df["dia"] = df["data e horário"].dt.nomalize()
df["dia"] = df["data e horário"].dt.date
# df["dia"] = df["data e horário"].dt.strftime("%d/%m/%y")

df = df.sort_values(["sala de audiência", "data e horário"])


# ---------------------------------------------------------
# FILTRO DE SALAS
# ---------------------------------------------------------
todas_salas = sorted(df["sala de audiência"].unique())

salas_selecionadas = st.multiselect(
    "Filtrar salas:",
    options=todas_salas,
    default=todas_salas,
)

if len(salas_selecionadas) == 0:
    st.warning("Selecione ao menos uma sala.")
    st.stop()
# ---------------------------------------------------------
# FILTRO DE DIA
# ---------------------------------------------------------
todos_dias = sorted(df["dia"].unique())
# df["dia"] = df["data e horário"].dt.strftime("%d/%m/%y")
dias_selecionados = st.multiselect(
    "Filtrar dia:",
    options=todos_dias,
    default=todos_dias,
    format_func=lambda d: d.strftime("%d/%m/%y")

)

if len(dias_selecionados) == 0:
    st.warning("Selecione ao menos um dia.")
    st.stop()

# ---------------------------------------------------------
# FUNÇÃO PARA MONTAR O BOX DE CADA PROCESSO
# ---------------------------------------------------------
def render_process_box(process_df, show_sensitive=False):
    row0 = process_df.iloc[0]

    with st.container():
        dt = row0["data e horário"]
        dt_str = dt.strftime("%H:%M") if pd.notna(dt) else row0.get("data e horário", "")
        # dt_str = dt.strftime("%d/%m/%Y %H:%M") if pd.notna(dt) else row0.get("data e horário", "")
        st.markdown(f"#### ⏰ {dt_str}")
        st.markdown(f"**Processo:** {row0.get('número do processo relacionado','')}")
        st.markdown(f"**Tipo:** {row0.get('parte a ser ouvida ou tipo de processo','')}")
        link = row0.get("link do processo", "")
        if link:
            # st.link_button(f"[🔗 Link do processo]",link)
            st.markdown(f"[🔗 Link da audiência]({link})")
        st.markdown(f"**Dimensão:** {row0.get('dimensão da audiência','')}")

        with st.expander("Resumo dos fatos"):
            st.write(row0.get("resumo dos fatos", ""))

        if show_sensitive:
            st.markdown("#### Partes:")
            for _, r in process_df.iloc[1:].iterrows():
                parte = r.get("parte a ser ouvida ou tipo de processo", "")
                telefone = r.get("telefone da parte", "")
                intimacao = r.get("estado da intimação", "")
                st.markdown(
                    f"""
                    <div style="margin-bottom:10px;">
                        <div style="font-weight:700; font-size:16px;">• {parte}</div>
                        <div style="margin-left:20px; font-size:14px; color:#444;">
                            Telefone: {telefone}<br>
                            Intimação: {intimacao}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

# ---------------------------------------------------------
# RENDERIZAÇÃO POR DIA E SALA
# ---------------------------------------------------------
def render_day(df_dia, show_sensitive):
    salas = [s for s in sorted(df_dia["sala de audiência"].unique()) if s in salas_selecionadas]
    if not salas:
        return
    cols = st.columns(len(salas))
    for idx, sala in enumerate(salas):
        with cols[idx]:
            st.markdown(f"## 🏛 Sala {sala}")
            df_sala = df_dia[df_dia["sala de audiência"] == sala]
            # st.markdown(f"##{len(df_sala["número do processo relacionado"])}")
            st.metric(label="",value="",delta=f"processos: {len(df_sala["número do processo relacionado"])}",delta_color="off")
            # st.markdown(f"{df_sala.groupby('data e horário')['processos'].nunique()}")

            for processo, bloco in df_sala.groupby("data e horário"):
            # for processo, bloco in df_sala.groupby("número do processo relacionado"):
                render_process_box(bloco, show_sensitive)

# ---------------------------------------------------------
# SECRETÁRIOS
# ---------------------------------------------------------
if password == SENHA_SECRETARIOS:
    DEFAULT_PACK = Path(
    r"C:\Users\henri\mcpje\assets\packs\des_bolo_04_11_2026"
)
SPREADSHEET_EXTENSIONS = {".xlsx", ".xlsm"}
CSV_EXTENSIONS = {".csv"}
PROCESS_PATTERN = re.compile(r"\d{7}-\d{2}\.\d{4}\.\d{1,2}\.\d{4}")


class LocalPdfRequestHandler(BaseHTTPRequestHandler):
    server: LocalPdfHttpServer

    def do_GET(self) -> None:
        if not self.path.startswith("/pdf/"):
            self.send_error(404)
            return

        token = self.path.removeprefix("/pdf/")
        pdf_path = self.server.pdf_paths.get(token)
        if pdf_path is None:
            self.send_error(404)
            return

        try:
            pdf_file = pdf_path.open("rb")
        except OSError:
            self.send_error(404)
            return

        with pdf_file:
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header(
                "Content-Length",
                str(os.fstat(pdf_file.fileno()).st_size),
            )
            self.send_header("Content-Disposition", "inline")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            shutil.copyfileobj(pdf_file, self.wfile)


class LocalPdfHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        self.pdf_paths: dict[str, Path] = {}
        self.path_tokens: dict[Path, str] = {}
        super().__init__(("127.0.0.1", 0), LocalPdfRequestHandler)

    def register_pdf(self, path: Path) -> str:
        resolved_path = path.resolve()
        token = self.path_tokens.get(resolved_path)
        if token is None:
            token = secrets.token_urlsafe(32)
            self.path_tokens[resolved_path] = token
            self.pdf_paths[token] = resolved_path
        return token


@st.cache_resource
def local_pdf_server() -> LocalPdfHttpServer:
    server = LocalPdfHttpServer()
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def local_pdf_url(path: Path) -> str:
    server = local_pdf_server()
    token = server.register_pdf(path)
    return f"http://127.0.0.1:{server.server_port}/pdf/{token}"


st.set_page_config(
    page_title="Sala de Controle",
    page_icon="📚",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container { padding-top: 1.7rem; padding-bottom: 3rem; max-width: 1500px; }
    [data-testid="stSidebar"] { border-right: 1px solid rgba(128,128,128,.2); }
    [data-testid="stMetric"] {
        background: rgba(128,128,128,.08); padding: 14px 18px;
        border-radius: 12px; border: 1px solid rgba(128,128,128,.16);
    }
    div.stButton > button { border-radius: 9px; }
    </style>
    """,
    unsafe_allow_html=True,
)

_COPY_SPREADSHEET_COMPONENT = st.components.v2.component(
    "copy_spreadsheet_to_clipboard",
    html="""
    <button class="copy-button" type="button">
      Copiar planilha
    </button>
    """,
    css="""
    .copy-button {
      width: 100%;
      min-height: 2.5rem;
      padding: 0.4rem 0.75rem;
      border: 1px solid var(--st-widget-border-color);
      border-radius: var(--st-button-radius);
      background: var(--st-secondary-background-color);
      color: var(--st-text-color);
      font: inherit;
      cursor: pointer;
    }
    .copy-button:hover {
      border-color: var(--st-primary-color);
    }
    .copy-button:focus-visible {
      outline: 2px solid var(--st-primary-color);
      outline-offset: 2px;
    }
    """,
    js="""
    export default function (component) {
      const { data, parentElement, setTriggerValue } = component
      const button = parentElement.querySelector(".copy-button")
      if (!button) return

      button.onclick = async () => {
        try {
          if (!navigator.clipboard?.writeText) {
            throw new Error("O navegador não permite acesso ao clipboard neste endereço.")
          }
          await navigator.clipboard.writeText(data.text)
          setTriggerValue("copied", true)
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error)
          setTriggerValue("copy_error", message)
        }
      }
    }
    """,
)


def stable_key(*parts: str) -> str:
    value = "|".join(parts).encode("utf-8")
    return hashlib.sha1(value).hexdigest()[:14]


def set_process_selection(processes: list[str], index: int) -> None:
    st.session_state["process_index"] = index
    st.session_state["process_selector"] = processes[index]


def save_expandable_state(
    key: str,
    state_key: str,
) -> None:
    states = st.session_state.setdefault(state_key, {})
    states[key] = st.session_state[key]


def set_expandable_state(
    keys: list[str],
    expanded: bool,
    state_key: str,
    default_key: str,
) -> None:
    states = st.session_state.setdefault(state_key, {})
    for key in keys:
        states[key] = expanded
    st.session_state[default_key] = expanded


def normalize_process(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return re.sub(r"\s+", "", str(value)).casefold()


def find_process_column(headers: list[Any]) -> int | None:
    for index, header in enumerate(headers):
        if str(header or "").strip().casefold() in {"processo", "processos"}:
            return index
    return None


def read_text_file(path: Path) -> tuple[str, str]:
    content = path.read_bytes()
    encodings = (
        ("utf-8-sig", "utf-8", "cp1252", "latin-1")
        if content.startswith(b"\xef\xbb\xbf")
        else ("utf-8", "cp1252", "latin-1")
    )
    for encoding in encodings:
        try:
            return content.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise UnicodeError(f"Não foi possível identificar a codificação de {path.name}.")


def load_processes(workbook_path: Path) -> list[str]:
    workbook = load_workbook(workbook_path, read_only=True, data_only=True)
    try:
        for sheet in workbook.worksheets:
            header_row = next(sheet.iter_rows(min_row=1, max_row=1), ())
            headers = [cell.value for cell in header_row]
            process_column = find_process_column(headers)
            if process_column is None:
                continue

            processes: list[str] = []
            seen: set[str] = set()
            for row in sheet.iter_rows(min_row=2, values_only=True):
                value = row[process_column] if process_column < len(row) else None
                if value is None or not str(value).strip():
                    continue
                process = str(value).strip()
                normalized = normalize_process(process)
                if normalized not in seen:
                    processes.append(process)
                    seen.add(normalized)
            return processes
    finally:
        workbook.close()
    raise ValueError(
        "A planilha raspagem.geral.xlsx não contém uma coluna Processo."
    )


def natural_sort_key(path: Path) -> list[Any]:
    return [
        int(part) if part.isdigit() else part.casefold()
        for part in re.split(r"(\d+)", path.name)
    ]


def process_pdf_files(process_folder: Path) -> list[Path]:
    if not process_folder.is_dir():
        return []
    return sorted(
        (
            path
            for path in process_folder.rglob("*")
            if path.is_file() and path.suffix.casefold() == ".pdf"
        ),
        key=natural_sort_key,
    )


def find_document_pdf(documents: list[Path], document_id: str) -> Path | None:
    identifier = re.compile(rf"(?<!\d){re.escape(document_id)}(?!\d)")
    return next((path for path in documents if identifier.search(path.stem)), None)


def markdown_process_section(text: str, process: str) -> tuple[str | None, int | None, int | None]:
    lines = text.splitlines(keepends=True)
    headings: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line.rstrip("\r\n"))
        if match:
            headings.append((index, len(match.group(1)), match.group(2).strip()))

    target = normalize_process(process)
    for position, (start, level, title) in enumerate(headings):
        identifiers = PROCESS_PATTERN.findall(title)
        matches = (
            any(normalize_process(identifier) == target for identifier in identifiers)
            if identifiers
            else normalize_process(title) == target
        )
        if not matches:
            continue
        end = len(lines)
        for next_start, next_level, _ in headings[position + 1 :]:
            if next_level <= level:
                end = next_start
                break
        section = "".join(lines[start + 1 : end]).strip("\r\n")
        return section, start, end
    return None, None, None


def replace_markdown_process_section(text: str, process: str, replacement: str) -> str:
    _, start, end = markdown_process_section(text, process)
    if start is None or end is None:
        raise ValueError(f"Não há uma seção de {process} no resumo geral.")
    lines = text.splitlines(keepends=True)
    heading = lines[start].rstrip("\r\n")
    newline = "\r\n" if "\r\n" in text else "\n"
    body = replacement.strip("\r\n")
    suffix = "".join(lines[end:])
    updated = heading + newline
    if body:
        updated += newline + body
    if suffix:
        updated += newline + newline
    elif body and text.endswith(("\n", "\r")):
        updated += newline
    return "".join(lines[:start]) + updated + suffix


def read_csv_rows(path: Path) -> tuple[list[list[str]], str, str]:
    text, encoding = read_text_file(path)
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    return rows, encoding, dialect.delimiter


def discover_process_tables(root: Path, process: str) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    candidates = sorted(
        (
            path
            for path in root.iterdir()
            if path.is_file()
            and not path.name.startswith("~$")
            and path.suffix.casefold() in SPREADSHEET_EXTENSIONS | CSV_EXTENSIONS
        ),
        key=lambda path: path.name.casefold(),
    )
    target = normalize_process(process)

    for path in candidates:
        if path.suffix.casefold() in SPREADSHEET_EXTENSIONS:
            workbook = load_workbook(
                path,
                read_only=True,
                data_only=False,
                keep_vba=path.suffix.casefold() == ".xlsm",
            )
            try:
                for sheet in workbook.worksheets:
                    header_row = next(sheet.iter_rows(min_row=1, max_row=1), ())
                    headers = [cell.value for cell in header_row]
                    process_column = find_process_column(headers)
                    if process_column is None:
                        continue
                    records = []
                    row_numbers = []
                    for row_number, row in enumerate(
                        sheet.iter_rows(min_row=2, values_only=True), start=2
                    ):
                        values = list(row[: len(headers)])
                        values.extend([None] * (len(headers) - len(values)))
                        value = values[process_column]
                        if normalize_process(value) == target:
                            records.append(values)
                            row_numbers.append(row_number)
                    if records:
                        tables.append(
                            {
                                "path": path,
                                "sheet": sheet.title,
                                "headers": headers,
                                "records": records,
                                "row_numbers": row_numbers,
                                "process_column": process_column,
                            }
                        )
            finally:
                workbook.close()
        else:
            rows, encoding, delimiter = read_csv_rows(path)
            if not rows:
                continue
            headers = rows[0]
            process_column = find_process_column(headers)
            if process_column is None:
                continue
            records = []
            row_numbers = []
            for row_number, row in enumerate(rows[1:], start=2):
                values = list(row[: len(headers)])
                values.extend([""] * (len(headers) - len(values)))
                if normalize_process(values[process_column]) == target:
                    records.append(values)
                    row_numbers.append(row_number)
            if records:
                tables.append(
                    {
                        "path": path,
                        "sheet": None,
                        "headers": headers,
                        "records": records,
                        "row_numbers": row_numbers,
                        "process_column": process_column,
                        "csv_encoding": encoding,
                        "csv_delimiter": delimiter,
                    }
                )
    return tables


def unique_headers(headers: list[Any]) -> list[str]:
    result: list[str] = []
    used: set[str] = set()
    for index, value in enumerate(headers, start=1):
        label = str(value).strip() if value is not None else ""
        label = label or f"Coluna {index}"
        candidate = label
        suffix = 2
        while candidate in used:
            candidate = f"{label} ({suffix})"
            suffix += 1
        used.add(candidate)
        result.append(candidate)
    return result


def values_equal(left: Any, right: Any) -> bool:
    left_missing = left is None or (not isinstance(left, (list, dict)) and pd.isna(left))
    right_missing = right is None or (not isinstance(right, (list, dict)) and pd.isna(right))
    if left_missing or right_missing:
        return left_missing and right_missing
    if isinstance(left, datetime) and isinstance(right, datetime):
        return round_datetime_to_minute(left) == round_datetime_to_minute(right)
    try:
        return bool(left == right)
    except (TypeError, ValueError):
        return False


def editor_value(value: Any) -> Any:
    if value is None or (not isinstance(value, (list, dict)) and pd.isna(value)):
        return None
    if hasattr(value, "to_pydatetime"):
        return value.to_pydatetime()
    if hasattr(value, "item"):
        return value.item()
    return value


def round_datetime_to_minute(value: Any) -> Any:
    if isinstance(value, datetime):
        return pd.Timestamp(value).round("min").to_pydatetime()
    return value


def spreadsheet_clipboard_text(
    edited: pd.DataFrame,
    labels: list[str],
    process: str,
    process_column: int,
    row_label: str,
) -> str:
    clipboard_frame = edited.loc[:, labels].copy()
    clipboard_frame.loc[edited[row_label].isna(), labels[process_column]] = process
    return clipboard_frame.to_csv(sep="\t", index=False, lineterminator="\n")


def atomic_write_bytes(path: Path, content: bytes) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".sala_controle_",
            suffix=path.suffix,
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def save_table_edits(
    table: dict[str, Any],
    edited: pd.DataFrame,
    labels: list[str],
    process: str,
    row_label: str,
) -> tuple[int, int]:
    path: Path = table["path"]
    original_rows = {
        row_number: record
        for row_number, record in zip(table["row_numbers"], table["records"])
    }
    appended_records: list[list[Any]] = []

    for _, edited_row in edited.iterrows():
        row_number = editor_value(edited_row[row_label])
        values = [editor_value(edited_row[label]) for label in labels]
        if row_number is None:
            if all(
                column_index == table["process_column"]
                or value is None
                or (isinstance(value, str) and not value.strip())
                for column_index, value in enumerate(values)
            ):
                continue
            values[table["process_column"]] = process
            appended_records.append(values)
            continue

        row_number = int(row_number)
        if row_number not in original_rows:
            raise ValueError(f"A linha {row_number} não corresponde aos dados carregados.")

    changed = 0
    if path.suffix.casefold() in SPREADSHEET_EXTENSIONS:
        workbook = load_workbook(
            path,
            keep_vba=path.suffix.casefold() == ".xlsm",
        )
        try:
            sheet = workbook[table["sheet"]]
            for _, edited_row in edited.iterrows():
                row_number = editor_value(edited_row[row_label])
                if row_number is None:
                    continue
                row_number = int(row_number)
                original_record = original_rows[row_number]
                for column_index, label in enumerate(labels):
                    if column_index == table["process_column"]:
                        continue
                    new_value = editor_value(edited_row[label])
                    old_value = original_record[column_index]
                    if not values_equal(new_value, old_value):
                        sheet.cell(row=row_number, column=column_index + 1).value = new_value
                        changed += 1

            if appended_records:
                insert_at = max(table["row_numbers"]) + 1
                template_row = insert_at - 1
                sheet.insert_rows(insert_at, amount=len(appended_records))
                for row_offset, record in enumerate(appended_records):
                    target_row = insert_at + row_offset
                    if template_row > 0:
                        for column_index in range(1, len(labels) + 1):
                            source_cell = sheet.cell(
                                row=template_row,
                                column=column_index,
                            )
                            target_cell = sheet.cell(
                                row=target_row,
                                column=column_index,
                            )
                            if source_cell.has_style:
                                target_cell._style = copy.copy(source_cell._style)
                            if source_cell.number_format:
                                target_cell.number_format = source_cell.number_format
                        source_dimension = sheet.row_dimensions[template_row]
                        if source_dimension.height is not None:
                            sheet.row_dimensions[target_row].height = source_dimension.height
                    for column_index, value in enumerate(record, start=1):
                        sheet.cell(row=target_row, column=column_index).value = value

            if changed or appended_records:
                with tempfile.NamedTemporaryFile(
                    prefix=".sala_controle_",
                    suffix=path.suffix,
                    dir=path.parent,
                    delete=False,
                ) as temporary:
                    temporary_path = Path(temporary.name)
                try:
                    workbook.save(temporary_path)
                    os.replace(temporary_path, path)
                finally:
                    if temporary_path.exists():
                        temporary_path.unlink()
        finally:
            workbook.close()
    else:
        rows, encoding, delimiter = read_csv_rows(path)
        for _, edited_row in edited.iterrows():
            row_number = editor_value(edited_row[row_label])
            if row_number is None:
                continue
            row_number = int(row_number)
            original_record = original_rows[row_number]
            for column_index, label in enumerate(labels):
                if column_index == table["process_column"]:
                    continue
                new_value = editor_value(edited_row[label])
                old_value = original_record[column_index]
                if not values_equal(new_value, old_value):
                    csv_row = rows[row_number - 1]
                    if len(csv_row) <= column_index:
                        csv_row.extend([""] * (column_index + 1 - len(csv_row)))
                    csv_row[column_index] = "" if new_value is None else str(new_value)
                    changed += 1

        if appended_records:
            insert_at = max(table["row_numbers"])
            for row_offset, record in enumerate(appended_records):
                rows.insert(
                    insert_at + row_offset,
                    ["" if value is None else str(value) for value in record],
                )
        if changed or appended_records:
            output = io.StringIO(newline="")
            csv.writer(output, delimiter=delimiter).writerows(rows)
            atomic_write_bytes(path, output.getvalue().encode(encoding))
    return changed, len(appended_records)


def render_spreadsheet_editor(
    table: dict[str, Any],
    process: str,
    state_key: str,
    default_key: str,
) -> None:
    path: Path = table["path"]
    sheet_name = table["sheet"] or "CSV"
    labels = unique_headers(table["headers"])
    frame = pd.DataFrame(table["records"], columns=labels)
    column_config: dict[str, Any] = {}
    for label in labels:
        if pd.api.types.is_datetime64_any_dtype(frame[label].dtype):
            frame[label] = frame[label].dt.round("min")
            column_config[label] = st.column_config.DatetimeColumn(
                label,
                format="DD/MM/YYYY HH:mm",
                step=60,
            )
    row_label = "Linha"
    while row_label in labels:
        row_label += " Excel"
    frame.insert(0, row_label, table["row_numbers"])
    disabled = [row_label, labels[table["process_column"]]]
    column_config[row_label] = st.column_config.NumberColumn(
        row_label,
        disabled=True,
    )

    if table["sheet"] is None:
        title = f"{path.name} · {len(frame)} linha(s)"
    else:
        title = f"{path.name} · {sheet_name} · {len(frame)} linha(s)"

    expander_key = f"spreadsheet_expander_{stable_key(str(path), sheet_name)}"
    states = st.session_state.setdefault(state_key, {})
    st.session_state[expander_key] = states.get(
        expander_key,
        st.session_state.get(default_key, True),
    )
    with st.expander(
        title,
        expanded=True,
        key=expander_key,
        on_change=save_expandable_state,
        args=(expander_key, state_key),
    ):
        editor_key = f"spreadsheet_{stable_key(str(path), sheet_name, process)}"
        edited = st.data_editor(
            frame,
            key=editor_key,
            hide_index=True,
            width="stretch",
            num_rows="add",
            disabled=disabled,
            column_config=column_config,
        )
        clipboard_result = _COPY_SPREADSHEET_COMPONENT(
            key=f"copy_{editor_key}",
            data={
                "text": spreadsheet_clipboard_text(
                    edited,
                    labels,
                    process,
                    table["process_column"],
                    row_label,
                )
            },
            width="stretch",
            height=42,
            on_copied_change=lambda: None,
            on_copy_error_change=lambda: None,
        )
        if clipboard_result.copied:
            st.toast(f"{path.name} copiada para o clipboard.")
        if clipboard_result.copy_error:
            st.error(
                f"Não foi possível copiar {path.name}: "
                f"{clipboard_result.copy_error}"
            )
        if st.button(
            "Salvar alterações nesta planilha",
            key=f"save_{editor_key}",
            type="primary",
            width="stretch",
        ):
            try:
                changed, added = save_table_edits(
                    table,
                    edited,
                    labels,
                    process,
                    row_label,
                )
            except (
                OSError,
                ValueError,
                BadZipFile,
                InvalidFileException,
            ) as error:
                st.error(f"Não foi possível salvar {path.name}: {error}")
            else:
                st.session_state.pop(editor_key, None)
                if changed or added:
                    st.success(
                        f"{changed} célula(s) atualizada(s) e "
                        f"{added} linha(s) adicionada(s) em {path.name}."
                    )
                else:
                    st.success("Nenhuma alteração para salvar.")
                st.rerun()


def render_markdown_editor(
    path: Path,
    process: str,
    *,
    general_summary: bool = False,
    documents: list[Path] | None = None,
) -> None:
    heading = "Resumo geral do pack" if general_summary else "Resumo do processo"
    if not path.is_file():
        st.info(f"Arquivo não encontrado: {path.name}")
        return
    try:
        text, encoding = read_text_file(path)
    except OSError as error:
        st.error(f"Não foi possível ler {path.name}: {error}")
        return

    if general_summary:
        section, start, end = markdown_process_section(text, process)
        if section is None:
            st.info(f"Não foi encontrada uma seção de {process} em {path.name}.")
            return
        st.markdown(section or "_A seção está vazia._")
    else:
        section = text
        start = end = None
        if documents is None:
            st.markdown(text or "_O resumo está vazio._")
        else:
            render_process_summary(text, path, process, documents)

    editor_key = f"markdown_{stable_key(str(path), process)}"
    with st.expander(f"Editar {heading}", expanded=False):
        updated = st.text_area(
            "Conteúdo Markdown",
            value=section,
            key=editor_key,
            height=280,
        )
        if st.button(
            f"Salvar {heading.lower()}",
            key=f"save_{editor_key}",
        ):
            try:
                if general_summary:
                    saved_text = replace_markdown_process_section(
                        text, process, updated
                    )
                else:
                    saved_text = updated
                atomic_write_bytes(path, saved_text.encode(encoding))
            except (OSError, ValueError, UnicodeError) as error:
                st.error(f"Não foi possível salvar {path.name}: {error}")
            else:
                st.session_state.pop(editor_key, None)
                st.success(f"{path.name} atualizado.")
                st.rerun()


def render_process_summary(
    text: str,
    summary_path: Path,
    process: str,
    documents: list[Path],
) -> None:
    if not text:
        st.markdown("_O resumo está vazio._")
        return

    heading_pattern = re.compile(
        r"^(#{1,6}\s+Documento\s+ID\s+(\d+)\s*)$", re.IGNORECASE
    )
    pending_lines: list[str] = []
    active_pdf_key = f"summary_pdf_{stable_key(str(summary_path), process)}"

    def render_pending_lines() -> None:
        if pending_lines:
            st.markdown("".join(pending_lines))
            pending_lines.clear()

    for line in text.splitlines(keepends=True):
        match = heading_pattern.match(line.rstrip("\r\n"))
        if match is None:
            pending_lines.append(line)
            continue

        render_pending_lines()
        document_id = match.group(2)
        button_key = (
            f"summary_pdf_button_{stable_key(str(summary_path), process, document_id)}"
        )
        heading, action = st.columns([12, 1], vertical_alignment="center")
        with heading:
            st.markdown(match.group(1))
        with action:
            open_document_ids = st.session_state.get(active_pdf_key, [])
            if not isinstance(open_document_ids, list):
                open_document_ids = (
                    [open_document_ids] if isinstance(open_document_ids, str) else []
                )
            is_open = document_id in open_document_ids
            if st.button(
                "Fechar" if is_open else "PDF",
                key=button_key,
                icon=":material/close:" if is_open else ":material/picture_as_pdf:",
                help="Fechar visualização" if is_open else "Abrir PDF deste documento",
            ):
                if is_open:
                    open_document_ids.remove(document_id)
                else:
                    open_document_ids.append(document_id)
                st.session_state[active_pdf_key] = open_document_ids
                is_open = not is_open

        if is_open:
            pdf_path = find_document_pdf(documents, document_id)
            if pdf_path is None:
                st.warning(f"Não encontrei PDF para o documento ID {document_id}.")
            else:
                try:
                    pdf_bytes = pdf_path.read_bytes()
                except OSError as error:
                    st.error(f"Não foi possível abrir {pdf_path.name}: {error}")
                else:
                    if importlib.util.find_spec("streamlit_pdf") is None:
                        st.error("O visualizador de PDF do Streamlit não está instalado.")
                        st.code("python -m pip install 'streamlit[pdf]'")
                    else:
                        with st.container(border=True):
                            st.caption(pdf_path.name)
                            st.pdf(
                                pdf_bytes,
                                height=680,
                                key=(
                                    f"summary_pdf_viewer_"
                                    f"{stable_key(str(summary_path), process, document_id)}"
                                ),
                                alt=f"Documento PDF {document_id} do processo {process}",
                            )

    render_pending_lines()


    def choose_pack_directory() -> str:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        try:
            return filedialog.askdirectory(title="Selecione a pasta do pack")
        finally:
            root.destroy()


    def render_pack(root: Path) -> None:
        spreadsheet = root / "raspagem.geral.xlsx"
        if not spreadsheet.is_file():
            st.error(f"Não encontrei raspagem.geral.xlsx em {root}.")
            return
        try:
            processes = load_processes(spreadsheet)
        except (OSError, InvalidFileException, BadZipFile, ValueError) as error:
            st.error(f"Não foi possível carregar a ordem dos processos: {error}")
            return
        if not processes:
            st.warning("A coluna Processo não contém processos para exibir.")
            return

        current_root = str(root.resolve())
        if st.session_state.get("loaded_root") != current_root:
            st.session_state["loaded_root"] = current_root
            st.session_state["process_index"] = 0
            st.session_state["process_selector"] = processes[0]
        elif st.session_state.get("process_selector") not in processes:
            st.session_state["process_index"] = 0
            st.session_state["process_selector"] = processes[0]

        index = processes.index(st.session_state["process_selector"])
        left, selector, right = st.columns([1, 8, 1])
        with left:
            st.button(
                "← Anterior",
                disabled=index == 0,
                width="stretch",
                on_click=set_process_selection,
                args=(processes, index - 1 if index > 0 else index),
            )
        with selector:
            selected = st.selectbox(
                "Ordem de apresentação · raspagem.geral.xlsx",
                processes,
                key="process_selector",
                format_func=lambda value: f"{processes.index(value) + 1:03d} / {len(processes):03d}  ·  {value}",
            )
        with right:
            st.button(
                "Próximo →",
                disabled=index >= len(processes) - 1,
                width="stretch",
                on_click=set_process_selection,
                args=(processes, index + 1 if index < len(processes) - 1 else index),
            )

    process_index = processes.index(selected)
    st.session_state["process_index"] = process_index
    process_folder = root / selected
    documents = process_pdf_files(process_folder)

    st.subheader("Pack carregado")
    st.caption(str(root))
    metrics = st.columns(3)
    metrics[0].metric("Processo", selected)
    metrics[1].metric("Posição no pack", f"{process_index + 1} / {len(processes)}")
    metrics[2].metric("Documentos PDF", len(documents))
    st.divider()

    st.subheader("Documentos do processo")
    if documents:
        pdf_options = [str(path) for path in documents]
        pdf_key = f"pdf_multi_selector_{stable_key(current_root, selected)}"
        if pdf_key not in st.session_state:
            st.session_state[pdf_key] = [pdf_options[0]]
        else:
            saved_pdfs = st.session_state[pdf_key]
            if not isinstance(saved_pdfs, list):
                saved_pdfs = []
            saved_pdfs = [path for path in saved_pdfs if path in pdf_options]
            if st.session_state[pdf_key] and not saved_pdfs:
                saved_pdfs = [pdf_options[0]]
            st.session_state[pdf_key] = saved_pdfs

        selected_pdfs = st.multiselect(
            "PDFs para visualizar simultaneamente",
            pdf_options,
            key=pdf_key,
            format_func=lambda path: Path(path).relative_to(process_folder).as_posix(),
        )
        if selected_pdfs:
            if importlib.util.find_spec("streamlit_pdf") is None:
                st.error("O visualizador de PDF do Streamlit não está instalado.")
                st.code("python -m pip install 'streamlit[pdf]'")
            else:
                for start in range(0, len(selected_pdfs), 2):
                    row_paths = selected_pdfs[start : start + 2]
                    columns = st.columns(len(row_paths))
                    for column, pdf_value in zip(columns, row_paths):
                        pdf_path = Path(pdf_value)
                        with column:
                            with st.container(border=True):
                                st.caption(
                                    pdf_path.relative_to(process_folder).as_posix()
                                )
                                st.link_button(
                                    "Abrir PDF",
                                    local_pdf_url(pdf_path),
                                    help=str(pdf_path),
                                    icon=":material/open_in_new:",
                                )
                                try:
                                    pdf_bytes = pdf_path.read_bytes()
                                except OSError as error:
                                    st.error(
                                        f"Não foi possível abrir {pdf_path.name}: {error}"
                                    )
                                else:
                                    st.pdf(
                                        pdf_bytes,
                                        height=760,
                                        key=(
                                            f"pdf_viewer_"
                                            f"{stable_key(current_root, selected, str(pdf_path))}"
                                        ),
                                        alt=f"Documento PDF do processo {selected}",
                                    )
        else:
            st.info("Selecione um ou mais PDFs para visualizar.")
    else:
        st.info(f"Nenhum PDF encontrado na pasta {process_folder}.")

    st.divider()
    with st.expander("Resumo do processo", expanded=True):
        render_markdown_editor(
            process_folder / "resumo_processo.md",
            selected,
            documents=documents,
        )

    st.divider()
    with st.expander("Trecho do resumo geral", expanded=True):
        render_markdown_editor(
            root / "resumo_geral_processos.md",
            selected,
            general_summary=True,
        )

    st.divider()
    try:
        tables = discover_process_tables(root, selected)
    except (
        OSError,
        BadZipFile,
        InvalidFileException,
        UnicodeError,
        csv.Error,
    ) as error:
        st.subheader("Planilhas do processo")
        st.error(f"Não foi possível ler as planilhas do pack: {error}")
        return
    if not tables:
        st.subheader("Planilhas do processo")
        st.info(
            "Nenhuma planilha na raiz contém uma coluna Processo ou Processos "
            "com este número de processo."
        )
        return
    expander_keys = [
        f"spreadsheet_expander_{stable_key(str(table['path']), table['sheet'] or 'CSV')}"
        for table in tables
    ]
    spreadsheet_state_key = (
        f"spreadsheet_expanded_states_{stable_key(current_root)}"
    )
    spreadsheet_default_key = (
        f"spreadsheet_expanded_default_{stable_key(current_root)}"
    )
    heading, collapse_button, expand_button = st.columns(
        [5, 1.5, 1.5],
        vertical_alignment="center",
    )
    with heading:
        st.subheader("Planilhas do processo")
    with collapse_button:
        st.button(
            "Recolher todas",
            key=f"collapse_spreadsheets_{stable_key(current_root, selected)}",
            on_click=set_expandable_state,
            args=(
                expander_keys,
                False,
                spreadsheet_state_key,
                spreadsheet_default_key,
            ),
            width="stretch",
        )
    with expand_button:
        st.button(
            "Expandir todas",
            key=f"expand_spreadsheets_{stable_key(current_root, selected)}",
            on_click=set_expandable_state,
            args=(
                expander_keys,
                True,
                spreadsheet_state_key,
                spreadsheet_default_key,
            ),
            width="stretch",
        )
    st.caption(
        "As colunas Processo/Processos e Linha são protegidas. "
        "As demais alterações são gravadas no arquivo original ao salvar."
    )
    for table in tables:
        render_spreadsheet_editor(
            table,
            selected,
            spreadsheet_state_key,
            spreadsheet_default_key,
        )


    st.title("Sala de Controle")
    st.caption("Navegação de processos, documentos e planilhas do pack.")

    with st.sidebar:
        st.header("Abrir um pack")
        if st.button("Selecionar pasta…", width="stretch"):
            selected_directory = choose_pack_directory()
            if selected_directory:
                st.session_state["pack_directory_input"] = selected_directory
        st.text_input(
            "Diretório do pack",
            value=str(DEFAULT_PACK),
            key="pack_directory_input",
            help="A pasta precisa conter raspagem.geral.xlsx.",
        )
        if st.button("Abrir pack", type="primary", width="stretch"):
            entered = st.session_state.get("pack_directory_input", "").strip()
            if not entered:
                st.error("Informe o diretório do pack.")
            else:
                st.session_state["pack_root"] = str(Path(entered).expanduser())

    pack_root_value = st.session_state.get("pack_root")
    if not pack_root_value:
        st.info("Informe ou selecione uma pasta de pack na barra lateral.")
    else:
        try:
            pack_root = Path(pack_root_value).expanduser().resolve()
        except OSError as error:
            st.error(f"Diretório inválido: {error}")
        else:
            if not pack_root.is_dir():
                st.error(f"A pasta informada não existe: {pack_root}")
            else:
                render_pack(pack_root)


                                


# ---------------------------------------------------------
# AUTORIDADES
# ---------------------------------------------------------
elif password == SENHA_AUTORIDADES:
    st.header("⚖ Painel das Autoridades - Audiências")
    das = df[df["dia"].isin(dias_selecionados)]

    for dia in sorted(das["dia"].unique()):
        df_dia = das[das["dia"] == dia].sort_values(by="data e horário")

        if any(df_dia["sala de audiência"].isin(salas_selecionadas)):
            st.divider()
            # st.markdown(f"# 📅 {dia}")
            st.markdown(f"# 📅 {str(dia).split("-")[2]}/{str(dia).split("-")[1]}/{str(dia).split("-")[0]}")
            render_day(df_dia, show_sensitive=False)


# ---------------------------------------------------------
# ACESSO NEGADO
# ---------------------------------------------------------
elif password.strip() != "":
    st.error("Chave inválida.")