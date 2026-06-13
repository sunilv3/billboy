"""SQLite database initialization and user management."""
import os
import secrets
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from core.utils import SQLITE_AVAILABLE, sqlite3_mod
from core.logger import log

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'infosec.db')

def init_db():
    if not SQLITE_AVAILABLE:
        return
    with sqlite3_mod.connect(DB_PATH) as conn:
        # Create tables if they don't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT, target TEXT, sev TEXT, title TEXT, sub TEXT,
                asset TEXT, cve TEXT, cvss TEXT, exploit TEXT, poc_link TEXT,
                owasp TEXT, mitre TEXT, details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE, target TEXT, status TEXT,
                risk_score REAL, total_findings INTEGER,
                stats TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webhook_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT, webhook_url TEXT, enabled INTEGER DEFAULT 0
            )
        """)
        # ─── FALSE-POSITIVE SUPPRESSIONS (self-learning FP reduction) ────────
        # When an analyst marks a finding as a false positive, its semantic
        # fingerprint is stored here so identical findings are auto-rejected
        # by the FP gate on every future scan.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fp_suppressions (
                fingerprint TEXT PRIMARY KEY,
                title TEXT, asset TEXT, reason TEXT, note TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Add missing columns to findings table if they don't exist (for schema migration)
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN owasp TEXT")
        except sqlite3_mod.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN mitre TEXT")
        except sqlite3_mod.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT")
        except sqlite3_mod.OperationalError:
            pass
        # Index for fast diff queries
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_fp ON findings(scan_id, fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_target ON scan_history(target, created_at DESC)")
        except sqlite3_mod.OperationalError:
            pass

        # ─── USERS TABLE (DB-backed authentication) ─────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        # IRON RULE 4: force first-run password change for auto-provisioned admins
        try:
            conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0")
        except sqlite3_mod.OperationalError:
            pass

        # ─── RISK ASSESSMENT TABLES ──────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                asset_type TEXT DEFAULT 'application',
                criticality INTEGER DEFAULT 3,
                data_class TEXT DEFAULT 'internal',
                business_owner TEXT,
                environment TEXT DEFAULT 'production',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS risks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                risk_id TEXT UNIQUE,
                title TEXT,
                description TEXT,
                asset_id INTEGER,
                asset_name TEXT,
                threat TEXT,
                vulnerability TEXT,
                methodology TEXT DEFAULT 'NIST',
                likelihood INTEGER DEFAULT 3,
                impact INTEGER DEFAULT 3,
                inherent_score INTEGER,
                inherent_level TEXT,
                control_effectiveness INTEGER DEFAULT 0,
                residual_likelihood INTEGER,
                residual_impact INTEGER,
                residual_score INTEGER,
                residual_level TEXT,
                treatment TEXT DEFAULT 'mitigate',
                treatment_plan TEXT,
                treatment_cost REAL DEFAULT 0,
                owner TEXT,
                review_date TEXT,
                status TEXT DEFAULT 'open',
                linked_findings TEXT,
                framework_refs TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS risk_treatments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                risk_pk INTEGER,
                task TEXT,
                assignee TEXT,
                due_date TEXT,
                status TEXT DEFAULT 'pending',
                cost_estimate REAL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS risk_acceptances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                risk_pk INTEGER,
                approved_by TEXT,
                approver_role TEXT,
                justification TEXT,
                expiry_date TEXT,
                compensating_controls TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # ─── OPERATOR TIMELINE LOG ─────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS operator_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, operator TEXT, action_type TEXT,
                target TEXT, detail TEXT, finding_id TEXT
            )
        """)
        # ─── SCOPE CONTRACTS (IRON RULE 1: authorization gate) ──────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scope_contracts (
                scope_id TEXT PRIMARY KEY,
                operator TEXT, client TEXT,
                contract_json TEXT NOT NULL,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # ─── AUTHORIZATION AUDIT (every allow/deny decision) ────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS authz_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, scope_id TEXT, operator TEXT, target TEXT,
                intensity TEXT, action TEXT, decision TEXT,
                reason TEXT, justification TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS kris (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kri_id TEXT UNIQUE,
                name TEXT,
                description TEXT,
                category TEXT,
                formula TEXT,
                current_value REAL,
                threshold_green REAL,
                threshold_amber REAL,
                threshold_red REAL,
                trend TEXT,
                last_computed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS kri_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kri_id TEXT,
                value REAL,
                status TEXT,
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS controls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                control_id TEXT UNIQUE,
                name TEXT,
                description TEXT,
                framework TEXT,
                control_type TEXT,
                implementation_status TEXT DEFAULT 'not_implemented',
                effectiveness REAL DEFAULT 0,
                owner TEXT,
                last_tested TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS risk_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                review_date TEXT,
                reviewer TEXT,
                notes TEXT,
                decisions TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Seed a small set of baseline controls + KRIs on first run
        cur = conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0]
        if cur == 0:
            for cid, name, fw, ctype in [
                ('CTRL-MFA-01', 'Multi-Factor Authentication', 'NIST IA-2', 'preventive'),
                ('CTRL-PATCH-01', 'Vulnerability Patching (Critical <= 7d)', 'NIST SI-2', 'corrective'),
                ('CTRL-BACKUP-01', 'Encrypted Offsite Backups', 'NIST CP-9', 'recovery'),
                ('CTRL-LOG-01', 'Centralized SIEM Logging', 'NIST AU-2', 'detective'),
                ('CTRL-NET-01', 'Network Segmentation', 'NIST SC-7', 'preventive'),
                ('CTRL-ENC-01', 'Encryption at Rest (AES-256)', 'NIST SC-28', 'preventive'),
                ('CTRL-ACC-01', 'Least Privilege Access Reviews', 'NIST AC-6', 'preventive'),
                ('CTRL-IR-01', 'Incident Response Plan & Testing', 'NIST IR-3', 'corrective'),
            ]:
                conn.execute(
                    "INSERT INTO controls(control_id,name,description,framework,control_type) VALUES (?,?,?,?,?)",
                    (cid, name, f'Baseline control: {name}', fw, ctype)
                )
        cur = conn.execute("SELECT COUNT(*) FROM kris").fetchone()[0]
        if cur == 0:
            for kid, name, desc, cat, formula, ga, am, rd in [
                ('KRI-01', 'Critical Findings Open > 30d', 'Number of unmitigated critical findings older than 30 days', 'Vulnerability', 'count(findings where sev=critical and age>30d)', 0, 2, 5),
                ('KRI-02', 'Mean Time to Remediate (days)', 'Average days from finding creation to mitigation', 'Vulnerability', 'avg(mitigated_at - created_at)', 7, 14, 30),
                ('KRI-03', 'Asset Coverage %', 'Percent of in-scope assets scanned in last 7 days', 'Asset', 'scanned_assets / total_assets * 100', 90, 70, 50),
                ('KRI-04', 'High-Risk Port Exposure', 'Count of high-risk ports (23,445,3389,3306,6379,27017) exposed', 'Network', 'count(open high_risk ports)', 0, 1, 3),
                ('KRI-05', 'Open Risks Above Appetite', 'Risks with residual score above organisational appetite', 'Risk', 'count(risks where residual > appetite)', 0, 2, 5),
                ('KRI-06', 'Expired Risk Acceptances', 'Acceptance records past their expiry date and not renewed', 'Governance', 'count(acceptances where expiry < today)', 0, 1, 3),
            ]:
                conn.execute(
                    "INSERT INTO kris(kri_id,name,description,category,formula,threshold_green,threshold_amber,threshold_red) VALUES (?,?,?,?,?,?,?,?)",
                    (kid, name, desc, cat, formula, ga, am, rd)
                )
    log('info', '[DB] SQLite initialized (with risk-assessment tables)')


USERS = {}  # populated on first request (DB-backed)
_USERS_LOCK = __import__('threading').Lock()

def _load_users_from_db():
    """Refresh in-memory USERS dict from SQLite."""
    if not SQLITE_AVAILABLE:
        return
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3_mod.Row
            rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
        new_users = {r['username']: r['password_hash'] for r in rows}
        with _USERS_LOCK:
            USERS.clear()
            USERS.update(new_users)
    except Exception as e:
        log('err', f'[AUTH] Could not load users from DB: {e}')

_DEFAULT_PW = '12345678'  # the legacy default we are eliminating — used only for detection


def _is_production():
    """Production is opt-in and explicit: INFOSEC_ENV=production."""
    return os.environ.get('INFOSEC_ENV', '').strip().lower() == 'production'


def _upsert_user(username, password, must_change=False):
    """Insert or update a user with an argon2id-hashed password."""
    if not SQLITE_AVAILABLE:
        return False
    try:
        from core.passwords import hash_password
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users(username, password_hash, must_change_password) VALUES (?, ?, ?) "
                "ON CONFLICT(username) DO UPDATE SET "
                "password_hash=excluded.password_hash, "
                "must_change_password=excluded.must_change_password",
                (username, hash_password(password), 1 if must_change else 0)
            )
        _load_users_from_db()
        return True
    except Exception as e:
        log('err', f'[AUTH] upsert user {username} failed: {e}')
        return False


def set_user_password(username, new_password):
    """Set a new argon2 password and clear the must-change flag (post first-run set)."""
    return _upsert_user(username, new_password, must_change=False)


def get_must_change(username):
    """Return True if this user must change their password before doing anything."""
    if not SQLITE_AVAILABLE:
        return False
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT must_change_password FROM users WHERE username=?", (username,)
            ).fetchone()
        return bool(row and row[0])
    except Exception:
        return False


def _set_must_change(username, value):
    if not SQLITE_AVAILABLE:
        return
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.execute("UPDATE users SET must_change_password=? WHERE username=?",
                         (1 if value else 0, username))
    except Exception:
        pass


def init_users():
    """Provision the admin account WITHOUT ever creating a known default credential.

    - ADMIN_PASSWORD set      → use it (no must_change).
    - dev, no admin, no env   → generate a strong one-time password, print once,
                                force a change on first login (must_change=1).
    - production, no admin    → do nothing; enforce_admin_security() refuses boot.
    """
    if USERS:
        return
    _load_users_from_db()
    env_pw = os.environ.get('ADMIN_PASSWORD')
    if env_pw:
        if len(env_pw) < 12:
            log('warn', '[AUTH] ADMIN_PASSWORD is shorter than 12 characters — consider a stronger password')
        if _upsert_user('admin', env_pw, must_change=False):
            log('info', '[AUTH] Loaded admin user from ADMIN_PASSWORD env var into DB')
        return
    if 'admin' not in USERS:
        if _is_production():
            # Never auto-create a credential in production — boot enforcement handles it.
            log('err', '[AUTH] No admin provisioned and ADMIN_PASSWORD unset (production).')
            return
        one_time = secrets.token_urlsafe(18)
        if _upsert_user('admin', one_time, must_change=True):
            log('warn', '=' * 72)
            log('warn', '[AUTH] No ADMIN_PASSWORD set. Generated a ONE-TIME admin password.')
            log('warn', f'[AUTH]   username: admin')
            log('warn', f'[AUTH]   password: {one_time}')
            log('warn', '[AUTH] You MUST change it on first login (forced). It is shown only once.')
            log('warn', '=' * 72)


def enforce_admin_security():
    """Boot-time gate (IRON RULE 4). Refuses to start an insecure production instance.

    Raises RuntimeError in production when:
      - argon2 is unavailable, or
      - no admin is provisioned and ADMIN_PASSWORD is unset, or
      - the admin still authenticates with the legacy default password.
    In dev, a detected default password is downgraded to a forced change.
    """
    from core.passwords import verify_password, ARGON2_AVAILABLE
    init_users()
    _load_users_from_db()
    prod = _is_production()
    admin_hash = USERS.get('admin')
    default_in_use = bool(admin_hash and verify_password(admin_hash, _DEFAULT_PW))

    if prod:
        if not ARGON2_AVAILABLE:
            raise RuntimeError(
                'Refusing to boot (production): argon2-cffi is not installed. '
                'Install it: pip install argon2-cffi')
        if not admin_hash and not os.environ.get('ADMIN_PASSWORD'):
            raise RuntimeError(
                'Refusing to boot (production): no admin provisioned and ADMIN_PASSWORD is unset.')
        if default_in_use:
            raise RuntimeError(
                'Refusing to boot (production): admin is using the default password. '
                'Set ADMIN_PASSWORD to a strong secret and restart.')
    elif default_in_use:
        _set_must_change('admin', True)
        log('warn', '[AUTH] Admin is using the legacy default password — forcing a change on next login.')


# ── Scope-contract persistence (IRON RULE 1) ──────────────────────────────────

def save_scope_contract(contract):
    """Insert/replace a scope contract. `contract` is the full dict (with signature)."""
    if not SQLITE_AVAILABLE:
        return False
    import json as _json
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO scope_contracts(scope_id, operator, client, contract_json, active) "
                "VALUES (?,?,?,?,1) ON CONFLICT(scope_id) DO UPDATE SET "
                "operator=excluded.operator, client=excluded.client, "
                "contract_json=excluded.contract_json, active=1",
                (contract.get('scope_id'), contract.get('operator', ''),
                 contract.get('client', ''), _json.dumps(contract))
            )
        return True
    except Exception as e:
        log('err', f'[SCOPE] save failed: {e}')
        return False


def get_scope_contract(scope_id, active_only=True):
    """Return the contract dict for scope_id, or None."""
    if not SQLITE_AVAILABLE:
        return None
    import json as _json
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            q = "SELECT contract_json, active FROM scope_contracts WHERE scope_id=?"
            row = conn.execute(q, (scope_id,)).fetchone()
        if not row:
            return None
        if active_only and not row[1]:
            return None
        return _json.loads(row[0])
    except Exception as e:
        log('err', f'[SCOPE] load failed: {e}')
        return None


def list_scope_contracts():
    """Return all contracts (metadata + parsed contract), newest first."""
    if not SQLITE_AVAILABLE:
        return []
    import json as _json
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3_mod.Row
            rows = conn.execute(
                "SELECT scope_id, operator, client, contract_json, active, created_at "
                "FROM scope_contracts ORDER BY created_at DESC"
            ).fetchall()
        out = []
        for r in rows:
            try:
                contract = _json.loads(r['contract_json'])
            except Exception:
                contract = {}
            out.append({'scope_id': r['scope_id'], 'operator': r['operator'],
                        'client': r['client'], 'active': bool(r['active']),
                        'created_at': r['created_at'], 'contract': contract})
        return out
    except Exception as e:
        log('err', f'[SCOPE] list failed: {e}')
        return []


def set_scope_active(scope_id, active):
    if not SQLITE_AVAILABLE:
        return False
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            cur = conn.execute("UPDATE scope_contracts SET active=? WHERE scope_id=?",
                               (1 if active else 0, scope_id))
        return cur.rowcount > 0
    except Exception as e:
        log('err', f'[SCOPE] set_active failed: {e}')
        return False


def log_authz(decision, action='start_scan', justification=''):
    """Append an authorization decision (allow/deny) to the audit trail."""
    if not SQLITE_AVAILABLE:
        return
    from datetime import datetime as _dt, timezone as _tz
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO authz_log(ts, scope_id, operator, target, intensity, "
                "action, decision, reason, justification) VALUES (?,?,?,?,?,?,?,?,?)",
                (_dt.now(_tz.utc).isoformat(), decision.scope_id, decision.operator,
                 decision.target, decision.intensity, action,
                 'allow' if decision.allowed else 'deny', decision.reason, justification)
            )
    except Exception as e:
        log('err', f'[SCOPE] authz log failed: {e}')


def get_authz_log(scope_id=None, limit=200):
    if not SQLITE_AVAILABLE:
        return []
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3_mod.Row
            if scope_id:
                rows = conn.execute(
                    "SELECT * FROM authz_log WHERE scope_id=? ORDER BY id DESC LIMIT ?",
                    (scope_id, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM authz_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        log('err', f'[SCOPE] authz read failed: {e}')
        return []
