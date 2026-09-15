import pandas as pd
import numpy as np
import re

def standardize_user_id(uid):
    """
    Standardize user_id formats: EMP12345, emp12345, EMP-12345, EMP 12345, 12345 -> EMP12345
    """
    if pd.isna(uid) or uid is None:
        return np.nan
    s = str(uid).strip()
    if not s or s.lower() in ['none', 'nan', 'null', '']:
        return np.nan
    digits = re.sub(r'\D', '', s)
    if digits:
        return f"EMP{digits}"
    return s.upper()

def standardize_hostname(h):
    """
    Standardize hostnames:
    - Uppercase & strip whitespace
    - Strip domain suffixes (e.g. .corp.local, .local, etc.)
    - Normalize separators (replace underscores with hyphens: LPT_12621 -> LPT-12621)
    """
    if pd.isna(h) or h is None:
        return np.nan
    s = str(h).strip().upper()
    if not s or s.lower() in ['none', 'nan', 'null', '', 'unknown']:
        return np.nan
    # Remove domain suffixes
    s = s.split('.')[0].strip()
    # Normalize underscores to hyphens
    s = s.replace('_', '-')
    return s

def standardize_session_id(s):
    """
    Standardize session IDs:
    - Uppercase, strip whitespace
    - Normalize prefix (e.g., sid191825 -> SID191825)
    """
    if pd.isna(s) or s is None:
        return np.nan
    s = str(s).strip().upper()
    if not s or s.lower() in ['none', 'nan', 'null', '', 'unknown']:
        return np.nan
    digits = re.sub(r'\D', '', s)
    if digits:
        return f"SID{digits}"
    return s

def standardize_department(dept):
    """
    Standardize department names to a consistent canonical taxonomy.
    """
    if pd.isna(dept) or dept is None:
        return "Unknown"
    dept = str(dept).strip().lower()
    
    mapping = {
        'it': 'IT',
        'information tech': 'IT',
        'infotech': 'IT',
        'sales team': 'Sales',
        'sales': 'Sales',
        'legal': 'Legal',
        'rnd': 'R&D',
        'r&d': 'R&D',
        'research & development': 'R&D',
        'research and development': 'R&D',
        'finance dept': 'Finance',
        'finance': 'Finance',
        'marketing': 'Marketing',
        'support': 'Support',
        'customer support': 'Support',
        'call center': 'Call Center',
        'compliance': 'Compliance',
        'operations': 'Operations',
        'ops': 'Operations',
        'supply chain': 'Supply Chain',
        'hr': 'HR',
        'human resources': 'HR'
    }
    return mapping.get(dept, dept.title())

def robust_parse_timestamps(series):
    """
    Intelligently parse timestamps handling:
    - Unix epoch integer/float strings (e.g. 1787085290 -> 2026-08-18 UTC)
    - ISO 8601 strings
    - Mixed regional formats (DD/MM/YYYY vs MM/DD/YYYY)
    Returns UTC-localized pd.Series of datetime64[ns, UTC].
    """
    s = series.astype(str).str.strip()
    result = pd.Series(index=series.index, dtype='datetime64[ns, UTC]')
    
    # 1. Match pure numeric unix epoch timestamps (9 to 11 digits)
    is_unix = s.str.match(r'^\d{9,11}$')
    if is_unix.any():
        result[is_unix] = pd.to_datetime(s[is_unix].astype(float), unit='s', utc=True)
    
    # 2. Non-unix strings
    non_unix_mask = ~is_unix & series.notna() & (~s.isin(['nan', 'None', '', 'NaT', 'null']))
    if non_unix_mask.any():
        result[non_unix_mask] = pd.to_datetime(
            s[non_unix_mask], format='mixed', dayfirst=True, utc=True, errors='coerce'
        )
    
    return result

def normalize_fw_actions(action):
    """
    Standardize firewall actions to canonical binary 'allow' or 'deny'.
    """
    if pd.isna(action) or action is None:
        return 'unknown'
    action = str(action).strip().lower()
    allow_list = ['permit', 'pass', 'allow', 'accept']
    deny_list = ['deny', 'block', 'drop', 'reject']
    
    if action in allow_list:
        return 'allow'
    if action in deny_list:
        return 'deny'
    return 'unknown'

def normalize_threat_flag(flag):
    """
    Normalize boolean/string threat flag to boolean True/False.
    """
    if pd.isna(flag) or flag is None:
        return False
    s = str(flag).strip().lower()
    return s in ['true', '1', 'y', 'yes', 't']

def normalize_iam_events(event):
    """
    Group IAM events into actionable categories:
    'login_success', 'login_failed', 'mfa_failure', 'other'
    """
    if pd.isna(event) or event is None:
        return 'other'
    event = str(event).strip().lower()
    success = ['logon_success', 'success_login', 'login_success', 'auth_success', 
               'successful login', 'sso_success']
    mfa_fail = ['mfa_failed', 'mfa failure', 'mfa_rejected', 'otp expired']
    failed = ['failed_login', 'invalid_credentials', 'login failed', 
              'logon_failure', 'auth_failed', 'failed logon', 'account locked',
              'wrong_password', 'expired password']
    
    if event in mfa_fail:
        return 'mfa_failure'
    if event in success:
        return 'login_success'
    if event in failed:
        return 'login_failed'
    return 'other'

def normalize_severity(sev):
    """
    Standardize Endpoint alert severities into 4 canonical tiers:
    CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    """
    if pd.isna(sev) or sev is None:
        return 'UNKNOWN'
    sev = str(sev).strip().lower()
    crit = ['severe', 'critical', 'crit', 'p1', 'major']
    high = ['high', 'h', 'p2']
    med = ['medium', 'm', 'p3', 'moderate']
    low = ['low', 'l', 'p4', 'minor']
    
    if sev in crit: return 'CRITICAL'
    if sev in high: return 'HIGH'
    if sev in med: return 'MEDIUM'
    if sev in low: return 'LOW'
    return 'UNKNOWN'

def clean_ip(ip):
    """
    Validate and clean IPv4 address.
    Returns valid IP or np.nan.
    """
    if pd.isna(ip) or ip is None:
        return np.nan
    ip = str(ip).strip()
    # Validate 4 octets between 0 and 255
    match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', ip)
    if match:
        octets = [int(g) for g in match.groups()]
        if all(0 <= o <= 255 for o in octets):
            return ip
    return np.nan

def clean_risk_score(score):
    """
    Extract clean numeric float from IAM risk score fields.
    """
    if pd.isna(score) or score is None:
        return np.nan
    score = str(score).strip().lower()
    if 'high' in score: return 90.0
    if 'med' in score: return 50.0
    if 'low' in score: return 10.0
    
    match = re.search(r'(\d+(?:\.\d+)?)', score)
    if match:
        val = float(match.group(1))
        return min(max(val, 0.0), 100.0)
    return np.nan

def clean_port(port):
    """
    Validate and return valid port integer (1-65535) or np.nan.
    """
    try:
        if pd.isna(port):
            return np.nan
        val = int(float(port))
        if 1 <= val <= 65535:
            return val
    except (ValueError, TypeError):
        pass
    return np.nan

def normalize_status(status):
    """
    Standardize employee status: 'Active', 'Terminated', 'On Leave'.
    """
    if pd.isna(status) or status is None:
        return 'Unknown'
    s = str(status).strip().lower()
    if s in ['active', 'live', 'a', 'working', 'enabled']:
        return 'Active'
    if s in ['disabled', 'deactivated', 'exited', 'left', 'd', 'terminated', 'resigned', 'blocked']:
        return 'Terminated'
    if s in ['leave', 'on leave', 'on_leave', 'lwp', 'ooo']:
        return 'On Leave'
    return 'Unknown'

def normalize_protocol(proto):
    """
    Standardize network protocol strings and IP protocol numbers to canonical TCP, UDP, ICMP.
    6 -> TCP, 17 -> UDP, 1 -> ICMP
    """
    if pd.isna(proto) or proto is None:
        return 'UNKNOWN'
    s = str(proto).strip().upper()
    if s in ['TCP', '6', 'TCP/6']:
        return 'TCP'
    if s in ['UDP', '17', 'UDP/17']:
        return 'UDP'
    if s in ['ICMP', '1', 'PING', 'ICMP/1']:
        return 'ICMP'
    return s

def normalize_endpoint_status(status):
    """
    Standardize EDR alert statuses into canonical workflow categories:
    NEW, OPEN, IN_PROGRESS, CLOSED, FALSE_POSITIVE
    """
    if pd.isna(status) or status is None:
        return 'UNKNOWN'
    s = str(status).strip().lower()
    if s in ['new', 'n', 'unassigned']:
        return 'NEW'
    if s in ['open', 'o', 'active']:
        return 'OPEN'
    if s in ['in progress', 'in_progress', 'wip', 'investigating']:
        return 'IN_PROGRESS'
    if s in ['resolved', 'r', 'closed', 'closed']:
        return 'CLOSED'
    if s in ['not malicious', 'false_positive', 'false positive', 'fp']:
        return 'FALSE_POSITIVE'
    return s.upper()

