# SafeHarbor Insurance - Vulnerability Remediation Report

Date: 2026-11-27 | Baseline: `982052f` | Fixes: `vuln-fix` branch | Stack: Flask, SQLite
Detection: bandit, pip-audit, manual code review. Verification: 19 regression tests, bandit and pip-audit re-run, Playwright walkthrough of both builds.

## Summary
| Check | Before | After |
|---|---|---|
| bandit (static analysis) | 11 findings (5 high/medium-high classes) | 3 low (subprocess usage in backup route) |
| pip-audit (dependency CVEs) | 59 across 7 packages | 0 |
| Issues found by code review (not caught by tools) | 7 | 7 fixed |
| Regression tests | 0 | 19 passing |

## Fixes, in the order applied
**Critical**
| Issue | CWE | Fix |
|---|---|---|
| SQL injection on login | 89 | Parameterized query; password checked with `check_password_hash` |
| Admin console trusts a client-editable `role` cookie | 285 | Role read from the signed server-side session |
| OS command injection in backup (`shell=True`) | 78 | Label allow-list, argv list, no shell |
| `eval()` on the premium formula | 95 | AST evaluator limited to + - * / |
| `pickle.loads` on user data | 502 | JSON, login required |
| `yaml.load` with full Loader | 502 | `yaml.safe_load` with error handling |

**High**
| Issue | CWE | Fix |
|---|---|---|
| IDOR: any customer can open any policy / file a claim on it | 639 | Ownership enforced in the SQL query |
| Stored XSS in claim description (`\|safe`) | 79 | Autoescape restored, CSP header added |
| Path traversal and cross-customer access in document download | 22/639 | Strict filename pattern, ownership check, `send_from_directory` |
| MD5 password hashes | 327 | Salted scrypt (`generate_password_hash`) |
| Hard-coded secrets, debug mode, bind to all interfaces | 798/489 | Environment variables; debug off; 127.0.0.1 by default |

**Medium**
| Issue | CWE | Fix |
|---|---|---|
| Reflected XSS in claim search (`\|safe`) | 79 | Autoescape restored |
| Open redirect via `?next=` | 601 | Same-site relative paths only |

**Dependencies:** Flask 2.2.0 to 3.1.3, Werkzeug 2.2.2 to 3.1.9, Jinja2 3.0.0 to 3.1.6, PyYAML 5.3.1 to 6.0.2. The unused `requests` was removed, which also dropped `idna` and `urllib3` (16 more CVEs).

## GitHub scanning (repo: florianwaeles021/safeharbor-insurance-demo)
| Source | `main` (vulnerable, 982052f) | PR #1 head (125528a) |
|---|---|---|
| CodeQL, extended suite | 12 alerts (4 critical, 6 high, 2 medium) | 0 open |
| Dependabot | 22 alerts on 5 packages | closes automatically after merge to main |
| Secret scanning | 0 | 0 |

Why the counts differ: Dependabot counts advisories on the 5 pinned packages (22). pip-audit also sees transitive packages (idna, urllib3) and counts every advisory (59).
CodeQL does not detect the access-control flaws (cookie-based admin role, missing ownership checks). Those came from code review and are covered by the regression tests and the Playwright before/after checks.

## Playwright before/after (signed in as Alice, customer uid 1)
| Request | Before | After |
|---|---|---|
| GET /policy/1 (own) | 200 | 200 |
| GET /policy/3 (Bob's) | 200, Bob's data returned | 404 |
| GET /documents/download?file=policy_3.txt | 200, Bob's document | 404 |
| POST /claims policy_id=3 | 302, claim accepted | 404 |
| GET /admin as customer | 403 | 403 |
| GET /dashboard not signed in | 302 to /login | 302 to /login |

## How it was verified
1. **Tests:** `tests/test_security.py`, 19 tests, all passing. Each asserts the safe behaviour (for example a customer gets 404 on another customer's policy, and an edited role cookie gets 403 on /admin).
2. **Re-scan:** bandit 11 to 3 (all low); pip-audit 59 to 0.
3. **Playwright:** the same normal-user journey (sign in, view policy, file a claim, use the calculator) was recorded against the vulnerable and the fixed build. Normal use works on both. On the fixed build, cross-customer policy access returns 404 and the admin console returns 403 for customers.

## Behaviour changes
- Admin access follows the signed session, not a cookie.
- Customers see only their own policies, claims and documents.
- `/api/session/restore` accepts base64 JSON, not pickle.
- The premium calculator allows + - * / only.
- Existing MD5 password hashes are invalid; users need a reset.

## Residual risk
- bandit still reports 3 low items for the backup route's `subprocess` call; input is allow-listed and no shell is used.
- Not addressed: CSRF protection, rate limiting and lockout, HTTPS enforcement, audit logging, SSN encryption at rest.
- Any real credential that was ever committed must be rotated; removing it from the tree does not remove it from history.
- Tests run through Flask's test client; there is no browser-level automated suite beyond the demo walkthrough.
