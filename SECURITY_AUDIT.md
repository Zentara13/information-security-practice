# Звіт аудиту безпеки — «Електронний деканат»

| Поле | Значення |
|---|---|
| Аудитор | Параваєнко Володимир, група Б2F501ЗОФ23 233з |
| Дата аудиту | 2026-10-15 |
| Версія системи | commit `1036d29` (гілка practical-work-2, після етапу 3) |
| Обсяг (scope) | API FastAPI, БД SQLite, Docker-образ, Nginx, залежності |
| Поза обсягом | фронтенд, хост-ОС, соціальна інженерія (лише оцінка ризику) |
| Методи | STRIDE, OWASP Top 10 (2021), Trivy, pip-audit, Bandit, security_check.sh, pentest_mini.sh |

## 1. Резюме для керівництва

Система «Електронний деканат» має сім шарів захисту: автентифікацію (bcrypt + JWT), RBAC, захист веб-рівня, шифрування персональних даних (Fernet + сліпий індекс), журнал аудиту з виявленням Brute Force, hardened-контейнер за HTTPS та автоматизоване сканування. Конфігураційні перевірки (`security_check.sh`) пройдено без FAIL, усі 12 мінітестів показали «захищено». Головні залишкові ризики — вразливі версії залежностей, зафіксовані ще в ЗПР-1 (starlette, python-multipart, python-jose/ecdsa), та відсутність MFA для викладачів і адміністратора. Рекомендації першої черги: оновити FastAPI/Starlette і мігрувати з python-jose на PyJWT; запровадити MFA для привілейованих ролей.

| Критичні | Високі | Середні | Низькі |
|---|---|---|---|
| 0 | 2 | 5 | 2 |

Автоматизовані сканери: pip-audit — 38 вразливостей у 5 пакетах, Trivy — 2 CRITICAL і 56 HIGH, Bandit — 0 проблем; `security_check.sh` — FAIL 0, WARN 2.

## 2. Інвентаризація активів

| Актив | Тип | Критичність | Обґрунтування |
|---|---|---|---|
| data/app.db | Дані | Критичний | ПІБ, email, телефони, оцінки студентів |
| ENCRYPTION_KEY, BLIND_INDEX_KEY, JWT_SECRET_KEY | Секрети | Критичний | Компрометація = доступ до PII / підробка токенів; втрата ENCRYPTION_KEY = втрата PII |
| data/backups/*.db.enc | Дані | Високий | Повна копія БД (зашифрована) |
| audit_log | Дані | Середній | Докази для розслідувань, підзвітність викладачів |
| nginx/certs/selfsigned.key | Секрет | Середній | Приватний ключ TLS; компрометація = MITM |
| Docker-образ information-security-practice-api | ПЗ | Високий | Містить код і залежності; вразливості в ньому — вектор атаки |
| Облікові записи admin / teacher | Ідентичності | Високий | Повні права / право змінювати оцінки |

## 3. Реалізовані шари захисту (Defense in Depth)

| Шар | Механізм | Де (файл / робота) |
|---|---|---|
| Автентифікація | bcrypt, JWT access+refresh | ЗПР-1, `app/security.py`, `app/auth/` |
| Авторизація | RBAC admin/teacher/student (ролі з БД) | ЗПР-1, `app/auth/dependencies.py` |
| Веб-рівень | Pydantic, bleach, CSP, CORS, slowapi | ЗПР-1, `app/middleware/` |
| Шифрування даних | Fernet для email/phone, сліпий індекс, зашифрований бекап | ЗПР-2, `app/crypto/`, `scripts/backup_db.py` |
| Аудит і моніторинг | audit_log 5W, Brute Force, off-hours, security-stats | ЗПР-2, `app/audit/` |
| Середовище | non-root, read-only FS, cap_drop ALL, no-new-privileges, HTTPS, API лише на 127.0.0.1 | ЗПР-2, `Dockerfile`, `docker-compose.yml`, `nginx/nginx.conf` |
| DevSecOps | Trivy, pip-audit, Bandit, security_check.sh, GitHub Actions | ЗПР-2, `reports/`, `.github/workflows/security.yml` |

## 4. Модель загроз STRIDE

| STRIDE | Загроза | Реалізований контрзахід | Залишковий ризик |
|---|---|---|---|
| Spoofing | Підбір пароля викладача; підробка JWT (зміна payload, alg=none) | bcrypt, HS256 з фіксованим `algorithms=[...]`, slowapi 5/min + детектор Brute Force (5 невдач/5 хв за IP або логіном) | Немає MFA; спільний симетричний ключ HS256 (бажано RS256 або PyJWT) |
| Tampering | Студент змінює оцінку; підміна шифротексту в БД | RBAC `require_role` (ролі з БД), Pydantic-валідація, HMAC у Fernet (змінений шифротекст → `[ПОМИЛКА РОЗШИФРУВАННЯ]`) | Записи журналу аудиту не підписані (немає hash-chain) |
| Repudiation | Викладач заперечує виставлену оцінку | `assigned_by`, audit_log 5W, подія `data_change` з old→new, логування перегляду журналу | Журнал у тій самій БД: адміністратор БД може стерти записи; немає віддаленого SIEM |
| Information Disclosure | Витік app.db або бекапу; перехоплення трафіку | Fernet для email/phone, сліпий індекс замість відкритого email, зашифрований бекап з правами 600, HTTPS TLS 1.2+, `server_tokens off` | `full_name` і оцінки зберігаються відкрито; ключі на тому ж хості, що й БД |
| Denial of Service | Флуд /auth/login; навмисне блокування чужого акаунта | slowapi, Nginx `limit_req` 10r/s, `client_max_body_size 1m` | Lockout за логіном: зловмисник 5 невдалими спробами блокує вхід жертви на 5 хв |
| Elevation of Privilege | Студент → admin; вихід із контейнера | RBAC, ролі з БД (не з токена), non-root `appuser`, `cap_drop: ALL`, `no-new-privileges`, read-only FS | Можливі IDOR у нових ендпоінтах; немає власного seccomp/AppArmor-профілю |

## 5. Матриця ризиків (залишковий ризик)

Ризик = Й × В. Рівні: 1–4 низький, 5–9 середній, 10–15 високий, 16–25 критичний.

| # | Загроза | Й | В | Ризик | Рівень | Обґрунтування |
|---|---|---|---|---|---|---|
| R1 | Brute Force | 2 | 4 | 8 | Середній | Два незалежні обмежувачі (slowapi + детектор) роблять перебір непрактичним, але слабкий пароль викладача все ж можна вгадати за довгий час, а наслідки — зміна оцінок. |
| R2 | SQL Injection | 1 | 5 | 5 | Середній | Усі запити через ORM або `text()` з параметрами (T10 → 401), але успішна ін'єкція дала б доступ до всієї БД. |
| R3 | Stored XSS | 1 | 3 | 3 | Низький | Pydantic + bleach відхиляють `<script>` (T9 → 422), CSP блокує inline-скрипти; вплив обмежений відсутністю фронтенду в scope. |
| R4 | Крадіжка JWT | 2 | 4 | 8 | Середній | Короткий час життя access-токена та HTTPS зменшують ймовірність, але немає відкликання токенів (blacklist), тож вкрадений токен діє до `exp`. |
| R5 | Витік БД або бекапу | 2 | 3 | 6 | Середній | email/phone і бекап зашифровані, проте ПІБ та оцінки в app.db відкриті, а ключі зберігаються на тому ж хості. |
| R6 | Втрата ENCRYPTION_KEY | 2 | 5 | 10 | Високий | Ключ лише в .env і менеджері паролів однієї людини; втрата = безповоротна втрата всіх email, бекап не допомагає. |
| R7 | Вразлива залежність | 4 | 3 | 12 | Високий | pip-audit знаходить 38 відомих вразливостей у 5 пакетах (starlette, python-multipart, python-jose/ecdsa тощо), Trivy — 2 CRITICAL у Python-пакетах образу; частина з них досяжна через публічні ендпоінти. |
| R8 | Фішинг викладача | 3 | 4 | 12 | Високий | Соціальна інженерія технічно не контролюється, MFA немає, тож викрадений пароль одразу дає право змінювати оцінки. |
| R9 | Зловживання lockout (DoS акаунта) | 3 | 2 | 6 | Середній | Будь-хто, знаючи логін, блокує вхід жертви на 5 хв; вплив тимчасовий і фіксується в журналі. |
| R10 | Підміна X-Forwarded-For | 1 | 3 | 3 | Низький | `--forwarded-allow-ips "*"` безпечний лише тому, що порт 8000 відкрито тільки на 127.0.0.1; при помилці конфігурації можна обійти детектор за IP. |

## 6. Знахідки та рекомендації

| ID | Рівень | Знахідка | Доказ | Рекомендація | Статус |
|---|---|---|---|---|---|
| F-01 | High | У docker-compose.yml (ЗПР-1) стояло `JWT_SECRET_KEY=` з порожнім значенням: змінна перекривала .env, і токени підписувались порожнім ключем (підробка JWT будь-ким); у config.py — fallback-секрет | Аналіз docker-compose.yml і config.py ЗПР-1 | Секрет лише з .env через `${…:?}`, без fallback, fail-fast при ключі < 32 символів | Виправлено (етапи 1 і 3), retest: T2/T3 → 401, security_check FAIL 0 |
| F-02 | High | Відомі вразливості starlette (через fastapi==0.111.0) та python-multipart | reports/pip-audit.txt | Оновити fastapi до актуальної версії (тягне виправлений starlette) і python-multipart; повторити pentest_mini.sh | Заплановано (пріоритет 1) |
| F-03 | Medium | python-jose залежить від ecdsa з відомою вразливістю (timing side-channel) | reports/pip-audit.txt | Код ECDSA не використовується (підпис HS256) → прийнятий ризик; план: міграція на PyJWT | Прийнятий ризик |
| F-04 | Medium | Контейнер працював від root, код змінюваний | security_check.sh (ЗПР-1): «Dockerfile без USER» | non-root appuser, read_only, cap_drop ALL | Виправлено (етап 3), retest: `whoami` → appuser |
| F-05 | Medium | Email зберігався відкрито | SELECT з БД (ЗПР-1) | Fernet + сліпий індекс | Виправлено (етап 1), retest: T11 → gAAAA |
| F-06 | Medium | Журнал аудиту можна змінити адміністратором БД | Аналіз архітектури | hash-chain записів, відправлення логів у зовнішній SIEM | Заплановано |
| F-07 | Low | Self-signed сертифікат | nginx/certs | Let's Encrypt у production | Прийнятий ризик (лабораторний стенд) |
| F-08 | Low | Немає відкликання JWT при виході / зміні пароля | Аналіз коду | Таблиця відкликаних jti або короткий TTL + rotation refresh | Заплановано |
| F-09 | Medium | Після hardening (non-root `appuser`) журнал аудиту мовчки перестав записувати події: файли БД у volume належали root, запис падав з помилкою, а логер (навмисно) не переривав запит. Детектор Brute Force при цьому не бачив невдалих спроб | KPI не змінювались після тестів; `docker compose logs api` → 28 × `audit_write_failed`; `ls -ln data/` → власник 0:0 | `chown -R 1000:1000` для volume; у production — алерт на `audit_write_failed` (моніторинг самого моніторингу) | Виправлено, retest: події пишуться, KPI оновлюються |

## 7. Чеклист OWASP Top 10 (2021)

| ID | Категорія | Статус | Доказ / коментар |
|---|---|---|---|
| A01 | Broken Access Control | ✅ | T5, T6, T7 → 403 для студента; T8 → 200 для адміна; `require_role` у `app/auth/dependencies.py` |
| A02 | Cryptographic Failures | ✅ | bcrypt (`app/security.py`), Fernet для PII (T11), TLS 1.2/1.3 (`nginx.conf`), секрети не в Git (security_check.sh) |
| A03 | Injection | ✅ | ORM + параметризований `text()` у `scripts/migrate_encrypt.py`; T10 → 401; Pydantic + bleach (T9 → 422) |
| A04 | Insecure Design | ⚠️ | Модель загроз є (розділ 4); компроміс lockout за логіном свідомо прийнято (R9); MFA відсутня |
| A05 | Security Misconfiguration | ✅ | Security Headers (security_check.sh розд. 3), CORS без `*`, `server_tokens off`, без fallback-секретів |
| A06 | Vulnerable and Outdated Components | ⚠️ | reports/pip-audit.txt: 38 вразливостей у 5 пакетах; reports/trivy.txt: 56 HIGH + 2 CRITICAL; план оновлення — F-02, F-03 |
| A07 | Identification and Authentication Failures | ✅ | slowapi 5/min, детектор Brute Force (T12 → 429), `exp` у JWT, refresh ≠ access (T4 → 401) |
| A08 | Software and Data Integrity Failures | ✅ | HMAC Fernet (підміна → `[ПОМИЛКА РОЗШИФРУВАННЯ]`), пін-версії в requirements.txt, перевірене відновлення бекапу (integrity_check=ok) |
| A09 | Security Logging and Monitoring Failures | ⚠️ | audit_log 5W, алерти brute_force_detected, `audit_log_viewed`; збій запису аудиту після hardening виявлено й виправлено (F-09); але журнал без захисту цілісності, без зовнішнього SIEM і без алерту на `audit_write_failed` |
| A10 | SSRF | N/A | Сервер не робить HTTP-запитів на URL від користувача (жодного `requests`/`httpx`/`urllib` у `app/` з даними клієнта) |

## 8. Результати автоматизованого сканування

| Інструмент | Тип | CRITICAL | HIGH | MEDIUM | Дія |
|---|---|---|---|---|---|
| Trivy | Container SCA | 2 (Python-пакети) | 56 (44 Debian + 12 Python) | — | Python-пакети — оновлення залежностей (F-02); Debian — оновлювати базовий образ `python:3.11-slim`, без виправлення — прийнятий ризик |
| pip-audit | Python SCA | — | 38 вразливостей у 5 пакетах | — | F-02 (оновлення), F-03 (прийнятий ризик) |
| Bandit | SAST | — | 0 | 0 | Дій не потрібно |
| security_check.sh | Конфігурація | FAIL: 0 | WARN: 2 | | WARN за pip-audit/Trivy описано в F-02, F-03 |

## 9. Результати мінітестів

Результати `reports/pentest_mini.md` (запуск 2026-10-15 на стенді за Nginx/HTTPS, повторно після виправлення F-09): **12 з 12 — захищено**.

| Тест | Фактично | Очікується | Висновок |
|---|---|---|---|
| T1 Доступ без токена (/auth/me) | 401 | 401 | ✅ захищено |
| T2 JWT з підробленим payload | 401 | 401 | ✅ захищено |
| T3 JWT з alg=none | 401 | 401 | ✅ захищено |
| T4 Refresh token замість access | 401 | 401 | ✅ захищено |
| T5 Студент → /admin/users | 403 | 403 | ✅ захищено |
| T6 Студент → /admin/audit-log | 403 | 403 | ✅ захищено |
| T7 Студент → чужі оцінки через /teachers | 403 | 403 | ✅ захищено |
| T8 Адмін → /admin/audit-log (контроль) | 200 | 200 | ✅ захищено |
| T9 XSS у full_name при реєстрації | 422 | 422 | ✅ захищено |
| T10 SQLi у логіні | 401 | 401 422 429 | ✅ захищено |
| T11 Email у БД зашифровано | gAAAA | gAAAA | ✅ захищено |
| T12 Brute Force (8 спроб) | 429 | 429 | ✅ захищено |

Примітка до T12: у цьому запуску 429 повернув перший рубіж — slowapi (5 запитів/хв з IP), бо скрипт до T12 уже виконав 3 запити входу; у журнал потрапили 2 `login_failed`, решту спроб відсічено до перевірки пароля. Другий рубіж — детектор Brute Force (5 невдач за 5 хв за IP або логіном) — перевірено окремим тестом етапу 2 з паузою 61 с між серіями: подія `brute_force_detected` о 15:54:16 UTC, відповідь 429 «Забагато невдалих спроб». Два незалежні механізми — приклад Defense in Depth.

**Ручний тест: CORS із чужого Origin.**

```bash
curl -sk -D - -o /dev/null https://localhost/health -H "Origin: https://evil.example" | grep -i access-control
```

Результат: заголовок `Access-Control-Allow-Origin` відсутній → браузер заблокує відповідь для evil.example. Для дозволеного `Origin: https://localhost` заголовок повертається. ✅

## 10. Моніторинг і KPI

| Показник | Значення | Джерело |
|---|---|---|
| Невдалих входів (вікно тестування, 1 год) | 9 | /admin/security-stats?hours=1 → failed_logins |
| Brute Force алертів | 1 | → brute_force_alerts |
| Відмов у доступі (403) | 4 | → access_denied (T5–T7 + тест етапу 2) |
| Усього подій аудиту / помилок сервера | 56 / 0 | → total_events, server_errors |
| MTTD / MTTR (тест Brute Force етапу 2) | 70,6 с / 0,013 с | audit_log: перший `login_failed` 15:53:06.009 → `brute_force_detected` 15:54:16.640 → блокувальна відповідь 15:54:16.653. MTTD майже повністю дорівнює паузі 61 с у самому тесті: детектор спрацьовує на першій же спробі після п'ятої невдачі; виявлення і блокування відбуваються в одному запиті |
| Останній бекап / відновлення перевірено | 2026-10-15 / так | scripts/restore_db.py: integrity_check=ok; з чужим ключем — InvalidToken |

## 11. План покращень

| Пріоритет | Захід | Яку загрозу закриває | Зусилля |
|---|---|---|---|
| 1 | Оновити fastapi/starlette, python-multipart; мігрувати python-jose → PyJWT | R7, A06 | Низьке (1 день + регресійні тести) |
| 2 | MFA (TOTP) для викладачів і адміністратора | R8, Spoofing | Середнє |
| 3 | Відправлення логів у зовнішній SIEM + hash-chain у audit_log | Repudiation, A09 | Середнє |
| 4 | Ключі в KMS / Vault замість .env, резервна копія ключа в другої відповідальної особи | R6, Information Disclosure | Середнє |
| 5 | Прогресивна затримка замість жорсткого lockout за логіном; CAPTCHA після N невдач | R9, DoS | Низьке |
| 6 | Відкликання JWT (jti blacklist) | R4 | Низьке |

## 12. Висновок

Система готова до пілотної експлуатації у внутрішній мережі університету за умови виконання пунктів 1 і 2 плану покращень (оновлення вразливих залежностей і MFA для привілейованих ролей) та заміни self-signed сертифіката на довірений. Найкритичніший залишковий ризик — вразливі залежності та фішинг викладача (R7, R8 = 12, високий): перший має публічно відомі експлойти й досяжний через API, другий обходить усі технічні контрзаходи одним викраденим паролем. Безпека — процес: після кожного оновлення залежностей потрібно повторювати security_check.sh і pentest_mini.sh (retest).
