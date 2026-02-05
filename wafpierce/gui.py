"""PySide6 GUI for WAFPierce (subprocess-backed)

This GUI runs the existing CLI module `wafpierce.pierce` in a subprocess so
we don't need to modify any scanner code. That lets the GUI provide a
responsive Start / Stop experience and save results to disk.

Run with:
    python3 -m wafpierce.gui
"""
from __future__ import annotations

import sys
import threading
import subprocess
import tempfile
import json
import os
import time
import concurrent.futures
from typing import Optional

# path to bundled logo (used for watermark/icon)
LOGO_PATH = os.path.join(os.path.dirname(__file__), 'logo_Temp', 'logo_wafpierce.png')


def _get_config_path() -> str:
    if os.name == 'nt':
        base = os.getenv('APPDATA') or os.path.expanduser('~')
    else:
        base = os.path.join(os.path.expanduser('~'), '.config')
    d = os.path.join(base, 'wafpierce')
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return os.path.join(d, 'gui_prefs.json')


# default settings, change if you want different ones for the application
def _load_prefs() -> dict:
    path = _get_config_path()
    defaults = {
        'font_size': 12,
        'watermark': True,
        'threads': 5,
        'concurrent': 1,
        'use_concurrent': False,
        'delay': 0.2,
        'window_geometry': '980x640',
        'qt_geometry': '1000x640',
        'remember_targets': True,
        'retry_failed': 0,
        'ui_density': 'comfortable',
        'last_targets': [],
        'language': 'en',
    }
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    defaults.update(data)
    except Exception:
        pass
    return defaults


# ==================== TRANSLATIONS ====================
TRANSLATIONS = {
    'en': {
        'window_title': 'WAFPierce - GUI (Qt)',
        'target_url': 'Target URL:',
        'add': 'Add',
        'remove': 'Remove',
        'settings': 'Settings',
        'threads': 'Threads:',
        'concurrent': 'Concurrent:',
        'use_concurrent': 'Use concurrent targets',
        'delay': 'Delay (s):',
        'queued': 'Queued',
        'running': 'Running',
        'done': 'Done',
        'error': 'Error',
        'target': 'Target',
        'status': 'Status',
        'output': 'Output',
        'results': '📊 Results',
        'start': 'Start',
        'stop': 'Stop',
        'save': 'Save',
        'clear': 'Clear',
        'results_explorer': 'Results Explorer',
        'sites': '🌐 Sites',
        'all_sites': '📋 All Sites',
        'findings': 'findings',
        'total': 'Total',
        'bypasses': 'Bypasses',
        'sort_by': 'Sort by:',
        'filter': 'Filter:',
        'search': 'Search:',
        'search_placeholder': 'Search techniques, categories...',
        'severity_high_low': 'Severity (High to Low)',
        'severity_low_high': 'Severity (Low to High)',
        'technique_az': 'Technique (A-Z)',
        'technique_za': 'Technique (Z-A)',
        'category': 'Category',
        'bypass_status': 'Bypass Status',
        'all_results': 'All Results',
        'critical_only': '🔴 CRITICAL only',
        'high_only': '🟠 HIGH only',
        'medium_only': '🟡 MEDIUM only',
        'low_only': '🔵 LOW only',
        'info_only': 'ℹ️ INFO only',
        'bypasses_only': '✅ Bypasses only',
        'non_bypasses_only': '❌ Non-bypasses only',
        'expand_all': 'Expand All',
        'collapse_all': 'Collapse All',
        'technique': 'Technique',
        'severity': 'Severity',
        'reason': 'Reason',
        'details': 'Details',
        'export_view': 'Export View',
        'close': 'Close',
        'no_results': 'No Results',
        'no_results_msg': 'No scan results available yet.',
        'font_size': 'Font size (only in outputs):',
        'show_watermark': 'Show watermark/logo',
        'remember_targets': 'Remember last targets',
        'retry_failed': 'Retry failed targets:',
        'ui_density': 'UI density:',
        'language': 'Language:',
        'cancel': 'Cancel',
        'saved': 'Saved',
        'save_failed': 'Save failed',
        'exported': 'Exported',
        'export_failed': 'Export failed',
        'missing_target': 'Missing target',
        'add_target_msg': 'Please add at least one target',
        'run_finished': '[+] Run finished',
        'lang_restart_warning': '⚠️ Language will change after restart',
        'restart_confirm': 'Restart Required',
        'restart_confirm_msg': 'Language changed. Restart now to apply?',
        'yes': 'Yes',
        'no': 'No',
        'legal_disclaimer_title': 'WAFPierce - Legal Disclaimer',
        'legal_disclaimer_header': '⚠️ LEGAL DISCLAIMER ⚠️',
        'i_agree': 'I Agree',
        'i_decline': 'I Decline',
        'clean': 'Clean',
        'no_tmp_files': 'No temporary result files to remove',
        'remove_files_confirm': 'Remove {count} files?',
        'removed_files': 'Removed {count} file(s)',
        'no_results_for': 'No results for {target}',
        'results_for': 'Results — {target}',
        'done_exploits': 'Done (Exploits)',
        'errors_label': 'Errors',
        'errors_details': 'Errors details',
        'export_results_view': 'Export Results View',
        'no_results_to_export': 'No results to export with current filters.',
        'exported_results': 'Exported {count} results to {path}',
        'stop_requested': 'Stop requested',
        'compact': 'compact',
        'comfortable': 'comfortable',
        'spacious': 'spacious',
        'description': 'Description',
        'legal_disclaimer': """WAFPierce – Legal Disclaimer

FOR AUTHORIZED SECURITY TESTING ONLY

This tool is provided solely for legitimate security research and authorized penetration testing. You must obtain explicit, written permission from the system owner before testing any network, application, or device that you do not personally own.

Unauthorized access to computer systems, networks, or data is illegal and may result in criminal and/or civil penalties under applicable laws, including but not limited to the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and similar legislation in your jurisdiction.

By clicking "I Agree", you acknowledge and confirm that:

• You will only test systems that you own or have explicit written authorization to test
• You will comply with all applicable local, national, and international laws and regulations
• You accept full responsibility for your actions and use of this tool
• You understand that misuse of this tool may result in legal consequences

Limitation of Liability:
The developers, contributors, distributors, and owners of WAFPierce assume no liability for misuse, damage, legal consequences, data loss, service disruption, or any other harm resulting from the use or inability to use this tool. This software is provided "as is", without warranty of any kind, expressed or implied. You agree that you use this tool entirely at your own risk.""",
    },
    'ar': {
        'window_title': 'WAFPierce - واجهة المستخدم',
        'target_url': 'رابط الهدف:',
        'add': 'إضافة',
        'remove': 'إزالة',
        'settings': 'الإعدادات',
        'threads': 'الخيوط:',
        'concurrent': 'متزامن:',
        'use_concurrent': 'استخدام أهداف متزامنة',
        'delay': 'التأخير (ث):',
        'queued': 'في الانتظار',
        'running': 'قيد التشغيل',
        'done': 'مكتمل',
        'error': 'خطأ',
        'target': 'الهدف',
        'status': 'الحالة',
        'output': 'المخرجات',
        'results': '📊 النتائج',
        'start': 'بدء',
        'stop': 'إيقاف',
        'save': 'حفظ',
        'clear': 'مسح',
        'results_explorer': 'مستكشف النتائج',
        'sites': '🌐 المواقع',
        'all_sites': '📋 جميع المواقع',
        'findings': 'نتيجة',
        'total': 'المجموع',
        'bypasses': 'الاختراقات',
        'sort_by': 'ترتيب حسب:',
        'filter': 'تصفية:',
        'search': 'بحث:',
        'search_placeholder': 'بحث في التقنيات والفئات...',
        'severity_high_low': 'الخطورة (من الأعلى للأدنى)',
        'severity_low_high': 'الخطورة (من الأدنى للأعلى)',
        'technique_az': 'التقنية (أ-ي)',
        'technique_za': 'التقنية (ي-أ)',
        'category': 'الفئة',
        'bypass_status': 'حالة الاختراق',
        'all_results': 'جميع النتائج',
        'critical_only': '🔴 حرج فقط',
        'high_only': '🟠 عالي فقط',
        'medium_only': '🟡 متوسط فقط',
        'low_only': '🔵 منخفض فقط',
        'info_only': 'ℹ️ معلومات فقط',
        'bypasses_only': '✅ الاختراقات فقط',
        'non_bypasses_only': '❌ غير المخترقة فقط',
        'expand_all': 'توسيع الكل',
        'collapse_all': 'طي الكل',
        'technique': 'التقنية',
        'severity': 'الخطورة',
        'reason': 'السبب',
        'details': 'التفاصيل',
        'export_view': 'تصدير العرض',
        'close': 'إغلاق',
        'no_results': 'لا توجد نتائج',
        'no_results_msg': 'لا توجد نتائج فحص متاحة بعد.',
        'font_size': 'حجم الخط (في المخرجات فقط):',
        'show_watermark': 'إظهار العلامة المائية/الشعار',
        'remember_targets': 'تذكر الأهداف السابقة',
        'retry_failed': 'إعادة المحاولة للأهداف الفاشلة:',
        'ui_density': 'كثافة الواجهة:',
        'language': 'اللغة:',
        'cancel': 'إلغاء',
        'saved': 'تم الحفظ',
        'save_failed': 'فشل الحفظ',
        'exported': 'تم التصدير',
        'export_failed': 'فشل التصدير',
        'missing_target': 'هدف مفقود',
        'add_target_msg': 'الرجاء إضافة هدف واحد على الأقل',
        'run_finished': '[+] انتهى الفحص',
        'lang_restart_warning': '⚠️ سيتم تغيير اللغة بعد إعادة التشغيل',
        'restart_confirm': 'إعادة التشغيل مطلوبة',
        'restart_confirm_msg': 'تم تغيير اللغة. إعادة التشغيل الآن للتطبيق؟',
        'yes': 'نعم',
        'no': 'لا',
        'legal_disclaimer_title': 'WAFPierce - إخلاء المسؤولية القانونية',
        'legal_disclaimer_header': '⚠️ إخلاء المسؤولية القانونية ⚠️',
        'i_agree': 'أوافق',
        'i_decline': 'أرفض',
        'clean': 'تنظيف',
        'no_tmp_files': 'لا توجد ملفات نتائج مؤقتة للإزالة',
        'remove_files_confirm': 'إزالة {count} ملفات؟',
        'removed_files': 'تمت إزالة {count} ملف(ات)',
        'no_results_for': 'لا توجد نتائج لـ {target}',
        'results_for': 'النتائج — {target}',
        'done_exploits': 'مكتمل (الثغرات)',
        'errors_label': 'الأخطاء',
        'errors_details': 'تفاصيل الأخطاء',
        'export_results_view': 'تصدير عرض النتائج',
        'no_results_to_export': 'لا توجد نتائج للتصدير مع الفلاتر الحالية.',
        'exported_results': 'تم تصدير {count} نتيجة إلى {path}',
        'stop_requested': 'تم طلب الإيقاف',
        'compact': 'مضغوط',
        'comfortable': 'مريح',
        'spacious': 'واسع',
        'description': 'الوصف',
        'legal_disclaimer': """WAFPierce - إخلاء المسؤولية القانونية

لاختبار الأمان المصرح به فقط

تم توفير هذه الأداة فقط لأبحاث الأمان المشروعة واختبار الاختراق المصرح به. يجب عليك الحصول على إذن كتابي صريح من مالك النظام قبل اختبار أي شبكة أو تطبيق أو جهاز لا تملكه شخصياً.

الوصول غير المصرح به إلى أنظمة الكمبيوتر أو الشبكات أو البيانات غير قانوني وقد يؤدي إلى عقوبات جنائية و/أو مدنية بموجب القوانين المعمول بها.

بالنقر على "أوافق"، فإنك تقر وتؤكد أنك:

• ستختبر فقط الأنظمة التي تملكها أو لديك إذن كتابي صريح لاختبارها
• ستلتزم بجميع القوانين واللوائح المحلية والوطنية والدولية المعمول بها
• تتحمل المسؤولية الكاملة عن أفعالك واستخدامك لهذه الأداة
• تفهم أن سوء استخدام هذه الأداة قد يؤدي إلى عواقب قانونية

حدود المسؤولية:
لا يتحمل المطورون والمساهمون والموزعون وأصحاب WAFPierce أي مسؤولية عن سوء الاستخدام أو الضرر أو العواقب القانونية أو فقدان البيانات أو انقطاع الخدمة أو أي ضرر آخر ناتج عن استخدام هذه الأداة أو عدم القدرة على استخدامها. يتم توفير هذا البرنامج "كما هو" بدون أي ضمان من أي نوع. أنت توافق على أنك تستخدم هذه الأداة على مسؤوليتك الخاصة بالكامل.""",
    },
    'uk': {
        'window_title': 'WAFPierce - Інтерфейс',
        'target_url': 'URL цілі:',
        'add': 'Додати',
        'remove': 'Видалити',
        'settings': 'Налаштування',
        'threads': 'Потоки:',
        'concurrent': 'Паралельно:',
        'use_concurrent': 'Використовувати паралельні цілі',
        'delay': 'Затримка (с):',
        'queued': 'В черзі',
        'running': 'Виконується',
        'done': 'Завершено',
        'error': 'Помилка',
        'target': 'Ціль',
        'status': 'Статус',
        'output': 'Вивід',
        'results': '📊 Результати',
        'start': 'Старт',
        'stop': 'Стоп',
        'save': 'Зберегти',
        'clear': 'Очистити',
        'results_explorer': 'Провідник результатів',
        'sites': '🌐 Сайти',
        'all_sites': '📋 Всі сайти',
        'findings': 'знахідок',
        'total': 'Всього',
        'bypasses': 'Обходи',
        'sort_by': 'Сортувати:',
        'filter': 'Фільтр:',
        'search': 'Пошук:',
        'search_placeholder': 'Пошук технік, категорій...',
        'severity_high_low': 'Серйозність (Висока→Низька)',
        'severity_low_high': 'Серйозність (Низька→Висока)',
        'technique_az': 'Техніка (А-Я)',
        'technique_za': 'Техніка (Я-А)',
        'category': 'Категорія',
        'bypass_status': 'Статус обходу',
        'all_results': 'Всі результати',
        'critical_only': '🔴 Тільки КРИТИЧНІ',
        'high_only': '🟠 Тільки ВИСОКІ',
        'medium_only': '🟡 Тільки СЕРЕДНІ',
        'low_only': '🔵 Тільки НИЗЬКІ',
        'info_only': 'ℹ️ Тільки ІНФО',
        'bypasses_only': '✅ Тільки обходи',
        'non_bypasses_only': '❌ Тільки без обходу',
        'expand_all': 'Розгорнути все',
        'collapse_all': 'Згорнути все',
        'technique': 'Техніка',
        'severity': 'Серйозність',
        'reason': 'Причина',
        'details': 'Деталі',
        'export_view': 'Експорт',
        'close': 'Закрити',
        'no_results': 'Немає результатів',
        'no_results_msg': 'Результати сканування ще недоступні.',
        'font_size': 'Розмір шрифту (тільки у виводі):',
        'show_watermark': 'Показати водяний знак/логотип',
        'remember_targets': 'Запам\'ятати останні цілі',
        'retry_failed': 'Повторити невдалі цілі:',
        'ui_density': 'Щільність інтерфейсу:',
        'language': 'Мова:',
        'cancel': 'Скасувати',
        'saved': 'Збережено',
        'save_failed': 'Помилка збереження',
        'exported': 'Експортовано',
        'export_failed': 'Помилка експорту',
        'missing_target': 'Ціль відсутня',
        'add_target_msg': 'Будь ласка, додайте принаймні одну ціль',
        'run_finished': '[+] Сканування завершено',
        'lang_restart_warning': '⚠️ Мова зміниться після перезапуску',
        'restart_confirm': 'Потрібен перезапуск',
        'restart_confirm_msg': 'Мову змінено. Перезапустити зараз?',
        'yes': 'Так',
        'no': 'Ні',
        'legal_disclaimer_title': 'WAFPierce - ЛЕГАЛЬНИЙ ДИСКЛЕЙМЕР',
        'legal_disclaimer_header': '⚠️ ЛЕГАЛЬНИЙ ДИСКЛЕЙМЕР ⚠️',
        'i_agree': 'Погоджуюсь',
        'i_decline': 'Відхиляю',
        'clean': 'Очистити',
        'no_tmp_files': 'Немає тимчасових файлів результатів для видалення',
        'remove_files_confirm': 'Видалити {count} файлів?',
        'removed_files': 'Видалено {count} файл(ів)',
        'no_results_for': 'Немає результатів для {target}',
        'results_for': 'Результати — {target}',
        'done_exploits': 'Завершено (Експлойти)',
        'errors_label': 'Помилки',
        'errors_details': 'Деталі помилок',
        'export_results_view': 'Експорт перегляду результатів',
        'no_results_to_export': 'Немає результатів для експорту з поточними фільтрами.',
        'exported_results': 'Експортовано {count} результатів до {path}',
        'stop_requested': 'Запит на зупинку',
        'compact': 'компактний',
        'comfortable': 'комфортний',
        'spacious': 'просторий',
        'description': 'Опис',
        'legal_disclaimer': """WAFPierce – Юридична відмова

ТІЛЬКИ ДЛЯ АВТОРИЗОВАНОГО ТЕСТУВАННЯ БЕЗПЕКИ

Цей інструмент надається виключно для законних досліджень безпеки та авторизованого тестування на проникнення. Ви повинні отримати явний письмовий дозвіл від власника системи перед тестуванням будь-якої мережі, додатку або пристрою, яким ви особисто не володієте.

Несанкціонований доступ до комп'ютерних систем, мереж або даних є незаконним і може призвести до кримінальної та/або цивільної відповідальності згідно з чинним законодавством.

Натискаючи "Погоджуюсь", ви підтверджуєте, що:

• Ви будете тестувати лише системи, якими володієте або маєте явний письмовий дозвіл на тестування
• Ви будете дотримуватися всіх застосовних місцевих, національних та міжнародних законів і правил
• Ви берете на себе повну відповідальність за свої дії та використання цього інструменту
• Ви розумієте, що неправильне використання цього інструменту може призвести до юридичних наслідків

Обмеження відповідальності:
Розробники, учасники, дистриб'ютори та власники WAFPierce не несуть жодної відповідальності за неправильне використання, збитки, юридичні наслідки, втрату даних, переривання обслуговування або будь-яку іншу шкоду, що виникає внаслідок використання або неможливості використання цього інструменту. Це програмне забезпечення надається "як є" без будь-яких гарантій. Ви погоджуєтесь, що використовуєте цей інструмент повністю на власний ризик.""",
    },
}

LANGUAGE_NAMES = {
    'en': 'English',
    'ar': 'العربية (Arabic)',
    'uk': 'Українська (Ukrainian)',
}

# Exploit/technique descriptions for better identification
EXPLOIT_DESCRIPTIONS = {
    'SQL Injection': 'Attempts to inject malicious SQL code into database queries. Can lead to data theft, authentication bypass, or database manipulation.',
    'SQL Injection (Union Based)': 'Uses UNION statements to combine results from injected queries with original query results to extract data.',
    'SQL Injection (Error Based)': 'Exploits database error messages to extract information about the database structure and data.',
    'SQL Injection (Blind)': 'Infers data through true/false responses when direct output is not visible. Time-consuming but effective.',
    'SQL Injection (Time Based)': 'Uses time delays (SLEEP/WAITFOR) to infer data when no visible output is available.',
    'XSS': 'Cross-Site Scripting - Injects malicious scripts into web pages viewed by other users.',
    'XSS (Reflected)': 'Non-persistent XSS where malicious script is reflected off the web server in error messages or search results.',
    'XSS (Stored)': 'Persistent XSS where malicious script is stored on the target server and executed when users view the page.',
    'XSS (DOM Based)': 'XSS that occurs in the DOM rather than in the HTML. Payload is executed as a result of modifying the DOM.',
    'Command Injection': 'Injects OS commands through vulnerable application inputs. Can lead to full system compromise.',
    'OS Command Injection': 'Executes arbitrary operating system commands on the host server through vulnerable inputs.',
    'Path Traversal': 'Attempts to access files outside the web root directory using ../ sequences.',
    'Directory Traversal': 'Also known as dot-dot-slash attack. Accesses restricted directories and files on the server.',
    'LFI': 'Local File Inclusion - Includes local files on the server through vulnerable include mechanisms.',
    'RFI': 'Remote File Inclusion - Includes remote files from external servers, potentially executing malicious code.',
    'SSRF': 'Server-Side Request Forgery - Makes the server perform requests to unintended locations.',
    'XXE': 'XML External Entity - Exploits XML parsers to read files, perform SSRF, or cause DoS.',
    'LDAP Injection': 'Manipulates LDAP queries to bypass authentication or extract directory information.',
    'NoSQL Injection': 'Targets NoSQL databases (MongoDB, CouchDB) with specially crafted queries.',
    'Template Injection': 'Injects malicious template directives that execute on the server (SSTI).',
    'SSTI': 'Server-Side Template Injection - Executes code through template engines like Jinja2, Twig, Freemarker.',
    'Header Injection': 'Injects malicious content into HTTP headers, potentially causing response splitting.',
    'CRLF Injection': 'Injects carriage return and line feed characters to manipulate HTTP responses.',
    'Log Injection': 'Injects fake log entries that may be used for log forging or exploiting log viewers.',
    'Unicode Bypass': 'Uses Unicode encoding variations to bypass input filters and WAF rules.',
    'Encoding Bypass': 'Uses various encoding schemes (URL, Base64, Hex) to evade security filters.',
    'Case Variation': 'Alternates character cases to bypass case-sensitive security filters.',
    'Comment Bypass': 'Uses SQL/code comments to break up malicious payloads and evade detection.',
    'Whitespace Bypass': 'Uses alternative whitespace characters or removes spaces to evade pattern matching.',
    'Null Byte Injection': 'Injects null bytes (%00) to truncate strings or bypass file extension checks.',
    'Double Encoding': 'Encodes payloads twice to bypass filters that decode input once.',
    'HTTP Parameter Pollution': 'Supplies multiple parameters with the same name to confuse the application.',
    'Verb Tampering': 'Uses unexpected HTTP methods to bypass security controls.',
    'Protocol Smuggling': 'Exploits differences in protocol parsing between security devices and servers.',
    'WAF Bypass': 'Techniques specifically designed to evade Web Application Firewall detection.',
    'Rate Limit Bypass': 'Attempts to circumvent request rate limiting mechanisms.',
    'Authentication Bypass': 'Techniques to bypass login and authentication mechanisms.',
    'Authorization Bypass': 'Attempts to access resources without proper authorization.',
    'IDOR': 'Insecure Direct Object Reference - Accesses objects by manipulating reference values.',
    'Mass Assignment': 'Exploits automatic parameter binding to modify unauthorized fields.',
    'Deserialization': 'Exploits unsafe deserialization of user-controlled data.',
    'JWT Attack': 'Attacks against JSON Web Token implementations (none algorithm, key confusion).',
    'GraphQL Injection': 'Exploits GraphQL APIs through malicious queries or mutations.',
    'WebSocket Injection': 'Injects malicious data through WebSocket connections.',
    'Prototype Pollution': 'Manipulates JavaScript object prototypes to affect application behavior.',
    'Buffer Overflow': 'Sends data exceeding buffer boundaries to potentially execute arbitrary code.',
    'Format String': 'Exploits format string vulnerabilities in C-like languages.',
    'Race Condition': 'Exploits timing vulnerabilities in multi-threaded applications.',
    'Open Redirect': 'Redirects users to malicious sites through vulnerable redirect parameters.',
    'CORS Bypass': 'Exploits misconfigured Cross-Origin Resource Sharing policies.',
    'CSP Bypass': 'Techniques to bypass Content Security Policy restrictions.',
    'Cache Poisoning': 'Manipulates cache systems to serve malicious content.',
    'Host Header Injection': 'Manipulates the Host header for cache poisoning or password reset attacks.',
}

def _get_exploit_description(technique: str) -> str:
    """Get detailed description for a technique/exploit."""
    # Try exact match first
    if technique in EXPLOIT_DESCRIPTIONS:
        return EXPLOIT_DESCRIPTIONS[technique]
    # Try partial match
    technique_lower = technique.lower()
    for key, desc in EXPLOIT_DESCRIPTIONS.items():
        if key.lower() in technique_lower or technique_lower in key.lower():
            return desc
    # Check for common patterns
    if 'sql' in technique_lower:
        return EXPLOIT_DESCRIPTIONS.get('SQL Injection', 'SQL-based attack technique.')
    if 'xss' in technique_lower:
        return EXPLOIT_DESCRIPTIONS.get('XSS', 'Cross-site scripting attack.')
    if 'inject' in technique_lower:
        return 'Injection attack that attempts to insert malicious data into the application.'
    if 'bypass' in technique_lower:
        return 'Technique designed to circumvent security controls or filters.'
    if 'traversal' in technique_lower or 'lfi' in technique_lower:
        return EXPLOIT_DESCRIPTIONS.get('Path Traversal', 'File system access attack.')
    return 'Security testing technique to identify potential vulnerabilities.'

def _t(key: str, lang: str = None) -> str:
    """Get translated text for a key."""
    if lang is None:
        try:
            lang = _load_prefs().get('language', 'en')
        except Exception:
            lang = 'en'
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, TRANSLATIONS['en'].get(key, key))


def _save_prefs(prefs: dict) -> None:
    path = _get_config_path()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(prefs, f, indent=2)
    except Exception:
        pass


LEGAL_DISCLAIMER = """WAFPierce – Legal Disclaimer

FOR AUTHORIZED SECURITY TESTING ONLY

This tool is provided solely for legitimate security research and authorized penetration testing. You must obtain explicit, written permission from the system owner before testing any network, application, or device that you do not personally own.

Unauthorized access to computer systems, networks, or data is illegal and may result in criminal and/or civil penalties under applicable laws, including but not limited to the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and similar legislation in your jurisdiction.

By clicking "I Agree", you acknowledge and confirm that:

• You will only test systems that you own or have explicit written authorization to test
• You will comply with all applicable local, national, and international laws and regulations
• You accept full responsibility for your actions and use of this tool
• You understand that misuse of this tool may result in legal consequences

Limitation of Liability:
The developers, contributors, distributors, and owners of WAFPierce assume no liability for misuse, damage, legal consequences, data loss, service disruption, or any other harm resulting from the use or inability to use this tool. This software is provided "as is", without warranty of any kind, expressed or implied. You agree that you use this tool entirely at your own risk."""


def _show_missing_packages_error():
    """Show an error message when PySide6 is not installed."""
    import webbrowser
    
    print("\n" + "="*70)
    print("❌ MISSING REQUIRED PACKAGES")
    print("="*70)
    print("\nWAFPierce requires PySide6 for the graphical user interface.")
    print("\nTo install the required packages, run:")
    print("\n    pip install PySide6>=6.10.1")
    print("\n    -- OR --")
    print("\n    pip install -r requirements.txt")
    print("\nPackage Links:")
    print("  • PySide6: https://pypi.org/project/PySide6/")
    print("  • Documentation: https://doc.qt.io/qtforpython-6/")
    print("\n" + "="*70)
    
    # Try to open the PyPI page in browser
    try:
        user_input = input("\nWould you like to open the PySide6 package page in your browser? (y/n): ")
        if user_input.lower().strip() in ['y', 'yes']:
            webbrowser.open('https://pypi.org/project/PySide6/')
            print("Opening browser...")
    except (EOFError, KeyboardInterrupt):
        pass
    
    sys.exit(1)


def _show_disclaimer_qt(app) -> bool:
    """Show legal disclaimer using PySide6/Qt. Returns True if user agrees, False otherwise."""
    from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout,
                                   QLabel, QPushButton, QTextEdit)
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QFontDatabase
    
    # Get current language from prefs
    lang = _load_prefs().get('language', 'en')
    
    # Find a font that supports Unicode (Arabic, Cyrillic, etc.)
    try:
        families = set(QFontDatabase.families())
    except Exception:
        try:
            families = set(QFontDatabase().families())
        except Exception:
            families = set()
    
    # Fonts with good Unicode support (Arabic, Cyrillic, etc.)
    unicode_fonts = ["Segoe UI", "Arial", "Noto Sans", "Tahoma", "Microsoft Sans Serif", "DejaVu Sans"]
    selected_font = next((f for f in unicode_fonts if f in families), "")
    
    dialog = QDialog()
    dialog.setWindowTitle(_t('legal_disclaimer_title', lang))
    dialog.setFixedSize(650, 520)
    dialog.setStyleSheet(f"""
        QDialog {{ background-color: #0f1112; }}
        QLabel {{ color: #d7e1ea; font-family: '{selected_font}'; }}
        QTextEdit {{ background-color: #16181a; color: #d7e1ea; border: none; font-family: '{selected_font}'; }}
        QPushButton {{ padding: 12px 30px; font-size: 12px; font-weight: bold; border-radius: 4px; font-family: '{selected_font}'; }}
    """)
    
    layout = QVBoxLayout(dialog)
    layout.setSpacing(15)
    layout.setContentsMargins(20, 20, 20, 20)
    
    # Header
    header = QLabel(_t('legal_disclaimer_header', lang))
    header.setAlignment(Qt.AlignCenter)
    header.setFont(QFont(selected_font, 14, QFont.Bold))
    header.setStyleSheet('color: #ff6b6b;')
    layout.addWidget(header)
    
    # Text area
    text_edit = QTextEdit()
    text_edit.setPlainText(_t('legal_disclaimer', lang))
    text_edit.setReadOnly(True)
    text_edit.setFont(QFont(selected_font, 10))
    layout.addWidget(text_edit)
    
    # Buttons
    btn_layout = QHBoxLayout()
    btn_layout.addStretch()
    
    agree_btn = QPushButton(_t('i_agree', lang))
    agree_btn.setStyleSheet('background-color: #28a745; color: white;')
    agree_btn.setCursor(Qt.PointingHandCursor)
    
    decline_btn = QPushButton(_t('i_decline', lang))
    decline_btn.setStyleSheet('background-color: #dc3545; color: white;')
    decline_btn.setCursor(Qt.PointingHandCursor)
    
    agree_btn.clicked.connect(dialog.accept)
    decline_btn.clicked.connect(dialog.reject)
    
    btn_layout.addWidget(agree_btn)
    btn_layout.addWidget(decline_btn)
    btn_layout.addStretch()
    layout.addLayout(btn_layout)
    
    result = dialog.exec()
    return result == QDialog.DialogCode.Accepted


def main() -> None:
    # Check if PySide6 is available
    try:
        from PySide6 import QtWidgets, QtCore
        from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                                       QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
                                       QTextEdit, QLabel, QFileDialog, QMessageBox, QCheckBox,
                                       QSpinBox, QDoubleSpinBox, QHeaderView, QGraphicsOpacityEffect)
        from PySide6.QtCore import QObject, Signal, QPropertyAnimation, QTimer, QEasingCurve
        from PySide6.QtGui import QBrush, QColor, QFont, QFontDatabase
    except ImportError:
        _show_missing_packages_error()
        return

    class QtWorker(QObject):
        finished = Signal()
        log_line = Signal(str)
        target_update = Signal(str, str, int)
        tmp_created = Signal(str, str)
        results_emitted = Signal(object)
        # emit per-target summary: target, done_list, errors_list
        target_summary = Signal(str, object, object)

        def __init__(self, targets, threads, delay, concurrent=1, use_concurrent=True, retry_failed=0, parent=None):
            super().__init__(parent)
            self.targets = targets
            self.threads = threads
            self.delay = delay
            self.concurrent = concurrent
            self.use_concurrent = use_concurrent
            self.retry_failed = int(retry_failed)
            self._abort = False
            # track running subprocesses so abort() can terminate them
            self._running_procs = {}

        def abort(self):
            self._abort = True
            # try to terminate any running subprocesses
            try:
                for p in list(getattr(self, '_running_procs', {}).values()):
                    try:
                        p.terminate()
                    except Exception:
                        pass
            except Exception:
                pass

        def run(self):
            # run targets concurrently up to the configured thread limit
            if not getattr(self, 'use_concurrent', True):
                max_workers = 1
            else:
                max_workers = max(1, min(len(self.targets), max(1, int(self.concurrent))))
            self._running_procs = {}

            def run_one(target: str, idx: int):
                if self._abort:
                    self.log_line.emit(f"[!] Aborted before starting {target}\n")
                    return

                last_status = None
                success = False
                done_count = 0
                for attempt in range(self.retry_failed + 1):
                    if self._abort:
                        break
                    if attempt == 0:
                        self.log_line.emit(f"\n[*] Starting target {idx}/{len(self.targets)}: {target}\n")
                    else:
                        self.log_line.emit(f"[!] Retrying {target} (attempt {attempt + 1}/{self.retry_failed + 1})\n")
                        self.target_update.emit(target, 'Retrying', idx)
                    self.target_update.emit(target, 'Running', idx)

                    tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
                    tmpf.close()
                    tmp_path = tmpf.name
                    try:
                        self.tmp_created.emit(target, tmp_path)
                    except Exception:
                        pass

                    # Use -u flag for unbuffered Python output to get real-time streaming
                    cmd = [sys.executable, '-u', '-m', 'wafpierce.pierce', target, '-t', str(self.threads), '-d', str(self.delay), '-o', tmp_path]
                    env = os.environ.copy()
                    env['PYTHONIOENCODING'] = 'utf-8'
                    env['PYTHONUNBUFFERED'] = '1'  # Force unbuffered output
                    try:
                        proc = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            encoding='utf-8',
                            errors='replace',
                            bufsize=1,  # Line buffered
                            env=env
                        )
                    except Exception as e:
                        self.log_line.emit(f"[!] Failed to start scanner for {target}: {e}\n")
                        last_status = 'Error'
                        continue

                    self._running_procs[target] = proc

                    log_lines = []
                    try:
                        if proc.stdout is not None:
                            for line in proc.stdout:
                                log_lines.append(line)
                                self.log_line.emit(line)
                                if self._abort:
                                    try:
                                        proc.terminate()
                                    except Exception:
                                        pass
                                    break
                    except Exception as e:
                        self.log_line.emit(f"[!] Error reading output for {target}: {e}\n")

                    proc.wait()
                    self._running_procs.pop(target, None)

                    if os.path.exists(tmp_path):
                        try:
                            with open(tmp_path, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                done_list = data if isinstance(data, list) else []
                                if isinstance(data, list):
                                    # Add target URL to each result
                                    for item in data:
                                        if isinstance(item, dict) and 'target' not in item:
                                            item['target'] = target
                                    self.log_line.emit(f"[+] Loaded {len(data)} result(s) from {tmp_path}\n")
                                    try:
                                        self.results_emitted.emit(data)
                                    except Exception:
                                        pass
                                    # parse errors from log_lines
                                    errors = []
                                    joined = '\n'.join(log_lines).lower()
                                    import re
                                    m = re.search(r"\[!\] Warning: (\d+) techniques encountered errors", joined)
                                    if m:
                                        try:
                                            cnt = int(m.group(1))
                                            errors.append(f"{cnt} technique errors")
                                        except Exception:
                                            pass
                                    # also collect traceback / exception lines
                                    for ln in log_lines:
                                        low = ln.lower()
                                        if 'traceback' in low or 'exception' in low or 'error:' in low:
                                            errors.append(ln.strip())
                                    try:
                                        self.target_summary.emit(target, done_list, errors)
                                    except Exception:
                                        pass
                                    success = True
                                    done_count = len(done_list)
                                    last_status = 'Done'
                                    break
                                else:
                                    self.log_line.emit(f"[!] Results file for {target} did not contain a list\n")
                                    last_status = 'NoResults'
                        except Exception:
                            self.log_line.emit(f"[!] No JSON results or failed to parse results for {target}\n")
                            last_status = 'ParseError'

                if self._abort:
                    self.log_line.emit('[!] Scan aborted by user\n')
                    self.target_update.emit(target, 'Aborted', 0)
                elif success:
                    self.target_update.emit(target, 'Done', done_count)
                else:
                    self.target_update.emit(target, last_status or 'Error', 0)

            # run with a small thread pool inside this QThread
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures = [ex.submit(run_one, target, idx) for idx, target in enumerate(self.targets, start=1)]
                    for fut in concurrent.futures.as_completed(futures):
                        if self._abort:
                            # terminate any remaining procs
                            for p in list(self._running_procs.values()):
                                try:
                                    p.terminate()
                                except Exception:
                                    pass
                            break
            except Exception as e:
                self.log_line.emit(f"[!] Worker execution error: {e}\n")

            self.finished.emit()

    class PierceQtApp(QWidget):
        def __init__(self):
            super().__init__()
            # Get current language
            self._lang = _load_prefs().get('language', 'en')
            self.setWindowTitle(_t('window_title', self._lang))

            self._worker_thread = None
            self._worker = None
            self._results = []
            self._tmp_result_paths = []
            self._target_tmp_map = {}
            # per-target storage for Qt: {'done': [], 'errors': [], 'tmp': path}
            self._per_target_results = {}
            
            # Easter egg state
            self._konami_sequence = []
            self._konami_code = ['up', 'up', 'down', 'down', 'left', 'right', 'left', 'right', 'b', 'a']
            self._title_clicks = 0
            self._hacker_mode = False

            # load prefs and build UI
            try:
                self._prefs = _load_prefs()
            except Exception:
                self._prefs = {'theme': 'dark', 'font_size': 11}
            try:
                size = self._prefs.get('qt_geometry', '1000x640')
                if isinstance(size, str) and 'x' in size:
                    w, h = size.split('x', 1)
                    self.resize(int(float(w)), int(float(h)))
                else:
                    self.resize(1000, 640)
            except Exception:
                self.resize(1000, 640)
            self._build_ui()
            try:
                self._apply_qt_prefs(self._prefs)
            except Exception:
                pass
            try:
                self._restore_qt_targets()
            except Exception:
                pass

        def _build_ui(self):
            v = QVBoxLayout(self)
            self._layout_main = v

            # top controls
            top = QHBoxLayout()
            self._layout_top = top
            self.target_edit = QLineEdit()
            try:
                self.target_edit.setPlaceholderText('https://example.com')
                # Easter egg: special target commands
                self.target_edit.textChanged.connect(self._check_easter_egg_input)
            except Exception:
                pass
            add_btn = QPushButton(_t('add', self._lang))
            add_btn.clicked.connect(self.add_target)
            remove_btn = QPushButton(_t('remove', self._lang))
            remove_btn.clicked.connect(self.remove_selected)
            top.addWidget(QLabel(_t('target_url', self._lang)))
            top.addWidget(self.target_edit)
            top.addWidget(add_btn)
            top.addWidget(remove_btn)
            # small compact settings button at the top-right
            try:
                top.addStretch()
                sbtn = QPushButton(_t('settings', self._lang))
                sbtn.setFixedHeight(28)
                sbtn.clicked.connect(self._open_qt_settings)
                top.addWidget(sbtn)
            except Exception:
                pass
            v.addLayout(top)

            # options (threads / delay)
            opts = QHBoxLayout()
            self._layout_opts = opts
            self.threads_spin = QSpinBox()
            self.threads_spin.setRange(1, 200)
            try:
                self.threads_spin.setValue(int(self._prefs.get('threads', 5)))
            except Exception:
                self.threads_spin.setValue(5)
            self.delay_spin = QDoubleSpinBox()
            self.delay_spin.setRange(0.0, 5.0)
            self.delay_spin.setSingleStep(0.05)
            try:
                self.delay_spin.setValue(float(self._prefs.get('delay', 0.2)))
            except Exception:
                self.delay_spin.setValue(0.2)
            self.concurrent_spin = QSpinBox()
            self.concurrent_spin.setRange(1, 200)
            try:
                self.concurrent_spin.setValue(int(self._prefs.get('concurrent', 2)))
            except Exception:
                self.concurrent_spin.setValue(2)
            # default to sequential execution (one target at a time)
            self.use_concurrent_chk = QCheckBox(_t('use_concurrent', self._lang))
            try:
                self.use_concurrent_chk.setChecked(bool(self._prefs.get('use_concurrent', False)))
            except Exception:
                self.use_concurrent_chk.setChecked(False)
            opts.addWidget(QLabel(_t('threads', self._lang)))
            opts.addWidget(self.threads_spin)
            opts.addWidget(QLabel(_t('concurrent', self._lang)))
            opts.addWidget(self.concurrent_spin)
            opts.addWidget(self.use_concurrent_chk)
            opts.addSpacing(10)
            opts.addWidget(QLabel(_t('delay', self._lang)))
            opts.addWidget(self.delay_spin)
            v.addLayout(opts)

            # legend for status colors
            try:
                legend_h = QHBoxLayout()
                # keep references so we can update counts live
                self._legend_labels = {}
                def _legend_label(key, text, color):
                    lbl = QLabel(f"{text} (0)")
                    lbl.setStyleSheet(f'background:{color}; padding:4px; color: white; border-radius:3px')
                    self._legend_labels[key] = lbl
                    return lbl
                legend_h.addWidget(_legend_label('queued', _t('queued', self._lang), '#2b2f33'))
                legend_h.addWidget(_legend_label('running', _t('running', self._lang), '#3b82f6'))
                legend_h.addWidget(_legend_label('done', _t('done', self._lang), '#163f19'))
                legend_h.addWidget(_legend_label('error', _t('error', self._lang), '#ff4d4d'))
                v.addLayout(legend_h)
            except Exception:
                pass

            # middle: tree and log
            middle = QHBoxLayout()
            self._layout_middle = middle
            self.tree = QTreeWidget()
            self.tree.setColumnCount(2)
            self.tree.setHeaderLabels([_t('target', self._lang), _t('status', self._lang)])
            try:
                header = self.tree.header()
                header.setStretchLastSection(False)
                header.setSectionResizeMode(0, QHeaderView.Stretch)
                header.setSectionResizeMode(1, QHeaderView.Fixed)
                self.tree.setColumnWidth(1, 120)
            except Exception:
                pass
            self.tree.itemDoubleClicked.connect(self.show_target_details)
            # single-click status to open details as well
            try:
                self.tree.itemClicked.connect(self._on_qt_item_clicked)
            except Exception:
                pass
            middle.addWidget(self.tree, 2)

            right_v = QVBoxLayout()
            self._layout_right = right_v
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            # Prefer modern fonts for Qt widgets when available
            try:
                mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    # fallback when API differs or method is not available
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                mono = next((f for f in mono_candidates if f in families), None)
                if mono:
                    self.log.setFont(QFont(mono, 10))
                else:
                    ui_candidates = ["Segoe UI", "Inter", "Helvetica", "Arial"]
                    ui = next((f for f in ui_candidates if f in families), None)
                    if ui:
                        self.log.setFont(QFont(ui, 10))
            except Exception:
                pass
            # attempt to set a faint watermark background using the bundled logo
            try:
                if os.path.exists(LOGO_PATH):
                    theme = self._prefs.get('theme', 'dark')
                    opacity = 0.18 if theme == 'light' else 0.08
                    tmp = self._create_qt_watermark(opacity)
                    if tmp and os.path.exists(tmp):
                        try:
                            from pathlib import Path
                            css_path = Path(tmp).as_posix()
                        except Exception:
                            css_path = tmp.replace('\\', '/')
                        self.log.setStyleSheet(
                            f"background-image: url('{css_path}'); background-repeat: no-repeat; background-position: center; background-attachment: fixed;"
                        )
            except Exception:
                pass
            right_v.addWidget(QLabel(_t('output', self._lang)))
            right_v.addWidget(self.log, 1)
            # Results button at bottom of output area
            self.results_btn = QPushButton(_t('results', self._lang))
            self.results_btn.setEnabled(False)
            self.results_btn.setFixedHeight(40)
            self._results_btn_base_style = '''
                QPushButton {
                    background-color: #2b2f33;
                    color: #d7e1ea;
                    border: none;
                    padding: 8px 20px;
                    border-radius: 5px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #3b4045;
                }
                QPushButton:disabled {
                    background-color: #1e2124;
                    color: #666;
                }
            '''
            self._results_btn_green_style = '''
                QPushButton {
                    background-color: #22c55e;
                    color: #000000;
                    border: none;
                    padding: 8px 20px;
                    border-radius: 5px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #16a34a;
                }
            '''
            self.results_btn.setStyleSheet(self._results_btn_base_style)
            self.results_btn.clicked.connect(self.show_results_summary)
            right_v.addWidget(self.results_btn)
            
            # Setup pulsating animation for Results button
            self._results_pulse_effect = QGraphicsOpacityEffect(self.results_btn)
            self.results_btn.setGraphicsEffect(self._results_pulse_effect)
            self._results_pulse_effect.setOpacity(1.0)
            self._results_pulse_anim = QPropertyAnimation(self._results_pulse_effect, b'opacity')
            self._results_pulse_anim.setDuration(1000)
            self._results_pulse_anim.setStartValue(1.0)
            self._results_pulse_anim.setEndValue(0.6)
            self._results_pulse_anim.setEasingCurve(QEasingCurve.InOutSine)
            self._results_pulse_anim.setLoopCount(-1)  # Infinite loop
            # Make it pulse back and forth
            self._results_pulse_anim.finished.connect(lambda: None)  # placeholder
            self._results_pulse_timer = QTimer()
            self._results_pulse_timer.timeout.connect(self._toggle_pulse_direction)
            self._results_pulse_forward = True
            
            middle.addLayout(right_v, 3)
            v.addLayout(middle, 1)

            # bottom controls
            bottom = QHBoxLayout()
            self._layout_bottom = bottom
            self.start_btn = QPushButton(_t('start', self._lang))
            self.start_btn.clicked.connect(self.start_scan)
            self.stop_btn = QPushButton(_t('stop', self._lang))
            self.stop_btn.setEnabled(False)
            self.stop_btn.clicked.connect(self.stop_scan)
            self.save_btn = QPushButton(_t('save', self._lang))
            self.save_btn.setEnabled(False)
            self.save_btn.clicked.connect(self.save_results)
            # cleanup button: clear temp files and also clear the UI
            self.clean_btn = QPushButton(_t('clear', self._lang))
            # when clicked by user from the UI, also clear the site list and outputs
            try:
                self.clean_btn.clicked.connect(lambda: self.clean_tmp_files(False, True))
            except Exception:
                try:
                    self.clean_btn.clicked.connect(self.clean_tmp_files)
                except Exception:
                    pass
            # removed bottom Settings button (moved to top controls)
            bottom.addWidget(self.start_btn)
            bottom.addWidget(self.stop_btn)
            bottom.addWidget(self.save_btn)
            bottom.addWidget(self.clean_btn)
            v.addLayout(bottom)

        def append_log(self, text: str):
            self.log.append(text)

        def _toggle_pulse_direction(self):
            """Toggle pulsating animation direction for Results button."""
            try:
                if self._results_pulse_forward:
                    self._results_pulse_anim.setStartValue(1.0)
                    self._results_pulse_anim.setEndValue(0.6)
                else:
                    self._results_pulse_anim.setStartValue(0.6)
                    self._results_pulse_anim.setEndValue(1.0)
                self._results_pulse_forward = not self._results_pulse_forward
                self._results_pulse_anim.start()
            except Exception:
                pass

        def _start_results_pulse(self):
            """Start the pulsating animation on the Results button."""
            try:
                self._results_pulse_forward = True
                self._results_pulse_anim.setStartValue(1.0)
                self._results_pulse_anim.setEndValue(0.6)
                self._results_pulse_anim.setLoopCount(1)
                self._results_pulse_anim.finished.connect(self._toggle_pulse_direction)
                self._results_pulse_anim.start()
            except Exception:
                pass

        def _stop_results_pulse(self):
            """Stop the pulsating animation and reset opacity."""
            try:
                self._results_pulse_anim.stop()
                self._results_pulse_effect.setOpacity(1.0)
            except Exception:
                pass

        # ==================== EASTER EGGS ====================
        
        def keyPressEvent(self, event):
            """Track key presses for Konami code easter egg."""
            try:
                from PySide6.QtCore import Qt
                key_map = {
                    Qt.Key_Up: 'up', Qt.Key_Down: 'down',
                    Qt.Key_Left: 'left', Qt.Key_Right: 'right',
                    Qt.Key_B: 'b', Qt.Key_A: 'a'
                }
                key = key_map.get(event.key())
                if key:
                    self._konami_sequence.append(key)
                    # Keep only last 10 keys
                    self._konami_sequence = self._konami_sequence[-10:]
                    if self._konami_sequence == self._konami_code:
                        self._trigger_konami_easter_egg()
                        self._konami_sequence = []
            except Exception:
                pass
            try:
                super().keyPressEvent(event)
            except Exception:
                pass

        def _check_easter_egg_input(self, text):
            """Check for special easter egg commands in target input."""
            try:
                lower = text.lower().strip()
                if lower == 'matrix':
                    self._trigger_matrix_easter_egg()
                    self.target_edit.clear()
                elif lower == 'hack the planet':
                    self._trigger_hacktheplanet_easter_egg()
                    self.target_edit.clear()
                elif lower == 'whoami':
                    self._trigger_whoami_easter_egg()
                    self.target_edit.clear()
                elif lower == '1337':
                    self._trigger_leet_easter_egg()
                    self.target_edit.clear()
            except Exception:
                pass

        def _trigger_konami_easter_egg(self):
            """Konami code activated - HACKER MODE!"""
            try:
                self._hacker_mode = not self._hacker_mode
                if self._hacker_mode:
                    self.setWindowTitle('WAFPierce - [HACKER MODE ACTIVATED] 💀')
                    self.append_log('\n' + '='*50)
                    self.append_log('🎮 KONAMI CODE ACTIVATED!')
                    self.append_log('💀 H A C K E R   M O D E   E N G A G E D 💀')
                    self.append_log('='*50)
                    self.append_log('"With great power comes great responsibility."')
                    self.append_log('='*50 + '\n')
                    # Add green glow effect
                    self.setStyleSheet(self.styleSheet() + '''
                        QWidget { border: 2px solid #00ff00; }
                    ''')
                else:
                    self.setWindowTitle('WAFPierce - GUI (Qt)')
                    self.append_log('\n[*] Hacker mode deactivated. Back to normal.\n')
                    # Remove glow - reload theme
                    try:
                        self._apply_qt_prefs(self._prefs)
                    except Exception:
                        pass
            except Exception:
                pass

        def _trigger_matrix_easter_egg(self):
            """Matrix rain effect in the log."""
            try:
                import random
                self.append_log('\n' + '='*50)
                self.append_log('🟢 ENTERING THE MATRIX... 🟢')
                self.append_log('='*50)
                chars = 'ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ01'
                for _ in range(5):
                    line = ''.join(random.choice(chars) for _ in range(40))
                    self.append_log(f'  {line}')
                self.append_log('='*50)
                self.append_log('"There is no spoon." - The Matrix')
                self.append_log('='*50 + '\n')
            except Exception:
                pass

        def _trigger_hacktheplanet_easter_egg(self):
            """Hackers (1995) movie reference."""
            try:
                self.append_log('\n' + '='*50)
                self.append_log('🌍 HACK THE PLANET! 🌍')
                self.append_log('='*50)
                quotes = [
                    '"Mess with the best, die like the rest."',
                    '"Never send a boy to do a woman\'s job."',
                    '"Type cookie, you idiot!"',
                    '"It\'s in that place where I put that thing that time."',
                    '"RISC is good."',
                ]
                import random
                self.append_log(f'  {random.choice(quotes)}')
                self.append_log('  - Hackers (1995)')
                self.append_log('='*50 + '\n')
            except Exception:
                pass

        def _trigger_whoami_easter_egg(self):
            """Classic whoami command."""
            try:
                import os
                import socket
                user = os.getenv('USERNAME') or os.getenv('USER') or 'l33t_hacker'
                host = socket.gethostname()
                self.append_log('\n' + '='*50)
                self.append_log('🔍 IDENTITY CHECK 🔍')
                self.append_log('='*50)
                self.append_log(f'  User: {user}')
                self.append_log(f'  Host: {host}')
                self.append_log(f'  Status: Certified Penetration Tester 🎖️')
                self.append_log(f'  Threat Level: MAXIMUM 💀')
                self.append_log('='*50 + '\n')
            except Exception:
                pass

        def _trigger_leet_easter_egg(self):
            """1337 speak mode."""
            try:
                self.append_log('\n' + '='*50)
                self.append_log('1337 H4X0R M0D3 4C71V473D!')
                self.append_log('='*50)
                self.append_log('  Y0U 4R3 N0W 4 7RU3 H4CK3R!')
                self.append_log('  R3M3MB3R: W17H GR347 P0W3R...')
                self.append_log('  C0M35 GR347 R35P0N51B1L17Y!')
                self.append_log('='*50)
                self.append_log('  PR0 71P: Try "hack the planet" 😉')
                self.append_log('='*50 + '\n')
            except Exception:
                pass

        # ==================== END EASTER EGGS ====================

        def add_target(self):
            text = self.target_edit.text().strip()
            if not text:
                return
            parts = [p.strip() for p in text.replace(',', '\n').splitlines() if p.strip()]
            existing = [self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
            for p in parts:
                if p in existing:
                    continue
                it = QTreeWidgetItem([p, 'Queued'])
                it.setData(0, 0, p)
                self.tree.addTopLevelItem(it)
            self.target_edit.clear()
            try:
                self._update_legend_counts()
            except Exception:
                pass

        def _on_qt_item_clicked(self, item, col):
            try:
                # if user clicked the status column (index 1) or the status text indicates done/error
                status = item.text(1).lower()
                if col == 1 or 'done' in status or 'error' in status or '❌' in item.text(1):
                    self.show_target_details(item, col)
            except Exception:
                pass

        def remove_selected(self):
            # remove selected top-level items from the tree
            sels = self.tree.selectedItems()
            if not sels:
                return
            for it in sels:
                try:
                    idx = self.tree.indexOfTopLevelItem(it)
                    self.tree.takeTopLevelItem(idx)
                except Exception:
                    try:
                        # fallback: iterate and remove by text match
                        txt = it.text(0)
                        for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                            if self.tree.topLevelItem(i).text(0) == txt:
                                self.tree.takeTopLevelItem(i)
                    except Exception:
                        pass
            try:
                self._update_legend_counts()
            except Exception:
                pass

        def clear_all(self):
            """Remove all targets and clear logs and internal state for the Qt UI."""
            try:
                # request abort of any running worker
                try:
                    if getattr(self, '_worker', None):
                        self._worker.abort()
                except Exception:
                    pass
                # remove all items
                for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                    try:
                        self.tree.takeTopLevelItem(i)
                    except Exception:
                        pass
                # clear log and reset internal state
                try:
                    self.log.clear()
                except Exception:
                    try:
                        self.log.setPlainText('')
                    except Exception:
                        pass
                self._results = []
                self._tmp_result_paths = []
                self._target_tmp_map = {}
                self._per_target_results = {}
                try:
                    self.save_btn.setEnabled(False)
                    self.results_btn.setEnabled(False)
                    self._stop_results_pulse()
                    self.results_btn.setStyleSheet(self._results_btn_base_style)
                except Exception:
                    pass
            except Exception:
                pass

        def start_scan(self):
            if self._worker_thread is not None:
                return
            targets = [self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
            if not targets:
                t = self.target_edit.text().strip()
                if t:
                    targets = [t]
            if not targets:
                QMessageBox.warning(self, _t('missing_target', self._lang), _t('add_target_msg', self._lang))
                return
            threads = int(self.threads_spin.value())
            delay = float(self.delay_spin.value())
            # reset
            self._results = []
            self._tmp_result_paths = []
            self._target_tmp_map = {}

            concurrent_val = int(self.concurrent_spin.value())
            use_concurrent = bool(self.use_concurrent_chk.isChecked())
            retry_failed = int(self._prefs.get('retry_failed', 0))

            # persist runtime prefs
            try:
                prefs = _load_prefs()
                prefs['threads'] = threads
                prefs['delay'] = delay
                prefs['concurrent'] = concurrent_val
                prefs['use_concurrent'] = use_concurrent
                prefs['qt_geometry'] = f"{self.width()}x{self.height()}"
                _save_prefs(prefs)
                self._prefs = prefs
            except Exception:
                pass
            self._worker = QtWorker(targets, threads, delay, concurrent_val, use_concurrent, retry_failed)
            self._worker_thread = QtCore.QThread()
            self._worker.moveToThread(self._worker_thread)
            self._worker.log_line.connect(self.append_log)
            self._worker.target_update.connect(self._on_target_update)
            self._worker.tmp_created.connect(self._on_tmp_created)
            self._worker.results_emitted.connect(self._on_results_emitted)
            self._worker.target_summary.connect(self._on_target_summary)
            self._worker.finished.connect(self._on_finished)
            self._worker_thread.started.connect(self._worker.run)
            self._worker_thread.start()
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            # disable controls while running
            try:
                self.threads_spin.setEnabled(False)
                self.delay_spin.setEnabled(False)
            except Exception:
                pass

        def stop_scan(self):
            if self._worker:
                self._worker.abort()
            self.stop_btn.setEnabled(False)
            self.append_log('[!] ' + _t('stop_requested', self._lang))

        def _on_target_update(self, target, status, extra):
            # update tree row matching target
            for i in range(self.tree.topLevelItemCount()):
                it = self.tree.topLevelItem(i)
                if it.text(0) == target:
                    if status == 'Done':
                        it.setText(1, f'Done ({extra})')
                        try:
                            it.setBackground(0, QBrush(QColor('#163f19')))
                        except Exception:
                            pass
                    elif status == 'Running':
                        it.setText(1, 'Running')
                        try:
                            it.setBackground(0, QBrush(QColor('#3b82f6')))
                        except Exception:
                            pass
                    else:
                        it.setText(1, status)
                    break
            try:
                self._update_legend_counts()
            except Exception:
                pass

        def _on_tmp_created(self, target, tmp_path):
            try:
                self._target_tmp_map[target] = tmp_path
            except Exception:
                pass
            try:
                self._tmp_result_paths.append(tmp_path)
            except Exception:
                pass
            # ensure per-target entry exists
            try:
                self._per_target_results.setdefault(target, {'done': [], 'errors': [], 'tmp': tmp_path})
                self._per_target_results[target]['tmp'] = tmp_path
            except Exception:
                pass

        def _update_legend_counts(self):
            try:
                if not getattr(self, '_legend_labels', None):
                    return
                counts = {'queued': 0, 'running': 0, 'done': 0, 'error': 0}
                for i in range(self.tree.topLevelItemCount()):
                    it = self.tree.topLevelItem(i)
                    st = (it.text(1) or '').lower()
                    if 'running' in st:
                        counts['running'] += 1
                    elif 'done' in st:
                        counts['done'] += 1
                    elif 'error' in st or '❌' in it.text(1) or 'parseerror' in st or 'noresults' in st or 'aborted' in st:
                        counts['error'] += 1
                    else:
                        counts['queued'] += 1
                mapping = {
                    'queued': _t('queued', self._lang),
                    'running': _t('running', self._lang),
                    'done': _t('done', self._lang),
                    'error': _t('error', self._lang)
                }
                for k, v in counts.items():
                    lbl = self._legend_labels.get(k)
                    if not lbl:
                        continue
                    try:
                        lbl.setText(f"{mapping.get(k, k.title())} ({v})")
                    except Exception:
                        pass
            except Exception:
                pass

        def _on_results_emitted(self, data):
            try:
                if isinstance(data, list):
                    self._results.extend(data)
                    # enable save and results buttons when we have any results
                    if self._results:
                        self.save_btn.setEnabled(True)
                        self.results_btn.setEnabled(True)
            except Exception:
                pass

        def _on_target_summary(self, target, done_list, errors):
            try:
                self._per_target_results[target] = {
                    'done': list(done_list) if isinstance(done_list, list) else [],
                    'errors': list(errors) if isinstance(errors, list) else [],
                    'tmp': self._target_tmp_map.get(target)
                }
            except Exception:
                pass

        def _on_finished(self):
            self.append_log(_t('run_finished', self._lang))
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            try:
                self.threads_spin.setEnabled(True)
                self.delay_spin.setEnabled(True)
            except Exception:
                pass
            # Change Results button to green when scan is done and has results, start pulsating
            try:
                if self._results:
                    self.results_btn.setEnabled(True)
                    self.results_btn.setStyleSheet(self._results_btn_green_style)
                    self._start_results_pulse()
            except Exception:
                pass
            # auto-clean removed; no automatic cleanup on finish
            # clean up worker thread
            try:
                if self._worker_thread is not None:
                    self._worker_thread.quit()
                    self._worker_thread.wait()
            except Exception:
                pass
            self._worker = None
            self._worker_thread = None
            try:
                self._update_legend_counts()
            except Exception:
                pass

        def _open_qt_settings(self):
            try:
                dlg = QtWidgets.QDialog(self)
                dlg.setWindowTitle(_t('settings', self._lang))
                layout = QtWidgets.QVBoxLayout(dlg)

                try:
                    prefs = _load_prefs()
                except Exception:
                    prefs = {}

                # font size
                h2 = QtWidgets.QHBoxLayout()
                h2.addWidget(QLabel(_t('font_size', self._lang)))
                font_spin = QSpinBox()
                font_spin.setRange(8, 20)
                try:
                    font_spin.setValue(int(prefs.get('font_size', 11)))
                except Exception:
                    font_spin.setValue(11)
                h2.addWidget(font_spin)
                layout.addLayout(h2)

                # watermark
                wm_chk = QCheckBox(_t('show_watermark', self._lang))
                try:
                    wm_chk.setChecked(bool(prefs.get('watermark', True)))
                except Exception:
                    wm_chk.setChecked(True)
                layout.addWidget(wm_chk)

                # remember targets
                remember_chk = QCheckBox(_t('remember_targets', self._lang))
                try:
                    remember_chk.setChecked(bool(prefs.get('remember_targets', True)))
                except Exception:
                    remember_chk.setChecked(True)
                layout.addWidget(remember_chk)

                # retry failed
                retry_layout = QtWidgets.QHBoxLayout()
                retry_layout.addWidget(QLabel(_t('retry_failed', self._lang)))
                retry_spin = QSpinBox()
                retry_spin.setRange(0, 5)
                try:
                    retry_spin.setValue(int(prefs.get('retry_failed', 0)))
                except Exception:
                    retry_spin.setValue(0)
                retry_layout.addWidget(retry_spin)
                layout.addLayout(retry_layout)

                # UI density
                density_layout = QtWidgets.QHBoxLayout()
                density_layout.addWidget(QLabel(_t('ui_density', self._lang)))
                density_combo = QtWidgets.QComboBox()
                density_combo.addItems([_t('compact', self._lang), _t('comfortable', self._lang), _t('spacious', self._lang)])
                try:
                    current_density = prefs.get('ui_density', 'comfortable')
                    density_map = {'compact': 0, 'comfortable': 1, 'spacious': 2}
                    density_combo.setCurrentIndex(density_map.get(current_density, 1))
                except Exception:
                    pass
                density_layout.addWidget(density_combo)
                layout.addLayout(density_layout)

                # Language selection
                lang_layout = QtWidgets.QHBoxLayout()
                lang_layout.addWidget(QLabel(_t('language')))
                lang_combo = QtWidgets.QComboBox()
                for code, name in LANGUAGE_NAMES.items():
                    lang_combo.addItem(name, code)
                try:
                    current_lang = prefs.get('language', 'en')
                    idx = list(LANGUAGE_NAMES.keys()).index(current_lang)
                    lang_combo.setCurrentIndex(idx)
                except Exception:
                    lang_combo.setCurrentIndex(0)
                lang_layout.addWidget(lang_combo)
                layout.addLayout(lang_layout)
                
                # Note about language change - updates dynamically when language selection changes
                lang_note = QLabel(_t('lang_restart_warning'))
                lang_note.setStyleSheet('color: #888; font-size: 10px;')
                layout.addWidget(lang_note)
                
                # Update warning text when language selection changes
                def _update_lang_warning():
                    selected_lang = lang_combo.currentData()
                    lang_note.setText(_t('lang_restart_warning', selected_lang))
                
                lang_combo.currentIndexChanged.connect(_update_lang_warning)

                btn_h = QtWidgets.QHBoxLayout()
                save_btn = QPushButton(_t('save'))
                cancel_btn = QPushButton(_t('cancel'))
                btn_h.addWidget(save_btn)
                btn_h.addWidget(cancel_btn)
                layout.addLayout(btn_h)

                def _save_qt():
                    try:
                        old_lang = prefs.get('language', 'en')
                        new_lang = lang_combo.currentData()
                        
                        prefs['font_size'] = int(font_spin.value())
                        prefs['watermark'] = bool(wm_chk.isChecked())
                        prefs['remember_targets'] = bool(remember_chk.isChecked())
                        prefs['retry_failed'] = int(retry_spin.value())
                        # Map density index back to key
                        density_keys = ['compact', 'comfortable', 'spacious']
                        prefs['ui_density'] = density_keys[density_combo.currentIndex()]
                        prefs['language'] = new_lang
                        _save_prefs(prefs)
                        self._prefs = prefs
                        self._apply_qt_prefs(prefs)
                        
                        # If language changed, ask to restart
                        if old_lang != new_lang:
                            dlg.accept()
                            reply = QMessageBox.question(
                                self,
                                _t('restart_confirm', new_lang),
                                _t('restart_confirm_msg', new_lang),
                                QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.Yes
                            )
                            if reply == QMessageBox.Yes:
                                # Restart the application
                                import sys
                                import os
                                python = sys.executable
                                os.execl(python, python, *sys.argv)
                            return
                    except Exception:
                        pass
                    try:
                        dlg.accept()
                    except Exception:
                        dlg.close()

                save_btn.clicked.connect(_save_qt)
                cancel_btn.clicked.connect(dlg.reject)
                dlg.exec()
            except Exception:
                pass

        def _apply_qt_prefs(self, prefs: dict):
            try:
                size = int(prefs.get('font_size', 11))
            except Exception:
                size = 11
            try:
                mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                mono = next((f for f in mono_candidates if f in families), None)
                if mono:
                    f = QFont(mono, size)
                    self.log.setFont(f)
                else:
                    pass
            except Exception:
                pass
            show_watermark = prefs.get('watermark', True)
            try:
                self.setStyleSheet('')
            except Exception:
                pass
            try:
                density = prefs.get('ui_density', 'comfortable')
                if density == 'compact':
                    spacing = 4
                    margins = 6
                    rowheight = 20
                elif density == 'spacious':
                    spacing = 10
                    margins = 12
                    rowheight = 28
                else:
                    spacing = 6
                    margins = 8
                    rowheight = 24
                for layout in [getattr(self, '_layout_main', None), getattr(self, '_layout_top', None),
                               getattr(self, '_layout_opts', None), getattr(self, '_layout_middle', None),
                               getattr(self, '_layout_right', None), getattr(self, '_layout_bottom', None)]:
                    if layout is None:
                        continue
                    layout.setSpacing(spacing)
                    try:
                        layout.setContentsMargins(margins, margins, margins, margins)
                    except Exception:
                        pass
                try:
                    self.tree.setStyleSheet(f"QTreeWidget::item{{height:{rowheight}px;}}")
                except Exception:
                    pass
            except Exception:
                pass
            try:
                if show_watermark:
                    tmp = self._create_qt_watermark(0.08)
                    if tmp and os.path.exists(tmp):
                        try:
                            from pathlib import Path
                            css_path = Path(tmp).as_posix()
                        except Exception:
                            css_path = tmp.replace('\\', '/')
                        self.log.setStyleSheet(
                            f"background-image: url('{css_path}'); background-repeat: no-repeat; background-position: center; background-attachment: fixed;"
                        )
                else:
                    self.log.setStyleSheet('')
            except Exception:
                pass

        def _restore_qt_targets(self):
            if not bool(self._prefs.get('remember_targets', True)):
                return
            targets = self._prefs.get('last_targets', [])
            if not isinstance(targets, list):
                return
            existing = {self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())}
            for t in targets:
                if not isinstance(t, str) or not t.strip() or t in existing:
                    continue
                item = QTreeWidgetItem([t, 'Queued'])
                self.tree.addTopLevelItem(item)

        def _create_qt_watermark(self, opacity: float = 0.08):
            try:
                if not os.path.exists(LOGO_PATH):
                    return None
                from PySide6.QtGui import QPixmap, QPainter
                from PySide6.QtCore import Qt
                pix = QPixmap(LOGO_PATH)
                if pix.isNull():
                    return None
                scaled = pix.scaled(400, 400, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                tmpf.close()
                trans = QPixmap(scaled.size())
                trans.fill(Qt.transparent)
                p = QPainter(trans)
                try:
                    p.setOpacity(opacity)
                    p.drawPixmap(0, 0, scaled)
                finally:
                    p.end()
                trans.save(tmpf.name)
                self._qt_watermark_tmp = tmpf.name
                return tmpf.name
            except Exception:
                return None

        def save_results(self):
            path, _ = QFileDialog.getSaveFileName(self, _t('save', self._lang), filter='JSON (*.json)')
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(self._results, f, indent=2)
                QMessageBox.information(self, _t('saved', self._lang), f'{_t("saved", self._lang)}: {path}')
                # auto-clean removed; do not clean automatically after save
            except Exception as e:
                QMessageBox.critical(self, _t('save_failed', self._lang), str(e))

        def show_results_summary(self):
            """Show results organized by severity and target in a separate dialog with site list."""
            if not self._results:
                QMessageBox.information(self, _t('no_results', self._lang), _t('no_results_msg', self._lang))
                return
            
            # Constants
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            severity_icons = {'CRITICAL': '\U0001F534', 'HIGH': '\U0001F7E0', 'MEDIUM': '\U0001F7E1', 'LOW': '\U0001F535', 'INFO': '\u2139\ufe0f'}
            severity_colors = {'CRITICAL': '#ff4444', 'HIGH': '#ff8c00', 'MEDIUM': '#ffd700', 'LOW': '#4169e1', 'INFO': '#808080'}
            
            # Group results by target
            by_target = {}
            for r in self._results:
                # Use the actual target URL, fallback to url field if target not available
                target = r.get('target') or r.get('url') or r.get('host') or 'Unknown Target'
                # Clean up the target if it's a full URL to show just the domain
                if target and target != 'Unknown Target':
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(target)
                        if parsed.netloc:
                            target = parsed.netloc
                        elif parsed.path and not parsed.scheme:
                            # Handle cases like 'example.com' without scheme
                            target = parsed.path.split('/')[0]
                    except Exception:
                        pass
                if target not in by_target:
                    by_target[target] = []
                by_target[target].append(r)
            
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle(_t('results_explorer', self._lang))
            dlg.resize(1100, 700)
            dlg.setStyleSheet("""
                QDialog { background-color: #0f1112; }
                QLabel { color: #d7e1ea; }
                QListWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QListWidget::item { padding: 8px; border-bottom: 1px solid #2b2f33; }
                QListWidget::item:selected { background-color: #3b82f6; }
                QListWidget::item:hover { background-color: #2b2f33; }
                QTreeWidget { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; }
                QTreeWidget::item { padding: 4px; }
                QTreeWidget::item:selected { background-color: #3b82f6; }
                QComboBox { background-color: #16181a; color: #d7e1ea; border: 1px solid #2b2f33; padding: 5px; }
                QComboBox::drop-down { border: none; }
                QComboBox QAbstractItemView { background-color: #16181a; color: #d7e1ea; selection-background-color: #3b82f6; }
                QPushButton { background-color: #2b2f33; color: #d7e1ea; border: none; padding: 8px 16px; border-radius: 4px; }
                QPushButton:hover { background-color: #3b3f43; }
                QCheckBox { color: #d7e1ea; }
                QGroupBox { color: #d7e1ea; border: 1px solid #2b2f33; margin-top: 10px; padding-top: 10px; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            """)
            
            main_layout = QHBoxLayout(dlg)
            
            # === LEFT PANEL: Site List ===
            left_panel = QVBoxLayout()
            left_panel.setSpacing(10)
            
            # Header
            sites_header = QLabel(_t('sites', self._lang))
            sites_header.setFont(QFont('', 12, QFont.Bold))
            sites_header.setStyleSheet('color: #d7e1ea; padding: 5px;')
            left_panel.addWidget(sites_header)
            
            # "All Sites" option
            site_list = QtWidgets.QListWidget()
            site_list.setFixedWidth(280)
            
            # Add "All Sites" first
            all_item = QtWidgets.QListWidgetItem(f'{_t("all_sites", self._lang)} ({len(self._results)} {_t("findings", self._lang)})')
            all_item.setData(256, '__ALL__')  # Qt.UserRole = 256
            site_list.addItem(all_item)
            
            # Add individual sites with counts
            for target, items in sorted(by_target.items()):
                # Count by severity
                crit = len([r for r in items if r.get('severity') == 'CRITICAL'])
                high = len([r for r in items if r.get('severity') == 'HIGH'])
                med = len([r for r in items if r.get('severity') == 'MEDIUM'])
                
                # Create display text with severity indicators
                indicators = []
                if crit > 0:
                    indicators.append(f'\U0001F534{crit}')
                if high > 0:
                    indicators.append(f'\U0001F7E0{high}')
                if med > 0:
                    indicators.append(f'\U0001F7E1{med}')
                
                indicator_str = ' '.join(indicators) if indicators else ''
                display = f'{target}\n   {len(items)} findings  {indicator_str}'
                
                item = QtWidgets.QListWidgetItem(display)
                item.setData(256, target)  # Qt.UserRole = 256
                site_list.addItem(item)
            
            left_panel.addWidget(site_list, 1)
            
            # Statistics summary at bottom of left panel
            stats_label = QLabel()
            total = len(self._results)
            bypasses = len([r for r in self._results if r.get('bypass', False)])
            stats_label.setText(f'{_t("total", self._lang)}: {total} | {_t("bypasses", self._lang)}: {bypasses}')
            stats_label.setStyleSheet('color: #808080; padding: 5px;')
            left_panel.addWidget(stats_label)
            
            main_layout.addLayout(left_panel)
            
            # === RIGHT PANEL: Results View ===
            right_panel = QVBoxLayout()
            right_panel.setSpacing(10)
            
            # Controls bar
            controls = QHBoxLayout()
            
            # Sort options
            sort_label = QLabel(_t('sort_by', self._lang))
            sort_combo = QtWidgets.QComboBox()
            sort_combo.addItems([
                _t('severity_high_low', self._lang),
                _t('severity_low_high', self._lang),
                _t('technique_az', self._lang),
                _t('technique_za', self._lang),
                _t('category', self._lang),
                _t('bypass_status', self._lang)
            ])
            sort_combo.setFixedWidth(200)
            controls.addWidget(sort_label)
            controls.addWidget(sort_combo)
            
            controls.addSpacing(20)
            
            # Filter options
            filter_label = QLabel(_t('filter', self._lang))
            filter_combo = QtWidgets.QComboBox()
            filter_combo.addItems([
                _t('all_results', self._lang),
                _t('critical_only', self._lang),
                _t('high_only', self._lang),
                _t('medium_only', self._lang),
                _t('low_only', self._lang),
                _t('info_only', self._lang),
                _t('bypasses_only', self._lang),
                _t('non_bypasses_only', self._lang)
            ])
            filter_combo.setFixedWidth(180)
            controls.addWidget(filter_label)
            controls.addWidget(filter_combo)
            
            right_panel.addLayout(controls)
            
            # Search bar row
            search_row = QHBoxLayout()
            search_label = QLabel('🔍 ' + _t('search', self._lang))
            search_edit = QLineEdit()
            search_edit.setPlaceholderText(_t('search_placeholder', self._lang))
            search_edit.setStyleSheet('''
                QLineEdit {
                    background-color: #16181a;
                    color: #d7e1ea;
                    border: 1px solid #2b2f33;
                    border-radius: 4px;
                    padding: 6px 10px;
                }
                QLineEdit:focus {
                    border: 1px solid #3b82f6;
                }
            ''')
            search_clear_btn = QPushButton('✕')
            search_clear_btn.setFixedWidth(30)
            search_clear_btn.setStyleSheet('QPushButton { padding: 4px; }')
            search_clear_btn.clicked.connect(lambda: search_edit.clear())
            
            search_row.addWidget(search_label)
            search_row.addWidget(search_edit, 1)
            search_row.addWidget(search_clear_btn)
            search_row.addSpacing(20)
            
            # Expand/Collapse buttons
            expand_btn = QPushButton(_t('expand_all', self._lang))
            collapse_btn = QPushButton(_t('collapse_all', self._lang))
            search_row.addWidget(expand_btn)
            search_row.addWidget(collapse_btn)
            
            right_panel.addLayout(search_row)
            
            # Results tree
            results_tree = QTreeWidget()
            results_tree.setColumnCount(4)
            results_tree.setHeaderLabels([_t('technique', self._lang), _t('severity', self._lang), _t('category', self._lang), _t('reason', self._lang)])
            results_tree.setAlternatingRowColors(True)
            results_tree.setSortingEnabled(False)  # We'll handle sorting manually
            
            try:
                results_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
                results_tree.header().setSectionResizeMode(1, QHeaderView.Fixed)
                results_tree.setColumnWidth(1, 100)
                results_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
                results_tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
            except Exception:
                pass
            
            right_panel.addWidget(results_tree, 1)
            
            # Details section
            details_group = QtWidgets.QGroupBox(_t('details', self._lang))
            details_layout = QVBoxLayout(details_group)
            details_text = QTextEdit()
            details_text.setReadOnly(True)
            details_text.setMaximumHeight(200)
            details_text.setStyleSheet('background-color: #16181a; border: none;')
            details_layout.addWidget(details_text)
            right_panel.addWidget(details_group)
            
            main_layout.addLayout(right_panel, 1)
            
            # === LOGIC FUNCTIONS ===
            def get_filtered_sorted_results(target_key, sort_idx, filter_idx, search_text=''):
                """Get results for a target with sorting, filtering, and search applied."""
                if target_key == '__ALL__':
                    results = list(self._results)
                else:
                    results = list(by_target.get(target_key, []))
                
                # Apply search filter
                if search_text:
                    search_lower = search_text.lower()
                    results = [r for r in results if 
                        search_lower in r.get('technique', '').lower() or
                        search_lower in r.get('category', '').lower() or
                        search_lower in r.get('reason', '').lower() or
                        search_lower in r.get('target', '').lower() or
                        search_lower in r.get('severity', '').lower()
                    ]
                
                # Apply filter
                if filter_idx == 1:  # CRITICAL only
                    results = [r for r in results if r.get('severity') == 'CRITICAL']
                elif filter_idx == 2:  # HIGH only
                    results = [r for r in results if r.get('severity') == 'HIGH']
                elif filter_idx == 3:  # MEDIUM only
                    results = [r for r in results if r.get('severity') == 'MEDIUM']
                elif filter_idx == 4:  # LOW only
                    results = [r for r in results if r.get('severity') == 'LOW']
                elif filter_idx == 5:  # INFO only
                    results = [r for r in results if r.get('severity') == 'INFO']
                elif filter_idx == 6:  # Bypasses only
                    results = [r for r in results if r.get('bypass', False)]
                elif filter_idx == 7:  # Non-bypasses only
                    results = [r for r in results if not r.get('bypass', False)]
                
                # Apply sort
                if sort_idx == 0:  # Severity High to Low
                    results.sort(key=lambda x: severity_order.index(x.get('severity', 'INFO')) if x.get('severity', 'INFO') in severity_order else 99)
                elif sort_idx == 1:  # Severity Low to High
                    results.sort(key=lambda x: severity_order.index(x.get('severity', 'INFO')) if x.get('severity', 'INFO') in severity_order else 99, reverse=True)
                elif sort_idx == 2:  # Technique A-Z
                    results.sort(key=lambda x: x.get('technique', '').lower())
                elif sort_idx == 3:  # Technique Z-A
                    results.sort(key=lambda x: x.get('technique', '').lower(), reverse=True)
                elif sort_idx == 4:  # Category
                    results.sort(key=lambda x: x.get('category', 'Other'))
                elif sort_idx == 5:  # Bypass Status
                    results.sort(key=lambda x: (0 if x.get('bypass', False) else 1, severity_order.index(x.get('severity', 'INFO')) if x.get('severity', 'INFO') in severity_order else 99))
                
                return results
            
            def update_results_tree():
                """Update the results tree based on current selection, filters, and search."""
                results_tree.clear()
                
                # Get selected site
                sel = site_list.currentItem()
                if not sel:
                    return
                target_key = sel.data(256)  # Qt.UserRole
                
                sort_idx = sort_combo.currentIndex()
                filter_idx = filter_combo.currentIndex()
                search_text = search_edit.text().strip()
                
                results = get_filtered_sorted_results(target_key, sort_idx, filter_idx, search_text)
                
                # Group by category for better organization
                by_category = {}
                for r in results:
                    cat = r.get('category', 'Other')
                    if cat not in by_category:
                        by_category[cat] = []
                    by_category[cat].append(r)
                
                for cat, items in sorted(by_category.items()):
                    # Create category parent
                    parent = QTreeWidgetItem([f'\U0001F4C1 {cat} ({len(items)})', '', '', ''])
                    parent.setFont(0, QFont('', 10, QFont.Bold))
                    results_tree.addTopLevelItem(parent)
                    
                    for r in items:
                        technique = r.get('technique', 'Unknown')
                        sev = r.get('severity', 'INFO')
                        category = r.get('category', 'Other')
                        reason = r.get('reason', '')
                        bypass = r.get('bypass', False)
                        
                        # Add bypass indicator to technique
                        if bypass:
                            technique = f'\u2705 {technique}'
                        
                        child = QTreeWidgetItem([technique, f'{severity_icons.get(sev, "")} {sev}', category, reason])
                        try:
                            child.setForeground(1, QBrush(QColor(severity_colors.get(sev, '#ffffff'))))
                        except Exception:
                            pass
                        
                        # Store full result data for details view
                        child.setData(0, 257, r)  # Qt.UserRole + 1
                        parent.addChild(child)
                    
                    parent.setExpanded(True)
            
            def on_site_selected():
                """Handle site selection change."""
                update_results_tree()
                details_text.clear()
            
            def on_result_selected():
                """Show details for selected result."""
                sel = results_tree.currentItem()
                if not sel or sel.childCount() > 0:  # Skip category headers
                    details_text.clear()
                    return
                
                r = sel.data(0, 257)  # Qt.UserRole + 1
                if not r:
                    return
                
                # Build details HTML with exploit description
                bypass_status = '\u2705 BYPASS SUCCESSFUL' if r.get('bypass', False) else '\u274C No bypass'
                sev = r.get('severity', 'INFO')
                technique = r.get('technique', 'Unknown')
                
                # Get detailed exploit description
                exploit_desc = _get_exploit_description(technique)
                
                details_html = f"""
                <div style='color: #d7e1ea; font-size: 12px;'>
                    <b>{_t('technique', self._lang)}:</b> {technique}<br>
                    <b>{_t('severity', self._lang)}:</b> <span style='color: {severity_colors.get(sev, "#808080")};'>{severity_icons.get(sev, '')} {sev}</span><br>
                    <b>{_t('status', self._lang)}:</b> {bypass_status}<br>
                    <b>{_t('category', self._lang)}:</b> {r.get('category', 'Other')}<br>
                    <b>{_t('target', self._lang)}:</b> {r.get('target', 'N/A')}<br>
                    <b>{_t('reason', self._lang)}:</b> {r.get('reason', 'N/A')}<br>
                    <hr style='border: 1px solid #2b2f33; margin: 8px 0;'>
                    <b>📖 {_t('description', self._lang)}:</b><br>
                    <span style='color: #a0aab5; font-style: italic;'>{exploit_desc}</span>
                </div>
                """
                details_text.setHtml(details_html)
            
            def expand_all():
                results_tree.expandAll()
            
            def collapse_all():
                results_tree.collapseAll()
            
            # Connect signals
            site_list.currentItemChanged.connect(on_site_selected)
            sort_combo.currentIndexChanged.connect(lambda: update_results_tree())
            filter_combo.currentIndexChanged.connect(lambda: update_results_tree())
            search_edit.textChanged.connect(lambda: update_results_tree())
            results_tree.currentItemChanged.connect(on_result_selected)
            expand_btn.clicked.connect(expand_all)
            collapse_btn.clicked.connect(collapse_all)
            
            # Select "All Sites" by default
            site_list.setCurrentRow(0)
            
            # Bottom buttons
            bottom_layout = QHBoxLayout()
            bottom_layout.addStretch()
            
            export_btn = QPushButton(_t('export_view', self._lang))
            export_btn.clicked.connect(lambda: self._export_results_view(get_filtered_sorted_results(
                site_list.currentItem().data(256) if site_list.currentItem() else '__ALL__',
                sort_combo.currentIndex(),
                filter_combo.currentIndex(),
                search_edit.text().strip()
            )))
            bottom_layout.addWidget(export_btn)
            
            close_btn = QPushButton(_t('close', self._lang))
            close_btn.clicked.connect(dlg.accept)
            bottom_layout.addWidget(close_btn)
            
            # Add bottom layout to right panel
            right_panel.addLayout(bottom_layout)
            
            dlg.exec()
        
        def _export_results_view(self, results):
            """Export the current filtered/sorted view to JSON."""
            if not results:
                QMessageBox.information(self, _t('no_results', self._lang), _t('no_results_to_export', self._lang))
                return
            path, _ = QFileDialog.getSaveFileName(self, _t('export_results_view', self._lang), filter='JSON (*.json)')
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2)
                QMessageBox.information(self, _t('exported', self._lang), _t('exported_results', self._lang).format(count=len(results), path=path))
            except Exception as e:
                QMessageBox.critical(self, _t('export_failed', self._lang), str(e))

        def show_target_details(self, item, col=None):
            target = item.text(0)
            tmp = self._target_tmp_map.get(target)
            per = self._per_target_results.get(target, {})
            if not tmp or not os.path.exists(tmp):
                QMessageBox.information(self, _t('no_results', self._lang), _t('no_results_for', self._lang).format(target=target))
                return
            try:
                with open(tmp, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    pretty = json.dumps(data, indent=2, ensure_ascii=False)
            except Exception:
                with open(tmp, 'r', encoding='utf-8', errors='replace') as f:
                    pretty = f.read()

            header = ''
            try:
                done_count = len(per.get('done', [])) if per.get('done') is not None else 'Unknown'
                errors = per.get('errors', [])
                header = f"{_t('done_exploits', self._lang)}: {done_count}\n{_t('errors_label', self._lang)}: {len(errors)}\n\n"
                if errors:
                    header += _t('errors_details', self._lang) + ":\n" + "\n".join(str(e) for e in errors) + "\n\n"
            except Exception:
                header = ''

            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle(_t('results_for', self._lang).format(target=target))
            dlg.resize(800, 480)
            layout = QtWidgets.QVBoxLayout(dlg)
            te = QTextEdit()
            # try to apply a modern font to the details dialog as well
            try:
                mono_candidates = ["JetBrains Mono", "Fira Code", "Consolas", "DejaVu Sans Mono", "Courier New"]
                try:
                    families = set(QFontDatabase.families())
                except Exception:
                    try:
                        families = set(QFontDatabase().families())
                    except Exception:
                        families = set()
                mono = next((f for f in mono_candidates if f in families), None)
                if mono:
                    te.setFont(QFont(mono, 10))
            except Exception:
                pass
            te.setPlainText(header + pretty)
            te.setReadOnly(True)
            layout.addWidget(te)
            dlg.exec()

        def clean_tmp_files(self, silent: bool = False, clear_targets: bool = False):
            paths = list(self._target_tmp_map.values()) + list(self._tmp_result_paths)
            unique = []
            for p in paths:
                if not p or p in unique:
                    continue
                if os.path.exists(p):
                    unique.append(p)
            if not unique:
                if not silent:
                    QMessageBox.information(self, _t('clear', self._lang), _t('no_tmp_files', self._lang))
                # still clear targets/logs if requested
                if clear_targets:
                    try:
                        for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                            try:
                                self.tree.takeTopLevelItem(i)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    try:
                        self.log.clear()
                    except Exception:
                        try:
                            self.log.setPlainText('')
                        except Exception:
                            pass
                    self._results = []
                    self._tmp_result_paths = []
                    self._target_tmp_map = {}
                    self._per_target_results = {}
                    try:
                        self.save_btn.setEnabled(False)
                        self.results_btn.setEnabled(False)
                        self._stop_results_pulse()
                        self.results_btn.setStyleSheet(self._results_btn_base_style)
                    except Exception:
                        pass
                try:
                    self._update_legend_counts()
                except Exception:
                    pass
                return
            if not silent:
                if QMessageBox.question(self, _t('clear', self._lang), _t('remove_files_confirm', self._lang).format(count=len(unique))) != QMessageBox.Yes:
                    return
            removed = 0
            for p in unique:
                try:
                    os.remove(p)
                    removed += 1
                except Exception:
                    pass
            # cleanup mapping
            for t, p in list(self._target_tmp_map.items()):
                if not os.path.exists(p):
                    self._target_tmp_map.pop(t, None)
            self._tmp_result_paths = [p for p in self._tmp_result_paths if os.path.exists(p)]
            if not silent:
                QMessageBox.information(self, _t('clear', self._lang), _t('removed_files', self._lang).format(count=removed))
            # If requested also clear targets and outputs
            if clear_targets:
                try:
                    for i in range(self.tree.topLevelItemCount()-1, -1, -1):
                        try:
                            self.tree.takeTopLevelItem(i)
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    self.log.clear()
                except Exception:
                    try:
                        self.log.setPlainText('')
                    except Exception:
                        pass
                self._results = []
                self._tmp_result_paths = []
                self._target_tmp_map = {}
                self._per_target_results = {}
                try:
                    self.save_btn.setEnabled(False)
                    self.results_btn.setEnabled(False)
                    self._stop_results_pulse()
                    self.results_btn.setStyleSheet(self._results_btn_base_style)
                except Exception:
                    pass
            try:
                self._update_legend_counts()
            except Exception:
                pass

        def closeEvent(self, event):
            try:
                prefs = _load_prefs()
                prefs['qt_geometry'] = f"{self.width()}x{self.height()}"
                prefs['threads'] = int(self.threads_spin.value())
                prefs['delay'] = float(self.delay_spin.value())
                prefs['concurrent'] = int(self.concurrent_spin.value())
                prefs['use_concurrent'] = bool(self.use_concurrent_chk.isChecked())
                if bool(prefs.get('remember_targets', True)):
                    prefs['last_targets'] = [self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
                else:
                    prefs['last_targets'] = []
                _save_prefs(prefs)
            except Exception:
                pass
            try:
                super().closeEvent(event)
            except Exception:
                pass

    def run_qt():
        app = QApplication([])
        # set application icon from bundled logo when available
        try:
            if os.path.exists(LOGO_PATH):
                from PySide6.QtGui import QIcon
                icon = QIcon(LOGO_PATH)
                app.setWindowIcon(icon)
        except Exception:
            pass
        
        # Show legal disclaimer first
        if not _show_disclaimer_qt(app):
            print("User declined the legal disclaimer. Exiting.")
            return 0
        
        w = PierceQtApp()
        w.show()
        # run the Qt event loop and capture exit code so we can cleanup the tmp watermark
        rc = app.exec()
        try:
            tmp = getattr(w, '_qt_watermark_tmp', None)
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass
        except Exception:
            pass
        return rc

    # run Qt GUI
    return_code = run_qt()
    sys.exit(return_code)


if __name__ == '__main__':
    main()

#    \|/          (__)    <-- GUI made by Marwan-verse
#         `\------(oo)
#           ||    (__)
#           ||w--||     \|/
#       \|/
# there are 5 easter eggs hidden in this codebase
# can you find them all?