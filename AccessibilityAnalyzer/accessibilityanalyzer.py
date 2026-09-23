#!/usr/bin/env python3
"""
AccessibilityAnalyzer v4.0 - Web Accessibility Analyzer
Analyzes website accessibility compliance with WCAG 2.2 guidelines.

New in v4.0:
  - Deeper accessibility feedback, training hints, conformance report,
    certification, and accessibility maturity deep-analysis checks
  - Refined WCAG 2.2 coverage, accessibility tree, screen reader, and
    keyboard navigation simulation fidelity
  - Refined WCAG scoring with per-level coverage, severity, priority,
    and governance-aware maturity modelling
  - Enhanced compliance dashboard, prioritization matrix, remediation
    roadmap, and accessibility statement output

New in v3.0:
  - Accessibility statement, feedback mechanism, training hints,
    conformance report, and certification checks
  - Refined WCAG 2.2 criteria, accessibility tree, screen reader and
    keyboard navigation simulation
  - Refined level scoring, issue severity, remediation priority,
    and governance-aware maturity model
  - Enhanced compliance dashboard, prioritization matrix,
    remediation roadmap, and accessibility statement generator

New in v2.0:
  - Cognitive, motor, visual, hearing, speech, and neurodiversity analysis
  - WCAG 2.2 success criteria, accessibility tree, screen reader and
    keyboard navigation simulation
  - Refined severity/priority scoring, conformance levels, maturity model
  - Compliance dashboard, prioritization matrix, remediation roadmap,
    accessibility statement generator
"""

import argparse
import json
import csv
import re
import sys
import os
from datetime import datetime
from urllib.parse import urlparse, urljoin
from io import StringIO

try:
    import requests
except ImportError:
    print("Installing requests...")
    os.system(f"{sys.executable} -m pip install requests -q")
    import requests

try:
    from bs4 import BeautifulSoup, Comment
except ImportError:
    print("Installing beautifulsoup4...")
    os.system(f"{sys.executable} -m pip install beautifulsoup4 -q")
    from bs4 import BeautifulSoup, Comment

BANNER = """
\x1b[36m╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  \x1b[33m    _    ____  _____  ______        __  _    _  _____  ____   __            \x1b[36m  ║
║  \x1b[33m   / \\  |  _ \\| ____||  ____|      / / | |  | || ____||  _ \\ / /            \x1b[36m  ║
║  \x1b[33m  / _ \\ | |_) |  _|  | |__        / /  | |  | ||  _|  | | | | /             \x1b[36m  ║
║  \x1b[33m / ___ \\|  __/| |___ |  ____|     / /   | |/ /| |___ | |_| | \\ \\            \x1b[36m  ║
║  \x1b[33m/_/   \\_\\_|   |_____||_|         /_/    |___/ |_____||____/   \\_\\            \x1b[36m  ║
║  \x1b[32m ____ _   _  _____ _____ ___  __        _  _____                                    \x1b[36m  ║
║  \x1b[32m/ ___| | | || ____|_   _|_ _| |/ /      / \\|_   _|                                   \x1b[36m  ║
║  \x1b[32m\\___ \\| | ||  _|   | |  | || ' /      / _ \\ | |                                     \x1b[36m  ║
║  \x1b[32m ___) | |_| || |___  | |  | | . \\     / ___ \\| |                                     \x1b[36m  ║
║  \x1b[32m|____/ \\___/ |_____| |_| |___|_|\\_\\  /_/   \\_\\_|                                     \x1b[36m  ║
║                                                                              ║
║  \x1b[35m[+] \x1b[37mVersion: \x1b[33m4.0                                                          \x1b[36m║
║  \x1b[35m[+] \x1b[37mWCAG 2.2 + Persona + Governance + Deep Maturity Checks              \x1b[36m║
║  \x1b[35m[+] \x1b[37mCategories: \x1b[33m28  \x1b[37m|  Max Score: \x1b[33m100                                         \x1b[36m║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝\x1b[0m
"""

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        for attr in ['RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA', 'CYAN', 'WHITE', 'GRAY', 'BOLD', 'DIM', 'RESET']:
            setattr(cls, attr, '')

WCAG_CRITERIA_LEVEL = {
    '1.1.1': 'A', '1.2.1': 'A', '1.2.2': 'A', '1.2.3': 'AAA', '1.2.4': 'AA',
    '1.2.5': 'AA', '1.2.6': 'AAA', '1.2.8': 'AAA', '1.3.1': 'A', '1.3.2': 'A',
    '1.3.3': 'A', '1.3.4': 'AA', '1.3.5': 'AA', '1.4.1': 'A', '1.4.2': 'A',
    '1.4.3': 'AA', '1.4.4': 'AA', '1.4.5': 'AA', '1.4.6': 'AAA', '1.4.7': 'AAA',
    '1.4.8': 'AAA', '1.4.9': 'AAA', '1.4.10': 'AA', '1.4.11': 'AA', '1.4.12': 'AA',
    '1.4.13': 'AA', '2.1.1': 'A', '2.1.2': 'A', '2.1.3': 'AAA', '2.2.1': 'A',
    '2.2.2': 'A', '2.2.3': 'AAA', '2.2.4': 'AAA', '2.2.5': 'AAA', '2.3.1': 'A',
    '2.3.2': 'AAA', '2.3.3': 'AAA', '2.4.1': 'A', '2.4.2': 'A', '2.4.3': 'A',
    '2.4.4': 'A', '2.4.5': 'AA', '2.4.6': 'AA', '2.4.7': 'AA', '2.4.8': 'AAA',
    '2.4.9': 'AAA', '2.4.10': 'AAA', '2.4.11': 'AA', '2.4.12': 'AAA', '2.4.13': 'AAA',
    '2.5.1': 'A', '2.5.2': 'A', '2.5.3': 'A', '2.5.4': 'A', '2.5.5': 'AAA',
    '2.5.6': 'AAA', '2.5.7': 'A', '2.5.8': 'AA', '3.1.1': 'A', '3.1.2': 'AA',
    '3.1.3': 'AAA', '3.1.4': 'AAA', '3.1.5': 'AAA', '3.2.1': 'A', '3.2.2': 'A',
    '3.2.3': 'AA', '3.2.4': 'AA', '3.2.5': 'AAA', '3.2.6': 'AA', '3.3.1': 'A',
    '3.3.2': 'A', '3.3.3': 'AA', '3.3.4': 'A', '3.3.5': 'AAA', '3.3.6': 'AAA',
    '3.3.7': 'A', '3.3.8': 'A', '3.3.9': 'AAA', '3.3.10': 'AAA', '3.3.11': 'AAA',
    '4.1.1': 'A', '4.1.2': 'A', '4.1.3': 'AA',
}

SEVERITY_WEIGHTS = {'Critical': 4, 'Serious': 3, 'Moderate': 2, 'Minor': 1}
SEVERITY_ORDER = ['Critical', 'Serious', 'Moderate', 'Minor']
LEVEL_ORDER = {'A': 1, 'AA': 2, 'AAA': 3}
ESCALATION_CRITERIA = {'1.1.1', '1.3.1', '1.4.2', '2.1.1', '2.1.2', '2.4.1',
                       '2.4.2', '3.3.2', '3.3.4', '4.1.2', '4.1.3'}
EFFORT_DAYS = {'Low': 0.5, 'Medium': 2.0, 'High': 5.0}
GOVERNANCE_PHASE = {'statement': 1, 'feedback': 1, 'training': 3,
                    'conformance_report': 4, 'certification': 4}

def severity_color(severity):
    if severity == 'Critical':
        return Colors.RED
    elif severity == 'Serious':
        return Colors.YELLOW
    elif severity == 'Moderate':
        return Colors.MAGENTA
    return Colors.GRAY

def score_color(score, max_score):
    pct = (score / max_score * 100) if max_score > 0 else 0
    if pct >= 90:
        return Colors.GREEN
    elif pct >= 70:
        return Colors.YELLOW
    elif pct >= 50:
        return Colors.MAGENTA
    return Colors.RED

def grade_from_score(score):
    if score >= 95:
        return 'A+'
    elif score >= 90:
        return 'A'
    elif score >= 75:
        return 'B'
    elif score >= 60:
        return 'C'
    elif score >= 40:
        return 'D'
    return 'F'

def wcag_level(score):
    if score >= 90:
        return 'AAA'
    elif score >= 75:
        return 'AA'
    elif score >= 50:
        return 'A'
    return 'Non-Compliant'

def priority_color(priority):
    if priority == 'P1':
        return Colors.RED
    elif priority == 'P2':
        return Colors.YELLOW
    elif priority == 'P3':
        return Colors.MAGENTA
    return Colors.GRAY

def effort_color(effort):
    if effort == 'Low':
        return Colors.GREEN
    elif effort == 'Medium':
        return Colors.YELLOW
    return Colors.RED

class Issue:
    def __init__(self, category, severity, title, description, remediation, wcag_ref='',
                 conformance='', effort='', priority=''):
        self.category = category
        self.severity = severity
        self.title = title
        self.description = description
        self.remediation = remediation
        self.wcag_ref = wcag_ref
        self.conformance = conformance
        self.effort = effort
        self.priority = priority

    def to_dict(self):
        return {
            'category': self.category,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'remediation': self.remediation,
            'wcag_ref': self.wcag_ref,
            'conformance': self.conformance,
            'effort': self.effort,
            'priority': self.priority,
        }

class AccessibilityAnalyzer:
    def __init__(self, url, timeout=15, level='AA', verbose=False):
        self.url = url
        self.timeout = timeout
        self.level = level
        self.verbose = verbose
        self.soup = None
        self.html = ''
        self.issues = []
        self.scores = {}
        self.raw_scores = {}
        self.max_scores = {
            'text_alt': 6, 'adaptable': 6, 'distinguishable': 5, 'keyboard': 6,
            'navigable': 4, 'input': 2, 'readable': 2, 'predictable': 2,
            'input_assist': 2, 'compatible': 4, 'aria': 6, 'multimedia': 2,
            'cognitive': 5, 'motor': 4, 'visual': 5, 'hearing': 4,
            'speech': 3, 'neurodiversity': 4, 'wcag22': 6, 'a11y_tree': 3,
            'screen_reader': 4, 'keyboard_nav': 3,
            'statement': 3, 'feedback': 2, 'training': 2,
            'conformance_report': 3, 'certification': 2,
            'maturity_deep': 3,
        }
        self.check_base_max = {
            'text_alt': 10, 'adaptable': 10, 'distinguishable': 10, 'keyboard': 10,
            'navigable': 10, 'input': 5, 'readable': 5, 'predictable': 5,
            'input_assist': 5, 'compatible': 10, 'aria': 10, 'multimedia': 5,
        }
        self.category_names = {
            'text_alt': 'Text Alternatives',
            'adaptable': 'Adaptable Content',
            'distinguishable': 'Distinguishable',
            'keyboard': 'Keyboard Accessible',
            'navigable': 'Navigable',
            'input': 'Input Modalities',
            'readable': 'Readable',
            'predictable': 'Predictable',
            'input_assist': 'Input Assistance',
            'compatible': 'Compatible',
            'aria': 'ARIA & Semantic HTML',
            'multimedia': 'Multimedia & Dynamic Content',
            'cognitive': 'Cognitive Accessibility',
            'motor': 'Motor Disability Access',
            'visual': 'Visual Impairment Access',
            'hearing': 'Hearing Impairment Access',
            'speech': 'Speech Disability Access',
            'neurodiversity': 'Neurodiversity Support',
            'wcag22': 'WCAG 2.2 Criteria',
            'a11y_tree': 'Accessibility Tree',
            'screen_reader': 'Screen Reader Sim',
            'keyboard_nav': 'Keyboard Nav Sim',
            'statement': 'Accessibility Statement',
            'feedback': 'Feedback Mechanism',
            'training': 'Training Hints',
            'conformance_report': 'Conformance Report',
            'certification': 'Certification Hints',
            'maturity_deep': 'Maturity Deep Analysis',
        }
        self.persona_categories = ['cognitive', 'motor', 'visual', 'hearing', 'speech', 'neurodiversity']
        self.governance_categories = ['statement', 'feedback', 'training',
                                      'conformance_report', 'certification']
        self.a11y_tree = {'nodes': [], 'roles': {}, 'missing_names': 0, 'broken_refs': 0,
                          'duplicate_ids': 0, 'heading_outline': [], 'landmarks': {},
                          'states': {}, 'unnamed_focusable': 0, 'hidden_focusable': 0}
        self.screen_reader_log = []
        self.keyboard_path = []
        self.keyboard_metrics = {'tab_stops': 0, 'positive_tabindex': 0, 'mouse_only': 0,
                                 'trap_risk': 0, 'unnamed_stops': 0, 'wasted_nav_stops': 0,
                                 'modal_count': 0, 'escape_exit_available': False,
                                 'key_only_widgets': 0}
        self.weighted_score = 0.0
        self.conformance = 'Non-Compliant'
        self.conformance_detail = {}
        self.maturity = {'stage': 0, 'name': 'Nonexistent', 'description': ''}
        self.roadmap = []
        self.matrix = {}
        self.statement = ''
        self.governance_score = 0.0
        self.statement_analysis = {'found': False, 'evidence': '', 'components': [],
                                   'missing_components': []}
        self.feedback_analysis = {'found': False, 'channels': [], 'accessible': False}
        self.training_hints = []
        self.conformance_report_info = {'found': False, 'signals': [], 'artifacts': []}
        self.certification_info = {'found': False, 'signals': []}
        self.maturity_deep = {'dimensions': {}, 'gaps': [], 'strengths': [],
                              'next_stage': '', 'readiness_pct': 0.0}

    def add_issue(self, category, severity, title, description, remediation, wcag_ref=''):
        severity = self._refine_severity(severity, wcag_ref)
        conformance = self._criterion_conformance(wcag_ref)
        effort = self._estimate_effort(remediation)
        priority = self._compute_priority(severity, effort, conformance)
        self.issues.append(Issue(category, severity, title, description, remediation, wcag_ref,
                                 conformance, effort, priority))

    @staticmethod
    def _criterion_conformance(wcag_ref):
        match = re.search(r'(\d+\.\d+\.\d+)', wcag_ref or '')
        if match:
            return WCAG_CRITERIA_LEVEL.get(match.group(1), 'AA')
        return 'AA'

    @staticmethod
    def _refine_severity(severity, wcag_ref):
        match = re.search(r'(\d+\.\d+\.\d+)', wcag_ref or '')
        if not match:
            return severity
        criterion = match.group(1)
        if criterion in ESCALATION_CRITERIA:
            if severity == 'Minor':
                return 'Moderate'
            if severity == 'Moderate':
                return 'Serious'
        if criterion.startswith('1.1.') or criterion.startswith('2.1.'):
            if severity == 'Minor':
                return 'Moderate'
        if criterion in ('1.4.2', '2.1.2', '2.2.1') and severity in ('Moderate', 'Serious'):
            return 'Serious' if severity == 'Moderate' else 'Critical'
        if criterion.startswith('2.3.') and severity == 'Serious':
            return 'Critical'
        return severity

    @staticmethod
    def _estimate_effort(remediation):
        text = (remediation or '').lower()
        high_kw = ['redesign', 'rebuild', 'rewrite', 'refactor', 'replace the',
                   'transcript', 'audio description', 'sign language', 're-architect',
                   'overhaul', 'restructure']
        medium_kw = ['add', 'update', 'modify', 'create', 'provide', 'implement',
                     'ensure', 'use ', 'change', 'include']
        if any(k in text for k in high_kw):
            return 'High'
        if len(text) > 140 or any(k in text for k in medium_kw):
            return 'Medium'
        return 'Low'

    @staticmethod
    def _compute_priority(severity, effort, level='AA'):
        if severity == 'Critical':
            priority = 'P1'
        elif severity == 'Serious':
            priority = 'P1' if effort == 'Low' else 'P2'
        elif severity == 'Moderate':
            priority = 'P2' if effort == 'Low' else 'P3'
        else:
            priority = 'P3' if effort in ('Low', 'Medium') else 'P4'
        if level == 'A' and priority in ('P2', 'P3', 'P4'):
            priority = {'P2': 'P1', 'P3': 'P2', 'P4': 'P3'}[priority]
        elif level == 'AA' and priority == 'P4':
            priority = 'P3'
        elif level == 'AAA' and priority == 'P2' and severity in ('Moderate', 'Minor'):
            priority = 'P3'
        if severity == 'Critical' and effort == 'Low':
            priority = 'P1'
        return priority

    def fetch_page(self):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            response = requests.get(self.url, timeout=self.timeout, headers=headers, verify=False)
            response.raise_for_status()
            self.html = response.text
            self.soup = BeautifulSoup(self.html, 'html.parser')
            return True
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}[!] Request timed out after {self.timeout}s{Colors.RESET}")
            return False
        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}[!] Could not connect to {self.url}{Colors.RESET}")
            return False
        except requests.exceptions.HTTPError as e:
            print(f"{Colors.RED}[!] HTTP Error: {e}{Colors.RESET}")
            return False
        except Exception as e:
            print(f"{Colors.RED}[!] Error fetching page: {e}{Colors.RESET}")
            return False

    def check_text_alternatives(self):
        score = 10
        issues_found = 0

        if not self.soup:
            return 0

        images = self.soup.find_all('img')
        for img in images:
            alt = img.get('alt')
            src = img.get('src', 'unknown')
            if alt is None:
                self.add_issue('text_alt', 'Critical', 'Missing alt attribute',
                    f"Image '{src}' is missing alt attribute",
                    "Add descriptive alt text to the image element", 'WCAG 1.1.1')
                score -= 1.5
                issues_found += 1
            elif alt.strip().lower() in ['', 'image', 'photo', 'picture', 'img', 'graphic']:
                if alt.strip() == '':
                    if img.get('role') == 'presentation' or img.get('aria-hidden') == 'true':
                        continue
                    self.add_issue('text_alt', 'Moderate', 'Empty alt text on non-decorative image',
                        f"Image '{src}' has empty alt text but is not marked as decorative",
                        "Add descriptive alt text or mark as decorative with role='presentation'", 'WCAG 1.1.1')
                    score -= 0.5
                else:
                    self.add_issue('text_alt', 'Serious', 'Non-descriptive alt text',
                        f"Image '{src}' has non-descriptive alt text: '{alt}'",
                        "Replace with descriptive alt text that conveys the image's purpose", 'WCAG 1.1.1')
                    score -= 1
                    issues_found += 1

        areas = self.soup.find_all('area')
        for area in areas:
            if not area.get('alt'):
                self.add_issue('text_alt', 'Critical', 'Missing alt on area element',
                    "Image map area is missing alt attribute",
                    "Add alt text to all area elements", 'WCAG 1.1.1')
                score -= 1
                issues_found += 1

        inputs = self.soup.find_all('input', {'type': 'image'})
        for inp in inputs:
            if not inp.get('alt'):
                self.add_issue('text_alt', 'Critical', 'Missing alt on image input',
                    "Image input is missing alt attribute",
                    "Add alt text to image input elements", 'WCAG 1.1.1')
                score -= 1
                issues_found += 1

        svgs = self.soup.find_all('svg')
        for svg in svgs:
            has_title = svg.find('title')
            has_aria_label = svg.get('aria-label')
            has_aria_labelledby = svg.get('aria-labelledby')
            has_role = svg.get('role')
            if not (has_title or has_aria_label or has_aria_labelledby):
                if has_role and has_role in ['img', 'graphics-document']:
                    self.add_issue('text_alt', 'Serious', 'SVG missing accessible name',
                        "SVG element with img role is missing accessible name",
                        "Add <title>, aria-label, or aria-labelledby to SVG", 'WCAG 1.1.1')
                    score -= 0.5
                    issues_found += 1
                elif not has_role:
                    pass

        canvases = self.soup.find_all('canvas')
        for canvas in canvases:
            if not canvas.get_text(strip=True) and not canvas.find('fallback'):
                self.add_issue('text_alt', 'Serious', 'Canvas missing fallback content',
                    "Canvas element has no fallback text content",
                    "Add text content inside canvas element for screen readers", 'WCAG 1.1.1')
                score -= 0.5
                issues_found += 1

        return max(0, score)

    def check_adaptable_content(self):
        score = 10
        issues_found = 0

        if not self.soup:
            return 0

        headings = self.soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        if headings:
            levels = [int(h.name[1]) for h in headings]
            prev_level = 0
            for level in levels:
                if level > prev_level + 1 and prev_level != 0:
                    self.add_issue('adaptable', 'Serious', 'Skipped heading level',
                        f"Heading level skipped from h{prev_level} to h{level}",
                        "Ensure heading levels are used in sequential order (h1 > h2 > h3)", 'WCAG 1.3.1')
                    score -= 1
                    issues_found += 1
                prev_level = level

            h1_count = levels.count(1)
            if h1_count == 0:
                self.add_issue('adaptable', 'Critical', 'Missing h1 heading',
                    "Page has no h1 heading",
                    "Add exactly one h1 heading to define the page's main topic", 'WCAG 1.3.1')
                score -= 1
                issues_found += 1
            elif h1_count > 1:
                self.add_issue('adaptable', 'Moderate', 'Multiple h1 headings',
                    f"Page has {h1_count} h1 headings",
                    "Use only one h1 per page for proper document structure", 'WCAG 1.3.1')
                score -= 0.5

        landmark_roles = ['banner', 'navigation', 'main', 'complementary', 'contentinfo']
        html5_landmarks = ['header', 'nav', 'main', 'aside', 'footer']
        found_landmarks = []

        for role in landmark_roles:
            elements = self.soup.find_all(attrs={'role': role})
            if elements:
                found_landmarks.append(role)

        for tag in html5_landmarks:
            elements = self.soup.find_all(tag)
            if elements and tag not in found_landmarks:
                found_landmarks.append(tag)

        if 'main' not in found_landmarks:
            self.add_issue('adaptable', 'Critical', 'Missing main landmark',
                "Page has no main content landmark",
                "Add <main> element or role='main' to identify main content", 'WCAG 1.3.1')
            score -= 1
            issues_found += 1

        if 'navigation' not in found_landmarks and 'nav' not in found_landmarks:
            self.add_issue('adaptable', 'Serious', 'No navigation landmark',
                "Page has no navigation landmark",
                "Use <nav> element or role='navigation' for navigation sections", 'WCAG 1.3.1')
            score -= 0.5
            issues_found += 1

        tables = self.soup.find_all('table')
        for table in tables:
            if table.find('table'):
                continue
            caption = table.find('caption')
            ths = table.find_all('th')
            has_headers = len(ths) > 0
            has_scope = any(th.get('scope') for th in ths)

            if not has_headers:
                self.add_issue('adaptable', 'Serious', 'Data table missing headers',
                    "Table is missing <th> header cells",
                    "Add <th> elements to identify header cells in data tables", 'WCAG 1.3.1')
                score -= 0.5
                issues_found += 1
            elif not has_scope:
                self.add_issue('adaptable', 'Moderate', 'Table headers missing scope',
                    "Table headers lack scope attribute",
                    "Add scope='col' or scope='row' to <th> elements", 'WCAG 1.3.1')
                score -= 0.25

            if not caption:
                self.add_issue('adaptable', 'Moderate', 'Table missing caption',
                    "Table has no caption element",
                    "Add <caption> to describe the table's content", 'WCAG 1.3.1')
                score -= 0.25

        lists_used = self.soup.find_all(['ul', 'ol', 'dl'])
        div_lists = self.soup.find_all('div', class_=lambda x: x and ('list' in str(x).lower()))
        for div in div_lists:
            spans = div.find_all('span', class_=lambda x: x and ('item' in str(x).lower()))
            if len(spans) > 2:
                self.add_issue('adaptable', 'Moderate', 'List not using proper markup',
                    "Content that appears to be a list is using divs instead of list elements",
                    "Use <ul>, <ol>, or <dl> elements for list content", 'WCAG 1.3.1')
                score -= 0.25
                issues_found += 1
                break

        forms = self.soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'select', 'textarea'])
            for inp in inputs:
                input_type = inp.get('type', 'text')
                if input_type in ['hidden', 'submit', 'button', 'reset', 'image']:
                    continue
                input_id = inp.get('id')
                has_label = False
                if input_id:
                    label = self.soup.find('label', attrs={'for': input_id})
                    if label:
                        has_label = True
                if inp.find_parent('label'):
                    has_label = True
                if inp.get('aria-label') or inp.get('aria-labelledby'):
                    has_label = True
                if inp.get('title'):
                    has_label = True

                if not has_label:
                    self.add_issue('adaptable', 'Critical', 'Form input missing label',
                        f"Form input '{inp.get('name', 'unnamed')}' has no associated label",
                        "Add a <label> element with for attribute matching the input's id", 'WCAG 1.3.1')
                    score -= 0.5
                    issues_found += 1

        html_tag = self.soup.find('html')
        if html_tag and not html_tag.get('lang'):
            self.add_issue('adaptable', 'Critical', 'Missing page language',
                "HTML element is missing lang attribute",
                "Add lang attribute to <html> element (e.g., lang='en')", 'WCAG 1.3.1')
            score -= 1
            issues_found += 1

        return max(0, score)

    def check_distinguishable(self):
        score = 10
        issues_found = 0

        if not self.soup:
            return 0

        text_elements = self.soup.find_all(['p', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'li'])
        color_issues = 0
        for elem in text_elements[:50]:
            style = elem.get('style', '')
            if style:
                style_lower = style.lower()
                if 'color:' in style_lower or 'background-color:' in style_lower:
                    has_color = any(c in style_lower for c in ['rgb', 'rgba', '#', 'color:'])
                    if has_color:
                        color_issues += 1

        if color_issues > 5:
            self.add_issue('distinguishable', 'Serious', 'Potential color contrast issues',
                f"Found {color_issues} elements with inline color styles that may have contrast issues",
                "Ensure all text meets WCAG AA contrast ratio of 4.5:1 for normal text", 'WCAG 1.4.3')
            score -= 2
            issues_found += 1

        images = self.soup.find_all('img')
        text_images = 0
        for img in images:
            alt = img.get('alt', '')
            src = img.get('src', '').lower()
            if any(ext in src for ext in ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp']):
                if len(alt) > 20:
                    text_images += 1

        if text_images > 2:
            self.add_issue('distinguishable', 'Serious', 'Images of text detected',
                f"Found {text_images} images that may contain text content",
                "Use actual text instead of images of text for better accessibility", 'WCAG 1.4.5')
            score -= 1
            issues_found += 1

        links = self.soup.find_all('a')
        vague_texts = ['click here', 'read more', 'more', 'here', 'link', 'learn more']
        for link in links:
            link_text = link.get_text(strip=True).lower()
            if link_text in vague_texts:
                self.add_issue('distinguishable', 'Moderate', 'Non-descriptive link text',
                    f"Link text '{link_text}' does not describe the link's purpose",
                    "Use descriptive link text that makes sense out of context", 'WCAG 1.4.4')
                score -= 0.5
                issues_found += 1

        title = self.soup.find('title')
        if not title or not title.get_text(strip=True):
            self.add_issue('distinguishable', 'Critical', 'Missing page title',
                "Page has no descriptive title",
                "Add a descriptive <title> element to the page head", 'WCAG 2.4.2')
            score -= 1
            issues_found += 1

        return max(0, score)

    def check_keyboard(self):
        score = 10
        issues_found = 0

        if not self.soup:
            return 0

        tabindex_elements = self.soup.find_all(attrs={'tabindex': True})
        for elem in tabindex_elements:
            tabindex_val = elem.get('tabindex')
            try:
                if int(tabindex_val) > 0:
                    self.add_issue('keyboard', 'Serious', 'Positive tabindex value',
                        f"Element has positive tabindex='{tabindex_val}' which disrupts focus order",
                        "Use tabindex='0' or tabindex='-1' instead of positive values", 'WCAG 2.4.3')
                    score -= 1
                    issues_found += 1
            except ValueError:
                pass

        interactive = self.soup.find_all(['a', 'button', 'input', 'select', 'textarea'])
        for elem in interactive:
            if elem.name == 'a':
                href = elem.get('href')
                if not href or href == '#':
                    onclick = elem.get('onclick')
                    if not onclick:
                        self.add_issue('keyboard', 'Moderate', 'Link without proper keyboard support',
                            "Anchor element has no href and may not be keyboard accessible",
                            "Add href attribute or use button element for actions", 'WCAG 2.1.1')
                        score -= 0.25
                        issues_found += 1

        skip_links = self.soup.find_all('a', href=lambda x: x and ('skip' in x.lower() or 'main' in x.lower()))
        skip_to_main = [link for link in skip_links if 'main' in str(link.get('href', '')).lower()]
        if not skip_to_main:
            body = self.soup.find('body')
            if body:
                first_link = body.find('a')
                if first_link:
                    href = first_link.get('href', '')
                    if not href.startswith('#'):
                        self.add_issue('keyboard', 'Moderate', 'No skip navigation link',
                            "Page lacks a skip navigation link for keyboard users",
                            "Add a skip link at the top that allows users to bypass navigation", 'WCAG 2.4.1')
                        score -= 0.5
                        issues_found += 1

        buttons = self.soup.find_all('button')
        for btn in buttons:
            if not btn.get_text(strip=True) and not btn.get('aria-label') and not btn.get('title'):
                self.add_issue('keyboard', 'Serious', 'Button missing accessible name',
                    "Button has no text content or aria-label",
                    "Add text content or aria-label to buttons for screen reader accessibility", 'WCAG 2.1.1')
                score -= 0.5
                issues_found += 1

        return max(0, score)

    def check_navigable(self):
        score = 10
        issues_found = 0

        if not self.soup:
            return 0

        title = self.soup.find('title')
        if title:
            title_text = title.get_text(strip=True)
            if len(title_text) < 5:
                self.add_issue('navigable', 'Moderate', 'Page title too short',
                    f"Page title '{title_text}' is too short to be descriptive",
                    "Make page titles descriptive and unique for each page", 'WCAG 2.4.2')
                score -= 0.5
                issues_found += 1
        else:
            self.add_issue('navigable', 'Critical', 'Missing page title',
                "Page has no title element",
                "Add a descriptive <title> element", 'WCAG 2.4.2')
            score -= 1
            issues_found += 1

        links = self.soup.find_all('a', href=True)
        vague_texts = ['click here', 'read more', 'more', 'here', 'link', 'learn more', 'continue']
        for link in links:
            text = link.get_text(strip=True).lower()
            if text in vague_texts:
                self.add_issue('navigable', 'Moderate', 'Non-descriptive link text',
                    f"Link text '{text}' is not descriptive",
                    "Use link text that describes the destination or purpose", 'WCAG 2.4.4')
                score -= 0.5
                issues_found += 1

        headings = self.soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        for heading in headings:
            text = heading.get_text(strip=True)
            if len(text) < 3:
                self.add_issue('navigable', 'Minor', 'Heading too short',
                    f"Heading '{text}' is too short to be descriptive",
                    "Ensure headings clearly describe the content they introduce", 'WCAG 2.4.6')
                score -= 0.25
                issues_found += 1

        navs = self.soup.find_all('nav')
        if not navs:
            self.add_issue('navigable', 'Minor', 'No navigation element',
                "Page has no <nav> navigation element",
                "Consider adding <nav> element for primary navigation", 'WCAG 2.4.1')
            score -= 0.25

        meta_desc = self.soup.find('meta', attrs={'name': 'description'})
        if not meta_desc:
            self.add_issue('navigable', 'Minor', 'Missing meta description',
                "Page has no meta description",
                "Add meta description for better page identification", 'WCAG 2.4.1')
            score -= 0.25

        return max(0, score)

    def check_input_modalities(self):
        score = 5
        issues_found = 0

        if not self.soup:
            return 0

        touch_targets = self.soup.find_all(['a', 'button', 'input', 'select', 'textarea'])
        small_targets = 0
        for elem in touch_targets:
            style = elem.get('style', '')
            width_match = False
            height_match = False
            if 'width' in style:
                width_match = True
            if 'height' in style:
                height_match = True
            if not width_match and not height_match:
                small_targets += 1

        if small_targets > 10:
            self.add_issue('input', 'Minor', 'Touch target sizes not specified',
                f"{small_targets} interactive elements don't specify dimensions",
                "Ensure interactive elements are at least 44x44px for touch targets", 'WCAG 2.5.5')
            score -= 0.5

        motion_elements = (self.soup.find_all(attrs={'onanimationend': True}) +
                           self.soup.find_all(attrs={'ontransitionend': True}))
        if motion_elements:
            self.add_issue('input', 'Moderate', 'Motion-based interactions detected',
                f"Found {len(motion_elements)} elements with motion-based event handlers",
                "Provide alternative input methods for users who cannot use motion", 'WCAG 2.5.1')
            score -= 0.5
            issues_found += 1

        iframes = self.soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src', '')
            if 'youtube' in src or 'vimeo' in src:
                self.add_issue('input', 'Minor', 'Embedded content may require specific input',
                    "Embedded video content may have specific interaction requirements",
                    "Ensure embedded content is accessible via keyboard and other input methods", 'WCAG 2.5.1')
                score -= 0.25
                issues_found += 1
                break

        return max(0, score)

    def check_readable(self):
        score = 5
        issues_found = 0

        if not self.soup:
            return 0

        html_tag = self.soup.find('html')
        if html_tag and html_tag.get('lang'):
            score -= 0
        else:
            self.add_issue('readable', 'Critical', 'Missing page language',
                "HTML element is missing lang attribute",
                "Add lang attribute to <html> element", 'WCAG 3.1.1')
            score -= 1
            issues_found += 1

        multilingual_content = self.soup.find_all(attrs={'lang': True})
        if multilingual_content:
            pass
        else:
            body_text = self.soup.find('body')
            if body_text:
                text = body_text.get_text()
                if len(text) > 500:
                    self.add_issue('readable', 'Minor', 'No language variations detected',
                        "Page has significant text content but no lang attributes on text elements",
                        "If content includes multiple languages, mark language changes with lang attribute", 'WCAG 3.1.2')
                    score -= 0.25

        abbreviations = self.soup.find_all('abbr')
        for abbr in abbreviations:
            if not abbr.get('title'):
                self.add_issue('readable', 'Moderate', 'Abbreviation without expansion',
                    f"Abbreviation '{abbr.get_text()}' has no title attribute with expansion",
                    "Add title attribute with the full expansion of the abbreviation", 'WCAG 3.1.3')
                score -= 0.25
                issues_found += 1

        return max(0, score)

    def check_predictable(self):
        score = 5
        issues_found = 0

        if not self.soup:
            return 0

        forms = self.soup.find_all('form')
        for form in forms:
            if form.get('onsubmit'):
                self.add_issue('predictable', 'Moderate', 'Unexpected context change on form submit',
                    "Form has onsubmit handler that may cause unexpected context change",
                    "Avoid unexpected context changes; provide clear feedback instead", 'WCAG 3.2.1')
                score -= 0.5
                issues_found += 1

        inputs = self.soup.find_all('input', {'type': 'checkbox'})
        for inp in inputs:
            if inp.get('onchange') or inp.get('onclick'):
                self.add_issue('predictable', 'Moderate', 'Unexpected context change on input',
                    "Checkbox input has event handler that may cause unexpected context change",
                    "Avoid automatic context changes on checkbox interactions", 'WCAG 3.2.2')
                score -= 0.25
                issues_found += 1

        status_elements = self.soup.find_all(attrs={'aria-live': True})
        if not status_elements:
            self.add_issue('predictable', 'Minor', 'No aria-live regions for dynamic content',
                "Page has no aria-live regions for announcing dynamic content changes",
                "Add aria-live regions for content that updates dynamically", 'WCAG 4.1.3')
            score -= 0.25

        return max(0, score)

    def check_input_assistance(self):
        score = 5
        issues_found = 0

        if not self.soup:
            return 0

        forms = self.soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'select', 'textarea'])
            required_fields = 0
            fields_with_validation = 0
            for inp in inputs:
                input_type = inp.get('type', 'text')
                if input_type in ['hidden', 'submit', 'button', 'reset']:
                    continue
                if inp.get('required') or inp.get('aria-required') == 'true':
                    required_fields += 1
                if inp.get('pattern') or inp.get('aria-invalid'):
                    fields_with_validation += 1

            if required_fields > 0 and fields_with_validation == 0:
                self.add_issue('input_assist', 'Moderate', 'No error identification for required fields',
                    "Form has required fields but no validation feedback mechanism",
                    "Add aria-invalid and error messages for form validation", 'WCAG 3.3.1')
                score -= 0.5
                issues_found += 1

        inputs = self.soup.find_all('input', {'required': True})
        for inp in inputs:
            if not inp.get('aria-required'):
                self.add_issue('input_assist', 'Minor', 'Required field not marked with aria-required',
                    f"Input '{inp.get('name', 'unnamed')}' is required but lacks aria-required",
                    "Add aria-required='true' for screen reader accessibility", 'WCAG 3.3.2')
                score -= 0.1
                issues_found += 1

        error_messages = self.soup.find_all(class_=lambda x: x and ('error' in str(x).lower() or 'invalid' in str(x).lower()))
        if not error_messages:
            pass

        return max(0, score)

    def check_compatible(self):
        score = 10
        issues_found = 0

        if not self.soup:
            return 0

        if '<!DOCTYPE' not in self.html[:100].upper():
            self.add_issue('compatible', 'Moderate', 'Missing doctype declaration',
                "Page is missing DOCTYPE declaration",
                "Add <!DOCTYPE html> at the beginning of the HTML document", 'WCAG 4.1.1')
            score -= 0.5
            issues_found += 1

        meta_charset = self.soup.find('meta', attrs={'charset': True})
        meta_content_type = self.soup.find('meta', attrs={'http-equiv': lambda x: x and 'content-type' in x.lower()})
        if not meta_charset and not meta_content_type:
            self.add_issue('compatible', 'Serious', 'Missing charset declaration',
                "Page is missing character encoding declaration",
                "Add <meta charset='UTF-8'> in the document head", 'WCAG 4.1.1')
            score -= 0.5
            issues_found += 1

        aria_elements = self.soup.find_all(attrs={'aria-hidden': True})
        for elem in aria_elements:
            if elem.name in ['input', 'button', 'a', 'select', 'textarea']:
                self.add_issue('compatible', 'Serious', 'Interactive element hidden from assistive technology',
                    f"Interactive <{elem.name}> element is hidden with aria-hidden='true'",
                    "Do not hide interactive elements from assistive technology", 'WCAG 4.1.2')
                score -= 0.5
                issues_found += 1

        custom_elements = self.soup.find_all(lambda tag: '-' in tag.name)
        for elem in custom_elements:
            if not elem.get('role') and not elem.get('aria-label'):
                self.add_issue('compatible', 'Moderate', 'Custom element missing ARIA',
                    f"Custom element <{elem.name}> lacks ARIA role or label",
                    "Add appropriate ARIA roles and labels to custom elements", 'WCAG 4.1.2')
                score -= 0.25
                issues_found += 1

        return max(0, score)

    def check_aria_semantics(self):
        score = 10
        issues_found = 0

        if not self.soup:
            return 0

        landmark_roles = ['banner', 'navigation', 'main', 'complementary', 'contentinfo', 'form', 'search']
        found_landmarks = set()
        for role in landmark_roles:
            elements = self.soup.find_all(attrs={'role': role})
            if elements:
                found_landmarks.add(role)

        html5_landmarks = {'banner': 'header', 'navigation': 'nav', 'main': 'main',
                          'complementary': 'aside', 'contentinfo': 'footer'}
        for role, tag in html5_landmarks.items():
            if role not in found_landmarks:
                if self.soup.find(tag):
                    found_landmarks.add(role)

        if 'main' not in found_landmarks:
            self.add_issue('aria', 'Critical', 'Missing main landmark',
                "Page has no main content landmark",
                "Add role='main' or <main> element", 'WCAG 1.3.1')
            score -= 1
            issues_found += 1

        if 'navigation' not in found_landmarks:
            self.add_issue('aria', 'Serious', 'Missing navigation landmark',
                "Page has no navigation landmark",
                "Add role='navigation' or <nav> element", 'WCAG 1.3.1')
            score -= 0.5
            issues_found += 1

        buttons = self.soup.find_all('button')
        for btn in buttons:
            if not btn.get_text(strip=True) and not btn.get('aria-label') and not btn.get('aria-labelledby'):
                self.add_issue('aria', 'Serious', 'Button missing accessible name',
                    "Button has no accessible name for screen readers",
                    "Add text content or aria-label to the button", 'WCAG 4.1.2')
                score -= 0.5
                issues_found += 1

        aria_invalid = self.soup.find_all(attrs={'aria-invalid': True})
        for elem in aria_invalid:
            if not elem.get('aria-describedby') and not elem.get('aria-errormessage'):
                self.add_issue('aria', 'Moderate', 'Invalid state not described',
                    "Element with aria-invalid has no associated error description",
                    "Add aria-describedby or aria-errormessage to describe the error", 'WCAG 4.1.2')
                score -= 0.25
                issues_found += 1

        aria_expanded = self.soup.find_all(attrs={'aria-expanded': True})
        for elem in aria_expanded:
            if not elem.get('aria-controls'):
                self.add_issue('aria', 'Moderate', 'Expanded state without controls',
                    "Element with aria-expanded lacks aria-controls attribute",
                    "Add aria-controls pointing to the expandable content", 'WCAG 4.1.2')
                score -= 0.25
                issues_found += 1

        semantic_elements = self.soup.find_all(['button', 'nav', 'article', 'section', 'aside', 'header', 'footer', 'main'])
        if len(semantic_elements) < 3:
            self.add_issue('aria', 'Minor', 'Limited semantic HTML usage',
                "Page uses few semantic HTML elements",
                "Use semantic elements like <nav>, <article>, <section> for better structure", 'WCAG 1.3.1')
            score -= 0.25

        return max(0, score)

    def check_multimedia(self):
        score = 5
        issues_found = 0

        if not self.soup:
            return 0

        videos = self.soup.find_all('video')
        for video in videos:
            if not video.find('track', {'kind': 'captions'}) and not video.find('track', {'kind': 'subtitles'}):
                self.add_issue('multimedia', 'Serious', 'Video missing captions',
                    "Video element has no caption or subtitle tracks",
                    "Add <track kind='captions'> to provide captions for video content", 'WCAG 1.2.2')
                score -= 0.75
                issues_found += 1

            if not video.get('controls') and not video.get('aria-label'):
                self.add_issue('multimedia', 'Moderate', 'Video controls not accessible',
                    "Video element has no controls or accessible label",
                    "Add controls attribute or custom accessible controls", 'WCAG 1.2.1')
                score -= 0.5
                issues_found += 1

        audio_elements = self.soup.find_all('audio')
        for audio in audio_elements:
            if not audio.find('track', {'kind': 'captions'}):
                self.add_issue('multimedia', 'Serious', 'Audio missing transcript',
                    "Audio element has no associated transcript",
                    "Provide a text transcript for audio content", 'WCAG 1.2.1')
                score -= 0.5
                issues_found += 1

        autoplay_media = self.soup.find_all(['video', 'audio'], autoplay=True)
        if not autoplay_media:
            autoplay_media = self.soup.find_all(['video', 'audio'])
            for media in autoplay_media:
                if media.get('autoplay') or (media.get('style') and 'display:none' in media.get('style', '').lower()):
                    autoplay_media = [media]
                    break
            else:
                autoplay_media = []

        for media in autoplay_media:
            self.add_issue('multimedia', 'Moderate', 'Auto-playing media detected',
                "Media element may auto-play, which can be disorienting",
                "Avoid auto-playing media or provide controls to pause/stop", 'WCAG 1.4.2')
            score -= 0.5
            issues_found += 1

        if not videos and not audio_elements and not autoplay_media:
            self.add_issue('multimedia', 'Minor', 'No multimedia content detected',
                "No video or audio elements found on the page",
                "If multimedia is added later, ensure proper accessibility", 'WCAG 1.2.1')
            score -= 0.1

        return max(0, score)

    def check_cognitive_accessibility(self):
        score = 5

        if not self.soup:
            return 0

        body = self.soup.find('body')
        text = body.get_text(' ', strip=True) if body else ''
        words = [w for w in re.split(r'\s+', text) if w.isalpha()] if text else []
        if words:
            long_words = [w for w in words if len(w) > 12]
            ratio = len(long_words) / len(words)
            if ratio > 0.12:
                self.add_issue('cognitive', 'Moderate', 'Complex vocabulary detected',
                    f"{ratio * 100:.0f}% of words are longer than 12 characters",
                    "Rewrite content using plain language; aim for a lower reading level", 'WCAG 3.1.5')
                score -= 0.75

        paragraphs = self.soup.find_all('p')
        walls = [p for p in paragraphs if len(p.get_text(strip=True)) > 500]
        if walls:
            self.add_issue('cognitive', 'Moderate', 'Dense text walls detected',
                f"{len(walls)} paragraph(s) exceed 500 characters without structure",
                "Break long text into shorter paragraphs with subheadings and lists", 'WCAG 1.3.3')
            score -= 0.5

        placeholder_only = 0
        for inp in self.soup.find_all(['input', 'textarea']):
            if inp.get('type') in ('hidden', 'submit', 'button', 'reset', 'image'):
                continue
            input_id = inp.get('id')
            has_label = False
            if input_id and self.soup.find('label', attrs={'for': input_id}):
                has_label = True
            if inp.find_parent('label') or inp.get('aria-label') or inp.get('aria-labelledby'):
                has_label = True
            if not has_label and inp.get('placeholder'):
                placeholder_only += 1
        if placeholder_only:
            self.add_issue('cognitive', 'Serious', 'Placeholder used as label',
                f"{placeholder_only} input(s) rely on placeholder text instead of a real label",
                "Add persistent <label> elements; placeholders disappear while typing", 'WCAG 3.3.2')
            score -= 0.75

        meta_refresh = self.soup.find('meta', attrs={'http-equiv': lambda x: x and 'refresh' in x.lower()})
        if meta_refresh:
            self.add_issue('cognitive', 'Serious', 'Automatic page redirect (meta refresh)',
                "Meta refresh can disorient users with cognitive disabilities",
                "Remove automatic redirects; provide a manual link instead", 'WCAG 2.2.1')
            score -= 0.75

        help_links = self.soup.find_all('a', href=lambda x: x and any(k in x.lower() for k in ['help', 'faq', 'support', 'contact']))
        if not help_links and not self.soup.find(attrs={'role': 'search'}) and not self.soup.find('search'):
            self.add_issue('cognitive', 'Minor', 'No contextual help available',
                "Page offers no help, FAQ, or search affordance for confused users",
                "Provide contextual help links or a search feature near complex tasks", 'WCAG 3.2.6')
            score -= 0.35

        seen_links = {}
        for link in self.soup.find_all('a', href=True):
            text = link.get_text(strip=True).lower()
            href = link.get('href', '')
            if text and text in seen_links and seen_links[text] != href:
                self.add_issue('cognitive', 'Moderate', 'Same link text, different destinations',
                    f"Link text '{text}' points to multiple different destinations",
                    "Make link text unique per destination so users can distinguish them", 'WCAG 2.4.4')
                score -= 0.5
                break
            if text:
                seen_links[text] = href

        forms_with_pattern = 0
        for inp in self.soup.find_all('input', attrs={'pattern': True}):
            described = inp.get('aria-describedby') or inp.get('title') or inp.get('list')
            if not described:
                forms_with_pattern += 1
        if forms_with_pattern:
            self.add_issue('cognitive', 'Moderate', 'Undescribed input pattern rules',
                f"{forms_with_pattern} field(s) enforce a pattern without explaining it",
                "Explain format requirements via aria-describedby or visible hint text", 'WCAG 3.3.2')
            score -= 0.5

        instructions_present = (self.soup.find(string=re.compile(r'required|must|format|example', re.I)) is not None)
        required_count = len(self.soup.find_all(attrs={'required': True})) + len(self.soup.find_all(attrs={'aria-required': 'true'}))
        if required_count > 2 and not instructions_present:
            self.add_issue('cognitive', 'Minor', 'No upfront form instructions',
                "Form has multiple required fields but no visible instructions before the form",
                "Provide clear instructions above complex forms (required formats, examples)", 'WCAG 3.3.2')
            score -= 0.3

        return max(0, score)

    def check_motor_accessibility(self):
        score = 4

        if not self.soup:
            return 0

        small_targets = 0
        for elem in self.soup.find_all(['a', 'button', 'input', 'select', 'textarea', '[role="button"]']):
            style = elem.get('style', '').lower()
            dims = re.findall(r'(?:width|height)\s*:\s*(\d+)px', style)
            if dims and any(int(d) < 24 for d in dims):
                small_targets += 1
        if small_targets:
            self.add_issue('motor', 'Serious', 'Touch target below 24x24 CSS pixels',
                f"{small_targets} interactive element(s) declare a size smaller than 24px",
                "Enlarge targets to at least 24x24px (44x44px preferred) or add spacing", 'WCAG 2.5.8')
            score -= 1

        drag_only = (len(self.soup.find_all(attrs={'ondragstart': True})) +
                     len(self.soup.find_all(attrs={'ondrag': True})) +
                     len(self.soup.find_all(draggable=True)))
        if drag_only:
            self.add_issue('motor', 'Serious', 'Drag interactions without alternatives',
                f"{drag_only} element(s) implement dragging functionality",
                "Provide a single-pointer alternative (buttons, menus) for dragging actions", 'WCAG 2.5.7')
            score -= 1

        hover_only = 0
        for elem in self.soup.find_all(attrs={'onmouseover': True}):
            if not elem.get('onfocus') and not elem.get('tabindex') and elem.name not in ('a', 'button', 'input', 'select', 'textarea'):
                hover_only += 1
        if hover_only:
            self.add_issue('motor', 'Moderate', 'Hover-only interactions',
                f"{hover_only} element(s) react to hover without keyboard focus support",
                "Mirror hover behavior with focus events and make elements focusable", 'WCAG 2.1.1')
            score -= 0.5

        click_divs = 0
        for elem in self.soup.find_all(['div', 'span', 'li']):
            if elem.get('onclick') and not elem.get('tabindex') and not elem.get('role'):
                click_divs += 1
        if click_divs > 3:
            self.add_issue('motor', 'Serious', 'Click-only non-interactive elements',
                f"{click_divs} div/span/li element(s) have onclick without keyboard support",
                "Use native <button> or <a> elements instead of click handlers on divs", 'WCAG 2.1.1')
            score -= 0.75

        timed = self.soup.find('meta', attrs={'http-equiv': lambda x: x and 'refresh' in x.lower()})
        if timed:
            self.add_issue('motor', 'Moderate', 'Time-limited session detected',
                "Auto-refresh imposes time limits that users with motor impairments may need to extend",
                "Allow users to extend or disable time limits on tasks", 'WCAG 2.2.1')
            score -= 0.5

        long_forms = 0
        for form in self.soup.find_all('form'):
            fields = [f for f in form.find_all(['input', 'select', 'textarea'])
                      if f.get('type', 'text') not in ('hidden', 'submit', 'button', 'reset')]
            if len(fields) >= 6 and not any(f.get('autocomplete') for f in fields):
                long_forms += 1
        if long_forms:
            self.add_issue('motor', 'Moderate', 'Long form without autocomplete',
                f"{long_forms} form(s) have 6+ fields without autocomplete attributes",
                "Add appropriate autocomplete tokens to reduce typing effort", 'WCAG 1.3.5')
            score -= 0.5

        double_clicks = len(self.soup.find_all(attrs={'ondblclick': True}))
        if double_clicks:
            self.add_issue('motor', 'Moderate', 'Double-click interaction detected',
                f"{double_clicks} element(s) require double-clicking",
                "Provide a single-click or keyboard alternative to double-click actions", 'WCAG 2.5.1')
            score -= 0.5

        return max(0, score)

    def check_visual_accessibility(self):
        score = 5

        if not self.soup:
            return 0

        viewport = self.soup.find('meta', attrs={'name': 'viewport'})
        if not viewport:
            self.add_issue('visual', 'Serious', 'Missing viewport meta tag',
                "Page has no viewport declaration, blocking responsive zoom/reflow",
                "Add <meta name='viewport' content='width=device-width, initial-scale=1'>", 'WCAG 1.4.4')
            score -= 0.75
        else:
            content = (viewport.get('content') or '').lower()
            if 'user-scalable=no' in content or 'maximum-scale=1' in content:
                self.add_issue('visual', 'Serious', 'Zoom disabled by viewport',
                    "Viewport forbids user scaling (user-scalable=no or maximum-scale=1)",
                    "Allow zooming by removing user-scalable=no and maximum-scale limits", 'WCAG 1.4.4')
                score -= 1

        fixed_width = 0
        for elem in self.soup.find_all(True):
            style = elem.get('style', '')
            m = re.search(r'width\s*:\s*(\d+)px', style)
            if m and int(m.group(1)) > 480:
                fixed_width += 1
        if fixed_width > 5:
            self.add_issue('visual', 'Serious', 'Fixed pixel widths may block reflow',
                f"{fixed_width} element(s) use fixed widths above 480px",
                "Use relative/fluid widths so content reflows at 320px (1.4.10)", 'WCAG 1.4.10')
            score -= 0.75

        style_tag = self.soup.find('style')
        css = style_tag.get_text() if style_tag else ''
        css_links = [l.get('href', '') for l in self.soup.find_all('link', rel=lambda x: x and 'stylesheet' in str(x))]
        outline_none = 'outline:none' in css.replace(' ', '') or 'outline: 0' in css or 'outline:0' in css.replace(' ', '')
        if outline_none and ':focus' not in css:
            self.add_issue('visual', 'Serious', 'Focus indicator removed without replacement',
                "CSS removes outline but defines no :focus style",
                "Provide a clearly visible custom focus indicator for all focusable elements", 'WCAG 2.4.7')
            score -= 0.75

        if ':focus-visible' not in css and ':focus' not in css and not css_links:
            self.add_issue('visual', 'Minor', 'No custom focus styles found',
                "No :focus or :focus-visible rules detected in inline styles",
                "Define visible focus styles so keyboard users can track position", 'WCAG 2.4.7')
            score -= 0.3

        small_fonts = re.findall(r'font-size\s*:\s*(\d+)px', css)
        tiny = [f for f in small_fonts if int(f) < 12]
        if tiny:
            self.add_issue('visual', 'Moderate', 'Very small font sizes in CSS',
                f"Found {len(tiny)} font-size declaration(s) below 12px",
                "Use at least 12px (16px recommended) and allow text resizing", 'WCAG 1.4.4')
            score -= 0.5

        if not re.search(r'(line-height|leading)\s*:', css):
            elements_with_spacing = [e for e in self.soup.find_all(True) if 'line-height' in (e.get('style') or '')]
            if not elements_with_spacing and len(self.soup.find_all(['p', 'li'])) > 5:
                self.add_issue('visual', 'Minor', 'No text spacing customization detected',
                    "Page does not define line-height, hindering text-spacing overrides",
                    "Define line-height and support the WCAG text spacing success criterion", 'WCAG 1.4.12')
                score -= 0.3

        color_only = 0
        for elem in self.soup.find_all(True):
            style = (elem.get('style') or '').lower()
            if 'color' in style and re.search(r'(required|error|invalid|new|sale)', elem.get_text(strip=True).lower() or 'zzz'):
                color_only += 1
        if color_only:
            self.add_issue('visual', 'Serious', 'Possible color-only state indication',
                f"{color_only} element(s) pair meaning-bearing text with color styling only",
                "Pair color cues with text labels, icons, or patterns (never color alone)", 'WCAG 1.4.1')
            score -= 0.75

        title_descs = self.soup.find_all(attrs={'title': True})
        long_title_descs = [t for t in title_descs if len(t.get('title', '')) > 60]
        if long_title_descs:
            self.add_issue('visual', 'Minor', 'Long descriptions only in title tooltips',
                f"{len(long_title_descs)} element(s) hide long descriptions in title attributes",
                "Provide descriptions as visible text or aria-describedby content", 'WCAG 1.4.13')
            score -= 0.3

        return max(0, score)

    def check_hearing_accessibility(self):
        score = 4

        if not self.soup:
            return 0

        videos = self.soup.find_all('video')
        for video in videos:
            has_captions = bool(video.find('track', {'kind': 'captions'}) or video.find('track', {'kind': 'subtitles'}))
            has_ad = bool(video.find('track', {'kind': 'descriptions'}))
            if not has_captions:
                self.add_issue('hearing', 'Critical', 'Video lacks captions for deaf users',
                    "Video content has no caption/subtitle track",
                    "Add synchronized captions (WebVTT) for all spoken audio", 'WCAG 1.2.2')
                score -= 0.75
            if not has_ad:
                self.add_issue('hearing', 'Moderate', 'No audio description track',
                    "Video has no audio description track for visual information",
                    "Provide audio descriptions or an extended description for visual-only content", 'WCAG 1.2.5')
                score -= 0.4

        audio_elements = self.soup.find_all('audio')
        for audio in audio_elements:
            parent = audio.parent
            has_transcript = False
            if parent:
                has_transcript = bool(parent.find(string=re.compile(r'transcript', re.I)))
            if not has_transcript:
                nearby = audio.find_next(string=re.compile(r'transcript', re.I)) if audio else None
                if not nearby:
                    self.add_issue('hearing', 'Serious', 'Audio without transcript',
                        "Audio element has no linked transcript for deaf/hard-of-hearing users",
                        "Provide a full text transcript near the audio player", 'WCAG 1.2.1')
                    score -= 0.5

        iframes = self.soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src', '').lower()
            if any(v in src for v in ['youtube', 'vimeo', 'player']):
                if 'captions' not in src and 'cc_load_policy=1' not in src:
                    self.add_issue('hearing', 'Moderate', 'Embedded player may not force captions',
                        "Embedded video player URL does not request captions explicitly",
                        "Enable captions by default in the embed (e.g., cc_load_policy=1)", 'WCAG 1.2.2')
                    score -= 0.4
                    break

        iframes_no_caption = [v for v in videos if not (v.find('track', {'kind': 'captions'}) or v.find('track', {'kind': 'subtitles'}))]
        sign_language_ref = bool(self.soup.find(attrs={'aria-label': re.compile(r'sign language', re.I)}))
        if iframes_no_caption and not sign_language_ref and self.level == 'AAA':
            self.add_issue('hearing', 'Minor', 'No sign language interpretation offered',
                "AAA target set but no sign language alternative detected",
                "Provide sign language interpretation for presented audio (WCAG 1.2.6)", 'WCAG 1.2.6')
            score -= 0.3

        bg_media = self.soup.find_all(['video', 'audio'], attrs={'autoplay': True})
        for media in bg_media:
            self.add_issue('hearing', 'Moderate', 'Auto-playing audio without mute control',
                "Auto-playing audio can mask screen-reader speech output",
                "Do not auto-play audio, or provide an immediate mute/stop control", 'WCAG 1.4.7')
            score -= 0.4
            break

        return max(0, score)

    def check_speech_accessibility(self):
        score = 3

        if not self.soup:
            return 0

        mismatches = 0
        for inp in self.soup.find_all(['input', 'select', 'textarea']):
            if inp.get('type') in ('hidden', 'submit', 'button', 'reset', 'image'):
                continue
            input_id = inp.get('id')
            visible_label = None
            if input_id:
                label = self.soup.find('label', attrs={'for': input_id})
                if label:
                    visible_label = label.get_text(strip=True)
            if not visible_label:
                parent_label = inp.find_parent('label')
                if parent_label:
                    visible_label = parent_label.get_text(strip=True)
            aria_label = inp.get('aria-label') or ''
            if visible_label and aria_label and visible_label.lower() not in aria_label.lower() and aria_label.lower() not in visible_label.lower():
                mismatches += 1
        if mismatches:
            self.add_issue('speech', 'Serious', 'Accessible name differs from visible label',
                f"{mismatches} control(s) have aria-label that does not contain the visible label text",
                "Ensure the accessible name starts with the visible label (Label in Name)", 'WCAG 2.5.3')
            score -= 1

        icon_only = 0
        for btn in self.soup.find_all('button'):
            text = btn.get_text(strip=True)
            has_img = bool(btn.find('img') or btn.find('svg'))
            if not text and (btn.get('aria-label') or btn.find('img') or btn.find('svg')):
                if has_img or btn.get('aria-hidden') == 'true':
                    icon_only += 1
        if icon_only > 2:
            self.add_issue('speech', 'Moderate', 'Many icon-only controls',
                f"{icon_only} button(s) show only icons; voice-control users cannot say a visible name",
                "Add visible text labels (or visually-hidden text) alongside icons", 'WCAG 2.5.3')
            score -= 0.5

        ambiguous = 0
        texts = {}
        for btn in self.soup.find_all(['button', 'a']):
            t = btn.get_text(strip=True).lower()
            if t:
                texts[t] = texts.get(t, 0) + 1
        for t, count in texts.items():
            if count > 3 and t in ('ok', 'yes', 'submit', 'next', 'go', 'click'):
                ambiguous += 1
        if ambiguous:
            self.add_issue('speech', 'Moderate', 'Ambiguous repeated command labels',
                "Identical short labels repeat across the page, confusing voice control",
                "Disambiguate repeated controls with unique visible names", 'WCAG 2.5.3')
            score -= 0.5

        title_only = 0
        for elem in self.soup.find_all(['a', 'button']):
            visible = elem.get_text(strip=True)
            if not visible and elem.get('title') and not elem.get('aria-label'):
                title_only += 1
        if title_only:
            self.add_issue('speech', 'Moderate', 'Controls named only by tooltip title',
                f"{title_only} control(s) expose no text except a title tooltip",
                "Provide a real accessible name via text or aria-label", 'WCAG 4.1.2')
            score -= 0.5

        phone_fields = self.soup.find_all('input', attrs={'type': 'tel'})
        name_hints = self.soup.find_all('input', attrs={'autocomplete': re.compile(r'tel|tel-national', re.I)})
        if phone_fields and not name_hints:
            self.add_issue('speech', 'Minor', 'Phone field missing telephone autocomplete',
                "Telephone inputs should declare autocomplete='tel' for voice/dictation tools",
                "Add autocomplete='tel' (or tel-national) to phone number inputs", 'WCAG 1.3.5')
            score -= 0.3

        return max(0, score)

    def check_neurodiversity(self):
        score = 4

        if not self.soup:
            return 0

        flashing = (self.soup.find_all('blink') +
                    self.soup.find_all('marquee') +
                    [e for e in self.soup.find_all(True)
                     if 'animation' in (e.get('style') or '').lower() and 'flash' in (e.get('style') or '').lower()])
        if flashing:
            self.add_issue('neurodiversity', 'Critical', 'Flashing/marquee content detected',
                f"{len(flashing)} element(s) flash or scroll automatically",
                "Remove flashing content or provide a stop/pause control (three-flash rule)", 'WCAG 2.3.1')
            score -= 1

        style_tag = self.soup.find('style')
        css = style_tag.get_text() if style_tag else ''
        keyframes = '@keyframes' in css
        reduced_motion = 'prefers-reduced-motion' in css
        if keyframes and not reduced_motion:
            self.add_issue('neurodiversity', 'Moderate', 'Animations without reduced-motion support',
                "CSS keyframe animations exist but no prefers-reduced-motion media query",
                "Add @media (prefers-reduced-motion: reduce) rules that disable animations", 'WCAG 2.3.3')
            score -= 0.5

        carousel_hints = self.soup.find_all(class_=lambda x: x and any(k in str(x).lower() for k in ['carousel', 'slider', 'slideshow']))
        if carousel_hints:
            has_pause = bool(self.soup.find(attrs={'aria-label': re.compile(r'pause|stop|stop slideshow', re.I)}) or
                             self.soup.find('button', string=re.compile(r'pause|stop', re.I)))
            if not has_pause:
                self.add_issue('neurodiversity', 'Serious', 'Auto-rotating carousel without pause',
                    "Carousel/slider content found without an explicit pause or stop control",
                    "Add visible pause/stop controls and avoid auto-advancing content", 'WCAG 2.2.2')
                score -= 0.75

        new_windows = [a for a in self.soup.find_all('a', target=True) if a.get('target') == '_blank']
        if len(new_windows) > 3:
            self.add_issue('neurodiversity', 'Minor', 'Many links open new windows',
                f"{len(new_windows)} link(s) open in a new tab/window without warning",
                "Warn users before opening new tabs or keep navigation in the same window", 'WCAG 3.2.5')
            score -= 0.3

        nav = self.soup.find('nav')
        if nav:
            nav_links = nav.find_all('a')
            if len(nav_links) > 30:
                self.add_issue('neurodiversity', 'Moderate', 'Overloaded navigation menu',
                    f"Primary navigation contains {len(nav_links)} links",
                    "Group and prioritize navigation links to reduce cognitive load", 'WCAG 2.4.5')
                score -= 0.5

        aria_live = self.soup.find_all(attrs={'aria-live': True})
        unexpected_updates = len(self.soup.find_all(attrs={'onchange': True})) + len(self.soup.find_all(attrs={'oninput': True}))
        if unexpected_updates > 5 and not aria_live:
            self.add_issue('neurodiversity', 'Moderate', 'Frequent silent content updates',
                f"{unexpected_updates} input change handlers without live-region announcements",
                "Announce dynamic updates via aria-live so changes are predictable", 'WCAG 4.1.3')
            score -= 0.5

        long_session = self.soup.find('meta', attrs={'http-equiv': lambda x: x and 'refresh' in x.lower()})
        if long_session:
            self.add_issue('neurodiversity', 'Minor', 'Automatic refresh may cause interruptions',
                "Automatic page refresh interrupts users who need extra processing time",
                "Allow users to extend sessions or refresh manually", 'WCAG 2.2.1')
            score -= 0.3

        complex_tables = 0
        for table in self.soup.find_all('table'):
            if table.find('table') or (len(table.find_all('th')) > 8 and table.find(attrs={'rowspan': True})):
                complex_tables += 1
        if complex_tables:
            self.add_issue('neurodiversity', 'Minor', 'Complex table structures',
                f"{complex_tables} table(s) have complex headers that are hard to parse",
                "Simplify tables or provide a linearized summary of the data", 'WCAG 1.3.1')
            score -= 0.3

        return max(0, score)

    def check_accessibility_statement(self):
        score = 3
        info = {'found': False, 'evidence': '', 'components': [], 'missing_components': []}
        if not self.soup:
            self.statement_analysis = info
            return 0

        statement_link = None
        for a in self.soup.find_all('a', href=True):
            text = a.get_text(' ', strip=True).lower()
            href = (a.get('href') or '').lower()
            if 'accessibility statement' in text or ('accessibility' in text and 'statement' in text):
                statement_link = a
                break
            if 'accessibility' in href and 'statement' in href:
                statement_link = a
                break

        body = self.soup.find('body')
        page_text = body.get_text(' ', strip=True) if body else ''
        page_lower = page_text.lower()
        inline_statement = 'accessibility statement' in page_lower

        if statement_link or inline_statement:
            info['found'] = True
            info['evidence'] = statement_link.get('href', 'inline') if statement_link else 'inline content'

        component_tests = [
            ('Conformance claim', ['conform', 'compliant', 'compliance', 'meets']),
            ('Standard referenced', ['wcag', 'web content accessibility', 'en 301 549', 'section 508']),
            ('Feedback channel', ['feedback', 'contact', 'email', 'report', 'reach out']),
            ('Evaluation date', ['last updated', 'evaluated', 'reviewed', 'updated on']),
            ('Formal complaints', ['complaint', 'enforcement', 'escalat', 'dispute']),
            ('Compatibility statement', ['compatib', 'browsers', 'assistive technology']),
            ('Known limitations', ['limitation', 'not fully', 'partially', 'known issue', 'does not']),
        ]
        for name, keywords in component_tests:
            if any(k in page_lower for k in keywords):
                info['components'].append(name)
            else:
                info['missing_components'].append(name)

        if not info['found']:
            self.add_issue('statement', 'Serious', 'No accessibility statement found',
                "The page provides no accessibility statement or link to one",
                "Publish an accessibility statement covering conformance status, feedback route, and known limitations", 'WCAG 4.1.3')
            score = 0
        else:
            missing = len(info['missing_components'])
            if missing:
                self.add_issue('statement', 'Moderate' if missing > 3 else 'Minor',
                    'Accessibility statement incomplete',
                    f"Statement detected but {missing} recommended section(s) appear absent: " + ', '.join(info['missing_components']),
                    "Expand the statement with conformance status, evaluation date, feedback route, and complaints process")
                score -= min(2.4, missing * 0.35)
            if 'wcag' not in page_lower:
                self.add_issue('statement', 'Minor', 'Statement omits the standard referenced',
                    "No mention of WCAG or an equivalent standard near the statement",
                    "Name the standard and level (e.g., WCAG 2.2 Level AA) explicitly in the statement")

        self.statement_analysis = info
        return max(0, score)

    def check_feedback_mechanism(self):
        score = 2
        info = {'found': False, 'channels': [], 'accessible': False,
                'channel_count': 0, 'diverse_channels': False,
                'response_time_promised': False, 'dedicated_page': False,
                'issues': []}
        if not self.soup:
            self.feedback_analysis = info
            return 0

        channels = []
        for a in self.soup.find_all('a', href=True):
            href = (a.get('href') or '').lower()
            text = a.get_text(' ', strip=True).lower()
            if href.startswith('mailto:'):
                channels.append('email link')
            if href.startswith('tel:'):
                channels.append('phone link')
            if any(k in href for k in ('contact', 'feedback', 'support', 'help', 'report-an-issue', 'report-issue')):
                channels.append('link: ' + href[:60])
            if any(k in text for k in ('accessibility feedback', 'report an accessibility',
                                       'accessibility issue', 'give feedback', 'send feedback')):
                channels.append('text: ' + text[:60])
            if 'accessibility' in href and any(k in href for k in ('contact', 'feedback', 'report', 'issue')):
                info['dedicated_page'] = True

        for form in self.soup.find_all('form'):
            form_text = form.get_text(' ', strip=True).lower()
            if any(k in form_text for k in ('feedback', 'contact', 'report', 'accessib')):
                channels.append('feedback form')

        body = self.soup.find('body')
        page_text = body.get_text(' ', strip=True).lower() if body else ''
        if re.search(r'(respond|reply|get back to you|acknowledge).{0,40}(within|in)\s+\d+\s*(business\s+|working\s+)?(day|hour)', page_text):
            info['response_time_promised'] = True

        if (re.search(r'(?:accessib\w*|feedback)[^@]{0,120}[\w.+-]+@[\w-]+\.[\w.]+', page_text) or
                re.search(r'[\w.+-]+@[\w-]+\.[\w.]+[^@]{0,120}(?:accessib\w*|feedback)', page_text)):
            channels.append('email address (in text)')

        info['channels'] = sorted(set(channels))
        info['channel_count'] = len(info['channels'])
        info['diverse_channels'] = info['channel_count'] >= 2
        info['found'] = bool(info['channels'])

        accessible_channel = False
        for form in self.soup.find_all('form'):
            form_text = form.get_text(' ', strip=True).lower()
            if not any(k in form_text for k in ('feedback', 'contact', 'report', 'accessib')):
                continue
            fields = [f for f in form.find_all(['input', 'select', 'textarea'])
                      if f.get('type', 'text') not in ('hidden', 'submit', 'button', 'reset')]
            labelled = 0
            for f in fields:
                fid = f.get('id')
                has_label = bool(fid and self.soup.find('label', attrs={'for': fid}))
                if f.find_parent('label') or f.get('aria-label') or f.get('aria-labelledby'):
                    has_label = True
                if has_label:
                    labelled += 1
            if fields and labelled == len(fields):
                accessible_channel = True
            elif fields:
                info['issues'].append(f"feedback form has {len(fields) - labelled} unlabelled field(s)")
        if any(c.startswith('email') or c.startswith('text') or c.startswith('phone') for c in info['channels']):
            accessible_channel = True
        info['accessible'] = accessible_channel

        if not info['found']:
            self.add_issue('feedback', 'Serious', 'No accessibility feedback mechanism detected',
                "No contact form, feedback link, or email route for reporting accessibility problems was found",
                "Add a visible way to report accessibility issues (form, mailto link, or dedicated page)", 'WCAG 4.1.3')
            score = 0
        else:
            if not info['accessible']:
                self.add_issue('feedback', 'Moderate', 'Feedback mechanism may not be accessible itself',
                    "A feedback channel exists but its form fields could not be confirmed as labelled",
                    "Ensure the feedback form has proper labels, error identification, and keyboard support", 'WCAG 3.3.2')
                score -= 1
            if not info['diverse_channels']:
                self.add_issue('feedback', 'Minor', 'Single feedback channel only',
                    "Only one feedback route was detected, limiting alternative ways to report issues",
                    "Offer at least two channels (e.g., email plus a form) for reporting accessibility problems")
                score -= 0.25
            if not info['response_time_promised']:
                self.add_issue('feedback', 'Minor', 'No response time commitment for feedback',
                    "No stated timeframe for acknowledging or resolving accessibility feedback was found",
                    "Commit to a response time (e.g., acknowledge within 5 business days) in the feedback route")
                score -= 0.25
            if info['issues']:
                score -= 0.25 * len(info['issues'])

        self.feedback_analysis = info
        return max(0, score)

    def check_training_hints(self):
        score = 2
        if not self.soup:
            self.training_hints = []
            return 0

        category_counts = {}
        severity_weights = {'Critical': 3, 'Serious': 2, 'Moderate': 1, 'Minor': 0.5}
        weighted_counts = {}
        for issue in self.issues:
            category_counts[issue.category] = category_counts.get(issue.category, 0) + 1
            weighted_counts[issue.category] = (weighted_counts.get(issue.category, 0) +
                                               severity_weights.get(issue.severity, 1))

        training_map = [
            ('text_alt', 'Content authoring: image descriptions and alt text',
             'Train writers and editors on when and how to write alt text (decorative vs informative).',
             'Authors'),
            ('adaptable', 'Structure: headings, landmarks, and form labels',
             'Coach authors on heading order, a single h1, and associating labels with fields.',
             'Authors'),
            ('distinguishable', 'Descriptive link text and colour contrast basics',
             'Short session on descriptive links and meeting 4.5:1 contrast when choosing colours.',
             'Designers'),
            ('keyboard', 'Keyboard-only interaction patterns',
             'Walk developers through focus order, skip links, and native interactive controls.',
             'Developers'),
            ('aria', 'Native HTML first, ARIA only when needed',
             'Train the team to prefer semantic HTML and know when ARIA is actually required.',
             'Developers'),
            ('wcag22', 'WCAG 2.2 delta briefing',
             'Brief the team on 2.2 criteria: target size, focus appearance, redundant entry, accessible authentication.',
             'Whole team'),
            ('multimedia', 'Captions, transcripts, and audio description workflow',
             'Set up a media workflow so every video ships with captions and a transcript.',
             'Media team'),
            ('cognitive', 'Plain language and upfront form instructions',
             'Coach content designers on plain language, examples, and instructions before complex forms.',
             'Authors'),
            ('input_assist', 'Error identification and input assistance patterns',
             'Train form developers on aria-invalid, error messaging, and instructions before complex fields.',
             'Developers'),
            ('screen_reader', 'Screen reader-friendly labelling',
             'Run a hands-on session where the team hears their own pages in a screen reader.',
             'Whole team'),
            ('keyboard_nav', 'Focus management and tab order drills',
             'Practice fixing tab order, focus traps, and skip links with keyboard-only walkthroughs.',
             'Developers'),
            ('motor', 'Pointer alternatives and target sizing',
             'Cover drag alternatives, target sizes, and single-pointer patterns for motor impairments.',
             'Designers'),
            ('visual', 'Zoom, reflow, and focus visibility',
             'Teach 200% zoom testing, reflow at 320px, and keeping visible focus indicators.',
             'Designers'),
            ('hearing', 'Captions and transcript standards',
             'Set caption/transcript standards and review embedded players for forced captions.',
             'Media team'),
            ('neurodiversity', 'Reduced motion and interruption control',
             'Cover prefers-reduced-motion, carousel pause controls, and predictable interactions.',
             'Designers'),
        ]
        gap_hints = []
        for cat, topic, action, audience in training_map:
            count = category_counts.get(cat, 0)
            weight = weighted_counts.get(cat, 0)
            if count >= 2 or weight >= 4:
                gap_hints.append({'topic': topic, 'action': action, 'audience': audience,
                                  'signal': f"{count} issue(s), severity load {weight:g}"})

        gap_hints.sort(key=lambda h: h.get('signal', ''), reverse=True)

        hints = list(gap_hints)
        if not hints:
            hints.append({'topic': 'Maintain baseline accessibility awareness',
                          'action': 'Keep periodic refreshers so standards stay current as the site evolves.',
                          'audience': 'Whole team',
                          'signal': 'Few recurring issue clusters detected'})

        guidance_links = []
        for a in self.soup.find_all('a', href=True):
            haystack = (a.get('href', '') + ' ' + a.get_text(' ', strip=True)).lower()
            if any(k in haystack for k in ('accessibility training', 'a11y training',
                                           'accessibility guide', 'accessibility style guide',
                                           'authoring guidelines')):
                guidance_links.append(a.get('href'))

        has_training_page = any(
            a.get('href') and 'training' in (a.get('href') or '').lower() and 'accessib' in
            ((a.get('href') or '') + ' ' + a.get_text(' ', strip=True).lower())
            for a in self.soup.find_all('a', href=True))

        self.training_hints = hints

        if len(gap_hints) >= 5:
            self.add_issue('training', 'Serious', 'Widespread training gaps indicated',
                f"Recurring weighted issues across {len(gap_hints)} areas suggest team-wide accessibility training is due",
                "Schedule role-specific workshops for developers, designers, and content authors")
            score -= 1.2
        elif len(gap_hints) >= 3:
            self.add_issue('training', 'Moderate', 'Widespread training gaps indicated',
                f"Recurring issues across {len(gap_hints)} areas suggest team-wide accessibility training is due",
                "Schedule role-specific workshops for developers, designers, and content authors")
            score -= 1.0
        elif gap_hints:
            self.add_issue('training', 'Minor', 'Targeted training gaps detected',
                f"{len(gap_hints)} recurring issue area(s) point to specific training needs",
                "Share focused guidance or run a short workshop on the affected topics")
            score -= 0.5

        if not guidance_links and not has_training_page:
            self.add_issue('training', 'Minor', 'No in-house accessibility guidance linked',
                "The site links no accessibility style guide, authoring guide, or training resource",
                "Publish an internal accessibility style guide and link it from contributor documentation")
            score -= 0.5
        elif not guidance_links:
            self.add_issue('training', 'Minor', 'Training material linked but no style guide found',
                "A training reference exists but no reusable authoring style guide is linked",
                "Add a durable accessibility style guide so day-to-day authoring questions have an answer")
            score -= 0.25

        return max(0, score)

    def check_conformance_report(self):
        score = 3
        info = {'found': False, 'signals': [], 'artifacts': [],
                'standards': [], 'dated': False, 'specific_level': ''}
        if not self.soup:
            self.conformance_report_info = info
            return 0

        body = self.soup.find('body')
        text = (body.get_text(' ', strip=True) if body else '').lower()
        signal_tests = {
            'VPAT': ['vpat'],
            'Accessibility Conformance Report (ACR)': ['accessibility conformance report'],
            'EN 301 549': ['en 301 549', 'en301549'],
            'Section 508': ['section 508', 'section508'],
            'WCAG conformance report': ['conformance report', 'wcag 2.2 level', 'wcag 2.1 level'],
        }
        for name, keywords in signal_tests.items():
            if any(k in text for k in keywords):
                info['signals'].append(name)

        standard_tests = [
            ('WCAG 2.2', ['wcag 2.2']),
            ('WCAG 2.1', ['wcag 2.1']),
            ('WCAG 2.0', ['wcag 2.0']),
            ('EN 301 549', ['en 301 549', 'en301549']),
            ('Section 508', ['section 508']),
            ('ADA', ['ada title iii', 'americans with disabilities act']),
            ('IAAP', ['iaap', 'cpacc', 'was ']),
        ]
        for name, keywords in standard_tests:
            if any(k in text for k in keywords):
                info['standards'].append(name)

        if re.search(r'(last (?:updated|reviewed|revised)|date[d]?:|published|updated on)\s*[:\s]*\w+\s+\d{1,2},?\s+(19|20)\d{2}', text):
            info['dated'] = True

        level_match = re.search(r'wcag 2\.\d level (aaa|aa|a)\b', text)
        if level_match:
            info['specific_level'] = level_match.group(1).upper()

        for a in self.soup.find_all('a', href=True):
            href = (a.get('href') or '').lower()
            label = a.get_text(' ', strip=True).lower()
            if href.endswith('.pdf') and any(k in (href + ' ' + label)
                                             for k in ('vpat', 'accessib', 'conformance', 'acr')):
                info['artifacts'].append(a.get('href'))
            if any(k in label for k in ('vpat', 'conformance report', 'accessibility report')):
                info['artifacts'].append(label[:80])

        info['signals'] = sorted(set(info['signals']))
        info['artifacts'] = sorted(set(info['artifacts']))
        info['standards'] = sorted(set(info['standards']))
        info['found'] = bool(info['signals'] or info['artifacts'])

        if not info['found']:
            self.add_issue('conformance_report', 'Moderate', 'No accessibility conformance report found',
                "No VPAT, ACR, EN 301 549, or Section 508 conformance report was detected",
                "Publish an accessibility conformance report (VPAT/ACR) covering the tested standard and level")
            score = 0
        else:
            if not info['artifacts']:
                self.add_issue('conformance_report', 'Minor', 'Conformance report mentioned but not linked',
                    "The page mentions conformance reporting but provides no downloadable artifact",
                    "Link the full VPAT/ACR document (PDF or HTML) from the accessibility page")
                score -= 1
            if not info['standards']:
                self.add_issue('conformance_report', 'Minor', 'Conformance report lacks a named standard',
                    "A report signal exists but no specific standard (WCAG, EN 301 549, Section 508) was named",
                    "Name the exact standard and edition the report evaluates against")
                score -= 0.5
            elif 'WCAG 2.2' not in info['standards'] and self.level:
                self.add_issue('conformance_report', 'Minor', 'Conformance report not citing WCAG 2.2',
                    "Report signals do not cite WCAG 2.2, the current recommendation",
                    "Update the conformance report to evaluate against WCAG 2.2 (current) alongside older editions")
                score -= 0.25
            if not info['dated']:
                self.add_issue('conformance_report', 'Minor', 'Conformance report has no visible date',
                    "No evaluation or last-updated date was detected with the conformance report",
                    "Date the conformance report and state its review cadence so readers can judge freshness")
                score -= 0.5
            if not info['specific_level']:
                self.add_issue('conformance_report', 'Minor', 'Conformance report omits conformance level',
                    "No WCAG level (A/AA/AAA) claim was found alongside the report signals",
                    "State the conformance level achieved (e.g., WCAG 2.2 Level AA) explicitly in the report")
                score -= 0.25

        self.conformance_report_info = info
        return max(0, score)

    def check_certification_hints(self):
        score = 2
        info = {'found': False, 'signals': [], 'named_body': False,
                'renewal_dated': False, 'credential_linked': False}
        if not self.soup:
            self.certification_info = info
            return 0

        body = self.soup.find('body')
        text = (body.get_text(' ', strip=True) if body else '').lower()
        signal_tests = [
            ('Third-party certification', ['certified', 'certification', 'officially certified']),
            ('Accessibility seal or badge', ['accessibility seal', 'accessibility badge', 'accessibility score']),
            ('Professional credential (IAAP)', ['iaap', 'cpacc', 'web accessibility specialist']),
            ('Trusted Tester programme', ['trusted tester']),
            ('Audited by a recognised vendor', ['audited by', 'audit by', 'independent audit']),
            ('ISO conformity claim', ['iso 37107', 'iso 40500', 'iso/iec']),
        ]
        for name, keywords in signal_tests:
            if any(k in text for k in keywords):
                info['signals'].append(name)

        certifying_bodies = ['iaap', 'dqa', 'level access', 'deque', 'tenon', 'siteimprove',
                             'accessible web', 'epic', 'abilitynet', 'w3c']
        info['named_body'] = any(b in text for b in certifying_bodies)

        info['renewal_dated'] = bool(re.search(
            r'(?:expires?|expiry|renew(?:al)?|valid (?:until|through))[^.]{0,40}\b(19|20)\d{2}\b',
            text))

        for a in self.soup.find_all('a', href=True):
            href = (a.get('href') or '').lower()
            label = a.get_text(' ', strip=True).lower()
            if any(k in (href + ' ' + label) for k in ('certif', 'credential', 'badge', 'seal')):
                if href.startswith('http') and 'accessib' in (href + ' ' + label):
                    info['credential_linked'] = True
                elif href.endswith('.png') or href.endswith('.svg') or href.endswith('.jpg'):
                    info['credential_linked'] = True

        info['signals'] = sorted(set(info['signals']))
        info['found'] = bool(info['signals'])

        if not info['found']:
            self.add_issue('certification', 'Minor', 'No accessibility certification signals detected',
                "The page shows no certification, badge, or independent audit credential",
                "Consider an independent accessibility audit and publish the certification or audit outcome")
            score = 0
        else:
            if not info['named_body']:
                self.add_issue('certification', 'Minor', 'Certification claim without a named certifying body',
                    "A certification or badge signal exists but no recognised certifying body is named",
                    "Name the accrediting body and link the verifiable credential so claims can be checked")
                score -= 0.5
            if not info['renewal_dated']:
                self.add_issue('certification', 'Minor', 'Certification has no expiry or renewal date',
                    "No expiry or renewal date was found with the certification claim",
                    "Show when the certification expires or was last renewed to prove it is current")
                score -= 0.5
            if not info['credential_linked']:
                self.add_issue('certification', 'Minor', 'Certification not linked to a verifiable credential',
                    "No link to a verifiable credential or badge record was detected",
                    "Link the badge or credential record so third parties can verify the claim")
                score -= 0.25

        self.certification_info = info
        return max(0, score)

    def check_maturity_deep_analysis(self):
        score = 3
        if not self.soup:
            self.maturity_deep = {'dimensions': {}, 'gaps': [], 'strengths': [],
                                  'next_stage': '', 'readiness_pct': 0.0}
            return 0

        def cat_pct(cat):
            mx = self.max_scores.get(cat, 1)
            return round((self.scores.get(cat, 0) / mx * 100) if mx else 0.0, 1)

        dimensions = {
            'Policy & Statement': cat_pct('statement'),
            'Feedback & Response': cat_pct('feedback'),
            'Team Training': cat_pct('training'),
            'Conformance Reporting': cat_pct('conformance_report'),
            'Independent Certification': cat_pct('certification'),
            'Core WCAG Implementation': round(
                sum(cat_pct(c) for c in
                    ['text_alt', 'adaptable', 'distinguishable', 'keyboard',
                     'navigable', 'input_assist', 'compatible', 'aria']) / 8, 1),
            'Persona Coverage': round(
                sum(cat_pct(c) for c in self.persona_categories) / len(self.persona_categories), 1),
            'WCAG 2.2 Currency': cat_pct('wcag22'),
            'Assistive-Tech Simulation': round(
                (cat_pct('a11y_tree') + cat_pct('screen_reader') + cat_pct('keyboard_nav')) / 3, 1),
        }

        readiness = round(sum(dimensions.values()) / len(dimensions), 1) if dimensions else 0.0

        gaps = sorted([k for k, v in dimensions.items() if v < 50])
        strengths = sorted([k for k, v in dimensions.items() if v >= 80])

        stage_order = ['Nonexistent', 'Initial', 'Managed', 'Defined', 'Measured', 'Optimizing']
        current_name = self.maturity.get('name', 'Initial')
        current_stage = stage_order.index(current_name) if current_name in stage_order else 1
        next_idx = min(current_stage + 1, len(stage_order) - 1)
        next_stage = stage_order[next_idx]
        gap_drivers = [g for g in gaps[:3]]
        next_detail = (f"Close gaps in {', '.join(gap_drivers)} to progress toward '{next_stage}'."
                       if gap_drivers else
                       f"Maintain current strengths to hold '{current_name}' and progress toward '{next_stage}'.")

        info = {'dimensions': dimensions, 'gaps': gaps, 'strengths': strengths,
                'next_stage': next_stage, 'readiness_pct': readiness,
                'next_detail': next_detail, 'current_stage': current_name}
        self.maturity_deep = info

        if not strengths:
            self.add_issue('maturity_deep', 'Moderate', 'No maturity dimension at strong level',
                "No governance or implementation dimension scores at or above 80%",
                "Pick the highest-impact gap below and drive it to 80% to build one strong dimension")
            score -= 0.75
        if len(gaps) >= 4:
            self.add_issue('maturity_deep', 'Serious', 'Multiple weak maturity dimensions',
                f"{len(gaps)} of {len(dimensions)} maturity dimensions score below 50%: " + ', '.join(gaps),
                "Treat these as a governance programme: assign owners, targets, and review dates")
            score -= 1.2
        elif gaps:
            self.add_issue('maturity_deep', 'Moderate', 'Maturity dimensions below target',
                f"{len(gaps)} maturity dimension(s) below 50%: " + ', '.join(gaps),
                "Set measurable targets for each weak dimension and track them per release")
            score -= 0.5

        if dimensions.get('Independent Certification', 0) < 40 and dimensions.get('Conformance Reporting', 0) < 40:
            self.add_issue('maturity_deep', 'Moderate', 'Weak external assurance posture',
                "Both conformance reporting and independent certification are weak or absent",
                "Publish a VPAT/ACR and commission an independent audit to strengthen external assurance")
            score -= 0.5

        return max(0, min(3, score))

    def check_wcag22_criteria(self):
        score = 6

        if not self.soup:
            return 0

        sticky = 0
        for tag in ['header', 'nav']:
            for elem in self.soup.find_all(tag):
                style = (elem.get('style') or '').lower()
                classes = ' '.join(elem.get('class') or []).lower()
                if 'fixed' in style or 'sticky' in classes or 'fixed' in classes:
                    sticky += 1
        if sticky:
            self.add_issue('wcag22', 'Moderate', 'Sticky/fixed header may obscure focus (2.4.11)',
                f"{sticky} fixed/sticky region(s) can cover the focused element",
                "Ensure focused elements are never fully obscured by sticky UI", 'WCAG 2.4.11')
            score -= 0.75

        style_tag = self.soup.find('style')
        css = style_tag.get_text() if style_tag else ''
        compact = css.replace(' ', '')
        if 'outline:none' in compact or 'outline:0' in compact:
            if ':focus-visible' not in css and ':focus' not in css:
                self.add_issue('wcag22', 'Serious', 'Focus appearance suppressed (2.4.13)',
                    "Outline is removed with no compensating focus indicator styles",
                    "Draw a high-contrast focus indicator with sufficient area (WCAG 2.4.13)", 'WCAG 2.4.13')
                score -= 1

        dragging = (len(self.soup.find_all(draggable=True)) +
                    len(self.soup.find_all(attrs={'ondragstart': True})))
        if dragging:
            self.add_issue('wcag22', 'Serious', 'Dragging movements without single-pointer alternative (2.5.7)',
                f"{dragging} draggable control(s) detected",
                "Offer a click/tap/keyboard alternative to every drag gesture", 'WCAG 2.5.7')
            score -= 1

        undersized = 0
        for elem in self.soup.find_all(['a', 'button', 'input', 'select', 'textarea']):
            style = (elem.get('style') or '').lower()
            dims = [int(d) for d in re.findall(r'(?:width|height)\s*:\s*(\d+)px', style)]
            if dims and max(dims) < 24:
                undersized += 1
        if undersized:
            self.add_issue('wcag22', 'Serious', 'Target size minimum not met (2.5.8)',
                f"{undersized} target(s) are smaller than 24x24 CSS pixels",
                "Meet the 24x24px minimum or provide sufficient spacing/exception", 'WCAG 2.5.8')
            score -= 0.75

        help_links = self.soup.find_all('a', href=lambda x: x and any(k in x.lower() for k in ['help', 'support', 'faq', 'contact']))
        if not help_links:
            self.add_issue('wcag22', 'Minor', 'Consistent help mechanism absent (3.2.6)',
                "No help/contact/FAQ link found in a consistent location",
                "Place a help link in the same relative position across pages", 'WCAG 3.2.6')
            score -= 0.5

        wizard_steps = self.soup.find_all(class_=lambda x: x and any(k in str(x).lower() for k in ['step', 'wizard', 'multistep']))
        for form in self.soup.find_all('form'):
            fields = [f for f in form.find_all(['input', 'select', 'textarea'])
                      if f.get('type', 'text') not in ('hidden', 'submit', 'button', 'reset')]
            if wizard_steps and len(fields) >= 4 and not any(f.get('autocomplete') for f in fields):
                self.add_issue('wcag22', 'Moderate', 'Redundant entry not eased in multi-step form (3.3.7)',
                    "Multi-step form does not prepopulate previously entered information",
                    "Auto-repopulate prior answers or allow editing earlier steps easily", 'WCAG 3.3.7')
                score -= 0.5
                break

        captcha_divs = self.soup.find_all(class_=lambda x: x and any(k in str(x).lower() for k in ['captcha', 'recaptcha', 'g-recaptcha']))
        captcha_iframes = [i for i in self.soup.find_all('iframe') if 'recaptcha' in (i.get('src') or '').lower() or 'captcha' in (i.get('src') or '').lower()]
        if captcha_divs or captcha_iframes:
            has_alt = bool(self.soup.find('a', href=lambda x: x and 'audio' in str(x).lower()) or
                           self.soup.find(string=re.compile(r'alternative test|audio challenge', re.I)))
            if not has_alt:
                self.add_issue('wcag22', 'Serious', 'CAPTCHA without accessible alternative (3.3.8)',
                    "CAPTCHA present without an audio/non-cognitive alternative",
                    "Provide an alternative CAPTCHA that does not require a cognitive function test", 'WCAG 3.3.8')
                score -= 1

        password_fields = self.soup.find_all('input', attrs={'type': 'password'})
        for pf in password_fields:
            cognitive_test = bool(pf.get('pattern')) and not (pf.get('autocomplete') or '')
            if cognitive_test:
                self.add_issue('wcag22', 'Moderate', 'Password may force a cognitive function test (3.3.8)',
                    "Password field enforces a strict pattern, blocking password managers",
                    "Allow password managers and paste; avoid object-recall style challenges", 'WCAG 3.3.8')
                score -= 0.5
                break

        for pf in password_fields:
            if not (pf.get('autocomplete') or ''):
                self.add_issue('wcag22', 'Moderate', 'Password field lacks autocomplete token (3.3.8)',
                    "Password input does not declare autocomplete, hindering password managers",
                    "Add autocomplete='current-password' so managers and paste keep working", 'WCAG 3.3.8')
                score -= 0.5
                break

        fixed_regions = 0
        for elem in self.soup.find_all(True):
            style = (elem.get('style') or '').lower().replace(' ', '')
            if 'position:fixed' in style:
                fixed_regions += 1
        if fixed_regions > 2:
            self.add_issue('wcag22', 'Moderate', 'Multiple fixed overlays may obscure focus (2.4.11)',
                f"{fixed_regions} fixed-position region(s) detected that can cover focused elements",
                "Inset scroll areas or shift focus so fixed chrome never fully hides the focused element", 'WCAG 2.4.11')
            score -= 0.5

        body = self.soup.find('body')
        body_text = (body.get_text(' ', strip=True) if body else '').lower()
        challenge_phrases = ('drag the', 'match the image', 'solve the puzzle',
                             'type the characters', 'remember this code', 'pick the matching')
        challenges = [p for p in challenge_phrases if p in body_text]
        if challenges:
            self.add_issue('wcag22', 'Serious', 'Cognitive function test suspected (3.3.8)',
                f"Page text suggests a puzzle or recall challenge: '{challenges[0]}'",
                "Offer an alternative path that does not require a cognitive function test", 'WCAG 3.3.8')
            score -= 0.75

        alert_count = (len(self.soup.find_all(attrs={'role': 'alert'})) +
                       len(self.soup.find_all(attrs={'aria-live': 'assertive'})))
        styled_errors = self.soup.find_all(class_=lambda x: x and any(
            k in str(x).lower() for k in ('error', 'invalid', 'alert')))
        if styled_errors and alert_count == 0:
            self.add_issue('wcag22', 'Moderate', 'Errors announced without assertive live region (4.1.3)',
                "Error styling found but no role='alert' or aria-live='assertive' status exists",
                "Announce validation errors via role='alert' or an assertive live region", 'WCAG 4.1.3')
            score -= 0.5

        focus_visible_inputs = self.soup.find_all(['input', 'select', 'textarea'])
        outline_suppressed_inputs = 0
        for el in focus_visible_inputs:
            style = (el.get('style') or '').lower().replace(' ', '')
            if 'outline:none' in style or 'outline:0' in style:
                outline_suppressed_inputs += 1
        if outline_suppressed_inputs:
            self.add_issue('wcag22', 'Serious', 'Form controls suppress their focus outline (2.4.13)',
                f"{outline_suppressed_inputs} form control(s) remove their focus outline inline",
                "Restore a visible focus indicator on every form control (WCAG 2.4.13)", 'WCAG 2.4.13')
            score -= 0.5

        auto_advance = self.soup.find(attrs={'data-autoplay': True}) or \
            self.soup.find(class_=lambda x: x and 'auto-advance' in str(x).lower())
        if auto_advance:
            self.add_issue('wcag22', 'Moderate', 'Auto-advancing content may lack pause control (2.2.2)',
                "Auto-advancing/carousel behaviour detected without a confirmed pause control",
                "Provide pause, stop, or hide controls for moving or auto-updating content", 'WCAG 2.2.2')
            score -= 0.5

        region_no_label = 0
        for reg in self.soup.find_all('section'):
            has_name = bool(reg.get('aria-label') or reg.get('aria-labelledby') or reg.find('h1', recursive=False) or reg.find('h2', recursive=False))
            if not has_name:
                region_no_label += 1
        if region_no_label > 2:
            self.add_issue('wcag22', 'Minor', 'Unnamed region elements in accessibility tree',
                f"{region_no_label} <section> element(s) expose no accessible region name",
                "Name regions with aria-label or a visible heading so landmark navigation stays useful", 'WCAG 1.3.1')
            score -= 0.25

        return max(0, score)

    IMPLICIT_ROLES = {
        'a': 'link', 'button': 'button', 'img': 'img', 'main': 'main',
        'nav': 'navigation', 'header': 'banner', 'footer': 'contentinfo',
        'aside': 'complementary', 'article': 'article', 'section': 'region',
        'ul': 'list', 'ol': 'list', 'li': 'listitem', 'dl': 'list',
        'form': 'form', 'table': 'table', 'tr': 'row',
        'textarea': 'textbox', 'select': 'combobox', 'hr': 'separator',
        'h1': 'heading', 'h2': 'heading', 'h3': 'heading',
        'h4': 'heading', 'h5': 'heading', 'h6': 'heading',
    }

    def _implicit_role(self, el):
        if el.get('role'):
            return el.get('role')
        name = el.name or ''
        if name == 'input':
            itype = (el.get('type') or 'text').lower()
            return {'button': 'button', 'submit': 'button', 'reset': 'button',
                    'checkbox': 'checkbox', 'radio': 'radio', 'range': 'slider',
                    'image': 'button'}.get(itype, 'textbox')
        if name == 'a':
            return 'link' if el.get('href') else None
        return self.IMPLICIT_ROLES.get(name)

    def _accessible_name(self, el):
        labelledby = el.get('aria-labelledby')
        if labelledby:
            parts = []
            for ref in labelledby.split():
                target = self.soup.find(id=ref) if self.soup else None
                if target:
                    parts.append(target.get_text(' ', strip=True))
            if parts:
                return ' '.join(parts)
        if el.get('aria-label'):
            return el.get('aria-label').strip()
        if el.name == 'img' and el.get('alt') is not None:
            return el.get('alt').strip()
        if el.name == 'input' and el.get('value') and (el.get('type') or 'text') in ('submit', 'button', 'reset'):
            return el.get('value').strip()
        el_id = el.get('id')
        if el_id and self.soup:
            label = self.soup.find('label', attrs={'for': el_id})
            if label:
                text = label.get_text(' ', strip=True)
                if text:
                    return text
        parent_label = el.find_parent('label')
        if parent_label:
            text = parent_label.get_text(' ', strip=True)
            if text:
                if el.get('value') and el.name == 'input':
                    text = text.replace(str(el.get('value')), '').strip()
                if text:
                    return text
        text = el.get_text(' ', strip=True)
        if text:
            return text
        if el.get('title'):
            return el.get('title').strip()
        return ''

    def build_accessibility_tree(self):
        tree = self.a11y_tree
        tree['nodes'] = []
        tree['roles'] = {}
        tree['missing_names'] = 0
        tree['broken_refs'] = 0
        tree['duplicate_ids'] = 0
        tree['heading_outline'] = []
        tree['landmarks'] = {}
        tree['states'] = {}
        tree['unnamed_focusable'] = 0
        tree['hidden_focusable'] = 0

        if not self.soup:
            return tree

        seen_ids = {}
        all_ids = [el.get('id') for el in self.soup.find_all(attrs={'id': True})]
        for i in all_ids:
            seen_ids[i] = seen_ids.get(i, 0) + 1
        tree['duplicate_ids'] = sum(1 for c in seen_ids.values() if c > 1)
        if tree['duplicate_ids']:
            self.add_issue('a11y_tree', 'Serious', 'Duplicate element IDs',
                f"{tree['duplicate_ids']} id value(s) are duplicated in the document",
                "Make every id unique; duplicate ids break aria-labelledby/describedby references", 'WCAG 4.1.2')

        name_required = {'button', 'link', 'img', 'checkbox', 'radio', 'textbox',
                         'combobox', 'slider', 'menuitem', 'tab', 'switch'}
        state_attrs = ('aria-expanded', 'aria-checked', 'aria-selected', 'aria-pressed',
                       'aria-disabled', 'aria-required', 'aria-invalid')
        landmark_roles = {'banner', 'navigation', 'main', 'complementary', 'contentinfo',
                          'search', 'form'}

        for el in self.soup.find_all(True):
            if el.name in ('script', 'style', 'meta', 'link', 'title', 'html', 'head', 'br', 'hr', 'source', 'track'):
                continue
            role = self._implicit_role(el)
            if not role:
                continue
            name = self._accessible_name(el)
            focusable = (el.name in ('a', 'button', 'input', 'select', 'textarea') or
                         el.get('tabindex') is not None)
            hidden = el.get('aria-hidden') == 'true' or el.get('hidden') is not None
            node = {
                'tag': el.name,
                'role': role,
                'name': name,
                'focusable': focusable,
                'hidden': hidden,
            }
            tree['nodes'].append(node)
            tree['roles'][role] = tree['roles'].get(role, 0) + 1

            if role in landmark_roles:
                tree['landmarks'][role] = tree['landmarks'].get(role, 0) + 1

            if el.name in ('h1', 'h2', 'h3', 'h4', 'h5', 'h6'):
                tree['heading_outline'].append({'level': int(el.name[1]), 'text': name[:80]})

            for attr in state_attrs:
                if el.get(attr) is not None:
                    tree['states'][attr] = tree['states'].get(attr, 0) + 1

            if role in name_required and not name and not hidden:
                tree['missing_names'] += 1

            if focusable and not name and not hidden:
                tree['unnamed_focusable'] += 1

            if focusable and hidden and role not in ('presentation', 'none'):
                tree['hidden_focusable'] += 1
                self.add_issue('a11y_tree', 'Serious', 'Focusable node hidden from accessibility tree',
                    f"<{el.name}> is aria-hidden but remains focusable",
                    "Remove aria-hidden from focusable content or make it unfocusable", 'WCAG 4.1.2')

            for attr in ('aria-labelledby', 'aria-describedby'):
                ref_val = el.get(attr)
                if ref_val:
                    for ref in ref_val.split():
                        if not self.soup.find(id=ref):
                            tree['broken_refs'] += 1
                            self.add_issue('a11y_tree', 'Serious', 'Broken ARIA ID reference',
                                f"{attr}='{ref}' points to an id that does not exist",
                                "Fix the reference or add the target element with that id", 'WCAG 1.3.1')
                            break

        if tree['missing_names']:
            self.add_issue('a11y_tree', 'Serious', 'Tree nodes missing accessible names',
                f"{tree['missing_names']} node(s) expose a name-requiring role with an empty name",
                "Give every interactive node an accessible name (text, aria-label, or aria-labelledby)", 'WCAG 4.1.2')

        if tree['unnamed_focusable']:
            self.add_issue('a11y_tree', 'Serious', 'Focusable nodes without accessible names',
                f"{tree['unnamed_focusable']} focusable node(s) would receive focus with no spoken name",
                "Name every focusable control with visible text or aria-label", 'WCAG 4.1.2')

        outline = tree['heading_outline']
        prev_level = 0
        skips = 0
        for heading in outline:
            lvl = heading['level']
            if prev_level and lvl > prev_level + 1:
                skips += 1
            prev_level = lvl
        if skips:
            self.add_issue('a11y_tree', 'Moderate', 'Heading outline skips levels in tree',
                f"Accessibility tree heading outline skips level(s) {skips} time(s)",
                "Keep heading levels sequential so tree-based navigation stays predictable", 'WCAG 1.3.1')

        if 'main' not in tree['roles']:
            self.add_issue('a11y_tree', 'Moderate', 'No main role in accessibility tree',
                "Accessibility tree contains no main landmark node",
                "Add a <main> landmark so assistive tech can jump to core content", 'WCAG 1.3.1')

        return tree

    def check_accessibility_tree(self):
        score = 3
        tree = self.build_accessibility_tree()
        if not tree['nodes']:
            return 0
        score -= min(1.0, tree['missing_names'] * 0.15)
        score -= min(1.0, tree['broken_refs'] * 0.3)
        score -= min(0.5, tree['duplicate_ids'] * 0.25)
        score -= min(0.75, tree['unnamed_focusable'] * 0.15)
        score -= min(0.5, tree['hidden_focusable'] * 0.25)
        if not tree['landmarks']:
            score -= 0.25

        role_total = sum(tree['roles'].values())
        if role_total:
            generic_share = tree['roles'].get('generic', 0) + tree['roles'].get('presentation', 0)
            if role_total > 10 and generic_share / role_total > 0.6:
                self.add_issue('a11y_tree', 'Moderate', 'Accessibility tree dominated by generic roles',
                    f"{generic_share} of {role_total} tree nodes expose generic/presentation roles",
                    "Replace generic containers with semantic roles or native elements", 'WCAG 1.3.1')
                score -= 0.5

        empty_headings = [h for h in tree['heading_outline'] if not h.get('text')]
        if empty_headings:
            self.add_issue('a11y_tree', 'Serious', 'Empty headings in accessibility tree',
                f"{len(empty_headings)} heading node(s) expose no text to assistive technology",
                "Give every heading a meaningful text label or remove the empty heading", 'WCAG 1.3.1')
            score -= min(0.5, len(empty_headings) * 0.2)

        landmark_total = sum(tree['landmarks'].values())
        if landmark_total and tree['landmarks'].get('main', 0) > 1:
            self.add_issue('a11y_tree', 'Moderate', 'Multiple main landmarks in tree',
                f"{tree['landmarks'].get('main', 0)} main landmark nodes found; assistive tech expects one",
                "Keep exactly one main landmark per page", 'WCAG 1.3.1')
            score -= 0.25

        if tree['nodes'] and not tree['states'] and any(
                r in tree['roles'] for r in ('button', 'checkbox', 'menuitem', 'tab', 'combobox')):
            self.add_issue('a11y_tree', 'Moderate', 'Widget roles expose no state information',
                "Interactive widget roles exist in the tree but no ARIA state attributes were observed",
                "Expose state (aria-expanded, aria-checked, aria-pressed) so assistive tech can announce it", 'WCAG 4.1.2')
            score -= 0.35

        return max(0, score)

    def simulate_screen_reader(self):
        score = 4
        log = []
        if not self.soup:
            self.screen_reader_log = log
            return 0

        title = self.soup.find('title')
        log.append(f"Document, {title.get_text(strip=True) if title else 'untitled'}")

        html_tag = self.soup.find('html')
        lang = html_tag.get('lang') if html_tag else None
        log.append(f"Language, {lang}" if lang else "Language, UNKNOWN - page has no lang attribute")

        landmarks = []
        for tag, label in [('header', 'banner'), ('nav', 'navigation'), ('main', 'main'),
                           ('aside', 'complementary'), ('footer', 'contentinfo')]:
            if self.soup.find(tag):
                landmarks.append(label)
        for role in ['banner', 'navigation', 'main', 'complementary', 'contentinfo', 'search', 'form']:
            if self.soup.find(attrs={'role': role}) and role not in landmarks:
                landmarks.append(role)
        log.append(("Landmarks: " + ", ".join(landmarks)) if landmarks else "Landmarks: NONE")

        for fs in self.soup.find_all('fieldset'):
            legend = fs.find('legend')
            legend_text = legend.get_text(' ', strip=True) if legend else ''
            log.append(f"group, {legend_text}" if legend_text else "group, UNTITLED fieldset")

        unnamed_links = 0
        for link in self.soup.find_all('a', href=True):
            name = self._accessible_name(link)
            if name:
                log.append(f"link, {name}")
            else:
                unnamed_links += 1
                log.append("link, EMPTY NAME - unlabelled link")
        if unnamed_links:
            self.add_issue('screen_reader', 'Serious', 'Screen reader announces unlabelled links',
                f"{unnamed_links} link(s) would be announced with no usable name",
                "Give every link descriptive visible text or an aria-label", 'WCAG 2.4.4')

        unlabelled_graphics = 0
        for img in self.soup.find_all('img'):
            if img.get('aria-hidden') == 'true' or img.get('role') == 'presentation':
                log.append("graphic, ignored (decorative)")
                continue
            alt = img.get('alt')
            if alt is None or alt.strip() == '':
                unlabelled_graphics += 1
                log.append("graphic, unlabelled")
            else:
                log.append(f"graphic, {alt.strip()}")
        if unlabelled_graphics:
            self.add_issue('screen_reader', 'Serious', 'Screen reader announces unlabelled graphics',
                f"{unlabelled_graphics} image(s) provide no text alternative for screen readers",
                "Add descriptive alt text to informative images", 'WCAG 1.1.1')

        unlabelled_fields = 0
        for inp in self.soup.find_all(['input', 'select', 'textarea']):
            if inp.get('type') in ('hidden', 'submit', 'button', 'reset'):
                continue
            name = self._accessible_name(inp)
            itype = (inp.get('type') or 'text').lower()
            states = []
            if inp.get('aria-required') == 'true' or inp.get('required') is not None:
                states.append('required')
            if inp.get('aria-invalid') not in (None, 'false'):
                states.append('invalid')
            state_txt = (', ' + ', '.join(states)) if states else ''
            if name:
                log.append(f"{itype} edit, {name}{state_txt}")
            else:
                unlabelled_fields += 1
                log.append(f"{itype} edit, UNLABELLED")
        if unlabelled_fields:
            self.add_issue('screen_reader', 'Critical', 'Screen reader announces unlabelled form fields',
                f"{unlabelled_fields} field(s) would be announced without a name",
                "Associate a <label> with each input or set aria-label", 'WCAG 3.3.2')

        for btn in self.soup.find_all('button'):
            name = self._accessible_name(btn)
            states = []
            if btn.get('aria-expanded') is not None:
                states.append('expanded' if btn.get('aria-expanded') == 'true' else 'collapsed')
            if btn.get('aria-pressed') is not None:
                states.append('pressed' if btn.get('aria-pressed') == 'true' else 'not pressed')
            if btn.get('disabled') is not None:
                states.append('unavailable')
            state_txt = (', ' + ', '.join(states)) if states else ''
            log.append(f"button, {name if name else 'UNLABELLED'}{state_txt}")

        for box in self.soup.find_all('input', {'type': ['checkbox', 'radio']}):
            name = self._accessible_name(box)
            checked = 'checked' if box.get('checked') is not None else 'not checked'
            log.append(f"{box.get('type')}, {name if name else 'UNLABELLED'}, {checked}")

        for heading in self.soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']):
            text = heading.get_text(strip=True)
            log.append(f"heading level {heading.name[1]}, {text if text else 'EMPTY HEADING'}")

        for lst in self.soup.find_all(['ul', 'ol']):
            items = lst.find_all('li', recursive=False)
            if items:
                log.append(f"list with {len(items)} items")

        for table in self.soup.find_all('table'):
            caption = table.find('caption')
            caption_text = caption.get_text(' ', strip=True) if caption else ''
            log.append(f"table, {caption_text if caption_text else 'no caption'}")

        for quote in self.soup.find_all('blockquote'):
            quote_text = quote.get_text(' ', strip=True)[:60]
            log.append(f"block quote, {quote_text}")

        if not self.soup.find_all(attrs={'aria-live': True}):
            log.append("Live regions, none - dynamic updates will be silent")
        else:
            for live in self.soup.find_all(attrs={'aria-live': True})[:5]:
                live_txt = live.get_text(' ', strip=True)[:50]
                polite = live.get('aria-live') == 'polite'
                log.append(f"live region ({'polite' if polite else live.get('aria-live')}), {live_txt}")

        for status in self.soup.find_all(attrs={'role': ['status', 'alert']})[:5]:
            status_txt = status.get_text(' ', strip=True)[:50]
            log.append(f"{status.get('role')}, {status_txt}")

        heading_levels = [int(h.name[1]) for h in self.soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])]
        skipped_headings = 0
        prev = 0
        for lvl in heading_levels:
            if prev and lvl > prev + 1:
                skipped_headings += 1
            prev = lvl
        if skipped_headings:
            log.append(f"heading navigation, {skipped_headings} level skip(s) detected in outline")
            self.add_issue('screen_reader', 'Moderate', 'Heading navigation skips levels',
                f"Screen reader heading list would jump over {skipped_headings} heading level(s)",
                "Keep heading levels sequential so heading navigation stays predictable", 'WCAG 1.3.1')

        navs = self.soup.find_all('nav')
        if len(navs) > 1:
            unnamed_navs = [n for n in navs if not (n.get('aria-label') or n.get('aria-labelledby'))]
            if unnamed_navs:
                log.append(f"navigation landmarks, {len(unnamed_navs)} of {len(navs)} have no distinct label")
                self.add_issue('screen_reader', 'Moderate', 'Multiple navigation landmarks without labels',
                    f"{len(unnamed_navs)} of {len(navs)} navigation landmarks have no aria-label to distinguish them",
                    "Label each nav landmark (aria-label='Primary', 'Footer', ...) when several exist", 'WCAG 1.3.1')

        tables_without_headers = 0
        for table in self.soup.find_all('table'):
            if not table.find('th'):
                tables_without_headers += 1
        if tables_without_headers:
            self.add_issue('screen_reader', 'Serious', 'Screen reader cannot navigate table cells',
                f"{tables_without_headers} table(s) lack header cells for cell navigation",
                "Use <th> with scope so screen readers can announce row/column headers", 'WCAG 1.3.1')
            log.append("table, no headers - cell navigation unavailable")

        self.screen_reader_log = log[:100]

        penalty = 0.0
        penalty += min(1.2, unlabelled_fields * 0.4)
        penalty += min(1.0, unlabelled_graphics * 0.2)
        penalty += min(0.8, unnamed_links * 0.2)
        if not landmarks:
            penalty += 0.5
            self.add_issue('screen_reader', 'Moderate', 'No landmarks for screen reader navigation',
                "Screen reader landmark list would be empty",
                "Add semantic landmark elements (header, nav, main, footer)", 'WCAG 1.3.1')
        if not self.soup.find_all(attrs={'aria-live': True}):
            penalty += 0.3
        untitled_fieldsets = len([fs for fs in self.soup.find_all('fieldset') if not fs.find('legend')])
        if untitled_fieldsets:
            penalty += min(0.3, untitled_fieldsets * 0.15)
            self.add_issue('screen_reader', 'Moderate', 'Form groups announced without a group name',
                f"{untitled_fieldsets} fieldset(s) have no legend, so groups are announced unnamed",
                "Add a <legend> to every fieldset that groups related controls", 'WCAG 1.3.1')
        penalty += min(0.5, skipped_headings * 0.2)
        if len(navs) > 1:
            penalty += min(0.3, len([n for n in navs if not (n.get('aria-label') or n.get('aria-labelledby'))]) * 0.15)
        tables_no_scope = 0
        for table in self.soup.find_all('table'):
            ths = table.find_all('th')
            if ths and not any(th.get('scope') for th in ths):
                tables_no_scope += 1
        if tables_no_scope:
            penalty += min(0.3, tables_no_scope * 0.15)
            self.add_issue('screen_reader', 'Minor', 'Table headers announced without scope',
                f"{tables_no_scope} table(s) have headers lacking scope, so cell context may be ambiguous",
                "Add scope='col' or scope='row' to header cells so cell navigation announces context", 'WCAG 1.3.1')

        return max(0, score - penalty)

    def simulate_keyboard_navigation(self):
        score = 3
        path = []
        if not self.soup:
            self.keyboard_path = path
            return 0

        positive_tabindex = []
        natural_focusables = []

        for el in self.soup.find_all(True):
            tabindex = el.get('tabindex')
            if tabindex is not None:
                try:
                    ti = int(tabindex)
                except ValueError:
                    continue
                if ti > 0:
                    positive_tabindex.append((ti, el))
                    continue
                if ti < 0 or el.get('disabled') is not None:
                    continue
                natural_focusables.append(el)
                continue
            if el.name == 'a' and el.get('href'):
                natural_focusables.append(el)
            elif el.name in ('button', 'select', 'textarea'):
                if el.get('disabled') is None:
                    natural_focusables.append(el)
            elif el.name == 'input' and (el.get('type') or 'text').lower() not in ('hidden',):
                if el.get('disabled') is None:
                    natural_focusables.append(el)

        positive_tabindex.sort(key=lambda pair: pair[0])
        for ti, el in positive_tabindex:
            self.add_issue('keyboard_nav', 'Serious', 'Positive tabindex distorts tab order',
                f"Element <{el.name}> has tabindex='{ti}' and is forced ahead of document order",
                "Remove positive tabindex; keep DOM order logical with tabindex 0/-1 only", 'WCAG 2.4.3')
            score -= 0.5
            path.append(f"[tabindex={ti}] <{el.name}> (forced early stop)")

        ordered = [el for _, el in positive_tabindex] + natural_focusables
        unnamed_stops = 0
        for el in ordered[:60]:
            name = self._accessible_name(el)
            if name:
                path.append(f"<{el.name}> {name[:60]}")
            else:
                unnamed_stops += 1
                path.append(f"<{el.name}> (no accessible name)")

        self.keyboard_path = path[:60]

        if unnamed_stops:
            self.add_issue('keyboard_nav', 'Serious', 'Tab stops announce with no accessible name',
                f"{unnamed_stops} focusable stop(s) in the simulated path have no accessible name",
                "Give each tab stop visible text or an aria-label", 'WCAG 2.4.3')
            score -= min(0.75, unnamed_stops * 0.2)

        unreachable = 0
        for el in self.soup.find_all(['div', 'span', 'li']):
            if el.get('onclick') and not el.get('tabindex') and el.name not in ('a', 'button'):
                unreachable += 1
        if unreachable:
            self.add_issue('keyboard_nav', 'Serious', 'Mouse-only controls unreachable by keyboard',
                f"{unreachable} clickable element(s) are not in the tab order",
                "Convert to buttons/links or add role='button' plus tabindex='0' and key handlers", 'WCAG 2.1.1')
            score -= min(1.0, unreachable * 0.15)

        custom_controls = [el for el in self.soup.find_all(True)
                           if el.get('role') in ('button', 'link', 'tab', 'menuitem', 'option')
                           and el.get('tabindex') is None
                           and el.name not in ('a', 'button', 'input', 'select', 'textarea')]
        if custom_controls:
            self.add_issue('keyboard_nav', 'Serious', 'ARIA widget roles missing from tab order',
                f"{len(custom_controls)} element(s) declare widget roles without tabindex",
                "Add tabindex='0' and keyboard handlers to custom role widgets, or use native elements", 'WCAG 2.1.1')
            score -= min(0.75, len(custom_controls) * 0.15)

        trap_risk = 0
        for el in self.soup.find_all(True):
            keys = el.get('onkeydown') or ''
            if 'preventDefault' in keys and el.get('tabindex') is not None:
                code = el.get('onkeyup') or ''
                if 'escape' not in code.lower() and 'esc' not in code.lower():
                    trap_risk += 1
        if trap_risk:
            self.add_issue('keyboard_nav', 'Critical', 'Possible keyboard trap',
                f"{trap_risk} element(s) suppress default key behavior without an Escape exit",
                "Ensure every keyboard interaction can be exited with Escape or Tab", 'WCAG 2.1.2')
            score -= min(1.5, trap_risk * 0.5)

        style_tag = self.soup.find('style')
        css = style_tag.get_text() if style_tag else ''
        compact = css.replace(' ', '')
        if ('outline:none' in compact or 'outline:0' in compact) and ':focus' not in css and ':focus-visible' not in css:
            self.add_issue('keyboard_nav', 'Serious', 'Tab stops have no visible focus indicator',
                "Focus outline is suppressed globally with no replacement styles",
                "Style :focus-visible with a high-contrast outline for every tab stop", 'WCAG 2.4.7')
            score -= 0.75

        links_no_href = len(self.soup.find_all('a', href=lambda x: not x or x == '#'))
        if links_no_href and not any(el.name == 'a' and el.get('tabindex') == '0' for el in self.soup.find_all('a')):
            if links_no_href > 2:
                self.add_issue('keyboard_nav', 'Moderate', 'Anchors without href are not focusable',
                    f"{links_no_href} anchor(s) lack href and drop out of the tab sequence",
                    "Use <button> for actions or give anchors href/tabindex", 'WCAG 2.1.1')
                score -= 0.4

        skip = self.soup.find('a', href=lambda x: x and x.startswith('#') and 'main' in x.lower())
        if not skip:
            self.add_issue('keyboard_nav', 'Moderate', 'No skip link in simulated tab path',
                "First tab stops are wasted traversing navigation",
                "Add a skip-to-main link as the first focusable element", 'WCAG 2.4.1')
            score -= 0.4

        wasted_stops = 0
        nav = self.soup.find('nav')
        if nav:
            wasted_stops = len([a for a in nav.find_all('a', href=True)
                                if not a.get('tabindex') or a.get('tabindex') == '0'])
        if wasted_stops > 25:
            self.add_issue('keyboard_nav', 'Moderate', 'Excessive tab stops before main content',
                f"Navigation alone exposes ~{wasted_stops} tab stops",
                "Group navigation links or provide a skip mechanism to bypass them", 'WCAG 2.4.1')
            score -= 0.4

        accesskeys = self.soup.find_all(attrs={'accesskey': True})
        if len(accesskeys) > 5:
            self.add_issue('keyboard_nav', 'Minor', 'Crowded accesskey shortcuts',
                f"{len(accesskeys)} accesskey attributes risk conflicts with browser/AT shortcuts",
                "Keep accesskey usage minimal and document any shortcuts you expose", 'WCAG 2.1.4')
            score -= 0.3

        if not ordered:
            self.add_issue('keyboard_nav', 'Critical', 'No focusable elements found',
                "Simulation found nothing reachable with the Tab key",
                "Ensure interactive controls are native elements or properly focusable", 'WCAG 2.1.1')
            score -= 1.5

        modal_dialogs = [el for el in self.soup.find_all(True)
                         if el.get('role') == 'dialog' or el.get('aria-modal') == 'true']
        escape_covered = any(
            'escape' in ((el.get('onkeydown') or '') + (el.get('onkeyup') or '')).lower() or
            'esc' in ((el.get('onkeydown') or '') + (el.get('onkeyup') or '')).lower()
            for el in self.soup.find_all(True))
        if modal_dialogs and not escape_covered:
            self.add_issue('keyboard_nav', 'Serious', 'Modal dialog without a keyboard exit',
                f"{len(modal_dialogs)} modal/dialog region(s) found with no Escape key handler",
                "Close modals with Escape and return focus to the triggering control", 'WCAG 2.1.2')
            score -= 0.6

        keydown_handlers = self.soup.find_all(attrs={'onkeydown': True})
        key_only_controls = [el for el in keydown_handlers
                             if el.get('role') in ('button', 'link', 'tab', 'menuitem')
                             and not (el.get('onclick') or el.get('href'))]
        if key_only_controls:
            self.add_issue('keyboard_nav', 'Moderate', 'Custom widgets lack click/activation parity',
                f"{len(key_only_controls)} role widget(s) handle keys but have no mouse activation",
                "Support both keyboard and pointer activation for custom widgets", 'WCAG 2.1.1')
            score -= 0.3

        positive_only_stops = [el for el in self.soup.find_all(True)
                               if (el.get('tabindex') or '').lstrip('-').isdigit()
                               and int(el.get('tabindex')) > 0
                               and el.name not in ('a', 'button', 'input', 'select', 'textarea')]
        if positive_only_stops:
            score -= min(0.3, len(positive_only_stops) * 0.1)

        self.keyboard_metrics = {
            'tab_stops': len(ordered),
            'positive_tabindex': len(positive_tabindex),
            'mouse_only': unreachable,
            'trap_risk': trap_risk,
            'unnamed_stops': unnamed_stops,
            'wasted_nav_stops': wasted_stops,
            'modal_count': len(modal_dialogs),
            'escape_exit_available': escape_covered,
            'key_only_widgets': len(key_only_controls),
        }

        return max(0, score)

    def compute_weighted_score(self):
        raw_total = sum(self.scores.values())
        max_total = sum(self.max_scores.values()) or 100
        total = raw_total / max_total * 100
        counts = self.severity_counts()
        penalty = (0.6 * counts.get('Critical', 0) +
                   0.3 * counts.get('Serious', 0) +
                   0.1 * counts.get('Moderate', 0))
        self.weighted_score = max(0.0, total - min(penalty, total * 0.3))
        return self.weighted_score

    def severity_counts(self):
        counts = {k: 0 for k in SEVERITY_ORDER}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts

    def determine_wcag_conformance(self):
        detail = {'A': 0, 'AA': 0, 'AAA': 0}
        blocking = {'A': 0, 'AA': 0, 'AAA': 0}
        crit_block = {'A': 0, 'AA': 0, 'AAA': 0}
        for issue in self.issues:
            level = issue.conformance if issue.conformance in detail else 'AA'
            detail[level] = detail.get(level, 0) + 1
            if issue.severity in ('Critical', 'Serious'):
                blocking[level] = blocking.get(level, 0) + 1
            if issue.severity == 'Critical':
                crit_block[level] = crit_block.get(level, 0) + 1

        criteria_by_level = {'A': 0, 'AA': 0, 'AAA': 0}
        for crit, lvl in WCAG_CRITERIA_LEVEL.items():
            if lvl == 'A':
                criteria_by_level['A'] += 1
            if lvl in ('A', 'AA'):
                criteria_by_level['AA'] += 1
            criteria_by_level['AAA'] += 1

        cumulative_issues = {
            'A': detail['A'],
            'AA': detail['A'] + detail['AA'],
            'AAA': detail['A'] + detail['AA'] + detail['AAA'],
        }
        cumulative_blocking = {
            'A': blocking['A'],
            'AA': blocking['A'] + blocking['AA'],
            'AAA': blocking['A'] + blocking['AA'] + blocking['AAA'],
        }
        cumulative_crit = {
            'A': crit_block['A'],
            'AA': crit_block['A'] + crit_block['AA'],
            'AAA': crit_block['A'] + crit_block['AA'] + crit_block['AAA'],
        }

        cat_total = sum(self.max_scores.values()) or 100
        cat_pct = (sum(self.scores.values()) / cat_total * 100) if cat_total else 0.0

        level_scores = {}
        coverage = {}
        for lvl in ('A', 'AA', 'AAA'):
            known = criteria_by_level[lvl] or 1
            failed_ratio = min(1.0, cumulative_blocking[lvl] / known)
            crit_ratio = min(1.0, cumulative_crit[lvl] / known)
            non_blocking = cumulative_issues[lvl] - cumulative_blocking[lvl]
            coverage[lvl] = round(max(0.0, (1.0 - failed_ratio) * 100 - crit_ratio * 10), 1)
            estimate = (self.weighted_score * 0.55
                        + cat_pct * 0.20
                        + coverage[lvl] * 0.25
                        - cumulative_crit[lvl] * 5.0
                        - (cumulative_blocking[lvl] - cumulative_crit[lvl]) * 3.0
                        - non_blocking * 0.5)
            if lvl != 'A':
                estimate += self.governance_score * 0.05
            level_scores[lvl] = round(max(0.0, min(100.0, estimate)), 1)

        self.conformance_detail = {
            'issue_counts': detail,
            'blocking_counts': blocking,
            'level_scores': level_scores,
            'coverage': coverage,
            'criteria_evaluated': criteria_by_level,
            'cumulative_issues': cumulative_issues,
            'cumulative_blocking': cumulative_blocking,
            'weighted_score': self.weighted_score,
            'category_pct': round(cat_pct, 1),
        }

        if (cumulative_crit['A'] > 0 or blocking['A'] > 0 or level_scores['A'] < 75 or self.weighted_score < 50):
            level = 'Non-Compliant'
        elif (cumulative_crit['AA'] > 0 or blocking['AA'] > 0 or level_scores['AA'] < 75 or self.weighted_score < 75):
            level = 'A'
        elif (blocking['AAA'] > 0 or level_scores['AAA'] < 90 or self.weighted_score < 90):
            level = 'AA'
        else:
            level = 'AAA'

        target = self.level
        if target in LEVEL_ORDER and level in LEVEL_ORDER:
            if LEVEL_ORDER[level] >= LEVEL_ORDER[target]:
                pass
        self.conformance = level
        return level

    def meets_target(self):
        if self.conformance not in LEVEL_ORDER or self.level not in LEVEL_ORDER:
            return False
        return LEVEL_ORDER[self.conformance] >= LEVEL_ORDER[self.level]

    def compute_governance_score(self):
        total = sum(self.max_scores.get(c, 0) for c in self.governance_categories)
        got = sum(self.scores.get(c, 0) for c in self.governance_categories)
        self.governance_score = round((got / total * 100) if total else 0.0, 1)
        return self.governance_score

    def compute_maturity(self):
        self.compute_governance_score()
        score = self.weighted_score
        counts = self.severity_counts()
        if score < 20:
            stage, name = 0, 'Nonexistent'
            desc = 'Accessibility is not addressed; users regularly hit blockers.'
        elif score < 40:
            stage, name = 1, 'Initial'
            desc = 'Some awareness and ad hoc fixes; no consistent process.'
        elif score < 60:
            stage, name = 2, 'Managed'
            desc = 'Accessibility issues are tracked and partially managed per release.'
        elif score < 75:
            stage, name = 3, 'Defined'
            desc = 'A documented accessibility standard is applied across the page set.'
        elif score < 90:
            stage, name = 4, 'Measured'
            desc = 'Accessibility is measured with audits, tooling, and regression checks.'
        else:
            stage, name = 5, 'Optimizing'
            desc = 'Continuous improvement with user testing and mature governance.'

        if counts.get('Critical', 0) > 0 and stage > 1:
            stage -= 1
            name = {0: 'Nonexistent', 1: 'Initial', 2: 'Managed',
                    3: 'Defined', 4: 'Measured', 5: 'Optimizing'}[stage]
            desc += ' Critical issues cap the maturity stage until resolved.'

        if self.governance_score < 30 and stage > 2:
            stage = 2
            name = 'Managed'
            desc = ('Governance foundations are weak (no statement, feedback route, or '
                    'reporting), capping maturity at Managed.')
        elif self.governance_score < 60 and stage > 3:
            stage = 3
            name = 'Defined'
            desc = ('Partial governance (statement/feedback/reporting gaps) caps maturity '
                    'at Defined despite strong automated scores.')

        dims = self.maturity_deep.get('dimensions') or {}
        if dims:
            readiness = self.maturity_deep.get('readiness_pct', 0.0)
            weak_dims = [k for k, v in dims.items() if v < 40]
            strong_dims = [k for k, v in dims.items() if v >= 75]
            if weak_dims and stage > 2:
                stage = min(stage, 3)
                name = {0: 'Nonexistent', 1: 'Initial', 2: 'Managed',
                        3: 'Defined', 4: 'Measured', 5: 'Optimizing'}[stage]
                desc = (f'Deep maturity analysis shows weak dimension(s) '
                        f'({", ".join(weak_dims[:3])}) capping the stage at {name}.')
            elif readiness >= 75 and stage < 5:
                desc += (f' Deep maturity readiness {readiness:.0f}% with strong '
                         f'dimension(s): {", ".join(strong_dims[:3]) or "n/a"}.')

        self.maturity = {'stage': stage, 'name': name, 'description': desc,
                         'readiness_pct': self.maturity_deep.get('readiness_pct', 0.0),
                         'dimensions': dims,
                         'next_stage': self.maturity_deep.get('next_stage', ''),
                         'next_detail': self.maturity_deep.get('next_detail', '')}

        if self.maturity_deep:
            stage_order = ['Nonexistent', 'Initial', 'Managed', 'Defined', 'Measured', 'Optimizing']
            current_stage = stage_order.index(name) if name in stage_order else 1
            next_idx = min(current_stage + 1, len(stage_order) - 1)
            next_stage = stage_order[next_idx]
            gap_drivers = self.maturity_deep.get('gaps', [])[:3]
            next_detail = (f"Close gaps in {', '.join(gap_drivers)} to progress toward '{next_stage}'."
                           if gap_drivers else
                           f"Maintain current strengths to hold '{name}' and progress toward '{next_stage}'.")
            self.maturity_deep['current_stage'] = name
            self.maturity_deep['next_stage'] = next_stage
            self.maturity_deep['next_detail'] = next_detail
            self.maturity['next_stage'] = next_stage
            self.maturity['next_detail'] = next_detail

        return self.maturity

    def build_prioritization_matrix(self):
        matrix = {}
        for sev in SEVERITY_ORDER:
            matrix[sev] = {'Low': [], 'Medium': [], 'High': []}
        for issue in self.issues:
            sev = issue.severity if issue.severity in matrix else 'Minor'
            effort = issue.effort if issue.effort in matrix[sev] else 'Medium'
            matrix[sev][effort].append({
                'title': issue.title,
                'priority': issue.priority,
                'wcag_ref': issue.wcag_ref,
                'effort': issue.effort,
                'category': self.category_names.get(issue.category, issue.category),
                'conformance': issue.conformance,
                'phase': GOVERNANCE_PHASE.get(issue.category),
            })
        for sev in matrix:
            for effort in matrix[sev]:
                matrix[sev][effort].sort(key=lambda e: (
                    ['P1', 'P2', 'P3', 'P4'].index(e['priority'])
                    if e['priority'] in ('P1', 'P2', 'P3', 'P4') else 9,
                    ['Low', 'Medium', 'High'].index(e['effort'])
                    if e['effort'] in ('Low', 'Medium', 'High') else 1))
        self.matrix = matrix
        return matrix

    def matrix_quadrant(self, sev, effort):
        if sev in ('Critical', 'Serious') and effort == 'Low':
            return 'Quick Wins'
        if sev == 'Critical':
            return 'Strategic'
        if sev == 'Serious' and effort in ('Medium', 'High'):
            return 'Strategic'
        if sev == 'Moderate' and effort == 'Low':
            return 'Fill-ins'
        if sev == 'Moderate':
            return 'Plan Ahead'
        return 'Backlog'

    def build_remediation_roadmap(self):
        phases = [
            {'id': 1, 'name': 'Phase 1 - Quick Wins', 'window': 'Week 1-2',
             'focus': 'Critical issues, low-effort fixes, and governance essentials (statement, feedback)',
             'exit_criteria': 'No Critical issues remain; statement and feedback route published',
             'issues': []},
            {'id': 2, 'name': 'Phase 2 - Core Conformance', 'window': 'Week 3-4',
             'focus': 'Remaining serious issues blocking Level AA',
             'exit_criteria': 'Level A blocking issues cleared; Level AA score >= 75%',
             'issues': []},
            {'id': 3, 'name': 'Phase 3 - Quality Pass', 'window': 'Month 2',
             'focus': 'Moderate issues, persona accommodations, training, WCAG 2.2 criteria',
             'exit_criteria': 'Moderate issues reduced by 80%; training gaps addressed',
             'issues': []},
            {'id': 4, 'name': 'Phase 4 - Maturity & AAA', 'window': 'Month 3+',
             'focus': 'Minor issues, AAA enhancements, conformance reporting, certification, monitoring',
             'exit_criteria': 'Conformance report published; maturity stage Measured or higher',
             'issues': []},
        ]

        def phase_for(issue):
            if issue.category in GOVERNANCE_PHASE:
                return GOVERNANCE_PHASE[issue.category]
            if issue.severity == 'Critical':
                return 1
            if issue.severity == 'Serious':
                return 1 if issue.effort == 'Low' else 2
            if issue.severity == 'Moderate':
                return 2 if issue.effort == 'Low' and issue.priority == 'P2' else 3
            return 4

        for issue in self.issues:
            idx = phase_for(issue) - 1
            phases[idx]['issues'].append({
                'title': issue.title,
                'severity': issue.severity,
                'priority': issue.priority,
                'effort': issue.effort,
                'category': self.category_names.get(issue.category, issue.category),
                'remediation': issue.remediation,
                'wcag_ref': issue.wcag_ref,
                'quadrant': self.matrix_quadrant(issue.severity, issue.effort),
            })

        for phase in phases:
            phase['count'] = len(phase['issues'])
            phase['estimated_days'] = round(sum(
                EFFORT_DAYS.get(item.get('effort', 'Medium'), 2.0)
                for item in phase['issues']), 1)
            phase['p1_count'] = len([i for i in phase['issues'] if i['priority'] == 'P1'])
            phase['quick_wins'] = len([i for i in phase['issues']
                                       if i.get('quadrant') == 'Quick Wins'])
            phase['categories'] = sorted({i['category'] for i in phase['issues']})[:5]
            phase['issues'].sort(key=lambda i: (SEVERITY_ORDER.index(i['severity'])
                                                if i['severity'] in SEVERITY_ORDER else 9))
            phase['issues'] = phase['issues'][:15]

        self.roadmap = phases
        return phases

    def generate_accessibility_statement(self):
        counts = self.severity_counts()
        today = datetime.now().strftime('%d %B %Y')
        level = self.conformance
        target = self.level
        level_scores = self.conformance_detail.get('level_scores', {})

        lines = []
        lines.append('ACCESSIBILITY STATEMENT')
        lines.append('=' * 60)
        lines.append('')
        lines.append(f'This statement applies to: {self.url}')
        lines.append(f'Statement date: {today}')
        lines.append(f'Standard: WCAG 2.2 Level {target}')
        lines.append('Assessment tool: AccessibilityAnalyzer v4.0')
        lines.append('')
        lines.append('SCOPE')
        lines.append('-' * 60)
        lines.append('This statement covers the page listed above and the templates it')
        lines.append('shares with the rest of the site. Content published after the')
        lines.append('statement date may not yet be reflected in this assessment.')
        lines.append('')
        lines.append('CONFORMANCE STATUS')
        lines.append('-' * 60)
        if self.meets_target():
            lines.append(f'This page aims to conform to WCAG 2.2 Level {target}.')
            lines.append(f'Automated analysis indicates conformance level: {level}.')
        else:
            lines.append(f'This page does not yet fully conform to WCAG 2.2 Level {target}.')
            lines.append(f'Automated analysis indicates conformance level: {level}.')
            lines.append('We are actively working to remediate the issues listed below.')
        lines.append('')
        if level_scores:
            lines.append('CONFORMANCE SCORES BY LEVEL')
            lines.append('-' * 60)
            for lvl in ('A', 'AA', 'AAA'):
                ls = level_scores.get(lvl, 0.0)
                lines.append(f'  WCAG 2.2 Level {lvl}: estimated {ls:.1f}%')
            lines.append('')
        lines.append('ASSESSED SCORE')
        lines.append('-' * 60)
        lines.append(f'Composite score: {self.weighted_score:.1f} / 100 (grade {grade_from_score(self.weighted_score)})')
        lines.append(f'Accessibility maturity: Stage {self.maturity["stage"]} - {self.maturity["name"]}')
        lines.append(f'Governance readiness: {self.governance_score:.1f} / 100')
        lines.append('')
        lines.append('KNOWN ISSUES (from automated scan)')
        lines.append('-' * 60)
        lines.append(f'Critical: {counts.get("Critical", 0)}   Serious: {counts.get("Serious", 0)}   '
                     f'Moderate: {counts.get("Moderate", 0)}   Minor: {counts.get("Minor", 0)}')
        lines.append('')
        top = sorted(self.issues,
                     key=lambda i: (SEVERITY_ORDER.index(i.severity) if i.severity in SEVERITY_ORDER else 9))[:10]
        for issue in top:
            lines.append(f'  [{issue.severity}] {issue.title} ({issue.wcag_ref or "n/a"})')
        if not top:
            lines.append('  No issues detected by the automated scan.')
        lines.append('')
        lines.append('PERSONA SUPPORT SNAPSHOT')
        lines.append('-' * 60)
        persona_notes = {
            'cognitive': 'Cognitive accessibility',
            'motor': 'Motor disability accommodation',
            'visual': 'Visual impairment accommodation',
            'hearing': 'Hearing impairment accommodation',
            'speech': 'Speech disability accommodation',
            'neurodiversity': 'Neurodiversity support',
        }
        for key, label in persona_notes.items():
            sc = self.scores.get(key, 0)
            mx = self.max_scores.get(key, 1)
            pct = (sc / mx * 100) if mx else 0
            status = 'good' if pct >= 80 else 'needs work' if pct >= 50 else 'poor'
            lines.append(f'  {label}: {pct:.0f}% ({status})')
        lines.append('')
        lines.append('FEEDBACK')
        lines.append('-' * 60)
        fb = self.feedback_analysis
        if fb.get('found'):
            lines.append('We welcome feedback on accessibility problems with this page.')
            lines.append(f'Detected feedback channels on this site: {fb.get("channel_count", len(fb.get("channels", [])))}.')
            if fb.get('response_time_promised'):
                lines.append('A response time commitment was detected on this site.')
            for channel in fb.get('channels', [])[:3]:
                lines.append(f'  - {channel}')
        else:
            lines.append('No in-page feedback channel was detected. Please contact the site')
            lines.append('owner describing the issue and the assistive technology you use.')
        lines.append('We aim to respond within 5 business days.')
        lines.append('')
        lines.append('ACCESSIBILITY STATEMENT STATUS')
        lines.append('-' * 60)
        stmt = self.statement_analysis
        if stmt.get('found'):
            lines.append(f'An accessibility statement was detected (source: {stmt.get("evidence", "n/a")}).')
            missing = stmt.get('missing_components', [])
            if missing:
                lines.append('Recommended sections still missing: ' + ', '.join(missing))
            else:
                lines.append('All recommended statement sections were detected.')
        else:
            lines.append('No published accessibility statement was detected for this site.')
            lines.append('Publishing one is strongly recommended (see remediation roadmap).')
        lines.append('')
        lines.append('MATURITY DEEP ANALYSIS')
        lines.append('-' * 60)
        deep = self.maturity_deep
        if deep.get('dimensions'):
            lines.append(f'Overall maturity readiness: {deep.get("readiness_pct", 0.0):.1f}%')
            lines.append(f'Current stage: {deep.get("current_stage", self.maturity["name"])}   '
                         f'Next stage: {deep.get("next_stage", "n/a")}')
            if deep.get('next_detail'):
                lines.append(f'Next step: {deep["next_detail"]}')
            lines.append('')
            for dim_name, dim_pct in sorted(deep.get('dimensions', {}).items(),
                                            key=lambda kv: kv[1]):
                lines.append(f'  {dim_name}: {dim_pct:.1f}%')
            gaps = deep.get('gaps', [])
            if gaps:
                lines.append('')
                lines.append('Weak dimensions: ' + ', '.join(gaps))
            strengths = deep.get('strengths', [])
            if strengths:
                lines.append('Strong dimensions: ' + ', '.join(strengths))
        else:
            lines.append('Deep maturity analysis was not available for this scan.')
        lines.append('')
        lines.append('CONFORMANCE REPORTING')
        lines.append('-' * 60)
        cr = self.conformance_report_info
        if cr.get('found'):
            lines.append('The following conformance reporting signals were detected:')
            for signal in cr.get('signals', [])[:5]:
                lines.append(f'  - {signal}')
            if cr.get('standards'):
                lines.append('Standards cited: ' + ', '.join(cr.get('standards', [])))
            if cr.get('specific_level'):
                lines.append(f'Conformance level claimed: WCAG 2.2 Level {cr.get("specific_level")}')
            if cr.get('dated'):
                lines.append('A report/evaluation date was detected.')
            for artifact in cr.get('artifacts', [])[:3]:
                lines.append(f'  - artifact: {artifact}')
        else:
            lines.append('No VPAT/ACR or equivalent conformance report was detected.')
            lines.append('Consider publishing one to back the claims in this statement.')
        lines.append('')
        lines.append('TRAINING & PROCESS NOTES')
        lines.append('-' * 60)
        if self.training_hints:
            for hint in self.training_hints[:5]:
                audience = hint.get('audience', 'Team')
                lines.append(f'  - {hint["topic"]}  [{audience}]')
                lines.append(f'    {hint["action"]}')
        else:
            lines.append('  No specific training gaps were identified from this scan.')
        lines.append('')
        lines.append('CERTIFICATION')
        lines.append('-' * 60)
        cert = self.certification_info
        if cert.get('found'):
            lines.append('Third-party or programme certification signals were detected:')
            for signal in cert.get('signals', [])[:4]:
                lines.append(f'  - {signal}')
            if cert.get('named_body'):
                lines.append('A named certifying body was detected.')
            if cert.get('renewal_dated'):
                lines.append('An expiry or renewal date was detected.')
            if cert.get('credential_linked'):
                lines.append('A verifiable credential link was detected.')
        else:
            lines.append('No independent certification or audit credential was detected.')
        lines.append('')
        lines.append('ALTERNATIVES')
        lines.append('-' * 60)
        lines.append('If you need information from this site in another format, please')
        lines.append('contact us and we will provide it in an accessible form.')
        lines.append('')
        lines.append('METHOD')
        lines.append('-' * 60)
        lines.append('This statement is based on an automated scan by AccessibilityAnalyzer v4.0')
        lines.append('(WCAG 2.2 heuristics, governance checks, accessibility tree inspection,')
        lines.append('screen reader and keyboard navigation simulation, and deep maturity')
        lines.append('modelling). Automated testing complements but does not replace manual')
        lines.append('testing with assistive technologies.')
        lines.append(f'Assessment date: {today}')
        lines.append('')
        lines.append('FORMAL COMPLAINTS')
        lines.append('-' * 60)
        lines.append('If you are not satisfied with our response, you may escalate the issue')
        lines.append('through the enforcement procedure for your jurisdiction.')

        self.statement = '\n'.join(lines)
        return self.statement

    def analyze(self):
        print(f"\n{Colors.CYAN}[*] Analyzing {self.url}...{Colors.RESET}\n")

        if not self.fetch_page():
            return False

        print(f"{Colors.GREEN}[+] Page fetched successfully ({len(self.html)} bytes){Colors.RESET}")

        checks = [
            ('text_alt', self.check_text_alternatives),
            ('adaptable', self.check_adaptable_content),
            ('distinguishable', self.check_distinguishable),
            ('keyboard', self.check_keyboard),
            ('navigable', self.check_navigable),
            ('input', self.check_input_modalities),
            ('readable', self.check_readable),
            ('predictable', self.check_predictable),
            ('input_assist', self.check_input_assistance),
            ('compatible', self.check_compatible),
            ('aria', self.check_aria_semantics),
            ('multimedia', self.check_multimedia),
            ('cognitive', self.check_cognitive_accessibility),
            ('motor', self.check_motor_accessibility),
            ('visual', self.check_visual_accessibility),
            ('hearing', self.check_hearing_accessibility),
            ('speech', self.check_speech_accessibility),
            ('neurodiversity', self.check_neurodiversity),
            ('statement', self.check_accessibility_statement),
            ('feedback', self.check_feedback_mechanism),
            ('conformance_report', self.check_conformance_report),
            ('certification', self.check_certification_hints),
            ('wcag22', self.check_wcag22_criteria),
            ('training', self.check_training_hints),
            ('a11y_tree', self.check_accessibility_tree),
            ('screen_reader', self.simulate_screen_reader),
            ('keyboard_nav', self.simulate_keyboard_navigation),
            ('maturity_deep', self.check_maturity_deep_analysis),
        ]

        for category, check_func in checks:
            print(f"{Colors.BLUE}  [-] Checking {self.category_names[category]}...{Colors.RESET}")
            try:
                raw = check_func()
            except Exception as e:
                raw = self.check_base_max.get(category, self.max_scores[category])
                if self.verbose:
                    print(f"{Colors.YELLOW}    [!] Error in check: {e}{Colors.RESET}")
            base = self.check_base_max.get(category, self.max_scores[category])
            self.raw_scores[category] = raw
            if base > 0:
                self.scores[category] = round(max(0.0, min(float(raw), float(base))) / float(base) *
                                              float(self.max_scores[category]), 2)
            else:
                self.scores[category] = 0.0

        self.compute_weighted_score()
        self.compute_governance_score()
        self.determine_wcag_conformance()
        self.compute_maturity()
        self.build_prioritization_matrix()
        self.build_remediation_roadmap()
        self.generate_accessibility_statement()

        return True

    def get_total_score(self):
        raw_total = sum(self.scores.values())
        max_total = sum(self.max_scores.values()) or 100
        return raw_total / max_total * 100

    def print_results(self):
        total = self.get_total_score()
        grade = grade_from_score(self.weighted_score)
        level = self.conformance

        print(f"\n{'='*80}")
        print(f"{Colors.BOLD}{Colors.CYAN}  ACCESSIBILITY ANALYSIS RESULTS (v4.0){Colors.RESET}")
        print(f"{'='*80}")
        print(f"\n  {Colors.WHITE}Target:{Colors.RESET} {self.url}")
        print(f"  {Colors.WHITE}Analyzed:{Colors.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  {Colors.WHITE}WCAG Level Target:{Colors.RESET} {self.level} (WCAG 2.2)")
        print(f"\n{'─'*80}")

        for category in self.max_scores:
            score = self.scores.get(category, 0)
            max_score = self.max_scores[category]
            color = score_color(score, max_score)
            bar_len = int((score / max_score) * 30) if max_score > 0 else 0
            bar = '█' * bar_len + '░' * (30 - bar_len)
            print(f"\n  {Colors.WHITE}{self.category_names[category]:30}{Colors.RESET} {color}{score:5.1f}/{max_score:5.1f}{Colors.RESET}")
            print(f"  {Colors.GRAY}{bar}{Colors.RESET}")

            cat_issues = [i for i in self.issues if i.category == category]
            for issue in cat_issues[:3]:
                sev_color = severity_color(issue.severity)
                print(f"    {sev_color}[{issue.severity:8}]{Colors.RESET} {issue.title} {Colors.GRAY}({issue.priority}, {issue.conformance}){Colors.RESET}")
            if len(cat_issues) > 3:
                print(f"    {Colors.GRAY}... and {len(cat_issues) - 3} more issues{Colors.RESET}")

        print(f"\n{'─'*80}")
        grade_color = Colors.GREEN if grade in ['A+', 'A'] else Colors.YELLOW if grade == 'B' else Colors.RED
        level_color = Colors.GREEN if level in ['AAA', 'AA'] else Colors.YELLOW if level == 'A' else Colors.RED

        counts = self.severity_counts()

        print(f"\n  {Colors.BOLD}SUMMARY{Colors.RESET}")
        print(f"  {Colors.WHITE}Raw Score:{Colors.RESET}       {score_color(total, 100)}{total:.1f} / 100.0{Colors.RESET}")
        print(f"  {Colors.WHITE}Weighted Score:{Colors.RESET}   {grade_color}{self.weighted_score:.1f} / 100.0{Colors.RESET}")
        print(f"  {Colors.WHITE}Grade:{Colors.RESET}            {grade_color}{Colors.BOLD}{grade}{Colors.RESET}")
        print(f"  {Colors.WHITE}WCAG Level:{Colors.RESET}       {level_color}{Colors.BOLD}{level}{Colors.RESET}")
        print(f"  {Colors.WHITE}Maturity:{Colors.RESET}         {Colors.CYAN}Stage {self.maturity['stage']} - {self.maturity['name']}{Colors.RESET}")
        print(f"  {Colors.WHITE}Total Issues:{Colors.RESET}    {Colors.YELLOW}{len(self.issues)}{Colors.RESET}")

        print(f"\n  {Colors.RED}Critical:{Colors.RESET} {counts['Critical']}  {Colors.YELLOW}Serious:{Colors.RESET} {counts['Serious']}  {Colors.MAGENTA}Moderate:{Colors.RESET} {counts['Moderate']}  {Colors.GRAY}Minor:{Colors.RESET} {counts['Minor']}")

        if self.meets_target():
            print(f"\n  {Colors.GREEN}[PASS]{Colors.RESET} Meets WCAG 2.2 Level {self.level} requirements")
        elif level in LEVEL_ORDER and LEVEL_ORDER[level] >= 1:
            print(f"\n  {Colors.YELLOW}[PARTIAL]{Colors.RESET} Meets WCAG 2.2 Level {level}, but not target {self.level}")
        else:
            print(f"\n  {Colors.RED}[FAIL]{Colors.RESET} Does not meet WCAG 2.2 Level {self.level} requirements")

        print(f"\n{'='*80}\n")

    def print_dashboard(self):
        grade = grade_from_score(self.weighted_score)
        counts = self.severity_counts()
        total = self.get_total_score()

        print(f"\n{'='*80}")
        print(f"{Colors.BOLD}{Colors.CYAN}  COMPLIANCE DASHBOARD{Colors.RESET}")
        print(f"{'='*80}\n")

        cards = [
            ('Score', f"{self.weighted_score:.1f}/100", score_color(self.weighted_score, 100)),
            ('Grade', grade, Colors.GREEN if grade in ('A+', 'A') else Colors.YELLOW if grade == 'B' else Colors.RED),
            ('WCAG 2.2', self.conformance, Colors.GREEN if self.conformance in ('AAA', 'AA') else Colors.RED),
            ('Maturity', f"{self.maturity['stage']}/5 {self.maturity['name']}", Colors.CYAN),
            ('Readiness', f"{self.maturity_deep.get('readiness_pct', 0.0):.0f}%",
             score_color(self.maturity_deep.get('readiness_pct', 0.0), 100)),
            ('Issues', str(len(self.issues)), Colors.YELLOW),
            ('P1 Items', str(len([i for i in self.issues if i.priority == 'P1'])), Colors.RED),
        ]
        card_line = '  '.join(f"{Colors.GRAY}{name}:{Colors.RESET} {color}{value}{Colors.RESET}" for name, value, color in cards)
        print(f"  {card_line}")
        print(f"\n  {Colors.GRAY}{self.maturity['description']}{Colors.RESET}")
        if self.maturity_deep.get('next_detail'):
            print(f"  {Colors.GRAY}Next maturity step: {self.maturity_deep['next_detail']}{Colors.RESET}")

        deep = self.maturity_deep
        if deep.get('dimensions'):
            print(f"\n  {Colors.BOLD}MATURITY DEEP ANALYSIS{Colors.RESET}")
            for dim_name, dim_pct in sorted(deep['dimensions'].items(), key=lambda kv: kv[1]):
                bar_len = int(dim_pct / 100 * 24)
                bar = '█' * bar_len + '░' * (24 - bar_len)
                color = score_color(dim_pct, 100)
                print(f"    {dim_name:32} {color}{bar} {dim_pct:5.1f}%{Colors.RESET}")
            if deep.get('gaps'):
                print(f"    {Colors.RED}Weak: {', '.join(deep['gaps'])}{Colors.RESET}")
            if deep.get('strengths'):
                print(f"    {Colors.GREEN}Strong: {', '.join(deep['strengths'])}{Colors.RESET}")

        print(f"\n  {Colors.BOLD}PERSONA READINESS{Colors.RESET}")
        for cat in self.persona_categories:
            sc = self.scores.get(cat, 0)
            mx = self.max_scores[cat]
            pct = (sc / mx * 100) if mx else 0
            bar_len = int(pct / 100 * 24)
            bar = '█' * bar_len + '░' * (24 - bar_len)
            color = score_color(sc, mx)
            label = self.category_names[cat]
            print(f"    {label:28} {color}{bar} {pct:5.1f}%{Colors.RESET}")

        print(f"\n  {Colors.BOLD}SEVERITY BREAKDOWN{Colors.RESET}")
        width = 40
        max_count = max(counts.values()) if any(counts.values()) else 1
        for sev in SEVERITY_ORDER:
            c = counts[sev]
            bar_len = int((c / max_count) * width) if max_count else 0
            bar = '█' * bar_len
            print(f"    {severity_color(sev)}{sev:10}{Colors.RESET} {c:3}  {bar}")

        print(f"\n  {Colors.BOLD}GOVERNANCE READINESS{Colors.RESET}")
        gov_labels = {
            'statement': 'Accessibility statement',
            'feedback': 'Feedback mechanism',
            'training': 'Training guidance',
            'conformance_report': 'Conformance report (VPAT/ACR)',
            'certification': 'Certification signals',
        }
        for cat in self.governance_categories:
            sc = self.scores.get(cat, 0)
            mx = self.max_scores.get(cat, 1)
            pct = (sc / mx * 100) if mx else 0
            status = 'present' if pct >= 80 else 'partial' if pct >= 40 else 'missing'
            color = Colors.GREEN if pct >= 80 else Colors.YELLOW if pct >= 40 else Colors.RED
            label = gov_labels.get(cat, cat)
            print(f"    {label:34} {color}{status:8} ({pct:5.1f}%){Colors.RESET}")
        gov_color = score_color(self.governance_score, 100)
        print(f"    {'Composite governance':34} {gov_color}{self.governance_score:5.1f}/100{Colors.RESET}")

        fb = self.feedback_analysis
        cr = self.conformance_report_info
        cert = self.certification_info
        fb_status = 'present' if fb.get('found') else 'missing'
        fb_color = Colors.GREEN if fb.get('found') else Colors.RED
        cr_status = 'present' if cr.get('found') else 'missing'
        cr_color = Colors.GREEN if cr.get('found') else Colors.RED
        cert_status = 'present' if cert.get('found') else 'missing'
        cert_color = Colors.GREEN if cert.get('found') else Colors.YELLOW if cert.get('signals') else Colors.RED
        print(f"    {'Feedback route':34} {fb_color}{fb_status:8} "
              f"({fb.get('channel_count', 0)} channel(s))"
              f"{' [response time promised]' if fb.get('response_time_promised') else ''}{Colors.RESET}")
        print(f"    {'Conformance report':34} {cr_color}{cr_status:8} "
              f"({len(cr.get('signals', []))} signal(s), "
              f"{'dated' if cr.get('dated') else 'undated'}){Colors.RESET}")
        print(f"    {'Certification':34} {cert_color}{cert_status:8} "
              f"({len(cert.get('signals', []))} signal(s)){Colors.RESET}")

        level_scores = self.conformance_detail.get('level_scores', {})
        coverage = self.conformance_detail.get('coverage', {})
        if level_scores:
            print(f"\n  {Colors.BOLD}LEVEL SCORE ESTIMATES{Colors.RESET}")
            for lvl in ('A', 'AA', 'AAA'):
                ls = level_scores.get(lvl, 0.0)
                cov = coverage.get(lvl, 0.0)
                bar_len = int(ls / 100 * 24)
                bar = '█' * bar_len + '░' * (24 - bar_len)
                color = score_color(ls, 100)
                print(f"    WCAG 2.2 {lvl:3}  {color}{bar} {ls:5.1f}%{Colors.RESET}  "
                      f"{Colors.GRAY}coverage {cov:5.1f}%{Colors.RESET}")

        print(f"\n  {Colors.BOLD}CONFORMANCE DETAIL{Colors.RESET}")
        issue_counts = self.conformance_detail.get('issue_counts', {})
        blocking = self.conformance_detail.get('blocking_counts', {})
        for lvl in ('A', 'AA', 'AAA'):
            ic = issue_counts.get(lvl, 0)
            bc = blocking.get(lvl, 0)
            status = Colors.GREEN if bc == 0 else Colors.RED
            print(f"    Level {lvl:3} issues: {ic:3}   blocking (Critical/Serious): {status}{bc}{Colors.RESET}")

        p1_issues = [i for i in self.issues if i.priority == 'P1']
        if p1_issues:
            top = p1_issues[0]
            print(f"\n  {Colors.BOLD}NEXT BEST ACTION{Colors.RESET}")
            print(f"    {priority_color(top.priority)}{top.priority}{Colors.RESET} "
                  f"{severity_color(top.severity)}[{top.severity}]{Colors.RESET} {top.title} "
                  f"{Colors.GRAY}({top.wcag_ref or 'n/a'}){Colors.RESET}")
            print(f"    {Colors.GRAY}{top.remediation}{Colors.RESET}")

        print(f"  {Colors.GRAY}Raw category total: {total:.1f}/100 | Weighted (severity-adjusted): {self.weighted_score:.1f}/100{Colors.RESET}")
        print(f"{'='*80}\n")

    def print_prioritization_matrix(self):
        print(f"\n{'='*80}")
        print(f"{Colors.BOLD}{Colors.CYAN}  ISSUE PRIORITIZATION MATRIX{Colors.RESET}")
        print(f"{'='*80}")
        print(f"  {Colors.GRAY}Rows = severity (impact), Columns = remediation effort, cells show priority mix{Colors.RESET}\n")

        header = f"  {'Severity':12} | {'Low effort':30} | {'Medium effort':30} | {'High effort':30}"
        print(header)
        print(f"  {'-'*12}-+-{'-'*30}-+-{'-'*30}-+-{'-'*30}")
        effort_totals = {'Low': 0, 'Medium': 0, 'High': 0}
        effort_days = {'Low': 0.0, 'Medium': 0.0, 'High': 0.0}
        for sev in SEVERITY_ORDER:
            cells = []
            for effort in ('Low', 'Medium', 'High'):
                entries = self.matrix.get(sev, {}).get(effort, [])
                effort_totals[effort] += len(entries)
                effort_days[effort] += EFFORT_DAYS.get(effort, 2.0) * len(entries)
                if not entries:
                    cells.append(f"{'-':30}")
                else:
                    pri_counts = {}
                    for e in entries:
                        pri_counts[e['priority']] = pri_counts.get(e['priority'], 0) + 1
                    pri_txt = ' '.join(f"{p}:{pri_counts[p]}"
                                       for p in ('P1', 'P2', 'P3', 'P4') if p in pri_counts)
                    quad = self.matrix_quadrant(sev, effort)
                    label = f"{len(entries)} [{pri_txt}] {quad}"
                    cells.append(f"{label[:30]:30}")
            print(f"  {severity_color(sev)}{sev:12}{Colors.RESET} | " + " | ".join(cells))
        print(f"\n  {Colors.GRAY}Totals - Low: {effort_totals['Low']} (~{effort_days['Low']:.1f}d)  "
              f"Medium: {effort_totals['Medium']} (~{effort_days['Medium']:.1f}d)  "
              f"High: {effort_totals['High']} (~{effort_days['High']:.1f}d){Colors.RESET}")

        quick = sum(len(self.matrix.get(sev, {}).get('Low', []))
                    for sev in ('Critical', 'Serious'))
        if quick:
            print(f"  {Colors.GREEN}Quick wins available: {quick} Critical/Serious item(s) with low effort — do these first.{Colors.RESET}")

        print(f"\n  {Colors.BOLD}PRIORITY LEGEND{Colors.RESET}")
        for p, desc in [('P1', 'Immediate - fix this sprint (blocks conformance)'),
                        ('P2', 'High - plan for next sprint'),
                        ('P3', 'Medium - schedule soon'),
                        ('P4', 'Low - backlog / AAA polish')]:
            print(f"    {priority_color(p)}{p}{Colors.RESET}  {desc}")
        print(f"\n  {Colors.BOLD}QUADRANT LEGEND{Colors.RESET}")
        for q, desc in [('Quick Wins', 'Critical/Serious + low effort - do first'),
                        ('Strategic', 'Critical/Serious + more effort - plan properly'),
                        ('Fill-ins', 'Moderate + low effort - opportunistic fixes'),
                        ('Plan Ahead', 'Moderate - schedule into a sprint'),
                        ('Backlog', 'Minor - batch when convenient')]:
            print(f"    {Colors.CYAN}{q:14}{Colors.RESET} {desc}")
        print(f"{'='*80}\n")

    def print_remediation_roadmap(self):
        print(f"\n{'='*80}")
        print(f"{Colors.BOLD}{Colors.CYAN}  REMEDIATION ROADMAP{Colors.RESET}")
        print(f"{'='*80}\n")

        if not self.roadmap:
            print(f"  {Colors.GRAY}No issues to schedule.{Colors.RESET}")
            return

        total_days = 0.0
        for phase in self.roadmap:
            days = phase.get('estimated_days', 0.0)
            total_days += days
            p1_count = phase.get('p1_count', 0)
            quick_wins = phase.get('quick_wins', 0)
            print(f"  {Colors.BOLD}{phase['name']}{Colors.RESET} {Colors.CYAN}[{phase['window']}]{Colors.RESET} "
                  f"{Colors.GRAY}({phase['count']} issue(s), ~{days:.1f} dev-day(s)){Colors.RESET}")
            print(f"    {Colors.GRAY}Focus: {phase['focus']}{Colors.RESET}")
            if phase.get('exit_criteria'):
                print(f"    {Colors.CYAN}Exit criteria: {phase['exit_criteria']}{Colors.RESET}")
            if phase.get('categories'):
                print(f"    {Colors.GRAY}Areas: {', '.join(phase['categories'])}{Colors.RESET}")
            for item in phase['issues'][:6]:
                sev = severity_color(item['severity'])
                pri = priority_color(item['priority'])
                quad = item.get('quadrant', '')
                quad_txt = f" {Colors.CYAN}{quad}{Colors.RESET}" if quad == 'Quick Wins' else ''
                print(f"    - {sev}{item['severity'][:8]:8}{Colors.RESET} {pri}{item['priority']}{Colors.RESET} "
                      f"{item['title']} {Colors.GRAY}({item['wcag_ref'] or 'n/a'}){Colors.RESET}{quad_txt}")
            if phase['count'] > 6:
                print(f"    {Colors.GRAY}... and {phase['count'] - 6} more in this phase{Colors.RESET}")
            if p1_count:
                print(f"    {Colors.RED}{p1_count} P1 item(s) in this phase{Colors.RESET}")
            if quick_wins:
                print(f"    {Colors.GREEN}{quick_wins} quick win(s) in this phase{Colors.RESET}")
            print()
        print(f"  {Colors.GRAY}Total estimated effort across roadmap: ~{total_days:.1f} dev-day(s){Colors.RESET}")
        print(f"{'='*80}\n")

    def print_screen_reader_simulation(self):
        print(f"\n{'='*80}")
        print(f"{Colors.BOLD}{Colors.CYAN}  SCREEN READER SIMULATION{Colors.RESET}")
        print(f"{'='*80}")
        print(f"  {Colors.GRAY}Simulated announcement sequence (what a screen reader user would hear):{Colors.RESET}\n")
        limit = 40 if self.verbose else 15
        for i, line in enumerate(self.screen_reader_log[:limit]):
            print(f"    {Colors.GREEN}>{Colors.RESET} {line}")
        if len(self.screen_reader_log) > limit:
            print(f"    {Colors.GRAY}... {len(self.screen_reader_log) - limit} more announcements (use --verbose for full log){Colors.RESET}")
        print(f"{'='*80}\n")

    def print_keyboard_simulation(self):
        print(f"\n{'='*80}")
        print(f"{Colors.BOLD}{Colors.CYAN}  KEYBOARD NAVIGATION SIMULATION{Colors.RESET}")
        print(f"{'='*80}")
        print(f"  {Colors.GRAY}Simulated Tab order (first {min(len(self.keyboard_path), 40)} stops):{Colors.RESET}\n")
        for i, stop in enumerate(self.keyboard_path[:40], 1):
            marker = f"{Colors.CYAN}{i:2}.{Colors.RESET}"
            name_issue = 'no accessible name' in stop
            color = Colors.RED if name_issue else Colors.WHITE
            print(f"    {marker} {color}{stop}{Colors.RESET}")
        if not self.keyboard_path:
            print(f"    {Colors.RED}No focusable elements found in simulation.{Colors.RESET}")
        m = self.keyboard_metrics
        print(f"\n  {Colors.GRAY}Tab stops: {m.get('tab_stops', 0)}  |  "
              f"Positive tabindex: {m.get('positive_tabindex', 0)}  |  "
              f"Mouse-only: {m.get('mouse_only', 0)}  |  "
              f"Trap risks: {m.get('trap_risk', 0)}  |  "
              f"Unnamed stops: {m.get('unnamed_stops', 0)}{Colors.RESET}")
        print(f"{'='*80}\n")

    def print_accessibility_statement(self):
        print(f"\n{'='*80}")
        print(f"{Colors.BOLD}{Colors.CYAN}  ACCESSIBILITY STATEMENT{Colors.RESET}")
        print(f"{'='*80}\n")
        for line in self.statement.splitlines():
            if line.isupper() and len(line) > 3:
                print(f"  {Colors.BOLD}{line}{Colors.RESET}")
            elif set(line) and set(line) <= set('-'):
                continue
            else:
                print(f"  {line}")
        print(f"\n{'='*80}\n")

    def export_results(self, format_type):
        total = self.get_total_score()
        grade = grade_from_score(self.weighted_score)
        level = self.conformance

        if format_type == 'json':
            return self.export_json(total, grade, level)
        elif format_type == 'csv':
            return self.export_csv(total, grade, level)
        elif format_type == 'html':
            return self.export_html(total, grade, level)
        elif format_type == 'statement':
            return self.export_statement()
        elif format_type == 'all':
            self.export_json(total, grade, level)
            self.export_csv(total, grade, level)
            self.export_html(total, grade, level)
            self.export_statement()
            return True
        return False

    def export_json(self, total, grade, level):
        data = {
            'tool': 'AccessibilityAnalyzer v4.0',
            'url': self.url,
            'timestamp': datetime.now().isoformat(),
            'wcag_target': self.level,
            'wcag_standard': 'WCAG 2.2',
            'total_score': total,
            'weighted_score': self.weighted_score,
            'grade': grade,
            'wcag_level': level,
            'meets_target': self.meets_target(),
            'maturity': self.maturity,
            'maturity_deep': self.maturity_deep,
            'governance_score': self.governance_score,
            'conformance_detail': self.conformance_detail,
            'scores': {cat: {'score': self.scores.get(cat, 0), 'max': self.max_scores[cat],
                             'name': self.category_names.get(cat, cat)}
                       for cat in self.max_scores},
            'persona_readiness': {cat: (self.scores.get(cat, 0) / self.max_scores[cat] * 100)
                                  if self.max_scores.get(cat) else 0
                                  for cat in self.persona_categories},
            'governance_readiness': {cat: (self.scores.get(cat, 0) / self.max_scores[cat] * 100)
                                     if self.max_scores.get(cat) else 0
                                     for cat in self.governance_categories},
            'issues': [issue.to_dict() for issue in self.issues],
            'prioritization_matrix': self.matrix,
            'matrix_quadrants': {sev: {eff: self.matrix_quadrant(sev, eff)
                                       for eff in ('Low', 'Medium', 'High')}
                                 for sev in SEVERITY_ORDER},
            'remediation_roadmap': self.roadmap,
            'screen_reader_simulation': self.screen_reader_log,
            'keyboard_navigation_simulation': self.keyboard_path,
            'keyboard_metrics': self.keyboard_metrics,
            'accessibility_statement': self.statement,
            'statement_analysis': self.statement_analysis,
            'feedback_analysis': self.feedback_analysis,
            'training_hints': self.training_hints,
            'conformance_report_info': self.conformance_report_info,
            'certification_info': self.certification_info,
            'accessibility_tree': {
                'node_count': len(self.a11y_tree.get('nodes', [])),
                'roles': self.a11y_tree.get('roles', {}),
                'missing_names': self.a11y_tree.get('missing_names', 0),
                'broken_refs': self.a11y_tree.get('broken_refs', 0),
                'duplicate_ids': self.a11y_tree.get('duplicate_ids', 0),
                'unnamed_focusable': self.a11y_tree.get('unnamed_focusable', 0),
                'hidden_focusable': self.a11y_tree.get('hidden_focusable', 0),
                'landmarks': self.a11y_tree.get('landmarks', {}),
                'heading_outline': self.a11y_tree.get('heading_outline', []),
                'states': self.a11y_tree.get('states', {}),
            },
        }

        filename = f"accessibility_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{Colors.GREEN}[+] Exported JSON report: {filename}{Colors.RESET}")
        return True

    def export_csv(self, total, grade, level):
        filename = f"accessibility_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Timestamp', 'Total Score', 'Weighted Score', 'Grade', 'WCAG Level', 'Maturity', 'Governance'])
            writer.writerow([self.url, datetime.now().isoformat(), total, round(self.weighted_score, 2),
                             grade, level, f"{self.maturity['stage']}-{self.maturity['name']}",
                             self.governance_score])
            writer.writerow([])
            writer.writerow(['Category', 'Score', 'Max Score', 'Percentage'])
            for cat in self.max_scores:
                score = self.scores.get(cat, 0)
                max_score = self.max_scores[cat]
                pct = (score / max_score * 100) if max_score > 0 else 0
                writer.writerow([self.category_names[cat], score, max_score, f"{pct:.1f}%"])
            writer.writerow([])
            writer.writerow(['Level', 'Estimated Score', 'Coverage %'])
            level_scores = self.conformance_detail.get('level_scores', {})
            coverage = self.conformance_detail.get('coverage', {})
            for lvl in ('A', 'AA', 'AAA'):
                writer.writerow([lvl, level_scores.get(lvl, 0.0), coverage.get(lvl, 0.0)])
            writer.writerow([])
            writer.writerow(['Severity', 'Priority', 'Effort', 'Conformance', 'Category',
                             'Title', 'Description', 'Remediation', 'WCAG Ref'])
            for issue in self.issues:
                writer.writerow([issue.severity, issue.priority, issue.effort, issue.conformance,
                                 self.category_names.get(issue.category, issue.category),
                                 issue.title, issue.description, issue.remediation, issue.wcag_ref])
            writer.writerow([])
            writer.writerow(['Phase', 'Window', 'Count', 'Est. Days', 'Exit Criteria', 'Sample Issues'])
            for phase in self.roadmap:
                sample = '; '.join(i['title'] for i in phase['issues'][:3])
                writer.writerow([phase['name'], phase['window'], phase['count'],
                                 phase.get('estimated_days', 0),
                                 phase.get('exit_criteria', ''), sample])
            writer.writerow([])
            writer.writerow(['Training Hint', 'Audience', 'Action', 'Signal'])
            for hint in self.training_hints:
                writer.writerow([hint.get('topic', ''), hint.get('audience', ''),
                                 hint.get('action', ''), hint.get('signal', '')])
            writer.writerow([])
            writer.writerow(['Maturity Dimension', 'Readiness %'])
            for dim_name, dim_pct in (self.maturity_deep.get('dimensions') or {}).items():
                writer.writerow([dim_name, dim_pct])
            writer.writerow(['Overall readiness', self.maturity_deep.get('readiness_pct', 0.0)])
            writer.writerow(['Next stage', self.maturity_deep.get('next_stage', '')])
        print(f"{Colors.GREEN}[+] Exported CSV report: {filename}{Colors.RESET}")
        return True

    def export_statement(self):
        filename = f"accessibility_statement_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(self.statement + '\n')
        print(f"{Colors.GREEN}[+] Exported accessibility statement: {filename}{Colors.RESET}")
        return True

    def export_html(self, total, grade, level):
        filename = f"accessibility_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        grade_color = '#22c55e' if grade in ['A+', 'A'] else '#eab308' if grade == 'B' else '#ef4444'

        scores_html = ''
        for cat in self.max_scores:
            score = self.scores.get(cat, 0)
            max_score = self.max_scores[cat]
            pct = (score / max_score * 100) if max_score > 0 else 0
            bar_color = '#22c55e' if pct >= 80 else '#eab308' if pct >= 60 else '#ef4444'
            scores_html += (
                '<div class="score-row">'
                f'<div class="score-label">{self.category_names[cat]}</div>'
                '<div class="score-bar-container">'
                f'<div class="score-bar" style="width: {pct:.1f}%; background: {bar_color};"></div>'
                '</div>'
                f'<div class="score-value">{score:.1f}/{max_score}</div>'
                '</div>'
            )

        persona_html = ''
        for cat in self.persona_categories:
            score = self.scores.get(cat, 0)
            max_score = self.max_scores[cat]
            pct = (score / max_score * 100) if max_score > 0 else 0
            bar_color = '#22c55e' if pct >= 80 else '#eab308' if pct >= 60 else '#ef4444'
            persona_html += (
                '<div class="score-row">'
                f'<div class="score-label">{self.category_names[cat]}</div>'
                '<div class="score-bar-container">'
                f'<div class="score-bar" style="width: {pct:.1f}%; background: {bar_color};"></div>'
                '</div>'
                f'<div class="score-value">{pct:.0f}%</div>'
                '</div>'
            )

        gov_html = ''
        for cat in self.governance_categories:
            score = self.scores.get(cat, 0)
            max_score = self.max_scores[cat]
            pct = (score / max_score * 100) if max_score > 0 else 0
            bar_color = '#22c55e' if pct >= 80 else '#eab308' if pct >= 40 else '#ef4444'
            gov_html += (
                '<div class="score-row">'
                f'<div class="score-label">{self.category_names[cat]}</div>'
                '<div class="score-bar-container">'
                f'<div class="score-bar" style="width: {pct:.1f}%; background: {bar_color};"></div>'
                '</div>'
                f'<div class="score-value">{pct:.0f}%</div>'
                '</div>'
            )

        deep_html = ''
        deep = self.maturity_deep
        if deep.get('dimensions'):
            for dim_name, dim_pct in sorted(deep['dimensions'].items(), key=lambda kv: kv[1]):
                bar_color = '#22c55e' if dim_pct >= 80 else '#eab308' if dim_pct >= 50 else '#ef4444'
                deep_html += (
                    '<div class="score-row">'
                    f'<div class="score-label">{dim_name}</div>'
                    '<div class="score-bar-container">'
                    f'<div class="score-bar" style="width: {dim_pct:.1f}%; background: {bar_color};"></div>'
                    '</div>'
                    f'<div class="score-value">{dim_pct:.1f}%</div>'
                    '</div>'
                )
            if deep.get('next_detail'):
                deep_html += f'<p class="muted" style="margin-top: 1rem;">{deep["next_detail"]}</p>'

        level_rows = ''
        level_scores = self.conformance_detail.get('level_scores', {})
        coverage = self.conformance_detail.get('coverage', {})
        for lvl in ('A', 'AA', 'AAA'):
            ls = level_scores.get(lvl, 0.0)
            cov = coverage.get(lvl, 0.0)
            level_rows += f'<tr><td>WCAG 2.2 {lvl}</td><td>{ls:.1f}%</td><td>{cov:.1f}%</td></tr>'

        issues_html = ''
        severity_colors = {'Critical': '#ef4444', 'Serious': '#f97316', 'Moderate': '#eab308', 'Minor': '#6b7280'}
        sorted_issues = sorted(self.issues,
                               key=lambda i: (SEVERITY_ORDER.index(i.severity) if i.severity in SEVERITY_ORDER else 9))
        for issue in sorted_issues:
            sev_color = severity_colors.get(issue.severity, '#6b7280')
            ref_html = f'<div class="issue-ref">Reference: {issue.wcag_ref} | Level {issue.conformance} | {issue.priority} | effort {issue.effort}</div>' if issue.wcag_ref else ''
            issues_html += (
                f'<div class="issue" style="border-left: 4px solid {sev_color};">'
                '<div class="issue-header">'
                f'<span class="severity" style="background: {sev_color};">{issue.severity}</span>'
                f'<span class="issue-title">{issue.title}</span>'
                f'<span class="priority-badge">{issue.priority}</span>'
                '</div>'
                f'<div class="issue-desc">{issue.description}</div>'
                f'<div class="issue-fix"><strong>Fix:</strong> {issue.remediation}</div>'
                f'{ref_html}'
                '</div>'
            )

        matrix_rows = ''
        for sev in SEVERITY_ORDER:
            cells = ''
            for effort in ('Low', 'Medium', 'High'):
                entries = self.matrix.get(sev, {}).get(effort, [])
                if entries:
                    quad = self.matrix_quadrant(sev, effort)
                    label = f'{len(entries)} item(s) - {quad}'
                else:
                    label = '-'
                cells += f'<td>{label}</td>'
            matrix_rows += f'<tr><td class="sev-{sev.lower()}">{sev}</td>{cells}</tr>'

        roadmap_html = ''
        for phase in self.roadmap:
            items = ''.join(
                f'<li>[{item["severity"]}] {item["title"]} <span class="muted">({item["wcag_ref"] or "n/a"})</span></li>'
                for item in phase['issues'][:8]
            )
            exit_txt = f'<p class="muted">Exit: {phase.get("exit_criteria", "")}</p>' if phase.get('exit_criteria') else ''
            roadmap_html += (
                f'<div class="phase"><h3>{phase["name"]} <span class="window">{phase["window"]}</span></h3>'
                f'<p class="muted">Focus: {phase["focus"]} ({phase["count"]} issues, ~{phase.get("estimated_days", 0)}d)</p>'
                f'{exit_txt}'
                f'<ul>{items}</ul></div>'
            )

        sr_log_html = ''.join(f'<div class="log-line">&gt; {line}</div>' for line in self.screen_reader_log[:40])
        kb_log_html = ''.join(f'<div class="log-line">{idx}. {stop}</div>'
                              for idx, stop in enumerate(self.keyboard_path[:40], 1))

        statement_html = ''.join(f'<div class="stmt-line">{line}</div>' for line in self.statement.splitlines())

        maturity = self.maturity
        counts = self.severity_counts()

        html = (
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            '    <meta charset="UTF-8">\n'
            '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            f'    <title>Accessibility Report - {self.url}</title>\n'
            '    <style>\n'
            '        * { margin: 0; padding: 0; box-sizing: border-box; }\n'
            "        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem; }\n"
            '        .container { max-width: 1200px; margin: 0 auto; }\n'
            '        h1 { color: #38bdf8; margin-bottom: 0.5rem; font-size: 1.8rem; }\n'
            '        h2 { color: #38bdf8; margin-bottom: 1rem; font-size: 1.2rem; }\n'
            '        h3 { color: #e2e8f0; margin-bottom: 0.35rem; font-size: 1rem; }\n'
            '        .subtitle { color: #94a3b8; margin-bottom: 2rem; }\n'
            '        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 1rem; margin-bottom: 2rem; }\n'
            '        .summary-card { background: #1e293b; padding: 1.5rem; border-radius: 8px; border: 1px solid #334155; }\n'
            '        .summary-card h3 { color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; margin-bottom: 0.5rem; }\n'
            '        .summary-card .value { font-size: 2rem; font-weight: bold; }\n'
            '        .panel { background: #1e293b; padding: 1.5rem; border-radius: 8px; border: 1px solid #334155; margin-bottom: 2rem; }\n'
            '        .score-row { display: flex; align-items: center; margin-bottom: 0.75rem; }\n'
            '        .score-label { width: 220px; font-size: 0.9rem; }\n'
            '        .score-bar-container { flex: 1; height: 8px; background: #334155; border-radius: 4px; margin: 0 1rem; overflow: hidden; }\n'
            '        .score-bar { height: 100%; border-radius: 4px; transition: width 0.3s; }\n'
            '        .score-value { width: 90px; text-align: right; font-size: 0.9rem; color: #94a3b8; }\n'
            '        .issue { background: #0f172a; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }\n'
            '        .issue-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; flex-wrap: wrap; }\n'
            '        .severity { padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; color: white; text-transform: uppercase; }\n'
            '        .priority-badge { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; border: 1px solid #475569; color: #cbd5e1; }\n'
            '        .issue-title { font-weight: 600; }\n'
            '        .issue-desc { color: #94a3b8; font-size: 0.9rem; margin-bottom: 0.5rem; }\n'
            '        .issue-fix { color: #86efac; font-size: 0.85rem; }\n'
            '        .issue-ref { color: #64748b; font-size: 0.8rem; margin-top: 0.25rem; }\n'
            '        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }\n'
            '        th, td { padding: 0.6rem; border-bottom: 1px solid #334155; text-align: left; }\n'
            '        th { color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; }\n'
            '        .sev-critical { color: #ef4444; font-weight: 600; }\n'
            '        .sev-serious { color: #f97316; font-weight: 600; }\n'
            '        .sev-moderate { color: #eab308; font-weight: 600; }\n'
            '        .sev-minor { color: #94a3b8; }\n'
            '        .phase { background: #0f172a; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }\n'
            '        .phase .window { color: #38bdf8; font-size: 0.8rem; font-weight: normal; }\n'
            '        .phase ul { margin: 0.5rem 0 0 1.2rem; color: #cbd5e1; font-size: 0.9rem; }\n'
            '        .phase li { margin-bottom: 0.25rem; }\n'
            '        .muted { color: #94a3b8; font-size: 0.85rem; }\n'
            '        .log-line { font-family: ui-monospace, monospace; font-size: 0.8rem; color: #a5f3fc; padding: 0.15rem 0; border-bottom: 1px dashed #1e293b; }\n'
            '        .stmt-line { font-size: 0.9rem; color: #cbd5e1; white-space: pre-wrap; }\n'
            '        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }\n'
            '        @media (max-width: 800px) { .grid-2 { grid-template-columns: 1fr; } .score-label { width: 130px; } }\n'
            '    </style>\n</head>\n<body>\n    <div class="container">\n'
            '        <h1>Accessibility Analysis Report</h1>\n'
            f'        <p class="subtitle">AccessibilityAnalyzer v4.0 | WCAG 2.2 | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Target: {self.url}</p>\n'
            '        <div class="summary">\n'
            f'            <div class="summary-card"><h3>Weighted Score</h3><div class="value" style="color: {grade_color};">{self.weighted_score:.1f}<span style="font-size: 1rem; color: #64748b;">/100</span></div></div>\n'
            f'            <div class="summary-card"><h3>Grade</h3><div class="value" style="color: {grade_color};">{grade}</div></div>\n'
            f'            <div class="summary-card"><h3>WCAG 2.2 Level</h3><div class="value" style="color: {grade_color};">{level}</div></div>\n'
            f'            <div class="summary-card"><h3>Maturity</h3><div class="value" style="color: #38bdf8;">{maturity["stage"]}/5</div><div class="muted">{maturity["name"]}</div></div>\n'
            f'            <div class="summary-card"><h3>Deep Readiness</h3><div class="value" style="color: #38bdf8;">{self.maturity_deep.get("readiness_pct", 0.0):.0f}<span style="font-size: 1rem; color: #64748b;">%</span></div></div>\n'
            f'            <div class="summary-card"><h3>Governance</h3><div class="value" style="color: #38bdf8;">{self.governance_score:.0f}<span style="font-size: 1rem; color: #64748b;">/100</span></div></div>\n'
            f'            <div class="summary-card"><h3>Total Issues</h3><div class="value" style="color: #fbbf24;">{len(self.issues)}</div></div>\n'
            f'            <div class="summary-card"><h3>P1 Issues</h3><div class="value" style="color: #ef4444;">{len([i for i in self.issues if i.priority == "P1"])}</div></div>\n'
            '        </div>\n'
            '        <div class="grid-2">\n'
            '            <div class="panel"><h2>Category Scores</h2>' + scores_html + '</div>\n'
            '            <div class="panel"><h2>Persona Readiness</h2>' + persona_html +
            f'                <p class="muted" style="margin-top: 1rem;">{maturity["description"]}</p></div>\n'
            '        </div>\n'
            '        <div class="grid-2">\n'
            '            <div class="panel"><h2>Governance Readiness</h2>' + gov_html + '</div>\n'
            '            <div class="panel"><h2>Maturity Deep Analysis</h2>' +
            (deep_html or '<p class="muted">No deep maturity data.</p>') + '</div>\n'
            '        </div>\n'
            '        <div class="grid-2">\n'
            '            <div class="panel"><h2>Level Score Estimates</h2>\n'
            '            <table><thead><tr><th>Level</th><th>Estimated Score</th><th>Coverage</th></tr></thead>\n'
            f'            <tbody>{level_rows}</tbody></table></div>\n'
            '            <div class="panel"><h2>Feedback, Report & Certification</h2>\n'
            f'            <p>Feedback channels: {len(self.feedback_analysis.get("channels", []))} '
            f'({"accessible" if self.feedback_analysis.get("accessible") else "unconfirmed"}); '
            f'response time promised: {"yes" if self.feedback_analysis.get("response_time_promised") else "no"}</p>\n'
            f'            <p>Conformance report: {"found" if self.conformance_report_info.get("found") else "not found"} '
            f'({len(self.conformance_report_info.get("signals", []))} signal(s), '
            f'{"dated" if self.conformance_report_info.get("dated") else "undated"})</p>\n'
            f'            <p>Certification: {"found" if self.certification_info.get("found") else "not found"} '
            f'({len(self.certification_info.get("signals", []))} signal(s))</p></div>\n'
            '        </div>\n'
            '        <div class="panel"><h2>Issue Prioritization Matrix</h2>\n'
            '            <table><thead><tr><th>Severity</th><th>Low effort</th><th>Medium effort</th><th>High effort</th></tr></thead>\n'
            f'            <tbody>{matrix_rows}</tbody></table></div>\n'
            '        <div class="panel"><h2>Remediation Roadmap</h2>' + roadmap_html + '</div>\n'
            '        <div class="panel"><h2>Severity Breakdown</h2>\n'
            f'            <p><span style="color:#ef4444">Critical: {counts["Critical"]}</span> &nbsp; '
            f'<span style="color:#f97316">Serious: {counts["Serious"]}</span> &nbsp; '
            f'<span style="color:#eab308">Moderate: {counts["Moderate"]}</span> &nbsp; '
            f'<span style="color:#94a3b8">Minor: {counts["Minor"]}</span></p></div>\n'
            '        <div class="grid-2">\n'
            '            <div class="panel"><h2>Screen Reader Simulation</h2>' +
            (sr_log_html or '<p class="muted">No simulation data.</p>') + '</div>\n'
            '            <div class="panel"><h2>Keyboard Navigation Path</h2>' +
            (kb_log_html or '<p class="muted">No focusable elements found.</p>') + '</div>\n'
            '        </div>\n'
            '        <div class="panel"><h2>Accessibility Statement</h2>' + statement_html + '</div>\n'
            '        <div class="panel"><h2>Issues Found (' + str(len(self.issues)) + ')</h2>' +
            (issues_html or '<p style="color: #94a3b8;">No issues found!</p>') +
            '        </div>\n    </div>\n</body>\n</html>'
        )

        with open(filename, 'w') as f:
            f.write(html)
        print(f"{Colors.GREEN}[+] Exported HTML report: {filename}{Colors.RESET}")
        return True

def main():
    parser = argparse.ArgumentParser(
        description='AccessibilityAnalyzer v4.0 - WCAG 2.2 Web Accessibility Analyzer with governance checks and deep maturity analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com --export json --verbose
  %(prog)s -u https://example.com --level AAA --export all
  %(prog)s -u https://example.com --export statement --no-dashboard
        '''
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL to analyze')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--export', choices=['all', 'json', 'csv', 'html', 'statement', 'none'], default='none',
                        help='Export format (default: none)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--level', choices=['A', 'AA', 'AAA'], default='AA',
                        help='WCAG compliance level target (default: AA)')
    parser.add_argument('--no-dashboard', action='store_true', help='Skip the compliance dashboard section')
    parser.add_argument('--no-simulations', action='store_true',
                        help='Skip screen reader and keyboard navigation simulations output')

    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    print(BANNER)

    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url

    analyzer = AccessibilityAnalyzer(
        url=args.url,
        timeout=args.timeout,
        level=args.level,
        verbose=args.verbose
    )

    if analyzer.analyze():
        analyzer.print_results()

        if not args.no_dashboard:
            analyzer.print_dashboard()

        if not args.no_simulations:
            analyzer.print_screen_reader_simulation()
            analyzer.print_keyboard_simulation()

        analyzer.print_prioritization_matrix()
        analyzer.print_remediation_roadmap()
        analyzer.print_accessibility_statement()

        if args.export != 'none':
            analyzer.export_results(args.export)
    else:
        print(f"\n{Colors.RED}[!] Analysis failed. Please check the URL and try again.{Colors.RESET}")
        sys.exit(1)

if __name__ == '__main__':
    main()
