#!/usr/bin/env python3
"""
SEOChecker v8.0 - Ultimate Website SEO Quality Analyzer
Comprehensive SEO analysis with structured data, sitemap, robots.txt, broken links,
readability, Core Web Vitals, E-E-A-T signals, voice search, AI/LLM readiness,
content freshness, topic clusters, entity/knowledge graph signals, ranking-factor
weighting, health dashboards, priority actions, and strategy recommendations.

New in v8.0: voice search deep analysis, visual search optimization, video
featured snippet optimization, image featured snippet optimization, local pack
optimization, refined knowledge panel and People Also Ask scoring integration,
search visibility score refinement, ranking potential estimation, content
competitiveness score, technical health score, refined SEO health dashboard,
refined priority action items, refined quick wins, and refined long-term
strategy output.
"""

import sys
import os
import re
import time
import argparse
import json
import csv
import math
import concurrent.futures
from urllib.parse import urljoin, urlparse, urldefrag
from collections import Counter
from datetime import datetime
from html.parser import HTMLParser

try:
    import requests
except ImportError:
    print("Installing requests...")
    os.system(f"{sys.executable} -m pip install requests -q")
    import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Installing beautifulsoup4...")
    os.system(f"{sys.executable} -m pip install beautifulsoup4 -q")
    from bs4 import BeautifulSoup

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    class _Fake:
        def __getattr__(self, n): return ''
    Fore = Style = _Fake()

def _disable_colors():
    global Fore, Style
    class _NC:
        def __getattr__(self, n): return ''
    Fore = Style = _NC()

CATEGORY_WEIGHTS = {
    'meta': 1.2,
    'content': 1.15,
    'technical': 1.1,
    'performance': 1.1,
    'security': 1.05,
    'mobile': 1.1,
    'social': 0.9,
    'links': 1.0,
    'eeat': 1.0,
    'voice': 0.85,
    'advanced': 0.95,
    'general': 1.0,
    'freshness': 1.05,
    'ai': 1.1,
    'entities': 0.95,
    'intent': 1.1,
    'visibility': 1.15,
    'competitive': 1.0,
    'snippet': 1.05,
    'visual': 0.95,
    'local': 1.0,
}

FACTOR_WEIGHTS = {
    'content': 0.35,
    'links': 0.25,
    'technical': 0.25,
    'ux': 0.15,
}

CATEGORY_TO_FACTOR = {
    'meta': 'content',
    'content': 'content',
    'freshness': 'content',
    'eeat': 'content',
    'entities': 'content',
    'intent': 'content',
    'visibility': 'content',
    'competitive': 'content',
    'snippet': 'content',
    'links': 'links',
    'technical': 'technical',
    'security': 'technical',
    'performance': 'technical',
    'general': 'technical',
    'mobile': 'ux',
    'social': 'ux',
    'voice': 'ux',
    'ai': 'ux',
    'advanced': 'ux',
    'visual': 'ux',
    'local': 'content',
}

FACTOR_ADVICE = {
    'content': 'Publish comprehensive pillar pages (2,000+ words) and support them with interlinked cluster content targeting related subtopics.',
    'links': 'Design a hub-and-spoke internal linking plan: route authority from top pages to money pages, diversify anchors, and earn editorial backlinks from relevant domains.',
    'technical': 'Keep crawl budget healthy: fix indexation, schema coverage, Core Web Vitals, and XML sitemap hygiene on a recurring basis.',
    'ux': 'Invest in mobile experience, page speed, and interaction readiness so engagement signals reinforce rankings.',
}

SEASONAL_TERMS = [
    'christmas', 'new year', 'black friday', 'cyber monday', 'halloween', 'easter',
    'thanksgiving', 'valentine', 'ramadan', 'diwali', 'eid mubarak', 'holiday gift',
    'summer sale', 'winter sale', 'spring sale', 'back to school', 'prime day',
    'boxing day', 'labour day', 'labor day', 'presidents day', 'memorial day',
    'independence day', 'golden week', 'singles day', 'end of financial year',
]

MONTH_NAMES = [
    'january', 'february', 'march', 'april', 'may', 'june',
    'july', 'august', 'september', 'october', 'november', 'december',
]

PENALTY_RULES = {
    'keyword_stuffing': {'threshold': 0.05, 'penalty': 10, 'description': 'Keyword density exceeds 5%'},
    'hidden_text': {'pattern': r'display:\s*none|visibility:\s*hidden|font-size:\s*0', 'penalty': 15, 'description': 'Hidden text detected'},
    'cloaking_hint': {'pattern': r'<noscript>.*<meta.*http-equiv.*refresh', 'penalty': 20, 'description': 'Possible cloaking via noscript redirect'},
    'doorway_pages': {'check': 'thin_content', 'penalty': 10, 'description': 'Possible doorway page (very thin content)'},
    'link_stuffing': {'threshold': 100, 'penalty': 10, 'description': 'Excessive outbound links'},
    'missing_nofollow_paid': {'check': 'paid_links_nofollow', 'penalty': 5, 'description': 'Paid/sponsored links without nofollow'},
    'auto_generated_content': {'check': 'auto_content', 'penalty': 10, 'description': 'Possible auto-generated content indicators'},
    'duplicate_content_signals': {'check': 'duplicate_signals', 'penalty': 5, 'description': 'Duplicate content signals found'},
}

BONUS_RULES = {
    'https_mixed_content': {'bonus': 3, 'description': 'All resources loaded over HTTPS'},
    'semantic_html': {'bonus': 3, 'description': 'Good use of semantic HTML elements'},
    'lazy_loading': {'bonus': 2, 'description': 'Images use lazy loading'},
    'preload_hints': {'bonus': 2, 'description': 'Resource hints found (preload/prefetch)'},
    'aria_labels': {'bonus': 2, 'description': 'Accessibility attributes found'},
    'structured_data_rich': {'bonus': 3, 'description': 'Multiple rich structured data types'},
    'core_web_vitals_good': {'bonus': 4, 'description': 'Core Web Vitals estimates are good'},
    'author_attribution': {'bonus': 3, 'description': 'Author attribution found'},
    'faq_schema': {'bonus': 3, 'description': 'FAQ schema found'},
    'howto_schema': {'bonus': 2, 'description': 'HowTo schema found'},
    'breadcrumbs': {'bonus': 2, 'description': 'Breadcrumb navigation found'},
    'mobile_optimized': {'bonus': 3, 'description': 'Mobile optimization looks good'},
    'reading_level_good': {'bonus': 2, 'description': 'Good reading level for general audience'},
    'llms_txt': {'bonus': 3, 'description': 'llms.txt found for AI/LLM crawlers'},
    'freshness_signals': {'bonus': 3, 'description': 'Strong publication/update date signals'},
    'entity_sameas': {'bonus': 2, 'description': 'Entity sameAs links found'},
    'knowledge_graph_rich': {'bonus': 3, 'description': 'Strong knowledge graph signals'},
    'topic_cluster': {'bonus': 3, 'description': 'Topic cluster structure detected'},
    'seasonal_fresh': {'bonus': 2, 'description': 'Seasonal content carries fresh date signals'},
    'clean_architecture': {'bonus': 2, 'description': 'Healthy internal linking architecture'},
    'featured_snippet_ready': {'bonus': 3, 'description': 'Featured snippet optimization signals found'},
    'paa_optimized': {'bonus': 3, 'description': 'People Also Ask optimization detected'},
    'knowledge_panel_ready': {'bonus': 3, 'description': 'Knowledge panel optimization signals found'},
    'image_search_ready': {'bonus': 3, 'description': 'Image search optimization is strong'},
    'video_search_ready': {'bonus': 3, 'description': 'Video search optimization is strong'},
    'strong_topic_authority': {'bonus': 3, 'description': 'Strong topic authority signals'},
    'intent_aligned': {'bonus': 2, 'description': 'Page content aligns with detected search intent'},
    'competitive_depth': {'bonus': 2, 'description': 'Content depth matches or exceeds competitor benchmark'},
    'voice_deep_ready': {'bonus': 3, 'description': 'Deep voice search optimization detected'},
    'visual_search_ready': {'bonus': 3, 'description': 'Visual search optimization is strong'},
    'video_snippet_ready': {'bonus': 2, 'description': 'Video featured snippet optimization detected'},
    'image_snippet_ready': {'bonus': 2, 'description': 'Image featured snippet optimization detected'},
    'local_pack_ready': {'bonus': 3, 'description': 'Local pack optimization signals found'},
}

BANNER = f"""{Fore.GREEN}{Style.BRIGHT}
     _____ ______   _______   ________  ___   _________  _______   ________
    / ___/\\______\\ \\  ___  \\ /  _____/ /   \\ /   __   /\\  ___  \\ /  _____/
   / /\\   /       \\ \\   __  /   \\  ___/  /|  \\  /  /  / \\   __  /   \\  ___
  / /  \\  \\___  /  \\ \\  \\ \\  \\  \\  \\  / |   \\  /  /  /   \\  \\ \\  \\ \\  \\  \\
 /_/    \\_______/   \\__|  \\__|  \\___\\ /__|___\\/__/__/     \\__|  \\__|  \\___\\
{Fore.CYAN}    +================================================================+
    |  {Fore.WHITE}ULTIMATE WEBSITE SEO QUALITY ANALYZER  {Fore.CYAN}|
    |  {Fore.YELLOW}v8.0 | Voice Deep | Visual | Local Pack | Ranking    {Fore.CYAN}|
    +================================================================+{Style.RESET_ALL}
"""


class HTMLValidator(HTMLParser):
    def __init__(self):
        super().__init__()
        self.errors = []
        self.warnings = []
        self.tag_count = 0
        self.self_closing = {'meta', 'link', 'img', 'br', 'hr', 'input', 'area', 'base', 'col', 'embed', 'source', 'track', 'wbr'}
        self.open_tags = []

    def handle_starttag(self, tag, attrs):
        self.tag_count += 1
        if tag not in self.self_closing:
            self.open_tags.append(tag)

    def handle_endtag(self, tag):
        if tag in self.self_closing:
            return
        if self.open_tags and self.open_tags[-1] == tag:
            self.open_tags.pop()
        elif tag in self.open_tags:
            while self.open_tags and self.open_tags[-1] != tag:
                self.warnings.append(f"Unclosed tag: <{self.open_tags.pop()}>")
            if self.open_tags:
                self.open_tags.pop()

    def handle_data(self, data):
        pass

    def get_results(self):
        for tag in self.open_tags:
            self.errors.append(f"Unclosed tag: <{tag}>")
        return {'errors': self.errors, 'warnings': self.warnings, 'tag_count': self.tag_count}


class SEOChecker:
    def __init__(self, url, timeout=15, user_agent=None, check_links=False, depth=1, competitors=None):
        self.url = url if url.startswith(('http://', 'https://')) else 'https://' + url
        self.timeout = timeout
        self.check_links_enabled = check_links
        self.depth = depth
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        self.results = {
            'url': self.url,
            'timestamp': datetime.now().isoformat(),
            'version': '8.0',
            'checks': [],
            'penalties': [],
            'bonuses': [],
            'score': 0,
            'max_score': 0,
            'weighted_score': 0,
            'weighted_max': 0,
            'category_scores': {},
            'warnings': [],
            'errors': [],
            'info': [],
            'quick_wins': [],
            'recommendations': [],
            'ranking_factors': {},
            'ranking_weighted_pct': 0.0,
            'priority_actions': [],
            'strategy': [],
            'eeat_breakdown': {},
            'freshness': 0,
            'freshness_refined': 0,
            'freshness_decay_pct': 0.0,
            'ai_readiness': 0,
            'content_quality_index': 0,
            'knowledge_graph': 0,
            'seasonal': False,
            'seasonal_terms': [],
            'search_intent': 'unknown',
            'secondary_intents': [],
            'intent_scores': {},
            'intent_alignment': 0,
            'search_visibility': 0.0,
            'search_visibility_breakdown': {},
            'topic_authority': 0,
            'content_gap': {},
            'cannibalization': {},
            'featured_snippet': {},
            'people_also_ask': {},
            'knowledge_panel': {},
            'image_search': {},
            'video_search': {},
            'voice_search_deep': {},
            'visual_search': {},
            'video_featured_snippet': {},
            'image_featured_snippet': {},
            'local_pack': {},
            'ranking_potential': {},
            'content_competitiveness': {},
            'technical_health': {},
            'competitive_position': {},
            'content_strategy': [],
            'intent_optimization': [],
            'competitor_urls': list(competitors) if competitors else [],
        }
        self.competitors = list(competitors) if competitors else []
        self.soup = None
        self.response = None
        self.page_text = ''
        self.visited_urls = set()
        self.broken_links = []
        self.external_links = []
        self.internal_links = []
        self.anchor_texts = []
        self.all_images = []
        self.schema_data = []
        self.all_links_raw = []
        self.robots_txt_content = None

    def _add_check(self, name, passed, points, max_points, detail='', category='general', weight=None):
        if weight is None:
            weight = CATEGORY_WEIGHTS.get(category, 1.0)
        points = max(0, min(points, max_points))
        self.results['checks'].append({
            'name': name, 'passed': passed, 'points': points, 'max_points': max_points,
            'detail': detail, 'category': category, 'weight': weight
        })
        self.results['score'] += points
        self.results['max_score'] += max_points
        self.results['weighted_score'] += points * weight
        self.results['weighted_max'] += max_points * weight

        if category not in self.results['category_scores']:
            self.results['category_scores'][category] = {'score': 0, 'max': 0, 'checks': []}
        self.results['category_scores'][category]['score'] += points
        self.results['category_scores'][category]['max'] += max_points
        self.results['category_scores'][category]['checks'].append(name)

        status = f"{Fore.GREEN}[PASS]" if passed else f"{Fore.RED}[FAIL]"
        score_str = f"{Fore.YELLOW}{points}/{max_points}"
        print(f"    {status} {name:<42} {score_str}{Style.RESET_ALL}")
        if detail:
            print(f"           {Fore.CYAN}{detail}{Style.RESET_ALL}")
        if not passed:
            self.results['warnings'].append(f"{name}: {detail}")
            self.results['recommendations'].append({
                'check': name, 'priority': 'high' if points == 0 else 'medium',
                'detail': detail, 'category': category
            })

    def _add_penalty(self, rule_key, detail):
        rule = PENALTY_RULES[rule_key]
        self.results['penalties'].append({'rule': rule_key, 'penalty': rule['penalty'], 'detail': detail})
        print(f"    {Fore.RED}[PENALTY] {rule['description']}: -{rule['penalty']} pts{Style.RESET_ALL}")
        print(f"           {Fore.YELLOW}{detail}{Style.RESET_ALL}")

    def _add_bonus(self, rule_key, detail):
        rule = BONUS_RULES[rule_key]
        self.results['bonuses'].append({'rule': rule_key, 'bonus': rule['bonus'], 'detail': detail})
        print(f"    {Fore.GREEN}[BONUS] {rule['description']}: +{rule['bonus']} pts{Style.RESET_ALL}")

    def _add_quick_win(self, title, description, impact='medium', effort='low'):
        for win in self.results['quick_wins']:
            if win.get('title') == title:
                return
        self.results['quick_wins'].append({
            'title': title, 'description': description,
            'impact': impact, 'effort': effort,
        })

    def _gauge(self, pct, width=20):
        pct = max(0.0, min(100.0, float(pct)))
        filled = int(round(pct / 100.0 * width))
        filled = max(0, min(width, filled))
        return '█' * filled + '░' * (width - filled)

    def _pct_color(self, pct):
        if pct >= 80:
            return Fore.GREEN
        if pct >= 60:
            return Fore.CYAN
        if pct >= 40:
            return Fore.YELLOW
        return Fore.RED

    def _parse_date(self, value):
        if not value or not isinstance(value, str):
            return None
        text = value.strip()
        if not text:
            return None
        m = re.match(r'(\d{4})-(\d{2})-(\d{2})', text)
        if m:
            try:
                return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                return None
        m = re.match(r'(\d{4})', text)
        if m:
            try:
                return datetime(int(m.group(1)), 1, 1)
            except ValueError:
                return None
        for fmt in ('%d %B %Y', '%B %d, %Y', '%b %d, %Y', '%d/%m/%Y', '%m/%d/%Y'):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
        return None

    def check_eeat_signals(self):
        experience_score = 0
        expertise_score = 0
        authority_score = 0
        trust_score = 0
        signals = []
        text_lower = self.page_text.lower()

        experience_markers = [
            'we tested', 'we tried', 'in our experience', 'first-hand', 'firsthand',
            'hands-on', 'we found', 'our team', 'we used', 'personally',
            'we reviewed', 'we compared', 'in our lab', 'we measured',
        ]
        exp_hits = sum(1 for marker in experience_markers if marker in text_lower)
        if exp_hits >= 3:
            experience_score += 3
            signals.append(f"{exp_hits} experience markers")
        elif exp_hits >= 1:
            experience_score += 2
            signals.append("first-hand experience markers")

        if re.search(r'\bwe\b|\bI\b|\bour\b', self.page_text):
            experience_score += 1

        author_meta = self.soup.find('meta', attrs={'name': 'author'})
        author_link = self.soup.find('a', rel='author')
        author_schema = False
        for schema in self.schema_data:
            if schema.get('@type') in ('Person', 'Organization') and schema.get('author'):
                author_schema = True
                break
        byline = bool(re.search(r'by\s+[A-Z][a-z]+(\s+[A-Z][a-z]+){1,3}', self.page_text))
        if author_meta or author_link or author_schema or byline:
            expertise_score += 2
            signals.append("author attribution")
            self._add_bonus('author_attribution', "Author attribution found")

        expertise_terms = ['expert', 'research', 'study', 'evidence', 'according to', 'published',
                           'peer-reviewed', 'data shows', 'analysis', 'findings']
        expertise_count = sum(1 for term in expertise_terms if term in text_lower)
        if expertise_count >= 3:
            expertise_score += 2
            signals.append(f"{expertise_count} expertise indicators")
        elif expertise_count >= 1:
            expertise_score += 1
            signals.append("expertise indicators")

        credential_patterns = [r'\bph\.?d\b', r'\bmd\b', r'\bdr\.?\s', r'certified', r'licensed',
                               r'professor', r'engineer', r'architect']
        if any(re.search(p, text_lower) for p in credential_patterns):
            expertise_score += 1
            signals.append("credential signals")

        citation_patterns = [r'\[\d+\]', r'\(.*?\d{4}\)', r'source[s]?:', r'reference[s]?:', r'bibliography']
        has_citations = any(re.search(p, self.page_text, re.I) for p in citation_patterns)
        if has_citations:
            authority_score += 2
            signals.append("citations found")

        authority_links = 0
        for link in self.external_links[:40]:
            host = urlparse(link).netloc.lower()
            if host.endswith('.gov') or host.endswith('.edu') or 'wikipedia.org' in host or 'britannica.com' in host:
                authority_links += 1
        if authority_links > 0:
            authority_score += 1
            signals.append(f"{authority_links} authoritative citations")

        org_schema = any(s.get('@type') == 'Organization' for s in self.schema_data)
        if org_schema:
            authority_score += 1
            signals.append("Organization schema")

        if self.url.startswith('https://'):
            trust_score += 2
            signals.append("HTTPS")

        nav_texts = []
        for a in self.soup.find_all('a', href=True):
            nav_texts.append((a['href'] + ' ' + a.get_text(' ', strip=True)).lower())
        has_contact = any('contact' in t for t in nav_texts)
        has_about = any('about' in t for t in nav_texts)
        has_privacy = any('privacy' in t or 'policy' in t for t in nav_texts)
        trust_bits = sum(1 for flag in (has_contact, has_about, has_privacy) if flag)
        trust_score += min(3, trust_bits)
        if trust_bits:
            signals.append("trust pages linked")

        date_meta = self.soup.find('meta', attrs={'name': 'date'}) or self.soup.find('meta', attrs={'property': 'article:published_time'})
        date_schema = any(s.get('datePublished') or s.get('dateModified') for s in self.schema_data)
        if date_meta or date_schema:
            trust_score += 1
            signals.append("date attribution")

        experience_score = min(4, experience_score)
        expertise_score = min(5, expertise_score)
        authority_score = min(4, authority_score)
        trust_score = min(6, trust_score)

        total = experience_score + expertise_score + authority_score + trust_score
        points = min(10, total)

        self.results['eeat_breakdown'] = {
            'experience': {'score': experience_score, 'max': 4},
            'expertise': {'score': expertise_score, 'max': 5},
            'authoritativeness': {'score': authority_score, 'max': 4},
            'trust': {'score': trust_score, 'max': 6},
        }

        detail = f"Score: {points}/10 | E:{experience_score}/4 Ex:{expertise_score}/5 A:{authority_score}/4 T:{trust_score}/6"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"
        else:
            detail += " | No E-E-A-T signals detected"

        self._add_check("E-E-A-T Signals", points >= 4, points, 10, detail, category='eeat')
        if points < 4:
            self._add_quick_win("Add author and expertise signals", "Add author info, dates, citations to improve credibility.", 'medium')

    def _compute_ranking_factors(self):
        factor_totals = {name: {'score': 0, 'max': 0} for name in FACTOR_WEIGHTS}
        for cat, data in self.results['category_scores'].items():
            factor = CATEGORY_TO_FACTOR.get(cat, 'technical')
            factor_totals[factor]['score'] += data['score']
            factor_totals[factor]['max'] += data['max']

        factors = {}
        weighted_total = 0.0
        for name, weight in FACTOR_WEIGHTS.items():
            data = factor_totals[name]
            pct = (data['score'] / data['max'] * 100) if data['max'] > 0 else 0.0
            factors[name] = {
                'score': data['score'],
                'max': data['max'],
                'pct': round(pct, 1),
                'weight': weight,
                'weighted': round(pct * weight, 2),
            }
            weighted_total += pct * weight

        self.results['ranking_factors'] = factors
        self.results['ranking_weighted_pct'] = round(weighted_total, 1)

    def _build_priority_actions(self):
        rank_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        prio_mult = {'critical': 3.0, 'high': 2.0, 'medium': 1.5, 'low': 1.0}
        actions = []

        for check in self.results['checks']:
            if check['passed']:
                continue
            lost = check['max_points'] - check['points']
            if lost <= 0:
                continue
            ratio = lost / max(1, check['max_points'])
            if lost >= 8 or ratio >= 0.7:
                priority = 'critical'
            elif lost >= 5 or ratio >= 0.5:
                priority = 'high'
            elif lost >= 2:
                priority = 'medium'
            else:
                priority = 'low'
            effort = 'low' if lost <= 3 else ('medium' if lost <= 7 else 'high')
            impact_score = round(lost * prio_mult[priority], 1)
            actions.append({
                'action': check['name'],
                'detail': (check.get('detail') or '')[:100],
                'priority': priority,
                'potential_gain': lost,
                'category': check.get('category', 'general'),
                'effort': effort,
                'impact_score': impact_score,
            })

        for penalty in self.results['penalties']:
            gain = penalty['penalty']
            actions.append({
                'action': penalty['rule'].replace('_', ' ').title(),
                'detail': penalty['detail'][:100],
                'priority': 'critical',
                'potential_gain': gain,
                'category': 'compliance',
                'effort': 'low',
                'impact_score': round(gain * prio_mult['critical'], 1),
            })

        actions.sort(key=lambda a: (rank_order.get(a['priority'], 3), -a.get('impact_score', 0)))
        self.results['priority_actions'] = actions[:14]

    def _build_strategy(self):
        strategies = []
        factors = self.results.get('ranking_factors', {})

        ordered = sorted(factors.items(), key=lambda kv: kv[1].get('pct', 0))
        for name, data in ordered[:2]:
            pct = data.get('pct', 100)
            if pct < 80:
                advice = FACTOR_ADVICE.get(name, 'Improve this ranking factor.')
                strategies.append(f"{name.capitalize()} factor at {pct:.0f}% - {advice}")

        if self.results.get('ai_readiness', 0) < 8:
            strategies.append("AI search: publish llms.txt, FAQ/HowTo schema, and concise question-answer sections to stay visible in AI answers.")
        if self.results.get('freshness', 0) < 6:
            strategies.append("Freshness: implement an editorial refresh calendar with dateModified markup so Googlebot sees regular updates.")
        eeat = self.results.get('eeat_breakdown', {})
        eeat_total = sum(v.get('score', 0) for v in eeat.values())
        if eeat_total < 10:
            strategies.append("E-E-A-T: build author biography pages with credentials, first-hand experience claims, and citation-rich sourcing.")
        if self.results.get('knowledge_graph', 0) < 5:
            strategies.append("Entity SEO: connect Organization/Person entities to Wikidata/Wikipedia and social profiles via sameAs.")

        visibility = self.results.get('search_visibility', 0)
        if visibility < 50:
            strategies.append(f"Search visibility is {visibility:.0f}% - prioritize featured snippet, PAA, and intent alignment fixes to lift SERP real estate.")
        intent = self.results.get('search_intent', '')
        alignment = self.results.get('intent_alignment', 0)
        if intent and alignment < 7:
            strategies.append(f"Intent: the page leans {intent} but alignment is only {alignment}/12 - rewrite headline elements and match the dominant SERP format.")
        gap = self.results.get('content_gap', {})
        if gap.get('missing_subtopics'):
            strategies.append(f"Content gaps: {len(gap['missing_subtopics'])} subtopics competitors cover are missing here - map them to new H2 sections or supporting pages.")
        if self.results.get('cannibalization', {}).get('issues'):
            strategies.append("Cannibalization: consolidate overlapping keyword targets so each URL owns one primary intent.")
        authority = self.results.get('topic_authority', 0)
        if authority < 60:
            strategies.append(f"Topic authority at {authority:.0f}% - build a hub-and-spoke cluster with sourced citations to compound rankings.")
        pos = self.results.get('competitive_position', {})
        if pos.get('label') in ('Competitor', 'Follower'):
            strategies.append("Competitive position: win long-tail intent clusters first, then graduate to head terms once authority catches up.")

        tech_health = self.results.get('technical_health', {})
        tech_pct = float(tech_health.get('pct', 0) or 0)
        if tech_pct and tech_pct < 75:
            strategies.append(f"Technical health is {tech_pct:.0f}% (grade {tech_health.get('grade', 'C')}) - clear failing technical, performance, and mobile checks; they cap every other gain.")

        ranking_pot = self.results.get('ranking_potential', {})
        rp_value = float(ranking_pot.get('potential', 0) or 0)
        if rp_value and rp_value < 60:
            limiting = ranking_pot.get('limiting_factors', [])
            limit_txt = (", ".join(limiting[:3]) if limiting else 'ranking factors')
            strategies.append(f"Ranking potential is {rp_value:.0f}% ({ranking_pot.get('label', 'Moderate')}) - lift the weakest inputs first: {limit_txt}.")

        competitiveness = self.results.get('content_competitiveness', {})
        comp_value = float(competitiveness.get('score', 0) or 0)
        if comp_value and comp_value < 55:
            strategies.append(f"Content competitiveness is {comp_value:.0f}% ({competitiveness.get('label', 'Developing')}) - close depth/coverage gaps and resolve cannibalization before scaling production.")

        voice_deep = self.results.get('voice_search_deep', {})
        if voice_deep and int(voice_deep.get('score', 0)) < 6:
            strategies.append("Voice deep: add speakable FAQ schema, conversational long-tail phrasing, and 8-22 word answer sentences for assistant queries.")

        visual = self.results.get('visual_search', {})
        if visual and int(visual.get('score', 0)) < 6:
            strategies.append("Visual search: ship descriptive alt text, WebP/AVIF formats, srcset, captions, and ImageObject markup for Google Lens discovery.")

        vid_snip = self.results.get('video_featured_snippet', {})
        if vid_snip.get('applicable') and int(vid_snip.get('score', 0)) < 6:
            strategies.append("Video snippets: add Clip/key-moments markup, transcript, timestamps, and duration so videos can win key-moment SERP placements.")

        img_snip = self.results.get('image_featured_snippet', {})
        if img_snip.get('applicable') and int(img_snip.get('score', 0)) < 6:
            strategies.append("Image snippets: place captioned, dimensioned images under question headings to compete for image pack and carousel slots.")

        local = self.results.get('local_pack', {})
        if local.get('applicable') and int(local.get('score', 0)) < 6:
            strategies.append("Local pack: complete LocalBusiness NAP data, geo coordinates, hours, reviews, and a maps embed to compete in local results.")

        if len(self.results.get('category_scores', {})) > 0:
            weakest_cat = None
            weakest_pct = 101
            for cat, data in self.results['category_scores'].items():
                if data['max'] <= 0:
                    continue
                pct = data['score'] / data['max'] * 100
                if pct < weakest_pct:
                    weakest_pct = pct
                    weakest_cat = cat
            if weakest_cat and weakest_pct < 60:
                strategies.append(f"Raise the weakest category ({weakest_cat}, {weakest_pct:.0f}%) with a focused remediation sprint before scaling content production.")
        strategies.append("Compound gains: review this dashboard monthly, track ranking-factor percentages, and re-run after each major site change.")

        seen = set()
        unique = []
        for s in strategies:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        self.results['strategy'] = unique[:10]

    def _print_health_dashboard(self):
        score = self.results['score']
        max_score = self.results['max_score']
        final_score = self.results.get('final_score', score)
        pct = (final_score / max_score * 100) if max_score > 0 else 0
        grade_letter, _, _ = self._get_grade(pct)
        factors = self.results.get('ranking_factors', {})

        print()
        print(f"    +================================================================+")
        print(f"    |{Fore.WHITE}{Style.BRIGHT}                 SEO HEALTH DASHBOARD (v8.0){Style.RESET_ALL}                     |")
        print(f"    +----------------------------------------------------------------+")

        bar = self._gauge(pct)
        color = self._pct_color(pct)
        print(f"    | OVERALL   {color}{bar}{Style.RESET_ALL} {pct:3.0f}%  Grade {grade_letter}")

        sv = float(self.results.get('search_visibility', 0) or 0)
        sv_bar = self._gauge(sv)
        sv_color = self._pct_color(sv)
        print(f"    | VISIBILITY{sv_color}{sv_bar}{Style.RESET_ALL} {sv:3.0f}%  Search Visibility")

        rp = self.results.get('ranking_potential', {})
        rp_pct = float(rp.get('potential', 0) or 0)
        rp_label = str(rp.get('label', 'n/a'))[:10]
        print(f"    | POTENTIAL {self._pct_color(rp_pct)}{self._gauge(rp_pct)}{Style.RESET_ALL} {rp_pct:3.0f}%  Ranking Potential")

        th = self.results.get('technical_health', {})
        th_pct = float(th.get('pct', 0) or 0)
        th_grade = str(th.get('grade', '-'))
        print(f"    | TECHNICAL {self._pct_color(th_pct)}{self._gauge(th_pct)}{Style.RESET_ALL} {th_pct:3.0f}%  Health Grade {th_grade}")

        cc = self.results.get('content_competitiveness', {})
        cc_pct = float(cc.get('score', 0) or 0)
        cc_label = str(cc.get('label', 'n/a'))[:10]
        print(f"    | COMPETE   {self._pct_color(cc_pct)}{self._gauge(cc_pct)}{Style.RESET_ALL} {cc_pct:3.0f}%  Content ({cc_label})")

        ta = float(self.results.get('topic_authority', 0) or 0)
        ta_color = self._pct_color(ta)
        intent = str(self.results.get('search_intent', 'unknown'))
        print(f"    | Intent: {Fore.YELLOW}{intent:<16}{Style.RESET_ALL} Topic Authority: {ta_color}{ta:.0f}%{Style.RESET_ALL}")

        factor_order = ['content', 'links', 'technical', 'ux']
        for fname in factor_order:
            data = factors.get(fname)
            if not data:
                continue
            fpct = data.get('pct', 0)
            fbar = self._gauge(fpct)
            fcolor = self._pct_color(fpct)
            weight = data.get('weight', 0)
            print(f"    | {fname.upper():<9} {fcolor}{fbar}{Style.RESET_ALL} {fpct:3.0f}%  (weight {weight:.0%})")

        w = self.results.get('ranking_weighted_pct', 0)
        wcolor = self._pct_color(w)
        print(f"    | Weighted SEO score: {wcolor}{w:.1f}%{Style.RESET_ALL}")
        print(f"    +================================================================+")

    def _print_priority_actions(self):
        actions = self.results.get('priority_actions', [])
        if not actions:
            return
        print(f"    |{Fore.WHITE}{Style.BRIGHT}                   PRIORITY ACTION ITEMS{Style.RESET_ALL}                     |")
        print(f"    |{'-'*70}|")
        shown = 0
        for act in actions:
            if shown >= 10:
                break
            pcolor = Fore.RED if act['priority'] in ('critical', 'high') else Fore.YELLOW
            tag = '[' + act['priority'].upper() + ']'
            gain = '+' + str(act['potential_gain']) + ' pts'
            effort = act.get('effort', 'med')[:1]
            title = act['action'][:30]
            print(f"    | {pcolor}{tag:<10}{Style.RESET_ALL} {title:<30} {Fore.GREEN}{gain:<8}{Style.RESET_ALL} Eff:{effort} |")
            if act['detail']:
                print(f"    |    {Fore.CYAN}{act['detail'][:62]:<62}{Style.RESET_ALL} |")
            shown += 1
        remaining = len(actions) - shown
        if remaining > 0:
            print(f"    | {Fore.CYAN}... and {remaining} more actions in the JSON/HTML report{Style.RESET_ALL} |")
        print(f"    +================================================================+")

    def _print_strategy(self):
        strategy = self.results.get('strategy', [])
        if not strategy:
            return
        print(f"    |{Fore.WHITE}{Style.BRIGHT}              LONG-TERM STRATEGY RECOMMENDATIONS{Style.RESET_ALL}                 |")
        print(f"    |{'-'*70}|")
        for i, item in enumerate(strategy[:10], 1):
            words = item.split()
            lines = []
            current = ''
            for word in words:
                candidate = (current + ' ' + word).strip()
                if len(candidate) > 64 and current:
                    lines.append(current)
                    current = word
                else:
                    current = candidate
            if current:
                lines.append(current)
            for line_i, chunk in enumerate(lines):
                if line_i == 0:
                    print(f"    | {Fore.YELLOW}{i}.{Style.RESET_ALL} {chunk}")
                else:
                    print(f"    |    {chunk}")
        print(f"    +================================================================+")

    def fetch_page(self, url=None, silent=False):
        target = url or self.url
        if not silent:
            print(f"\n    {Fore.YELLOW}[*] Fetching {target}...{Style.RESET_ALL}")
        try:
            start = time.time()
            self.response = requests.get(target, headers=self.headers, timeout=self.timeout, allow_redirects=True, verify=True)
            load_time = time.time() - start
            if not url:
                self.results['load_time'] = round(load_time, 2)
                self.results['status_code'] = self.response.status_code
                self.results['final_url'] = self.response.url
                self.results['content_length'] = len(self.response.content)
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
                self.page_text = self.soup.get_text(separator=' ', strip=True)
            print(f"    {Fore.GREEN}[+] Status: {self.response.status_code} | Size: {len(self.response.content):,} bytes | Time: {load_time:.2f}s{Style.RESET_ALL}")
            return True
        except requests.exceptions.SSLError:
            if not silent:
                print(f"    {Fore.RED}[-] SSL certificate error{Style.RESET_ALL}")
            return False
        except requests.exceptions.ConnectionError:
            if not silent:
                print(f"    {Fore.RED}[-] Connection failed{Style.RESET_ALL}")
            return False
        except requests.exceptions.Timeout:
            if not silent:
                print(f"    {Fore.RED}[-] Request timed out{Style.RESET_ALL}")
            return False
        except Exception as e:
            if not silent:
                print(f"    {Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
            return False

    def check_ssl(self):
        is_ssl = self.url.startswith('https://')
        self._add_check("SSL/HTTPS", is_ssl, 10 if is_ssl else 0, 10,
                        "Site uses HTTPS" if is_ssl else "Site does NOT use HTTPS - security risk!",
                        category='security')

    def check_title(self):
        title_tag = self.soup.find('title')
        if title_tag and title_tag.string:
            title = title_tag.string.strip()
            length = len(title)
            passed = 30 <= length <= 60
            points = 10 if passed else (5 if 20 <= length <= 70 else 0)
            detail = f"'{title[:50]}...' ({length} chars)" if length > 50 else f"'{title}' ({length} chars)"
            if not passed:
                if length < 30:
                    detail += " - Too short! Aim for 30-60 chars"
                    self._add_quick_win("Shorten title to 30-60 chars", f"Current title is {length} chars. Aim for 30-60 for optimal search display.", 'medium')
                else:
                    detail += " - Too long! Aim for 30-60 chars"
                    self._add_quick_win("Shorten title to 60 chars max", f"Current title is {length} chars. Search engines may truncate it.", 'medium')
            self._add_check("Title Tag", passed, points, 10, detail, category='meta')
        else:
            self._add_check("Title Tag", False, 0, 10, "No title tag found!", category='meta')
            self._add_quick_win("Add a title tag", "No <title> tag found. This is critical for SEO.", 'high')

    def check_meta_description(self):
        meta = self.soup.find('meta', attrs={'name': 'description'})
        if meta and meta.get('content'):
            desc = meta['content'].strip()
            length = len(desc)
            passed = 120 <= length <= 160
            points = 10 if passed else (5 if 80 <= length <= 200 else 0)
            detail = f"'{desc[:60]}...' ({length} chars)"
            if not passed:
                if length < 120:
                    detail += " - Too short! Aim for 120-160 chars"
                    self._add_quick_win("Expand meta description", f"Current description is {length} chars. Aim for 120-160 to maximize CTR.", 'high')
                else:
                    detail += " - Too long! Aim for 120-160 chars"
            self._add_check("Meta Description", passed, points, 10, detail, category='meta')
        else:
            self._add_check("Meta Description", False, 0, 10, "No meta description found!", category='meta')
            self._add_quick_win("Add meta description", "No meta description found. This directly impacts click-through rate.", 'high')

    def check_meta_keywords(self):
        meta = self.soup.find('meta', attrs={'name': 'keywords'})
        if meta and meta.get('content'):
            keywords = meta['content'].strip()
            count = len([k for k in keywords.split(',') if k.strip()])
            passed = 3 <= count <= 10
            self._add_check("Meta Keywords", passed, 5 if passed else 2, 5, f"{count} keywords found", category='meta')
        else:
            self._add_check("Meta Keywords", False, 0, 5, "No meta keywords found (optional but recommended)", category='meta')

    def check_headings(self):
        headings = {}
        for i in range(1, 7):
            tags = self.soup.find_all(f'h{i}')
            if tags:
                headings[f'h{i}'] = len(tags)

        h1_count = headings.get('h1', 0)
        has_h1 = h1_count == 1
        has_any = len(headings) > 0
        points = 0
        max_pts = 15

        if has_h1:
            points += 10
        elif h1_count > 1:
            points += 3
        if has_any:
            points += 5

        detail_parts = []
        for h, c in sorted(headings.items()):
            detail_parts.append(f"{h}:{c}")
        detail = ", ".join(detail_parts) if detail_parts else "No headings found"

        if h1_count == 0:
            detail += " - Missing H1!"
            self._add_quick_win("Add an H1 tag", "No H1 found. Each page should have exactly one H1.", 'high')
        elif h1_count > 1:
            detail += " - Multiple H1s! Use only one"

        self._add_check("Heading Structure", has_h1, min(points, max_pts), max_pts, detail, category='content')

    def check_images(self):
        images = self.soup.find_all('img')
        total = len(images)
        with_alt = sum(1 for img in images if img.get('alt'))
        without_alt = total - with_alt
        self.all_images = images

        if total == 0:
            self._add_check("Image Alt Text", False, 0, 10, "No images found on page", category='content')
            return

        passed = without_alt == 0
        points = int((with_alt / total) * 10)
        detail = f"{with_alt}/{total} images have alt text"
        if without_alt > 0:
            detail += f" ({without_alt} missing!)"
            self._add_quick_win(f"Add alt text to {without_alt} images", "Missing alt text hurts accessibility and image SEO.", 'high')
        self._add_check("Image Alt Text", passed, points, 10, detail, category='content')

    def check_image_seo(self):
        images = self.soup.find_all('img')
        if not images:
            self._add_check("Image SEO", False, 0, 10, "No images to analyze", category='content')
            return

        total = len(images)
        issues = []
        good = 0

        for img in images:
            src = img.get('src', '') or img.get('data-src', '')
            alt = img.get('alt', '')
            width = img.get('width', '')
            height = img.get('height', '')
            loading = img.get('loading', '')

            img_ok = True
            if alt and len(alt.strip()) > 0:
                good += 1
            else:
                img_ok = False

            if src:
                parsed_src = urlparse(src)
                filename = parsed_src.path.split('/')[-1].lower() if parsed_src.path else ''
                if filename and re.match(r'^[a-z0-9_-]+\.[a-z]+$', filename):
                    good += 1
                elif filename and re.match(r'^img[_-]?\d+\.[a-z]+$', filename):
                    issues.append(f"Generic filename: {filename}")

            if loading == 'lazy':
                good += 1

        points = min(10, good // max(1, total) * 10)
        detail = f"Analyzed {total} images"
        if issues:
            detail += f" | Issues: {'; '.join(issues[:3])}"
        self._add_check("Image SEO", points >= 7, points, 10, detail, category='content')

    def check_links(self):
        links = self.soup.find_all('a', href=True)
        internal = 0
        external = 0
        nofollow = 0
        empty = 0
        base_domain = urlparse(self.url).netloc

        for link in links:
            href = link['href'].strip()
            if not href or href.startswith('#') or href.startswith('javascript:'):
                empty += 1
                continue
            full_url = urljoin(self.url, href)
            link_domain = urlparse(full_url).netloc
            if link_domain == base_domain:
                internal += 1
                self.internal_links.append(full_url)
            else:
                external += 1
                self.external_links.append(full_url)
            if link.get('rel') and 'nofollow' in link.get('rel', []):
                nofollow += 1
            anchor_text = link.get_text(strip=True)
            if anchor_text:
                self.anchor_texts.append(anchor_text)

        total = internal + external
        passed = total > 0 and internal > 0
        points = 0
        if internal > 0:
            points += 5
        if external > 0:
            points += 2
        if nofollow == 0:
            points += 3

        self._add_check("Internal Links", internal > 0, 5 if internal > 0 else 0, 5,
                        f"{internal} internal links found", category='links')
        if internal == 0:
            self._add_quick_win("Add internal links", "No internal links found. Internal linking helps SEO.", 'high')
        self._add_check("External Links", True, 2 if external > 0 else 1, 3,
                        f"{external} external links, {nofollow} nofollow", category='links')

        self.all_links_raw = links
        if len(self.external_links) > 100:
            self._add_penalty('link_stuffing', f"Found {len(self.external_links)} outbound links on one page")

    def check_internal_link_structure(self):
        if not self.internal_links:
            self._add_check("Internal Link Structure", False, 0, 8, "No internal links found", category='links')
            return

        unique_internal = set(self.internal_links)
        depth_analysis = {}
        base_path = urlparse(self.url).path

        for link in unique_internal:
            parsed = urlparse(link)
            link_path = parsed.path
            depth = len([p for p in link_path.split('/') if p])
            depth_analysis[depth] = depth_analysis.get(depth, 0) + 1

        shallow = sum(v for k, v in depth_analysis.items() if k <= 1)
        medium = sum(v for k, v in depth_analysis.items() if 2 <= k <= 2)
        deep = sum(v for k, v in depth_analysis.items() if k > 2)

        points = 0
        if shallow > 0:
            points += 3
        if medium > 0:
            points += 3
        if deep > 0:
            points += 2

        detail = f"{len(unique_internal)} unique internal links | Shallow:{shallow} Medium:{medium} Deep:{deep}"
        self._add_check("Internal Link Structure", points >= 5, min(points, 8), 8, detail, category='links')

    def check_anchor_text_distribution(self):
        if not self.anchor_texts:
            self._add_check("Anchor Text Distribution", False, 0, 5, "No anchor text to analyze", category='links')
            return

        counter = Counter(self.anchor_texts)
        total = len(self.anchor_texts)
        top = counter.most_common(5)

        generic = sum(1 for t in self.anchor_texts if t.lower() in ('click here', 'here', 'read more', 'more', 'link', 'this'))
        generic_pct = generic / total * 100 if total > 0 else 0

        points = 5
        if generic_pct > 30:
            points -= 3
        elif generic_pct > 15:
            points -= 1

        detail = f"{total} anchor texts | Top: {', '.join([f'{t[:20]}({c})' for t, c in top[:3]])}"
        if generic_pct > 15:
            detail += f" | {generic_pct:.0f}% generic anchors"
        self._add_check("Anchor Text Distribution", points >= 3, points, 5, detail, category='links')

    def check_outbound_link_quality(self):
        if not self.external_links:
            self._add_check("Outbound Link Quality", True, 5, 5, "No outbound links (neutral)", category='links')
            return

        suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.buzz', '.click']
        suspicious_count = 0
        for link in self.external_links[:30]:
            parsed = urlparse(link)
            if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
                suspicious_count += 1

        points = 5
        if suspicious_count > 0:
            points -= min(3, suspicious_count)

        detail = f"{len(self.external_links)} outbound links"
        if suspicious_count > 0:
            detail += f" | {suspicious_count} potentially low-quality domains"
        self._add_check("Outbound Link Quality", points >= 3, points, 5, detail, category='links')

    def check_broken_links(self):
        if not self.check_links_enabled:
            return

        print(f"\n    {Fore.YELLOW}[*] Checking for broken links (this may take a moment)...{Style.RESET_ALL}")
        all_links = list(set(self.internal_links[:20] + self.external_links[:20]))
        broken = []

        def check_url(url):
            try:
                resp = requests.head(url, headers=self.headers, timeout=10, allow_redirects=True, verify=False)
                return (url, resp.status_code, resp.status_code >= 400)
            except:
                return (url, 0, True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_url, url): url for url in all_links}
            for future in concurrent.futures.as_completed(futures):
                url, status, is_broken_link = future.result()
                if is_broken_link:
                    broken.append((url, status))

        self.broken_links = broken
        if broken:
            detail = f"{len(broken)} broken links found!"
            for url, status in broken[:3]:
                detail += f"\n           {Fore.RED}{url[:60]} (HTTP {status}){Style.RESET_ALL}"
            self._add_check("Broken Links", False, 0, 10, detail, category='links')
            self._add_quick_win("Fix broken links", f"{len(broken)} broken links found. Fix or remove them.", 'high')
        else:
            self._add_check("Broken Links", True, 10, 10, f"All {len(all_links)} links are working", category='links')

    def check_og_tags(self):
        og_tags = ['og:title', 'og:description', 'og:image', 'og:url', 'og:type', 'og:site_name']
        found = []
        missing = []
        for tag in og_tags:
            if self.soup.find('meta', property=tag):
                found.append(tag)
            else:
                missing.append(tag)

        passed = len(found) >= 3
        points = int((len(found) / len(og_tags)) * 10)
        detail = f"{len(found)}/{len(og_tags)} Open Graph tags found"
        if missing:
            detail += f" (missing: {', '.join(missing[:3])})"
            if 'og:image' in missing:
                self._add_quick_win("Add og:image tag", "Missing og:image hurts social media sharing appearance.", 'medium')
        self._add_check("Open Graph Tags", passed, points, 10, detail, category='social')

    def check_twitter_card(self):
        twitter_tags = ['twitter:card', 'twitter:title', 'twitter:description', 'twitter:image', 'twitter:site']
        found = []
        missing = []
        for tag in twitter_tags:
            if self.soup.find('meta', attrs={'name': tag}):
                found.append(tag)
            else:
                missing.append(tag)

        passed = len(found) >= 2
        points = int((len(found) / len(twitter_tags)) * 5)
        detail = f"{len(found)}/{len(twitter_tags)} Twitter tags found"
        if missing:
            detail += f" (missing: {', '.join(missing[:3])})"
        self._add_check("Twitter Cards", passed, points, 5, detail, category='social')

    def check_social_media_completeness(self):
        og_tags = ['og:title', 'og:description', 'og:image', 'og:url', 'og:type', 'og:site_name']
        twitter_tags = ['twitter:card', 'twitter:title', 'twitter:description', 'twitter:image', 'twitter:site']

        og_found = sum(1 for t in og_tags if self.soup.find('meta', property=t))
        twitter_found = sum(1 for t in twitter_tags if self.soup.find('meta', attrs={'name': t}))

        total = len(og_tags) + len(twitter_tags)
        found = og_found + twitter_found
        points = int((found / total) * 8)

        detail = f"OG: {og_found}/{len(og_tags)} | Twitter: {twitter_found}/{len(twitter_tags)}"
        self._add_check("Social Media Meta Tags", found >= total * 0.5, points, 8, detail, category='social')

    def check_robots_meta(self):
        robots = self.soup.find('meta', attrs={'name': 'robots'})
        if robots:
            content = robots.get('content', '').lower()
            noindex = 'noindex' in content
            nofollow = 'nofollow' in content
            if noindex:
                self._add_check("Robots Meta", False, 0, 5, "Page has noindex - search engines won't index it!", category='technical')
            elif nofollow:
                self._add_check("Robots Meta", False, 2, 5, "Page has nofollow - link equity not passed", category='technical')
            else:
                self._add_check("Robots Meta", True, 5, 5, f"Robots: {content}", category='technical')
        else:
            self._add_check("Robots Meta", True, 5, 5, "No robots meta tag (defaults to index,follow)", category='technical')

    def check_canonical(self):
        canonical = self.soup.find('link', rel='canonical')
        if canonical and canonical.get('href'):
            self._add_check("Canonical URL", True, 5, 5, f"Canonical: {canonical['href'][:60]}", category='technical')
        else:
            self._add_check("Canonical URL", False, 0, 5, "No canonical URL set - may cause duplicate content issues", category='technical')

    def check_viewport(self):
        viewport = self.soup.find('meta', attrs={'name': 'viewport'})
        if viewport and viewport.get('content'):
            content = viewport['content']
            passed = 'width=device-width' in content
            self._add_check("Mobile Viewport", passed, 10 if passed else 0, 10,
                            f"Viewport: {content[:50]}", category='mobile')
        else:
            self._add_check("Mobile Viewport", False, 0, 10, "No viewport meta tag - site may not be mobile-friendly!", category='mobile')
            self._add_quick_win("Add viewport meta tag", "No viewport tag found. Essential for mobile SEO.", 'high')

    def check_lang(self):
        html_tag = self.soup.find('html')
        if html_tag and html_tag.get('lang'):
            lang = html_tag['lang']
            self._add_check("HTML Lang Attribute", True, 5, 5, f"Language: {lang}", category='technical')
        else:
            self._add_check("HTML Lang Attribute", False, 0, 5, "No lang attribute on <html> tag", category='technical')

    def check_favicon(self):
        favicon = self.soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        if favicon:
            self._add_check("Favicon", True, 3, 3, "Favicon found", category='technical')
        else:
            self._add_check("Favicon", False, 0, 3, "No favicon found", category='technical')

    def check_word_count(self):
        words = len(self.page_text.split())
        passed = words >= 300
        points = min(10, words // 100)
        self._add_check("Word Count", passed, points, 10, f"{words:,} words (aim for 300+)", category='content')

    def check_content_length_analysis(self):
        words = len(self.page_text.split())
        chars = len(self.page_text)

        if words < 300:
            length_grade = "Very Thin"
            detail = f"{words:,} words ({chars:,} chars) - Below minimum for competitive content"
            self._add_quick_win("Increase content length", f"Only {words} words. Competitive pages typically have 1,500+ words.", 'high')
        elif words < 800:
            length_grade = "Short"
            detail = f"{words:,} words ({chars:,} chars) - Below average for competitive topics"
        elif words < 1500:
            length_grade = "Moderate"
            detail = f"{words:,} words ({chars:,} chars) - Good baseline length"
        elif words < 3000:
            length_grade = "Comprehensive"
            detail = f"{words:,} words ({chars:,} chars) - Strong content depth"
        else:
            length_grade = "In-depth"
            detail = f"{words:,} words ({chars:,} chars) - Very thorough coverage"

        points = min(10, words // 300)
        self._add_check("Content Length Analysis", words >= 800, points, 10, f"{detail} [{length_grade}]", category='content')

    def check_page_size(self):
        size_kb = len(self.response.content) / 1024
        passed = size_kb < 500
        points = 10 if size_kb < 200 else (5 if size_kb < 500 else 0)
        detail = f"{size_kb:.1f} KB"
        if size_kb > 500:
            detail += " - Very large page! Aim for under 500KB"
            self._add_quick_win("Reduce page size", f"Page is {size_kb:.0f}KB. Aim for under 500KB.", 'medium')
        self._add_check("Page Size", passed, points, 10, detail, category='performance')

    def check_load_time(self):
        lt = self.results.get('load_time', 0)
        passed = lt < 3
        points = 10 if lt < 1 else (7 if lt < 2 else (4 if lt < 3 else 0))
        detail = f"{lt:.2f}s"
        if lt > 3:
            detail += " - Too slow! Aim for under 3s"
            self._add_quick_win("Improve page load time", f"Page loads in {lt:.1f}s. Aim for under 2s.", 'high')
        self._add_check("Load Time", passed, points, 10, detail, category='performance')

    def check_core_web_vitals(self):
        if not self.response:
            self._add_check("Core Web Vitals", False, 0, 12, "Cannot analyze - no page data", category='performance')
            return

        html_text = self.response.text
        html_size = len(html_text)

        render_blocking = len(re.findall(r'<link[^>]+rel=["\']stylesheet["\']', html_text, re.I))
        inline_css = len(re.findall(r'<style[^>]*>', html_text, re.I))

        scripts = re.findall(r'<script[^>]*>', html_text, re.I)
        sync_scripts = sum(1 for s in scripts if 'async' not in s.lower() and 'defer' not in s.lower())
        async_scripts = sum(1 for s in scripts if 'async' in s.lower() or 'defer' in s.lower())

        images = re.findall(r'<img[^>]+>', html_text, re.I)
        lazy_images = sum(1 for img in images if 'loading="lazy"' in img.lower() or 'data-src' in img.lower())
        total_images = len(images)

        lcp_elements = re.findall(r'<(?:img|video|div|section|header)[^>]+(?:src|poster|style)[^>]*>', html_text, re.I)

        layout_shift_risk = 0
        if re.search(r'<img[^>]+(?:width|height)\s*=', html_text, re.I):
            layout_shift_risk += 1
        if 'font-display:' in html_text and 'swap' in html_text:
            layout_shift_risk -= 1
        if re.search(r'aspect-ratio', html_text, re.I):
            layout_shift_risk -= 1

        fid_proxy = sync_scripts + (html_size // 50000)

        points = 12
        lcp_score = 0
        fid_score = 0
        cls_score = 0

        if render_blocking <= 1:
            lcp_score = 4
        elif render_blocking <= 3:
            lcp_score = 2
            points -= 1
        else:
            lcp_score = 0
            points -= 2

        if sync_scripts <= 2:
            fid_score = 4
        elif sync_scripts <= 5:
            fid_score = 2
            points -= 1
        else:
            fid_score = 0
            points -= 2

        if layout_shift_risk <= 0:
            cls_score = 4
        elif layout_shift_risk <= 1:
            cls_score = 2
            points -= 1
        else:
            cls_score = 0
            points -= 2

        detail_parts = []
        detail_parts.append(f"Render-blocking: {render_blocking}")
        detail_parts.append(f"Sync scripts: {sync_scripts}")
        detail_parts.append(f"Lazy images: {lazy_images}/{total_images}")
        detail_parts.append(f"Layout risk: {'Good' if layout_shift_risk <= 0 else 'Fair' if layout_shift_risk <= 1 else 'Poor'}")

        detail = " | ".join(detail_parts)
        self._add_check("Core Web Vitals Est.", points >= 8, max(0, points), 12, detail, category='performance')

        if points >= 10:
            self._add_bonus('core_web_vitals_good', "Core Web Vitals estimates look good")

    def check_url_structure(self):
        parsed = urlparse(self.url)
        path = parsed.path
        has_clean_path = '/' in path and len(path) < 100
        no_underscores = '_' not in path
        short_path = len(path) < 50
        points = (5 if has_clean_path else 0) + (2 if no_underscores else 0) + (3 if short_path else 0)
        detail = f"Path: {path[:50]}" if path else "Root URL"
        self._add_check("URL Structure", points >= 7, points, 10, detail, category='technical')

    def check_content_quality(self):
        text = self.page_text.lower()
        issues = []
        points = 10

        if len(text) < 100:
            issues.append("Very thin content")
            points -= 5
            self._add_penalty('doorway_pages', "Page has very thin content (<100 chars)")

        paragraphs = self.soup.find_all('p')
        if len(paragraphs) < 3:
            issues.append(f"Only {len(paragraphs)} paragraphs")
            points -= 3

        text_length = len(self.page_text)
        if text_length > 0:
            html_length = len(self.response.text)
            text_ratio = text_length / html_length if html_length > 0 else 0
            if text_ratio < 0.1:
                issues.append("Low text-to-HTML ratio")
                points -= 2

        detail = "; ".join(issues) if issues else "Content structure looks good"
        self._add_check("Content Quality", points >= 7, max(0, points), 10, detail, category='content')

    def check_structured_data(self):
        json_ld = self.soup.find_all('script', type='application/ld+json')
        microdata = self.soup.find_all(attrs={'itemtype': True})

        found_types = []
        schema_details = []
        for script in json_ld:
            try:
                data = json.loads(script.string)
                if isinstance(data, dict) and '@type' in data:
                    found_types.append(data['@type'])
                    schema_details.append(data)
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and '@type' in item:
                            found_types.append(item['@type'])
                            schema_details.append(item)
            except:
                pass

        for item in microdata:
            itemtype = item.get('itemtype', '')
            if itemtype:
                found_types.append(itemtype.split('/')[-1])

        self.schema_data = schema_details

        if found_types:
            detail = f"Found: {', '.join(found_types[:5])}"
            passed = len(found_types) >= 1
            self._add_check("Structured Data", passed, 10 if passed else 5, 10, detail, category='technical')
            if len(found_types) >= 2:
                self._add_bonus('structured_data_rich', f"Found {len(found_types)} structured data types")
        else:
            self._add_check("Structured Data", False, 0, 10, "No structured data (JSON-LD/Microdata) found", category='technical')

    def check_schema_validation(self):
        if not self.schema_data:
            self._add_check("Schema Validation", False, 0, 8, "No schema data to validate", category='technical')
            return

        valid = 0
        issues = []
        for schema in self.schema_data:
            schema_type = schema.get('@type', 'Unknown')
            if '@context' in schema:
                valid += 1
            else:
                issues.append(f"{schema_type} missing @context")
            if schema_type == 'Article' or schema_type == 'BlogPosting':
                if not schema.get('headline') and not schema.get('name'):
                    issues.append(f"{schema_type} missing headline/name")
            if schema_type == 'Product':
                if not schema.get('name'):
                    issues.append("Product missing name")
            if schema_type == 'LocalBusiness':
                if not schema.get('address') and not schema.get('telephone'):
                    issues.append("LocalBusiness missing address/telephone")

        points = min(8, valid * 4)
        detail = f"{valid}/{len(self.schema_data)} schemas valid"
        if issues:
            detail += f" | Issues: {'; '.join(issues[:3])}"
        self._add_check("Schema Validation", points >= 4, points, 8, detail, category='technical')

    def check_sitemap(self):
        base_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}"
        sitemap_urls = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.txt']
        found = False
        sitemap_content = None

        for sitemap_path in sitemap_urls:
            try:
                resp = requests.get(f"{base_url}{sitemap_path}", headers=self.headers, timeout=10, verify=False)
                if resp.status_code == 200 and ('<?xml' in resp.text[:100] or '<urlset' in resp.text[:500]):
                    found = True
                    sitemap_content = resp.text
                    break
            except:
                pass

        if found:
            url_count = sitemap_content.count('<loc>')
            detail = f"Sitemap found with {url_count} URLs"
            self._add_check("XML Sitemap", True, 10, 10, detail, category='technical')
        else:
            self._add_check("XML Sitemap", False, 0, 10, "No XML sitemap found at standard locations", category='technical')

    def check_robots_txt(self):
        base_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}"
        try:
            resp = requests.get(f"{base_url}/robots.txt", headers=self.headers, timeout=10, verify=False)
            if resp.status_code == 200 and ('user-agent' in resp.text.lower() or 'disallow' in resp.text.lower()):
                self.robots_txt_content = resp.text
                has_sitemap = 'sitemap:' in resp.text.lower()
                has_disallow = 'disallow:' in resp.text.lower()
                detail = "Found robots.txt"
                if has_sitemap:
                    detail += " with Sitemap directive"
                if has_disallow:
                    detail += " with Disallow rules"
                self._add_check("robots.txt", True, 5, 5, detail, category='technical')
            else:
                self.robots_txt_content = resp.text if resp.status_code == 200 else ''
                self._add_check("robots.txt", False, 0, 5, "No valid robots.txt found", category='technical')
        except:
            self._add_check("robots.txt", False, 0, 5, "Could not fetch robots.txt", category='technical')

    def check_https_redirect(self):
        if self.url.startswith('https://'):
            http_url = self.url.replace('https://', 'http://', 1)
            try:
                resp = requests.get(http_url, headers=self.headers, timeout=10, allow_redirects=False, verify=False)
                if resp.status_code in (301, 302, 307, 308):
                    redirect_url = resp.headers.get('Location', '')
                    if redirect_url.startswith('https://'):
                        self._add_check("HTTPS Redirect", True, 5, 5, "HTTP properly redirects to HTTPS", category='security')
                    else:
                        self._add_check("HTTPS Redirect", False, 2, 5, f"Redirects to: {redirect_url[:50]}", category='security')
                else:
                    self._add_check("HTTPS Redirect", False, 0, 5, "HTTP does not redirect to HTTPS", category='security')
            except:
                self._add_check("HTTPS Redirect", True, 5, 5, "Could not test (HTTPS is active)", category='security')
        else:
            self._add_check("HTTPS Redirect", False, 0, 5, "Site not using HTTPS", category='security')

    def check_readability(self):
        sentences = re.split(r'[.!?]+', self.page_text)
        sentences = [s.strip() for s in sentences if s.strip() and len(s.strip()) > 5]
        words = self.page_text.split()

        if not words or not sentences:
            self._add_check("Readability Score", False, 0, 10, "Insufficient text for analysis", category='content')
            return

        avg_words_per_sentence = len(words) / max(1, len(sentences))
        total_syllables = 0
        sample_size = min(200, len(words))
        for word in words[:sample_size]:
            word_lower = word.lower().strip('.,!?;:')
            syllables = max(1, len(re.findall(r'[aeiouy]+', word_lower)))
            total_syllables += syllables
        avg_syllables_per_word = total_syllables / max(1, sample_size)

        asl = avg_words_per_sentence
        asw = avg_syllables_per_word
        fre = 206.835 - 1.015 * asl - 84.6 * asw
        fre = max(0, min(100, fre))

        if fre >= 60:
            level = "Easy (6th grade)"
            passed = True
            points = 10
            self._add_bonus('reading_level_good', "Easy reading level for broad audience")
        elif fre >= 40:
            level = "Standard (8th grade)"
            passed = True
            points = 7
        elif fre >= 20:
            level = "Difficult (High school)"
            passed = False
            points = 4
        else:
            level = "Very Difficult (College)"
            passed = False
            points = 1

        self._add_check("Readability Score", passed, points, 10,
                        f"Flesch Reading Ease: {fre:.1f} - {level}", category='content')

    def check_keyword_density(self):
        words = self.page_text.lower().split()
        words = [w.strip('.,!?;:"()[]{}') for w in words if len(w) > 3]
        word_freq = Counter(words)
        total_words = len(words)

        if total_words < 10:
            self._add_check("Keyword Density", False, 0, 5, "Insufficient text", category='content')
            return

        stop_words = {'this', 'that', 'with', 'from', 'have', 'been', 'were', 'they', 'their', 'what',
                      'will', 'would', 'could', 'should', 'about', 'which', 'when', 'where', 'there',
                      'here', 'than', 'them', 'then', 'some', 'more', 'also', 'just', 'only', 'very',
                      'into', 'over', 'such', 'your', 'does', 'most', 'other', 'each', 'make', 'like',
                      'does', 'been', 'being', 'having', 'doing', 'these', 'those', 'every', 'both'}
        top_words = word_freq.most_common(10)
        content_words = [(w, c) for w, c in top_words if w not in stop_words][:5]

        if content_words:
            densities = []
            stuffing_detected = False
            for w, c in content_words:
                density = c / total_words * 100
                densities.append(f"{w} ({c}, {density:.1f}%)")
                if density > 5:
                    stuffing_detected = True

            detail = "Top keywords: " + ", ".join(densities)
            if stuffing_detected:
                detail += " | WARNING: Possible keyword stuffing!"
                self._add_penalty('keyword_stuffing', "One or more keywords exceed 5% density")
                self._add_quick_win("Reduce keyword density", "One or more keywords appear excessively. Use synonyms and natural language.", 'high')

            self._add_check("Keyword Density", True, 5, 5, detail, category='content')
        else:
            self._add_check("Keyword Density", False, 0, 5, "No significant keywords found", category='content')

    def check_html_validation(self):
        validator = HTMLValidator()
        try:
            validator.feed(self.response.text)
        except:
            pass

        results = validator.get_results()
        if results['errors']:
            detail = f"{len(results['errors'])} errors found"
            for err in results['errors'][:3]:
                detail += f"\n           {err}"
            self._add_check("HTML Validation", False, 0, 5, detail, category='technical')
        elif results['warnings']:
            self._add_check("HTML Validation", True, 3, 5,
                           f"{len(results['warnings'])} warnings, {results['tag_count']} tags", category='technical')
        else:
            self._add_check("HTML Validation", True, 5, 5,
                           f"Clean HTML ({results['tag_count']} tags)", category='technical')

    def check_hreflang(self):
        hreflang_tags = self.soup.find_all('link', rel='alternate', hreflang=True)
        if hreflang_tags:
            langs = [tag.get('hreflang', '') for tag in hreflang_tags]
            detail = f"Found: {', '.join(langs[:5])}"
            self._add_check("Hreflang Tags", True, 5, 5, detail, category='technical')
        else:
            self._add_check("Hreflang Tags", False, 0, 5, "No hreflang tags found", category='technical')

    def check_accelerated_mobile(self):
        amp_link = self.soup.find('link', rel='amphtml')
        if amp_link:
            self._add_check("AMP Page", True, 5, 5, "AMP version available", category='mobile')
        else:
            self._add_check("AMP Page", False, 0, 5, "No AMP version found (optional)", category='mobile')

    def check_mobile_first_indexing(self):
        score = 0
        issues = []
        good = []

        viewport = self.soup.find('meta', attrs={'name': 'viewport'})
        if viewport and 'width=device-width' in viewport.get('content', ''):
            score += 3
            good.append("viewport set")
        else:
            issues.append("missing viewport")

        responsive_css = bool(re.search(r'@media\s*\(', self.response.text, re.I))
        if responsive_css:
            score += 2
            good.append("responsive CSS")
        else:
            issues.append("no @media queries found")

        tap_targets = len(re.findall(r'touch-action|tap-highlight|pointer-events', self.response.text, re.I))
        if tap_targets > 0:
            score += 1
            good.append("touch handling")

        mobile_meta = self.soup.find('meta', attrs={'name': 'format-detection'})
        score += 1

        font_sizes = re.findall(r'font-size:\s*(\d+)', self.response.text, re.I)
        small_fonts = sum(1 for fs in font_sizes if int(fs) < 12)
        if small_fonts == 0:
            score += 1
            good.append("good font sizes")
        else:
            issues.append(f"{small_fonts} small font declarations")

        points = min(8, score)
        detail = f"Score: {points}/8"
        if good:
            detail += f" | Good: {', '.join(good[:3])}"
        if issues:
            detail += f" | Issues: {', '.join(issues[:3])}"

        self._add_check("Mobile-First Readiness", points >= 5, points, 8, detail, category='mobile')
        if points >= 6:
            self._add_bonus('mobile_optimized', "Mobile optimization indicators are good")

    def check_voice_search_optimization(self):
        score = 0
        features = []

        faq_schema = False
        for schema in self.schema_data:
            if schema.get('@type') in ('FAQPage', 'FAQ'):
                faq_schema = True
                break
        if faq_schema:
            score += 3
            features.append("FAQ schema")
            self._add_bonus('faq_schema', "FAQ schema found - boosts voice search")

        howto_schema = False
        for schema in self.schema_data:
            if schema.get('@type') in ('HowTo',):
                howto_schema = True
                break
        if howto_schema:
            score += 2
            features.append("HowTo schema")
            self._add_bonus('howto_schema', "HowTo schema found")

        question_headings = len(re.findall(r'<h[1-6][^>]*>.*\?</h[1-6]>', self.response.text, re.I | re.S))
        if question_headings > 0:
            score += 2
            features.append(f"{question_headings} question headings")

        sentences = re.split(r'[.!?]+', self.page_text)
        short_sentences = sum(1 for s in sentences if 10 < len(s.strip().split()) < 20)
        if len(sentences) > 0 and short_sentences / max(1, len(sentences)) > 0.5:
            score += 1
            features.append("natural language")

        schema_org = self.soup.find_all('script', type='application/ld+json')
        if schema_org:
            score += 1
            features.append("structured data present")

        points = min(8, score)
        detail = f"Score: {points}/8"
        if features:
            detail += f" | Features: {', '.join(features)}"
        else:
            detail += " | No voice search optimization detected"

        self._add_check("Voice Search SEO", points >= 3, points, 8, detail, category='voice')

    def check_voice_search_deep_analysis(self):
        score = 0
        signals = []
        text_lower = self.page_text.lower()
        words = len(self.page_text.split())

        question_openers = ['how to', 'how do', 'how can', 'what is', 'what are',
                            'why is', 'why do', 'when should', 'where can',
                            'which is the best', 'who is', 'what makes']
        opener_hits = sum(1 for q in question_openers if q in text_lower)
        if opener_hits >= 6:
            score += 3
            signals.append(f"{opener_hits} question openers")
        elif opener_hits >= 3:
            score += 2
            signals.append(f"{opener_hits} question openers")
        elif opener_hits >= 1:
            score += 1
            signals.append("question openers present")

        sentences = [s.strip() for s in re.split(r'[.!?]+', self.page_text) if s.strip()]
        speakable = sum(1 for s in sentences if 8 <= len(s.split()) <= 22)
        if sentences and speakable / len(sentences) >= 0.5:
            score += 2
            signals.append(f"{speakable} speakable sentences (8-22 words)")
        elif sentences and speakable / len(sentences) >= 0.3:
            score += 1
            signals.append("some speakable sentences")

        definition_count = len(re.findall(r'\b[\w\s-]{2,40}\s+is\s+(?:a|an|the)\s+', text_lower))
        if definition_count >= 5:
            score += 2
            signals.append(f"{definition_count} definition patterns")
        elif definition_count >= 2:
            score += 1
            signals.append("definition patterns present")

        speakable_schema = any('speakable' in s for s in self.schema_data)
        if speakable_schema:
            score += 2
            signals.append("speakable schema property")

        faq_schema = any(s.get('@type') in ('FAQPage', 'FAQ') for s in self.schema_data)
        if faq_schema:
            score += 1
            signals.append("FAQ schema")

        q_headings = len(re.findall(r'<h[1-6][^>]*>.*\?</h[1-6]>', self.response.text, re.I | re.S))
        if q_headings >= 3:
            score += 1
            signals.append(f"{q_headings} question headings")

        if words >= 800:
            score += 1
            signals.append("content depth supports conversational answers")

        points = min(12, score)
        self.results['voice_search_deep'] = {
            'score': points, 'max': 12,
            'question_openers': opener_hits,
            'speakable_sentences': speakable,
            'definitions': definition_count,
            'speakable_schema': speakable_schema,
        }

        detail = f"Deep Score: {points}/12"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"
        else:
            detail += " | No deep voice optimization detected"

        passed = points >= 6
        self._add_check("Voice Search Deep Analysis", passed, points, 12, detail, category='voice')
        if passed:
            self._add_bonus('voice_deep_ready', "Deep voice search optimization detected")
        else:
            self._add_quick_win("Deep-optimize for voice search",
                                "Add speakable FAQ schema, conversational question openers, and 8-22 word answer sentences.", 'medium')

    def check_visual_search_optimization(self):
        images = self.soup.find_all('img')
        if not images:
            self.results['visual_search'] = {'score': 0, 'max': 10, 'images': 0, 'applicable': True}
            self._add_check("Visual Search Optimization", False, 0, 10,
                            "No images on page - no visual search presence possible", category='visual')
            return

        total = len(images)
        score = 0
        signals = []

        with_alt = sum(1 for img in images if (img.get('alt') or '').strip())
        alt_ratio = with_alt / total
        if alt_ratio >= 0.95:
            score += 3
            signals.append(f"alt coverage {alt_ratio:.0%}")
        elif alt_ratio >= 0.7:
            score += 2
            signals.append(f"alt coverage {alt_ratio:.0%}")
        elif alt_ratio >= 0.4:
            score += 1
            signals.append(f"alt coverage {alt_ratio:.0%}")

        html_text = self.response.text if self.response else ''
        modern = len(re.findall(r'\.(webp|avif)\b', html_text, re.I))
        if modern > 0:
            score += 1
            signals.append("modern formats (WebP/AVIF)")

        srcset = len(re.findall(r'srcset\s*=', html_text, re.I))
        if srcset > 0:
            score += 1
            signals.append("responsive srcset")

        captions = len(self.soup.find_all('figcaption'))
        if captions > 0:
            score += 1
            signals.append(f"{captions} captions")

        descriptive = 0
        for img in images:
            src = img.get('src', '') or img.get('data-src', '')
            filename = urlparse(src).path.split('/')[-1].lower() if src else ''
            if filename and '-' in filename and re.match(r'^[a-z0-9][a-z0-9_-]*\.[a-z]+$', filename):
                descriptive += 1
        if descriptive >= max(1, total // 3):
            score += 1
            signals.append("descriptive filenames")

        image_schema = False
        for schema in self.schema_data:
            st = str(schema.get('@type', ''))
            if 'ImageObject' in st or schema.get('primaryImageOfPage') or schema.get('image'):
                image_schema = True
                break
        if image_schema:
            score += 1
            signals.append("image markup in structured data")

        context_ok = 0
        for img in images[:8]:
            parent = img.find_parent(['p', 'figure', 'section', 'article'])
            if parent and len(parent.get_text(' ', strip=True).split()) >= 15:
                context_ok += 1
        if context_ok >= 3:
            score += 1
            signals.append("image context text nearby")

        lens_text = self.page_text.lower()
        google_lens_cue = bool(re.search(r'visual search|google lens|scan|image recognition', lens_text))
        if google_lens_cue:
            score += 1
            signals.append("visual-search related content")

        points = min(10, score)
        self.results['visual_search'] = {
            'score': points, 'max': 10,
            'images': total,
            'alt_coverage': round(alt_ratio * 100, 1),
            'applicable': True,
        }

        detail = f"Score: {points}/10 | {total} images"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"

        passed = points >= 6
        self._add_check("Visual Search Optimization", passed, points, 10, detail, category='visual')
        if passed:
            self._add_bonus('visual_search_ready', "Visual search optimization is strong")
        else:
            self._add_quick_win("Optimize for visual search",
                                "Add descriptive alt text, WebP/AVIF formats, srcset, captions, and ImageObject markup for Lens-style discovery.", 'medium')

    def check_video_featured_snippet_optimization(self):
        video_tags = self.soup.find_all('video')
        video_iframes = []
        for frame in self.soup.find_all('iframe'):
            src = (frame.get('src') or '').lower()
            if any(host in src for host in ('youtube', 'youtu.be', 'vimeo', 'wistia',
                                            'dailymotion', 'brightcove', 'vidyard')):
                video_iframes.append(frame)
        video_schema = [s for s in self.schema_data if 'VideoObject' in str(s.get('@type', ''))]
        total_videos = len(video_tags) + len(video_iframes) + len(video_schema)

        if total_videos == 0:
            self.results['video_featured_snippet'] = {'score': 5, 'max': 10, 'videos': 0, 'applicable': False}
            self._add_check("Video Featured Snippet Opt.", True, 5, 10,
                            "No video content detected (neutral score)", category='snippet')
            return

        score = 0
        signals = []
        score += 2
        signals.append(f"{len(video_tags) + len(video_iframes)} video embed(s)/tag(s)")

        if video_schema:
            score += 2
            signals.append("VideoObject schema")
            v = video_schema[0]
            if v.get('name') or v.get('headline'):
                score += 1
            if v.get('description'):
                score += 1
            if v.get('thumbnailUrl') or v.get('thumbnail'):
                score += 1
            if v.get('uploadDate') or v.get('datePublished'):
                score += 1
            if v.get('duration'):
                score += 1
        else:
            signals.append("no VideoObject schema")

        text_lower = self.page_text.lower()
        transcript_cues = ('transcript', 'watch time', 'video description', 'in this video',
                           'timestamps', 'chapter markers')
        if any(c in text_lower for c in transcript_cues):
            score += 1
            signals.append("transcript/description cues")

        clip_schema = False
        for schema in self.schema_data:
            if schema.get('clip') or schema.get('hasPart') or schema.get('@type') in ('Clip', 'SeekToAction'):
                clip_schema = True
                break
        if clip_schema:
            score += 1
            signals.append("clip/key-moment markup")

        points = min(10, score)
        self.results['video_featured_snippet'] = {
            'score': points, 'max': 10,
            'videos': total_videos,
            'video_schema': bool(video_schema),
            'clip_markup': clip_schema,
            'applicable': True,
        }

        detail = f"Score: {points}/10 | {total_videos} video signals"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"

        passed = points >= 6
        self._add_check("Video Featured Snippet Opt.", passed, points, 10, detail, category='snippet')
        if passed:
            self._add_bonus('video_snippet_ready', "Video featured snippet optimization detected")
        else:
            self._add_quick_win("Optimize video for featured snippets",
                                "Add VideoObject schema with thumbnail, duration, transcript, and clip/key-moment markup.", 'medium')

    def check_image_featured_snippet_optimization(self):
        images = self.soup.find_all('img')
        if not images:
            self.results['image_featured_snippet'] = {'score': 5, 'max': 10, 'images': 0, 'applicable': False}
            self._add_check("Image Featured Snippet Opt.", True, 5, 10,
                            "No images on page (neutral score)", category='snippet')
            return

        total = len(images)
        score = 0
        signals = []

        with_alt = sum(1 for img in images if (img.get('alt') or '').strip())
        alt_ratio = with_alt / total
        if alt_ratio >= 0.95:
            score += 3
            signals.append(f"alt coverage {alt_ratio:.0%}")
        elif alt_ratio >= 0.7:
            score += 2
            signals.append(f"alt coverage {alt_ratio:.0%}")
        elif alt_ratio >= 0.4:
            score += 1
            signals.append(f"alt coverage {alt_ratio:.0%}")

        captions = len(self.soup.find_all('figcaption'))
        if captions > 0:
            score += 2
            signals.append(f"{captions} figcaptions")
        elif total >= 3:
            score += 1
            signals.append("images present without captions")

        top_images = images[:3]
        top_alt = sum(1 for img in top_images if (img.get('alt') or '').strip())
        if top_alt >= 2:
            score += 2
            signals.append("top images have alt text")

        headings = self.soup.find_all(['h2', 'h3'])
        img_under_headings = 0
        for h in headings:
            nxt = h.find_next('img')
            if nxt:
                img_under_headings += 1
        if img_under_headings >= 2:
            score += 1
            signals.append(f"{img_under_headings} images near headings")

        image_schema = False
        for schema in self.schema_data:
            st = str(schema.get('@type', ''))
            if 'ImageObject' in st or schema.get('primaryImageOfPage') or schema.get('image'):
                image_schema = True
                break
        if image_schema:
            score += 1
            signals.append("image markup in structured data")
        elif self.soup.find('meta', property='og:image'):
            score += 1
            signals.append("og:image present")

        html_text = self.response.text if self.response else ''
        if len(re.findall(r'srcset\s*=', html_text, re.I)) > 0:
            score += 1
            signals.append("responsive srcset")

        points = min(10, score)
        self.results['image_featured_snippet'] = {
            'score': points, 'max': 10,
            'images': total,
            'alt_coverage': round(alt_ratio * 100, 1),
            'captions': captions,
            'applicable': True,
        }

        detail = f"Score: {points}/10 | {total} images"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"

        passed = points >= 6
        self._add_check("Image Featured Snippet Opt.", passed, points, 10, detail, category='snippet')
        if passed:
            self._add_bonus('image_snippet_ready', "Image featured snippet optimization detected")
        else:
            self._add_quick_win("Optimize images for featured snippets",
                                "Add descriptive alt text, figcaptions, responsive srcset, and ImageObject markup for image snippets.", 'medium')

    def check_local_pack_optimization(self):
        score = 0
        signals = []
        text_lower = self.page_text.lower()

        local_schema = [s for s in self.schema_data
                        if 'LocalBusiness' in str(s.get('@type', ''))]
        has_local_schema = bool(local_schema)

        if has_local_schema:
            score += 3
            signals.append("LocalBusiness schema")
            lb = local_schema[0]
            if lb.get('address'):
                score += 2
                signals.append("address in schema")
            if lb.get('telephone'):
                score += 1
                signals.append("telephone in schema")
            if lb.get('openingHours') or lb.get('openingHoursSpecification'):
                score += 1
                signals.append("opening hours in schema")
            if lb.get('geo'):
                score += 1
                signals.append("geo coordinates in schema")
            if lb.get('aggregateRating') or lb.get('review'):
                score += 1
                signals.append("ratings/reviews in schema")
        else:
            signals.append("no LocalBusiness schema")

        nav_texts = []
        for a in self.soup.find_all('a', href=True):
            nav_texts.append((a.get_text(' ', strip=True) + ' ' + a['href']).lower())
        has_contact = any('contact' in t for t in nav_texts)
        if has_contact:
            score += 1
            signals.append("contact page linked")

        address_patterns = [r'\d+\s+[a-zA-Z\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|way|court|ct|place|pl)\b',
                            r'\b[A-Z]{2}\s+\d{5}(?:-\d{4})?\b']
        has_address = any(re.search(p, self.page_text) for p in address_patterns)
        if has_address:
            score += 1
            signals.append("physical address found on page")

        phone_pattern = r'(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'
        has_phone = bool(re.search(phone_pattern, self.page_text))
        if has_phone:
            score += 1
            signals.append("phone number found")

        maps_embed = False
        for frame in self.soup.find_all('iframe'):
            src = (frame.get('src') or '').lower()
            if 'google.com/maps' in src or 'maps.google' in src or 'openstreetmap' in src:
                maps_embed = True
                break
        if maps_embed:
            score += 1
            signals.append("map embed found")

        service_area = bool(re.search(r'service area|areas we serve|serving|now serving|located in', text_lower))
        if service_area:
            score += 1
            signals.append("service area content")

        review_signals = len(re.findall(r'\breview\b|\brating\b|\bstars?\b|\bbest in\b|\baward', text_lower))
        if review_signals >= 3:
            score += 1
            signals.append(f"{review_signals} review signals")

        points = min(10, score)
        local_applicable = has_local_schema or has_address or has_phone or maps_embed
        self.results['local_pack'] = {
            'score': points, 'max': 10,
            'local_schema': has_local_schema,
            'address': has_address,
            'phone': has_phone,
            'map_embed': maps_embed,
            'applicable': local_applicable,
        }

        if not local_applicable:
            detail = f"Score: {points}/10 | No local signals detected (may not be a local business page)"
            passed = points >= 4
            self._add_check("Local Pack Optimization", passed, points, 10, detail, category='local')
            return

        detail = f"Score: {points}/10"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"

        passed = points >= 6
        self._add_check("Local Pack Optimization", passed, points, 10, detail, category='local')
        if passed:
            self._add_bonus('local_pack_ready', "Local pack optimization signals found")
        else:
            self._add_quick_win("Optimize for local pack",
                                "Add LocalBusiness schema with address, phone, hours, geo, reviews, and a map embed.", 'medium')

    def check_hidden_text(self):
        hidden_indicators = 0
        html = self.response.text.lower()

        patterns = [
            r'display:\s*none',
            r'visibility:\s*hidden',
            r'font-size:\s*0',
            r'opacity:\s*0',
            r'color:\s*(?:white|#[fF]{6}|#fff(?:fff)?)',
            r'position:\s*absolute.*left:\s*-9999',
            r'clip:\s*rect\(0,\s*0,\s*0,\s*0\)',
        ]
        for pattern in patterns:
            if re.search(pattern, html):
                hidden_indicators += 1

        if hidden_indicators >= 2:
            self._add_penalty('hidden_text', f"Found {hidden_indicators} hidden text indicators")
            self._add_check("Hidden Text Detection", False, 0, 5, f"{hidden_indicators} potential hidden text indicators", category='technical')
        else:
            self._add_check("Hidden Text Detection", True, 5, 5, "No hidden text detected", category='technical')

    def check_semantic_html(self):
        semantic_tags = ['header', 'nav', 'main', 'article', 'section', 'aside', 'footer', 'figure', 'figcaption', 'time', 'address']
        found = {}
        for tag in semantic_tags:
            count = len(self.soup.find_all(tag))
            if count > 0:
                found[tag] = count

        total_semantic = sum(found.values())
        points = min(5, total_semantic)

        if found:
            detail = f"Found: {', '.join([f'{t}({c})' for t, c in list(found.items())[:5]])}"
        else:
            detail = "No semantic HTML elements found"

        self._add_check("Semantic HTML", total_semantic >= 3, points, 5, detail, category='technical')
        if total_semantic >= 3:
            self._add_bonus('semantic_html', "Good use of semantic HTML elements")

    def check_accessibility_basics(self):
        score = 0
        features = []

        lang_attr = self.soup.find('html', attrs={'lang': True})
        if lang_attr:
            score += 1
            features.append("lang attr")

        aria_count = len(re.findall(r'aria-', self.response.text, re.I))
        if aria_count > 0:
            score += 1
            features.append(f"{aria_count} aria attrs")
            self._add_bonus('aria_labels', "Accessibility attributes found")

        skip_links = self.soup.find('a', href='#main') or self.soup.find('a', href='#content')
        if skip_links:
            score += 1
            features.append("skip link")

        h1 = self.soup.find('h1')
        if h1:
            score += 1

        landmarks = len(re.findall(r'role="(main|navigation|banner|contentinfo|complementary)"', self.response.text, re.I))
        if landmarks > 0:
            score += 1
            features.append(f"{landmarks} landmarks")

        points = min(5, score)
        detail = f"Score: {points}/5"
        if features:
            detail += f" | {', '.join(features)}"

        self._add_check("Accessibility Basics", points >= 3, points, 5, detail, category='technical')

    def check_page_hints(self):
        hints = 0
        features = []

        preload = len(re.findall(r'rel=["\']preload["\']', self.response.text, re.I))
        prefetch = len(re.findall(r'rel=["\']prefetch["\']', self.response.text, re.I))
        preconnect = len(re.findall(r'rel=["\']preconnect["\']', self.response.text, re.I))
        dns_prefetch = len(re.findall(r'rel=["\']dns-prefetch["\']', self.response.text, re.I))

        if preload > 0:
            hints += preload
            features.append(f"{preload} preload")
        if prefetch > 0:
            hints += prefetch
            features.append(f"{prefetch} prefetch")
        if preconnect > 0:
            hints += preconnect
            features.append(f"{preconnect} preconnect")
        if dns_prefetch > 0:
            hints += dns_prefetch
            features.append(f"{dns_prefetch} dns-prefetch")

        points = min(5, hints)
        detail = f"Score: {points}/5"
        if features:
            detail += f" | {', '.join(features)}"

        self._add_check("Resource Hints", hints >= 2, points, 5, detail, category='performance')
        if hints >= 2:
            self._add_bonus('preload_hints', "Resource hints found (preload/prefetch)")

    def check_lazy_loading(self):
        images = self.soup.find_all('img')
        if not images:
            self._add_check("Lazy Loading", True, 3, 3, "No images to check", category='performance')
            return

        total = len(images)
        lazy = sum(1 for img in images if img.get('loading') == 'lazy' or img.get('data-src'))
        points = 3 if lazy > 0 else 0

        detail = f"{lazy}/{total} images use lazy loading"
        self._add_check("Lazy Loading", lazy > 0, points, 3, detail, category='performance')
        if lazy > 0:
            self._add_bonus('lazy_loading', "Images use lazy loading")

    def check_ai_llm_readiness(self):
        score = 0
        signals = []
        issues = []

        base_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}"

        robots_body = self.robots_txt_content
        if robots_body is None:
            try:
                r = requests.get(base_url + '/robots.txt', headers=self.headers, timeout=8, verify=False)
                robots_body = r.text if r.status_code == 200 else ''
            except Exception:
                robots_body = ''
            self.robots_txt_content = robots_body

        llms_ok = False
        try:
            r = requests.get(base_url + '/llms.txt', headers=self.headers, timeout=8, verify=False)
            llms_ok = r.status_code == 200 and len(r.text.strip()) > 20
        except Exception:
            llms_ok = False

        if llms_ok:
            score += 3
            signals.append("llms.txt present")
            self._add_bonus('llms_txt', "llms.txt found for AI/LLM crawlers")
        else:
            issues.append("no llms.txt")
            self._add_quick_win("Add llms.txt", "Publish /llms.txt summarizing key pages for AI/LLM crawlers.", 'low')

        robots_lower = (robots_body or '').lower()
        ai_agents = ['gptbot', 'claudebot', 'anthropic-ai', 'google-extended', 'ccbot', 'perplexitybot', 'cohere-ai']
        blocked_agents = []
        for agent in ai_agents:
            match = re.search(r'user-agent:\s*' + re.escape(agent) + r'(.*?)(?:\n\s*\n|\Z)', robots_lower, re.S | re.I)
            if match and re.search(r'disallow:\s*/\s*(?:\n|$)', match.group(1)):
                blocked_agents.append(agent)
        if blocked_agents:
            issues.append("AI crawlers blocked: " + ", ".join(blocked_agents))
        else:
            score += 2
            signals.append("AI crawlers allowed")

        question_headings = len(re.findall(r'<h[1-6][^>]*>.*\?</h[1-6]>', self.response.text, re.I | re.S))
        if question_headings >= 3:
            score += 2
            signals.append(f"{question_headings} question headings")
        elif question_headings >= 1:
            score += 1
            signals.append("question headings present")

        text_lower = self.page_text.lower()
        definition_count = 0
        for _ in re.finditer(r'\b[\w\s-]{2,50}\s+is\s+(?:a|an|the)\s+', text_lower):
            definition_count += 1
            if definition_count >= 6:
                break
        if definition_count >= 3:
            score += 2
            signals.append("definition-style sentences")
        elif definition_count >= 1:
            score += 1
            signals.append("some definition-style sentences")

        list_count = len(self.soup.find_all(['ul', 'ol']))
        if list_count >= 3:
            score += 1
            signals.append("extractable lists")

        if self.schema_data:
            score += 2
            signals.append("structured data present")

        points = min(12, score)
        self.results['ai_readiness'] = points

        detail = f"Score: {points}/12"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"
        if issues:
            detail += f" | Gaps: {', '.join(issues)}"

        passed = points >= 6
        self._add_check("AI/LLM Readiness", passed, points, 12, detail, category='ai')
        if not passed:
            self._add_quick_win("Optimize for AI/LLM crawlers",
                                "Add llms.txt, question-answer headings, definitions, and structured data.", 'medium')

    def check_content_freshness(self):
        score = 0
        signals = []
        now = datetime.now()

        date_published = None
        date_modified = None
        for schema in self.schema_data:
            if not date_published and schema.get('datePublished'):
                date_published = self._parse_date(schema.get('datePublished'))
            if not date_modified and schema.get('dateModified'):
                date_modified = self._parse_date(schema.get('dateModified'))

        meta_pub = self.soup.find('meta', attrs={'property': 'article:published_time'}) or self.soup.find('meta', attrs={'name': 'date'})
        meta_mod = self.soup.find('meta', attrs={'property': 'article:modified_time'}) or self.soup.find('meta', attrs={'name': 'last-modified'})
        if not date_published and meta_pub and meta_pub.get('content'):
            date_published = self._parse_date(meta_pub.get('content'))
        if not date_modified and meta_mod and meta_mod.get('content'):
            date_modified = self._parse_date(meta_mod.get('content'))

        if date_published:
            score += 2
            signals.append(f"published {date_published.strftime('%Y-%m-%d')}")
        if date_modified:
            score += 2
            signals.append(f"modified {date_modified.strftime('%Y-%m-%d')}")

        visible_date = bool(re.search(
            r'(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}'
            r'|\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}'
            r'|\d{4}-\d{2}-\d{2}',
            self.page_text))
        if visible_date:
            score += 1
            signals.append("visible date on page")

        if self.response is not None:
            lm = self.response.headers.get('Last-Modified')
            if lm:
                try:
                    from email.utils import parsedate_to_datetime
                    last_modified_header = parsedate_to_datetime(lm)
                    age_days = max(0, (now - last_modified_header.replace(tzinfo=None)).days)
                    if age_days <= 90:
                        score += 2
                        signals.append(f"updated {age_days}d ago")
                    elif age_days <= 365:
                        score += 1
                        signals.append(f"updated {age_days}d ago")
                    else:
                        signals.append(f"last modified {age_days}d ago")
                except Exception:
                    pass

        if str(now.year) in self.page_text:
            score += 1
            signals.append(f"{now.year} referenced")

        newest = date_modified or date_published
        freshness_age_days = None
        if newest:
            freshness_age_days = max(0, (now - newest).days)
            if freshness_age_days <= 30:
                score += 3
                signals.append(f"updated {freshness_age_days}d ago (peak freshness)")
            elif freshness_age_days <= 90:
                score += 2
                signals.append(f"updated {freshness_age_days}d ago (fresh)")
            elif freshness_age_days <= 180:
                score += 1
                signals.append(f"updated {freshness_age_days}d ago")
            elif freshness_age_days > 730:
                signals.append(f"content is {freshness_age_days}d old (stale)")
            else:
                signals.append(f"content is {freshness_age_days}d old")

        if date_published and date_modified and date_modified > date_published:
            score += 1
            signals.append("update cadence (dateModified newer than datePublished)")

        points = min(10, score)
        self.results['freshness'] = points
        self.results['freshness_refined'] = points
        if freshness_age_days is not None:
            decay_pct = max(0.0, min(100.0, 100.0 - (freshness_age_days / 3.65)))
            self.results['freshness_decay_pct'] = round(decay_pct, 1)
        else:
            self.results['freshness_decay_pct'] = 0.0

        if points >= 6:
            self._add_bonus('freshness_signals', "Strong publication/update date signals")

        detail = f"Score: {points}/10"
        if signals:
            detail += f" | {', '.join(signals)}"
        if points <= 3:
            detail += " | Stale or undated content"
            self._add_quick_win("Add/update content dates",
                                "Expose datePublished and dateModified in schema and on-page.", 'medium')

        self._add_check("Content Freshness", points >= 5, points, 10, detail, category='freshness')

    def check_content_depth_competition(self):
        benchmark = 1800
        words = len(self.page_text.split())
        h_tags = len(self.soup.find_all(['h2', 'h3', 'h4']))
        images = len(self.soup.find_all('img'))
        lists = len(self.soup.find_all(['ul', 'ol']))
        tables = len(self.soup.find_all('table'))
        quotes = len(self.soup.find_all('blockquote'))

        points = 0

        if words >= benchmark:
            points += 4
        elif words >= benchmark * 0.75:
            points += 3
        elif words >= benchmark * 0.5:
            points += 2
        elif words >= 300:
            points += 1

        headings_per_500 = h_tags / max(1, words / 500)
        if headings_per_500 >= 1.5:
            points += 2
        elif headings_per_500 >= 0.8:
            points += 1

        media_per_500 = images / max(1, words / 500)
        if media_per_500 >= 1:
            points += 2
        elif media_per_500 >= 0.4:
            points += 1

        depth_devices = lists + tables + quotes
        if depth_devices >= 5:
            points += 2
        elif depth_devices >= 2:
            points += 1

        points = min(10, points)
        gap = benchmark - words
        if gap > 0:
            detail = f"{words:,} words vs ~{benchmark:,} competitor benchmark | Gap: {gap:,} words | Headings: {h_tags} | Depth devices: {depth_devices}"
        else:
            detail = f"{words:,} words vs ~{benchmark:,} competitor benchmark | Surplus: {-gap:,} words | Headings: {h_tags} | Depth devices: {depth_devices}"

        passed = points >= 6
        self._add_check("Content Depth vs Competition", passed, points, 10, detail, category='content')
        if gap > 600:
            self._add_quick_win("Close the content depth gap",
                                f"Add roughly {gap:,} words of substantive coverage to match typical competitors.", 'high')

    def check_seasonal_content(self):
        text_lower = self.page_text.lower()
        title_tag = self.soup.find('title')
        title_lower = title_tag.get_text().lower() if title_tag and title_tag.string else ''

        seasonal_hits = [term for term in SEASONAL_TERMS if term in text_lower or term in title_lower]
        month_hits = [month for month in MONTH_NAMES if re.search(r'\b' + month + r'\b', text_lower)]

        is_seasonal = bool(seasonal_hits) or len(month_hits) >= 2
        self.results['seasonal'] = is_seasonal

        if is_seasonal:
            detail_bits = []
            if seasonal_hits:
                detail_bits.append("terms: " + ", ".join(seasonal_hits[:4]))
            if month_hits:
                detail_bits.append(f"{len(month_hits)} month references")
            detail = "Seasonal content detected | " + "; ".join(detail_bits)

            fresh_ok = self.results.get('freshness', 0) >= 5
            points = 3 + (2 if fresh_ok else 0)
            if fresh_ok:
                self._add_bonus('seasonal_fresh', "Seasonal content carries fresh date signals")
            else:
                detail += " | Refresh dates before the next season"
                self._add_quick_win("Refresh seasonal content",
                                    "Update dates, offers, and year references before the seasonal peak.", 'high')
            passed = fresh_ok
        else:
            points = 5
            passed = True
            detail = "No seasonal signals - likely evergreen content (neutral/positive)"

        self._add_check("Seasonal Content Detection", passed, points, 5, detail, category='freshness')
        self.results['seasonal_terms'] = seasonal_hits

    def check_content_quality_index(self):
        word_list = self.page_text.split()
        words = len(word_list)
        paragraphs = len(self.soup.find_all('p'))
        headings = len(self.soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']))
        images = len(self.soup.find_all('img'))

        structure_pts = 0
        if paragraphs >= 6:
            structure_pts += 2
        elif paragraphs >= 3:
            structure_pts += 1
        if headings >= 4:
            structure_pts += 1

        sentences = [s for s in re.split(r'[.!?]+', self.page_text) if s.strip() and len(s.strip()) > 5]
        readability_pts = 0
        if words and sentences:
            asl = words / max(1, len(sentences))
            sample = word_list[:200]
            syllables = 0
            for word in sample:
                w = word.lower().strip('.,!?;:')
                syllables += max(1, len(re.findall(r'[aeiouy]+', w)))
            asw = syllables / max(1, len(sample))
            fre = 206.835 - 1.015 * asl - 84.6 * asw
            fre = max(0, min(100, fre))
            if fre >= 50:
                readability_pts = 3
            elif fre >= 30:
                readability_pts = 2
            elif fre >= 15:
                readability_pts = 1

        depth_pts = 0
        if words >= 1500:
            depth_pts = 2
        elif words >= 800:
            depth_pts = 1

        media_pts = 0
        if images >= 4:
            media_pts = 2
        elif images >= 1:
            media_pts = 1

        ratio_pts = 0
        if self.response is not None and len(self.response.text) > 0:
            text_ratio = len(self.page_text) / len(self.response.text)
            if text_ratio >= 0.2:
                ratio_pts = 2
            elif text_ratio >= 0.1:
                ratio_pts = 1

        points = min(12, structure_pts + readability_pts + depth_pts + media_pts + ratio_pts)
        self.results['content_quality_index'] = points

        detail = (f"CQI {points}/12 | structure {structure_pts}/3 | readability {readability_pts}/3"
                  f" | depth {depth_pts}/2 | media {media_pts}/2 | text ratio {ratio_pts}/2")
        passed = points >= 7
        self._add_check("Content Quality Index", passed, points, 12, detail, category='content')

    def check_internal_linking_architecture(self):
        score = 0
        signals = []

        breadcrumb_schema = any(s.get('@type') == 'BreadcrumbList' for s in self.schema_data)
        breadcrumb_nav = bool(self.soup.find('nav', attrs={'aria-label': re.compile('breadcrumb', re.I)}))
        if not breadcrumb_nav:
            breadcrumb_nav = bool(self.soup.find('ol', class_=re.compile('breadcrumb', re.I)))
        if not breadcrumb_nav:
            breadcrumb_nav = bool(self.soup.find('ul', class_=re.compile('breadcrumb', re.I)))
        if breadcrumb_schema or breadcrumb_nav:
            score += 2
            signals.append("breadcrumbs")
            self._add_bonus('breadcrumbs', "Breadcrumb navigation found")
        else:
            self._add_quick_win("Add breadcrumb navigation",
                                "Breadcrumbs improve site architecture, UX, and can appear in SERPs.", 'medium')

        nav = self.soup.find('nav')
        nav_links = len(nav.find_all('a', href=True)) if nav else 0
        if nav_links >= 3:
            score += 2
            signals.append(f"nav links: {nav_links}")
        elif nav_links >= 1:
            score += 1
            signals.append("minimal nav links")

        main = self.soup.find('main') or self.soup.find('article')
        main_internal = 0
        if main:
            base_domain = urlparse(self.url).netloc
            for a in main.find_all('a', href=True):
                full = urljoin(self.url, a['href'])
                if urlparse(full).netloc == base_domain:
                    main_internal += 1
        if main_internal >= 3:
            score += 2
            signals.append(f"content-area internal links: {main_internal}")
        elif main_internal >= 1:
            score += 1
            signals.append("some content-area internal links")

        if self.internal_links:
            unique_ratio = len(set(self.internal_links)) / max(1, len(self.internal_links))
            if unique_ratio >= 0.7:
                score += 2
                signals.append(f"unique ratio {unique_ratio:.0%}")
            elif unique_ratio >= 0.4:
                score += 1
                signals.append(f"unique ratio {unique_ratio:.0%}")
        else:
            signals.append("no internal links")

        generic = {'click here', 'here', 'read more', 'more', 'link', 'this', 'learn more'}
        if self.anchor_texts:
            non_generic = sum(1 for t in self.anchor_texts if t.lower().strip() not in generic)
            non_generic_ratio = non_generic / max(1, len(self.anchor_texts))
            if non_generic_ratio >= 0.7:
                score += 2
                signals.append("descriptive anchors")
            elif non_generic_ratio >= 0.4:
                score += 1
                signals.append("mixed anchor quality")

        points = min(10, score)
        detail = f"Score: {points}/10"
        if signals:
            detail += f" | {', '.join(signals)}"

        passed = points >= 6
        self._add_check("Linking Architecture", passed, points, 10, detail, category='links')
        if points >= 8:
            self._add_bonus('clean_architecture', "Healthy internal linking architecture")

    def check_topic_clusters(self):
        subtopics = []
        for tag in self.soup.find_all(['h2', 'h3']):
            text = tag.get_text(' ', strip=True)
            if text and len(text) <= 80:
                subtopics.append(text)

        words = len(self.page_text.split())
        internal_count = len(set(self.internal_links))

        score = 0
        signals = []

        if len(subtopics) >= 5:
            score += 3
            signals.append(f"{len(subtopics)} subtopics")
        elif len(subtopics) >= 3:
            score += 2
            signals.append(f"{len(subtopics)} subtopics")
        elif len(subtopics) >= 1:
            score += 1
            signals.append("some subtopic structure")

        if words >= 1500:
            score += 2
            signals.append("pillar-depth content")
        elif words >= 800:
            score += 1
            signals.append("moderate depth")

        if internal_count >= 6:
            score += 2
            signals.append(f"{internal_count} internal links")
        elif internal_count >= 3:
            score += 1
            signals.append(f"{internal_count} internal links")

        schema_keywords = False
        for schema in self.schema_data:
            if schema.get('keywords') or schema.get('about') or schema.get('mainEntity'):
                schema_keywords = True
                break
        meta_kw = self.soup.find('meta', attrs={'name': 'keywords'})
        if schema_keywords or (meta_kw and meta_kw.get('content')):
            score += 1
            signals.append("keyword/topic markup")

        points = min(8, score)
        detail = f"Score: {points}/8"
        if subtopics:
            preview = "; ".join(subtopics[:4])
            detail += f" | Subtopics: {preview}"
        if signals:
            detail += f" | {', '.join(signals)}"

        passed = points >= 5
        self._add_check("Topic Cluster Detection", passed, points, 8, detail, category='content')
        if points >= 6:
            self._add_bonus('topic_cluster', "Topic cluster structure detected")
        elif not passed:
            self._add_quick_win("Structure content into topic clusters",
                                "Break content into H2/H3 subtopics and interlink supporting pages.", 'medium')

    def check_entity_recognition(self):
        entity_types = []
        for schema in self.schema_data:
            st = schema.get('@type')
            if not st:
                continue
            if isinstance(st, list):
                st = ' '.join(str(x) for x in st)
            st_str = str(st)
            for known in ('Person', 'Organization', 'Product', 'Place', 'Event', 'CreativeWork', 'Brand', 'SoftwareApplication'):
                if known in st_str and known not in entity_types:
                    entity_types.append(known)

        sameas_count = 0
        for schema in self.schema_data:
            sameas = schema.get('sameAs')
            if isinstance(sameas, str) and sameas:
                sameas_count += 1
            elif isinstance(sameas, list):
                sameas_count += len(sameas)

        authority_mentions = 0
        for link in self.external_links[:50]:
            host = urlparse(link).netloc.lower()
            if 'wikipedia.org' in host or 'wikidata.org' in host or 'britannica.com' in host:
                authority_mentions += 1
        text_lower = self.page_text.lower()
        if 'wikipedia.org' in text_lower or 'wikidata' in text_lower:
            authority_mentions += 1

        tokens = re.findall(r"\b[A-Za-z][A-Za-z'-]{2,}\b", self.page_text)
        proper = sum(1 for t in tokens if t[0].isupper())
        proper_ratio = proper / max(1, len(tokens))

        cited_domains = 0
        for link in self.external_links[:50]:
            host = urlparse(link).netloc.lower()
            if host.endswith('.gov') or host.endswith('.edu') or host.endswith('.org'):
                cited_domains += 1

        score = 0
        signals = []

        if entity_types:
            score += 2
            signals.append("entities: " + ", ".join(entity_types[:4]))
        if sameas_count > 0:
            score += 2
            signals.append(f"{sameas_count} sameAs links")
            self._add_bonus('entity_sameas', "Entity sameAs links found")
        if authority_mentions > 0:
            score += 2
            signals.append("authority references")
        if proper_ratio >= 0.08:
            score += 1
            signals.append(f"proper-noun ratio {proper_ratio:.0%}")
        if cited_domains > 0:
            score += 1
            signals.append(f"{cited_domains} .gov/.edu/.org citations")

        points = min(8, score)
        detail = f"Score: {points}/8"
        if signals:
            detail += f" | {', '.join(signals)}"

        passed = points >= 4
        self._add_check("Entity Recognition Hints", passed, points, 8, detail, category='entities')

    def check_knowledge_graph_signals(self):
        score = 0
        signals = []

        org_schemas = [s for s in self.schema_data if s.get('@type') == 'Organization' or 'Organization' in str(s.get('@type', ''))]
        person_schemas = [s for s in self.schema_data if s.get('@type') == 'Person']

        if org_schemas:
            score += 2
            signals.append("Organization schema")
            org = org_schemas[0]
            if org.get('logo'):
                score += 1
                signals.append("logo")
            sameas = org.get('sameAs')
            if sameas:
                score += 1
                if isinstance(sameas, list):
                    signals.append(f"{len(sameas)} org sameAs links")
                else:
                    signals.append("org sameAs link")
            if org.get('contactPoint') or org.get('telephone') or org.get('address'):
                score += 1
                signals.append("contact data")
        else:
            signals.append("no Organization schema")

        if person_schemas:
            person = person_schemas[0]
            if person.get('sameAs') or person.get('url') or person.get('jobTitle'):
                score += 1
                signals.append("Person entity profile")

        kg_links = 0
        for link in self.external_links[:50]:
            host = urlparse(link).netloc.lower()
            if 'wikidata.org' in host or 'wikipedia.org' in host:
                kg_links += 1
        if kg_links > 0:
            score += 1
            signals.append("Wikidata/Wikipedia links")

        if any(s.get('@type') in ('WebSite',) for s in self.schema_data):
            score += 1
            signals.append("WebSite schema")

        points = min(8, score)
        self.results['knowledge_graph'] = points
        detail = f"Score: {points}/8"
        if signals:
            detail += f" | {', '.join(signals)}"

        passed = points >= 4
        self._add_check("Knowledge Graph Signals", passed, points, 8, detail, category='entities')
        if points >= 6:
            self._add_bonus('knowledge_graph_rich', "Strong knowledge graph signals")
        if not passed:
            self._add_quick_win("Strengthen knowledge graph signals",
                                "Add Organization/Person schema with logo, sameAs, and Wikidata/Wikipedia links.", 'medium')

    def check_search_intent_analysis(self):
        title_tag = self.soup.find('title')
        title_lower = title_tag.get_text(' ', strip=True).lower() if title_tag else ''
        h1_tag = self.soup.find('h1')
        h1_lower = h1_tag.get_text(' ', strip=True).lower() if h1_tag else ''
        meta = self.soup.find('meta', attrs={'name': 'description'})
        meta_lower = (meta.get('content') or '').lower() if meta else ''
        path_lower = urlparse(self.url).path.lower()
        text_lower = self.page_text.lower()

        intent_keywords = {
            'transactional': ['buy', 'price', 'pricing', 'cheap', 'discount', 'deal', 'coupon',
                              'order', 'shop', 'cart', 'checkout', 'for sale', 'subscribe',
                              'hire', 'book now', 'get started', 'sign up'],
            'commercial': ['best', 'top 10', 'top 5', 'review', 'reviews', ' vs ', 'versus',
                           'compare', 'comparison', 'alternative', 'pros and cons', 'benchmark',
                           'which should', 'recommended', 'worth it'],
            'navigational': ['login', 'sign in', 'download', 'official site', 'homepage',
                             'dashboard', 'portal', 'app download', 'customer portal'],
            'informational': ['what is', 'what are', 'how to', 'how do', 'why ', 'guide',
                              'tutorial', 'learn', 'tips', 'examples', 'meaning', 'definition',
                              'explained', 'checklist', 'ideas', 'overview'],
        }

        scores = {}
        for intent, kws in intent_keywords.items():
            score = 0
            for kw in kws:
                if kw in title_lower or kw in h1_lower or kw in meta_lower or kw in path_lower:
                    score += 2
                elif kw in text_lower:
                    score += 1
            scores[intent] = score

        question_pattern = re.compile(r'\b(how|what|why|when|where|who|which)\b', re.I)
        if question_pattern.search(title_lower) or question_pattern.search(h1_lower):
            scores['informational'] += 2

        primary = 'informational'
        best = -1
        for intent in ('transactional', 'commercial', 'navigational', 'informational'):
            if scores.get(intent, 0) > best:
                best = scores.get(intent, 0)
                primary = intent
        if best <= 0:
            best = 0

        ranked = sorted(scores.items(), key=lambda kv: -kv[1])
        secondary = [name for name, val in ranked if name != primary and val > 0][:2]
        self.results['search_intent'] = primary
        self.results['secondary_intents'] = secondary
        self.results['intent_scores'] = scores

        points = 0
        align_signals = []

        if best >= 4:
            points += 3
            align_signals.append("clear primary intent")
        elif best >= 2:
            points += 1
            align_signals.append("weak intent signals")

        primary_kws = intent_keywords[primary]
        if any(kw in title_lower for kw in primary_kws):
            points += 3
            align_signals.append("title matches intent")
        elif any(kw in title_lower for kw in [k for v in intent_keywords.values() for k in v]):
            points += 1
            align_signals.append("title has some intent keyword")

        if any(kw in h1_lower for kw in primary_kws):
            points += 2
            align_signals.append("H1 matches intent")
        elif h1_lower and title_lower and (h1_lower[:15] in title_lower or title_lower[:15] in h1_lower):
            points += 1
            align_signals.append("H1/title aligned")

        intent_satisfied = False
        if primary == 'informational':
            lists_ok = len(self.soup.find_all(['ul', 'ol'])) >= 2
            defs = len(re.findall(r'\b\w[\w\s-]{1,40}\s+is\s+(?:a|an|the)\s+', text_lower))
            headings_ok = len(self.soup.find_all(['h2', 'h3'])) >= 3
            intent_satisfied = headings_ok and (lists_ok or defs >= 2)
            if intent_satisfied:
                align_signals.append("informational format (headings/lists/definitions)")
        elif primary == 'commercial':
            tables_ok = len(self.soup.find_all('table')) >= 1
            lists_ok = len(self.soup.find_all(['ul', 'ol'])) >= 1
            verdict_words = sum(1 for w in ('best', 'winner', 'recommend', 'our pick', 'overall') if w in text_lower)
            intent_satisfied = tables_ok or (lists_ok and verdict_words >= 1)
            if intent_satisfied:
                align_signals.append("commercial format (tables/lists/verdicts)")
        elif primary == 'transactional':
            cta_words = ('buy now', 'add to cart', 'checkout', 'sign up', 'get started',
                         'order now', 'subscribe', 'shop now', 'book now', 'try free', 'start free')
            cta_count = sum(1 for w in cta_words if w in text_lower)
            intent_satisfied = cta_count >= 1
            if intent_satisfied:
                align_signals.append(f"{cta_count} transactional CTAs")
        elif primary == 'navigational':
            nav_ok = bool(self.soup.find('nav'))
            brand_in_title = bool(title_lower) and urlparse(self.url).netloc.split('.')[0][:4] in title_lower
            intent_satisfied = nav_ok and brand_in_title
            if intent_satisfied:
                align_signals.append("brand/nav aligned")

        if intent_satisfied:
            points += 2
        else:
            align_signals.append("content format does not fully satisfy intent")

        if any(kw in meta_lower for kw in primary_kws):
            points += 2
        elif meta_lower:
            points += 1

        points = min(12, points)
        self.results['intent_alignment'] = points

        score_bits = ", ".join(f"{name}:{val}" for name, val in ranked)
        detail = f"Primary: {primary}"
        if secondary:
            detail += f" (secondary: {', '.join(secondary)})"
        detail += f" | Score {points}/12 | Signals: {score_bits}"
        if align_signals:
            detail += " | " + "; ".join(align_signals)

        passed = points >= 7
        self._add_check("Search Intent Analysis", passed, points, 12, detail, category='intent')
        if passed:
            self._add_bonus('intent_aligned', "Page content aligns with detected search intent")
        else:
            self._add_quick_win(f"Optimize for {primary} intent",
                                f"Align title, H1, meta description, and content format with {primary} intent.", 'high')

    def check_featured_snippet_optimization(self):
        questions = []
        for tag in self.soup.find_all(['h2', 'h3', 'h4']):
            text = tag.get_text(' ', strip=True)
            if text.endswith('?'):
                questions.append(tag)

        score = 0
        signals = []
        ready_blocks = 0
        for qtag in questions:
            nxt = qtag.find_next('p')
            if nxt:
                answer_words = len(nxt.get_text(' ', strip=True).split())
                if 20 <= answer_words <= 90:
                    ready_blocks += 1

        if ready_blocks >= 2:
            score += 4
            signals.append(f"{ready_blocks} tight Q&A answer blocks")
        elif ready_blocks == 1:
            score += 3
            signals.append("1 tight Q&A answer block")
        elif questions:
            score += 1
            signals.append(f"{len(questions)} questions without tight answers")

        list_blocks = 0
        for lst in self.soup.find_all(['ul', 'ol']):
            items = lst.find_all('li')
            if len(items) >= 3:
                prev = lst.find_previous(['h2', 'h3'])
                if prev:
                    list_blocks += 1
        if list_blocks >= 2:
            score += 3
            signals.append(f"{list_blocks} list blocks under headings")
        elif list_blocks == 1:
            score += 2
            signals.append("1 list block under a heading")

        tables = self.soup.find_all('table')
        if tables:
            score += 2
            signals.append(f"{len(tables)} table(s) for table snippets")

        text_lower = self.page_text.lower()
        definition_count = len(re.findall(r'\b[\w\s-]{2,40}\s+is\s+(?:a|an|the)\s+', text_lower))
        if definition_count >= 3:
            score += 1
            signals.append("definition-style sentences")

        faq_schema = any(s.get('@type') in ('FAQPage', 'FAQ') for s in self.schema_data)
        if faq_schema:
            score += 2
            signals.append("FAQ schema")

        points = min(10, score)
        self.results['featured_snippet'] = {
            'score': points,
            'max': 10,
            'question_headings': len(questions),
            'ready_answer_blocks': ready_blocks,
            'list_blocks': list_blocks,
            'tables': len(tables),
        }

        detail = f"Score: {points}/10"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"
        else:
            detail += " | No featured snippet optimization detected"

        passed = points >= 6
        self._add_check("Featured Snippet Optimization", passed, points, 10, detail, category='snippet')
        if passed:
            self._add_bonus('featured_snippet_ready', "Featured snippet optimization signals found")
        else:
            self._add_quick_win("Structure answers for featured snippets",
                                "Add question-form headings followed by 20-90 word direct answers, lists, and tables.", 'medium')

    def check_people_also_ask_optimization(self):
        question_headings = []
        for tag in self.soup.find_all(['h1', 'h2', 'h3', 'h4']):
            text = tag.get_text(' ', strip=True)
            if text.endswith('?') or re.match(r'^(how|what|why|when|where|who|which|can|does|is|are)\b', text, re.I):
                question_headings.append(tag)

        score = 0
        signals = []

        q_count = len(question_headings)
        if q_count >= 5:
            score += 3
            signals.append(f"{q_count} question headings")
        elif q_count >= 3:
            score += 2
            signals.append(f"{q_count} question headings")
        elif q_count >= 1:
            score += 1
            signals.append(f"{q_count} question heading(s)")

        faq_schema = any(s.get('@type') in ('FAQPage', 'FAQ') for s in self.schema_data)
        if faq_schema:
            score += 3
            signals.append("FAQPage schema")

        direct_answers = 0
        for qtag in question_headings:
            nxt = qtag.find_next('p')
            if nxt:
                answer_words = len(nxt.get_text(' ', strip=True).split())
                if 15 <= answer_words <= 100:
                    direct_answers += 1
        if direct_answers >= 3:
            score += 2
            signals.append(f"{direct_answers} direct answers")
        elif direct_answers >= 1:
            score += 1
            signals.append(f"{direct_answers} direct answer(s)")

        text_lower = self.page_text.lower()
        related_phrases = ('people also ask', 'related questions', 'you may also ask',
                           'frequently asked', 'common questions', 'faqs')
        if any(p in text_lower for p in related_phrases):
            score += 1
            signals.append("related-questions section")

        lists = len(self.soup.find_all(['ul', 'ol']))
        if lists >= 3:
            score += 1
            signals.append("extractable lists")

        points = min(10, score)
        self.results['people_also_ask'] = {
            'score': points,
            'max': 10,
            'question_headings': q_count,
            'direct_answers': direct_answers,
            'faq_schema': faq_schema,
        }

        detail = f"Score: {points}/10"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"
        else:
            detail += " | No PAA optimization detected"

        passed = points >= 5
        self._add_check("People Also Ask Optimization", passed, points, 10, detail, category='snippet')
        if passed:
            self._add_bonus('paa_optimized', "People Also Ask optimization detected")
        else:
            self._add_quick_win("Add question-form subheadings",
                                "Use 5+ question H2/H3s with direct answers and FAQPage schema to win PAA slots.", 'medium')

    def check_knowledge_panel_optimization(self):
        score = 0
        signals = []

        org_schemas = [s for s in self.schema_data
                       if 'Organization' in str(s.get('@type', '')) or 'Brand' in str(s.get('@type', ''))]
        person_schemas = [s for s in self.schema_data if s.get('@type') == 'Person']

        if org_schemas or person_schemas:
            score += 2
            signals.append("Organization/Person entity schema")
        else:
            signals.append("no entity schema")

        logo = False
        if org_schemas and org_schemas[0].get('logo'):
            logo = True
        if not logo and self.soup.find('meta', property='og:image'):
            logo = True
        if logo:
            score += 1
            signals.append("logo/brand image")

        sameas_count = 0
        for schema in self.schema_data:
            sameas = schema.get('sameAs')
            if isinstance(sameas, str) and sameas:
                sameas_count += 1
            elif isinstance(sameas, list):
                sameas_count += len(sameas)
        if sameas_count >= 4:
            score += 2
            signals.append(f"{sameas_count} sameAs identity links")
        elif sameas_count >= 1:
            score += 1
            signals.append(f"{sameas_count} sameAs link(s)")

        kg_links = 0
        for link in self.external_links[:50]:
            host = urlparse(link).netloc.lower()
            if 'wikidata.org' in host or 'wikipedia.org' in host:
                kg_links += 1
        if kg_links > 0:
            score += 2
            signals.append("Wikidata/Wikipedia references")
        else:
            signals.append("no Wikidata/Wikipedia references")

        nav_texts = []
        for a in self.soup.find_all('a', href=True):
            nav_texts.append((a.get_text(' ', strip=True) + ' ' + a['href']).lower())
        has_about = any('about' in t for t in nav_texts)
        has_contact = any('contact' in t for t in nav_texts)
        if has_about:
            score += 1
            signals.append("about page linked")
        if has_contact:
            score += 1
            signals.append("contact page linked")

        title_tag = self.soup.find('title')
        og_site = self.soup.find('meta', property='og:site_name')
        if title_tag and og_site and og_site.get('content'):
            score += 1
            signals.append("brand name in title + og:site_name")

        if any(s.get('@type') == 'WebSite' for s in self.schema_data):
            score += 1
            signals.append("WebSite schema")

        points = min(10, score)
        self.results['knowledge_panel'] = {
            'score': points,
            'max': 10,
            'sameas': sameas_count,
            'kg_links': kg_links,
            'entity_schema': bool(org_schemas or person_schemas),
        }

        detail = f"Score: {points}/10"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"

        passed = points >= 5
        self._add_check("Knowledge Panel Optimization", passed, points, 10, detail, category='entities')
        if passed:
            self._add_bonus('knowledge_panel_ready', "Knowledge panel optimization signals found")
        elif points < 5:
            self._add_quick_win("Build knowledge panel eligibility",
                                "Add entity schema with logo/sameAs, about+contact pages, and Wikidata/Wikipedia links.", 'medium')

    def check_image_search_optimization(self):
        images = self.soup.find_all('img')
        if not images:
            self.results['image_search'] = {'score': 0, 'max': 10, 'images': 0}
            self._add_check("Image Search Optimization", False, 0, 10,
                            "No images on page - no image search visibility possible", category='content')
            return

        total = len(images)
        score = 0
        signals = []

        with_alt = sum(1 for img in images if (img.get('alt') or '').strip())
        alt_ratio = with_alt / total
        if alt_ratio >= 0.95:
            score += 3
            signals.append(f"alt coverage {alt_ratio:.0%}")
        elif alt_ratio >= 0.7:
            score += 2
            signals.append(f"alt coverage {alt_ratio:.0%}")
        elif alt_ratio >= 0.4:
            score += 1
            signals.append(f"alt coverage {alt_ratio:.0%}")

        descriptive = 0
        generic = 0
        for img in images:
            src = img.get('src', '') or img.get('data-src', '')
            filename = urlparse(src).path.split('/')[-1].lower() if src else ''
            if filename and re.match(r'^img[_-]?\d+\.[a-z]+$', filename):
                generic += 1
            elif filename and re.match(r'^[a-z0-9][a-z0-9_-]*\.[a-z]+$', filename) and '-' in filename:
                descriptive += 1
        if descriptive >= max(1, total // 3):
            score += 2
            signals.append("descriptive filenames")
        elif generic > 0:
            signals.append(f"{generic} generic filenames")

        sized = sum(1 for img in images if img.get('width') and img.get('height'))
        if sized / total >= 0.5:
            score += 1
            signals.append("explicit dimensions")

        lazy = sum(1 for img in images if img.get('loading') == 'lazy' or img.get('data-src'))
        if lazy > 0:
            score += 1
            signals.append("lazy loading")

        captions = len(self.soup.find_all('figcaption'))
        if captions > 0:
            score += 1
            signals.append(f"{captions} image captions")

        responsive = len(re.findall(r'srcset\s*=', self.response.text, re.I)) if self.response else 0
        if responsive > 0:
            score += 1
            signals.append("responsive srcset")

        image_schema = False
        for schema in self.schema_data:
            st = str(schema.get('@type', ''))
            if 'ImageObject' in st or schema.get('primaryImageOfPage') or schema.get('image') or schema.get('thumbnailUrl'):
                image_schema = True
                break
        if image_schema:
            score += 1
            signals.append("image markup in structured data")
        elif self.soup.find('meta', property='og:image'):
            score += 1
            signals.append("og:image present")

        points = min(10, score)
        self.results['image_search'] = {
            'score': points,
            'max': 10,
            'images': total,
            'alt_coverage': round(alt_ratio * 100, 1),
        }

        detail = f"Score: {points}/10 | {total} images"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"

        passed = points >= 6
        self._add_check("Image Search Optimization", passed, points, 10, detail, category='content')
        if passed:
            self._add_bonus('image_search_ready', "Image search optimization is strong")
        elif alt_ratio < 0.95:
            self._add_quick_win("Optimize images for image search",
                                "Add descriptive alt text, filenames, captions, and ImageObject markup.", 'medium')

    def check_video_search_optimization(self):
        video_tags = self.soup.find_all('video')
        video_iframes = []
        for frame in self.soup.find_all('iframe'):
            src = (frame.get('src') or '').lower()
            if any(host in src for host in ('youtube', 'youtu.be', 'vimeo', 'wistia',
                                            'dailymotion', 'brightcove', 'vidyard')):
                video_iframes.append(frame)
        video_schema = [s for s in self.schema_data if 'VideoObject' in str(s.get('@type', ''))]
        total_videos = len(video_tags) + len(video_iframes) + len(video_schema)

        if total_videos == 0:
            self.results['video_search'] = {'score': 5, 'max': 10, 'videos': 0}
            self._add_check("Video Search Optimization", True, 5, 10,
                            "No video content detected (neutral score)", category='content')
            return

        score = 0
        signals = []

        score += 2
        signals.append(f"{len(video_tags) + len(video_iframes)} video embed(s)/tag(s)")

        if video_schema:
            score += 3
            signals.append("VideoObject schema")
            v = video_schema[0]
            if v.get('name') or v.get('headline'):
                score += 1
            if v.get('description'):
                score += 1
            if v.get('thumbnailUrl') or v.get('thumbnail'):
                score += 1
            if v.get('uploadDate') or v.get('datePublished'):
                score += 1
            if v.get('duration'):
                score += 1
        else:
            signals.append("no VideoObject schema")

        text_lower = self.page_text.lower()
        transcript_cues = ('transcript', 'watch time', 'video description', 'in this video',
                           'timestamps', 'chapter markers')
        if any(c in text_lower for c in transcript_cues):
            score += 1
            signals.append("transcript/description cues")
        elif len(video_tags) + len(video_iframes) > 0 and len(self.page_text.split()) >= 500:
            score += 1
            signals.append("supporting text near video")

        if self.soup.find('meta', property='og:image') or self.soup.find('meta', attrs={'name': 'twitter:card'}):
            score += 1
            signals.append("share/thumbnail meta")

        points = min(10, score)
        self.results['video_search'] = {
            'score': points,
            'max': 10,
            'videos': total_videos,
            'video_schema': bool(video_schema),
        }

        detail = f"Score: {points}/10 | {total_videos} video signals"
        if signals:
            detail += f" | Signals: {', '.join(signals)}"

        passed = points >= 6
        self._add_check("Video Search Optimization", passed, points, 10, detail, category='content')
        if passed:
            self._add_bonus('video_search_ready', "Video search optimization is strong")
        else:
            self._add_quick_win("Optimize videos for search",
                                "Add VideoObject schema with thumbnail, duration, description, and supporting text.", 'medium')

    def check_keyword_cannibalization(self):
        issues = []
        stop_words = {'the', 'a', 'an', 'and', 'or', 'of', 'for', 'to', 'in', 'on',
                      'with', 'your', 'our', 'how', 'what', 'why', 'best', 'top'}

        def significant_words(text):
            return [w for w in re.findall(r'[a-z0-9]+', text.lower())
                    if w not in stop_words and len(w) > 2]

        headings = []
        for tag in self.soup.find_all(['h1', 'h2', 'h3']):
            text = tag.get_text(' ', strip=True)
            if text:
                headings.append(text)

        heading_phrases = []
        for h in headings:
            words = significant_words(h)
            if len(words) >= 3:
                heading_phrases.append(' '.join(words[:3]))
            elif len(words) == 2:
                heading_phrases.append(' '.join(words))

        phrase_counts = Counter(heading_phrases)
        repeated = {p: c for p, c in phrase_counts.items() if c >= 2 and p}

        severe = {p: c for p, c in repeated.items() if c >= 3}
        mild = {p: c for p, c in repeated.items() if c == 2 and p not in severe}

        if severe:
            worst = max(severe.items(), key=lambda kv: kv[1])
            issues.append(f"target phrase '{worst[0]}' appears in {worst[1]} headings")
        if mild:
            issues.append(f"{len(mild)} phrase(s) repeated across 2 headings")

        anchor_map = {}
        base_domain = urlparse(self.url).netloc
        for a in self.soup.find_all('a', href=True):
            href = a['href'].strip()
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue
            full = urljoin(self.url, href)
            if urlparse(full).netloc != base_domain:
                continue
            anchor = a.get_text(' ', strip=True).lower()
            if len(anchor.split()) >= 2:
                anchor_map.setdefault(anchor, set()).add(full)

        conflicting_anchors = {anc: urls for anc, urls in anchor_map.items() if len(urls) >= 3}
        if conflicting_anchors:
            sample = next(iter(conflicting_anchors))
            issues.append(f"anchor '{sample[:30]}' points to {len(conflicting_anchors[sample])} different pages")

        title_tag = self.soup.find('title')
        h1_tag = self.soup.find('h1')
        title_words = significant_words(title_tag.get_text(' ', strip=True))[:3] if title_tag else []
        h1_words = significant_words(h1_tag.get_text(' ', strip=True))[:3] if h1_tag else []
        if title_words and h1_words and not set(title_words) & set(h1_words):
            issues.append("title and H1 target different keyword phrases")

        points = 8
        if severe:
            points -= 3
        if mild:
            points -= 2
        if conflicting_anchors:
            points -= 2
        if title_words and h1_words and not set(title_words) & set(h1_words):
            points -= 1
        points = max(0, points)

        self.results['cannibalization'] = {
            'score': points,
            'max': 8,
            'issues': issues,
            'repeated_phrases': repeated,
            'conflicting_anchors': len(conflicting_anchors),
        }

        if issues:
            detail = f"Score: {points}/8 | " + "; ".join(issues[:3])
        else:
            detail = f"Score: {points}/8 | No within-page cannibalization signals detected"

        passed = points >= 6
        self._add_check("Keyword Cannibalization", passed, points, 8, detail, category='content')
        if not passed:
            self._add_quick_win("Resolve keyword cannibalization",
                                "Consolidate overlapping sections, differentiate heading targets, and unify anchor text per destination.", 'high')

    def check_content_gap_analysis(self):
        words = len(self.page_text.split())
        text_lower = self.page_text.lower()
        my_headings = []
        for tag in self.soup.find_all(['h2', 'h3']):
            text = tag.get_text(' ', strip=True)
            if text:
                my_headings.append(text.lower())

        my_schema_types = set()
        for schema in self.schema_data:
            st = schema.get('@type')
            if isinstance(st, list):
                for item in st:
                    my_schema_types.add(str(item))
            elif st:
                my_schema_types.add(str(st))

        my_images = len(self.soup.find_all('img'))

        gaps = {
            'mode': 'heuristic',
            'competitors_analyzed': 0,
            'competitors_failed': 0,
            'word_gap': 0,
            'media_gap': 0,
            'missing_subtopics': [],
            'missing_schema': [],
            'coverage_pct': 0.0,
        }

        competitor_words = []
        competitor_headings = []
        competitor_schema = set()
        competitor_images = []
        analyzed = 0
        failed = 0

        for comp_url in self.competitors[:5]:
            try:
                resp = requests.get(comp_url, headers=self.headers, timeout=self.timeout,
                                    allow_redirects=True, verify=False)
                if resp.status_code != 200:
                    failed += 1
                    continue
                comp_soup = BeautifulSoup(resp.text, 'html.parser')
                comp_text = comp_soup.get_text(separator=' ', strip=True)
                competitor_words.append(len(comp_text.split()))
                for tag in comp_soup.find_all(['h2', 'h3']):
                    t = tag.get_text(' ', strip=True)
                    if t and len(t) <= 90:
                        competitor_headings.append(t.lower())
                for script in comp_soup.find_all('script', type='application/ld+json'):
                    try:
                        data = json.loads(script.string)
                        items = data if isinstance(data, list) else [data]
                        for item in items:
                            if isinstance(item, dict) and item.get('@type'):
                                st = item['@type']
                                if isinstance(st, list):
                                    for s in st:
                                        competitor_schema.add(str(s))
                                else:
                                    competitor_schema.add(str(st))
                    except Exception:
                        pass
                competitor_images.append(len(comp_soup.find_all('img')))
                analyzed += 1
            except Exception:
                failed += 1

        gaps['competitors_analyzed'] = analyzed
        gaps['competitors_failed'] = failed

        if analyzed > 0:
            gaps['mode'] = 'competitors'
            avg_comp_words = sum(competitor_words) / len(competitor_words)
            gaps['word_gap'] = int(max(0, avg_comp_words - words))
            avg_comp_images = sum(competitor_images) / len(competitor_images)
            gaps['media_gap'] = int(max(0, avg_comp_images - my_images))

            stop = {'the', 'a', 'an', 'and', 'or', 'of', 'for', 'to', 'in', 'on', 'with'}
            missing = []
            for ch in competitor_headings:
                ch_words = [w for w in re.findall(r'[a-z0-9]+', ch) if w not in stop and len(w) > 2]
                if len(ch_words) < 2:
                    continue
                phrase = ' '.join(ch_words[:3])
                if phrase and phrase not in text_lower:
                    if ch not in missing:
                        missing.append(ch)
            gaps['missing_subtopics'] = missing[:8]
            missing_schema = sorted(s for s in competitor_schema
                                    if s not in my_schema_types
                                    and s in ('FAQPage', 'HowTo', 'Article', 'Product', 'Review',
                                              'VideoObject', 'BreadcrumbList', 'Organization'))
            gaps['missing_schema'] = missing_schema[:6]
            total_expected = max(1, len(set(competitor_headings)))
            covered = max(0, total_expected - len(missing))
            gaps['coverage_pct'] = round(covered / total_expected * 100, 1)
        else:
            expected_subtopics = [
                'benefits', 'examples', 'comparison', 'pricing', 'how it works',
                'pros and cons', 'alternatives', 'steps', 'faq', 'case study',
                'statistics', 'review', 'guide', 'tips',
            ]
            missing = []
            present = 0
            for sub in expected_subtopics:
                if sub in text_lower or any(sub in h for h in my_headings):
                    present += 1
                else:
                    missing.append(sub)
            gaps['missing_subtopics'] = missing
            benchmark = 1800
            gaps['word_gap'] = max(0, benchmark - words)
            expected_schema = {'Article', 'BreadcrumbList', 'Organization'}
            gaps['missing_schema'] = sorted(s for s in expected_schema if s not in my_schema_types)
            gaps['coverage_pct'] = round(present / len(expected_subtopics) * 100, 1)

        points = 0
        if gaps['word_gap'] == 0:
            points += 4
        elif gaps['word_gap'] < 400:
            points += 3
        elif gaps['word_gap'] < 800:
            points += 2
        elif gaps['word_gap'] < 1400:
            points += 1

        coverage = gaps['coverage_pct']
        if coverage >= 85:
            points += 4
        elif coverage >= 65:
            points += 3
        elif coverage >= 45:
            points += 2
        elif coverage >= 25:
            points += 1

        if not gaps['missing_schema']:
            points += 2
        elif len(gaps['missing_schema']) <= 1:
            points += 1

        if gaps['media_gap'] <= 0:
            points += 2
        elif gaps['media_gap'] <= 3:
            points += 1

        points = min(12, points)
        self.results['content_gap'] = gaps

        mode_label = "competitor comparison" if gaps['mode'] == 'competitors' else "heuristic benchmark"
        detail = (f"Score: {points}/12 | Mode: {mode_label} | Coverage: {coverage:.0f}%"
                  f" | Word gap: {gaps['word_gap']:,}")
        if gaps['missing_subtopics']:
            preview = "; ".join(gaps['missing_subtopics'][:4])
            detail += f" | Missing: {preview}"

        passed = points >= 7
        self._add_check("Content Gap Analysis", passed, points, 12, detail, category='competitive')
        if gaps['word_gap'] > 600 or coverage < 65:
            self._add_quick_win("Close content gaps vs competitors",
                                f"Cover {len(gaps['missing_subtopics'])} missing subtopics and close a {gaps['word_gap']:,}-word depth gap.", 'high')
        if analyzed == 0:
            self.results['info'].append("Tip: pass --competitors url1,url2 for real competitor gap analysis")

    def check_topic_authority(self):
        words = len(self.page_text.split())
        subtopics = len(self.soup.find_all(['h2', 'h3']))
        unique_internal = len(set(self.internal_links))
        text_lower = self.page_text.lower()

        authority_links = 0
        for link in self.external_links[:50]:
            host = urlparse(link).netloc.lower()
            if (host.endswith('.gov') or host.endswith('.edu') or 'wikipedia.org' in host
                    or 'britannica.com' in host or 'wikidata.org' in host):
                authority_links += 1

        citation_patterns = [r'\[\d+\]', r'source[s]?:', r'according to', r'research shows',
                             r'study (?:found|shows)', r'data shows']
        citations = sum(1 for p in citation_patterns if re.search(p, self.page_text, re.I))

        schema_rich = len(set(str(s.get('@type', '')) for s in self.schema_data))
        freshness_pts = self.results.get('freshness', 0)

        depth_ratio = min(1.0, words / 2500)
        breadth_ratio = min(1.0, subtopics / 12)
        internal_ratio = min(1.0, unique_internal / 15)
        citation_ratio = min(1.0, authority_links / 3)
        sourcing_ratio = min(1.0, citations / 4)
        schema_ratio = min(1.0, schema_rich / 4)
        freshness_ratio = min(1.0, freshness_pts / 10)

        authority_pct = round(100 * (
            0.24 * depth_ratio +
            0.18 * breadth_ratio +
            0.16 * internal_ratio +
            0.14 * citation_ratio +
            0.10 * sourcing_ratio +
            0.10 * schema_ratio +
            0.08 * freshness_ratio
        ), 1)

        self.results['topic_authority'] = authority_pct
        points = min(10, int(round(authority_pct / 10)))

        signals = [
            f"depth {depth_ratio:.0%}",
            f"breadth {breadth_ratio:.0%}",
            f"internal {internal_ratio:.0%}",
            f"citations {citation_ratio:.0%}",
            f"schema {schema_ratio:.0%}",
        ]
        detail = f"Authority {authority_pct:.1f}% | Score {points}/10 | " + ", ".join(signals)

        passed = points >= 6
        self._add_check("Topic Authority Score", passed, points, 10, detail, category='content')
        if passed:
            self._add_bonus('strong_topic_authority', "Strong topic authority signals")
        else:
            self._add_quick_win("Build topic authority",
                                "Deepen coverage, add sourced citations, and earn links from .gov/.edu/wiki references.", 'high')

    def _compute_search_visibility(self):
        max_score = self.results.get('max_score', 0)
        final_score = self.results.get('final_score', self.results.get('score', 0))
        final_pct = (final_score / max_score * 100) if max_score > 0 else 0.0

        intent_pct = (self.results.get('intent_alignment', 0) / 12) * 100
        snippet_pct = float(self.results.get('featured_snippet', {}).get('score', 0)) / 10 * 100
        paa_pct = float(self.results.get('people_also_ask', {}).get('score', 0)) / 10 * 100
        authority_pct = float(self.results.get('topic_authority', 0))
        freshness_pct = float(self.results.get('freshness', 0)) / 10 * 100
        kp_pct = float(self.results.get('knowledge_panel', {}).get('score', 0)) / 10 * 100
        img_pct = float(self.results.get('image_search', {}).get('score', 0)) / 10 * 100
        vid_pct = float(self.results.get('video_search', {}).get('score', 0)) / 10 * 100
        voice_deep_pct = float(self.results.get('voice_search_deep', {}).get('score', 0)) / 12 * 100
        visual_pct = float(self.results.get('visual_search', {}).get('score', 0)) / 10 * 100
        local_pct = float(self.results.get('local_pack', {}).get('score', 0)) / 10 * 100
        vid_snip_pct = float(self.results.get('video_featured_snippet', {}).get('score', 0)) / 10 * 100
        img_snip_pct = float(self.results.get('image_featured_snippet', {}).get('score', 0)) / 10 * 100
        ranking_pct = float(self.results.get('ranking_weighted_pct', 0))

        components = {
            'ranking_factors': (ranking_pct, 0.22),
            'overall_score': (final_pct, 0.12),
            'intent_alignment': (intent_pct, 0.11),
            'topic_authority': (authority_pct, 0.11),
            'featured_snippet': (snippet_pct, 0.09),
            'people_also_ask': (paa_pct, 0.07),
            'freshness': (freshness_pct, 0.07),
            'knowledge_panel': (kp_pct, 0.05),
            'voice_search_deep': (voice_deep_pct, 0.04),
            'image_search': (img_pct, 0.03),
            'video_search': (vid_pct, 0.03),
            'visual_search': (visual_pct, 0.02),
            'local_pack': (local_pct, 0.02),
            'video_featured_snippet': (vid_snip_pct, 0.01),
            'image_featured_snippet': (img_snip_pct, 0.01),
        }

        visibility = 0.0
        breakdown = {}
        for name, (value, weight) in components.items():
            clamped = max(0.0, min(100.0, float(value)))
            breakdown[name] = {'value': round(clamped, 1), 'weight': weight}
            visibility += clamped * weight

        self.results['search_visibility'] = round(visibility, 1)
        self.results['search_visibility_breakdown'] = breakdown

    def _compute_ranking_potential(self):
        ranking_pct = float(self.results.get('ranking_weighted_pct', 0) or 0)
        visibility = float(self.results.get('search_visibility', 0) or 0)
        authority = float(self.results.get('topic_authority', 0) or 0)
        technical = float(self.results.get('technical_health', {}).get('pct', 0) or 0)
        freshness = float(self.results.get('freshness', 0) or 0) * 10
        intent_align = float(self.results.get('intent_alignment', 0) or 0) / 12 * 100
        competitiveness = float(self.results.get('content_competitiveness', {}).get('score', 0) or 0)

        potential = round(
            0.22 * ranking_pct +
            0.16 * visibility +
            0.14 * authority +
            0.14 * technical +
            0.10 * freshness +
            0.12 * intent_align +
            0.12 * competitiveness,
            1
        )
        potential = max(0.0, min(100.0, potential))

        if potential >= 80:
            label = 'Elite'
        elif potential >= 65:
            label = 'Strong'
        elif potential >= 50:
            label = 'Moderate'
        elif potential >= 35:
            label = 'Limited'
        else:
            label = 'Low'

        inputs = {
            'ranking_factors': ranking_pct,
            'search_visibility': visibility,
            'topic_authority': authority,
            'technical_health': technical,
            'freshness': freshness,
            'intent_alignment': intent_align,
            'content_competitiveness': competitiveness,
        }
        limiting = [k for k, v in sorted(inputs.items(), key=lambda kv: kv[1]) if v < 60][:4]

        self.results['ranking_potential'] = {
            'potential': potential,
            'label': label,
            'inputs': {k: round(v, 1) for k, v in inputs.items()},
            'limiting_factors': limiting,
        }

    def _compute_content_competitiveness(self):
        gap = self.results.get('content_gap', {})
        coverage = float(gap.get('coverage_pct', 50) or 50)
        word_gap = float(gap.get('word_gap', 0) or 0)
        authority = float(self.results.get('topic_authority', 0) or 0)
        freshness = float(self.results.get('freshness', 0) or 0) * 10
        snippet = float(self.results.get('featured_snippet', {}).get('score', 0) or 0) / 10 * 100
        paa = float(self.results.get('people_also_ask', {}).get('score', 0) or 0) / 10 * 100
        intent_align = float(self.results.get('intent_alignment', 0) or 0) / 12 * 100
        depth_pct = max(0.0, min(100.0, 100.0 - (word_gap / 20.0)))

        score = round(
            0.22 * coverage +
            0.18 * depth_pct +
            0.16 * authority +
            0.12 * freshness +
            0.12 * snippet +
            0.08 * paa +
            0.12 * intent_align,
            1
        )
        score = max(0.0, min(100.0, score))

        if score >= 80:
            label = 'Leader'
        elif score >= 65:
            label = 'Challenger'
        elif score >= 50:
            label = 'Competitor'
        elif score >= 35:
            label = 'Follower'
        else:
            label = 'Laggard'

        self.results['content_competitiveness'] = {
            'score': score,
            'label': label,
            'coverage_pct': coverage,
            'depth_pct': round(depth_pct, 1),
            'word_gap': int(word_gap),
        }

    def _compute_technical_health(self):
        tech_cats = ['technical', 'performance', 'security', 'mobile', 'general']
        tech_score = 0
        tech_max = 0
        cat_breakdown = {}

        for cat in tech_cats:
            data = self.results['category_scores'].get(cat)
            if not data:
                continue
            pct = (data['score'] / data['max'] * 100) if data['max'] > 0 else 0.0
            cat_breakdown[cat] = {'score': data['score'], 'max': data['max'], 'pct': round(pct, 1)}
            tech_score += data['score']
            tech_max += data['max']

        tech_pct = (tech_score / tech_max * 100) if tech_max > 0 else 0.0
        tech_pct = round(tech_pct, 1)

        if tech_pct >= 90:
            grade = 'A+'
        elif tech_pct >= 80:
            grade = 'A'
        elif tech_pct >= 70:
            grade = 'B'
        elif tech_pct >= 60:
            grade = 'C'
        elif tech_pct >= 50:
            grade = 'D'
        else:
            grade = 'F'

        self.results['technical_health'] = {
            'pct': tech_pct,
            'grade': grade,
            'score': tech_score,
            'max': tech_max,
            'breakdown': cat_breakdown,
        }

    def _build_competitive_position(self):
        visibility = float(self.results.get('search_visibility', 0))
        authority = float(self.results.get('topic_authority', 0))
        freshness_pct = float(self.results.get('freshness', 0)) * 10
        gap = self.results.get('content_gap', {})
        depth_pct = max(0.0, min(100.0, 100.0 - (float(gap.get('word_gap', 0)) / 20.0)))
        coverage_pct = float(gap.get('coverage_pct', 50))

        composite = round(
            0.35 * visibility +
            0.30 * authority +
            0.15 * freshness_pct +
            0.20 * ((depth_pct + coverage_pct) / 2),
            1
        )

        if composite >= 75:
            label = 'Leader'
        elif composite >= 55:
            label = 'Challenger'
        elif composite >= 35:
            label = 'Competitor'
        else:
            label = 'Follower'

        points = []
        points.append(f"Search visibility {visibility:.0f}% feeds competitive standing")
        if gap.get('mode') == 'competitors':
            points.append(f"Word depth gap of {gap.get('word_gap', 0):,} words vs competitor average")
        else:
            points.append(f"Content coverage at {coverage_pct:.0f}% of expected subtopics")
        points.append(f"Topic authority {authority:.0f}%")
        if label == 'Leader':
            points.append("Position: protect rankings with refresh cadence and incremental updates")
        elif label == 'Challenger':
            points.append("Position: close remaining depth/authority gaps to overtake leaders")
        elif label == 'Competitor':
            points.append("Position: differentiate with unique data, media, and internal link strength")
        else:
            points.append("Position: prioritize foundational fixes before competing on head terms")

        self.results['competitive_position'] = {
            'label': label,
            'composite': composite,
            'depth_pct': round(depth_pct, 1),
            'coverage_pct': coverage_pct,
            'points': points,
        }

    def _build_intent_optimization(self):
        primary = self.results.get('search_intent', 'informational')
        secondary = self.results.get('secondary_intents', [])
        alignment = self.results.get('intent_alignment', 0)
        items = []

        intent_playbooks = {
            'informational': [
                "Lead with a 40-80 word direct answer under the primary question heading.",
                "Use step-by-step sections, definition sentences, and example blocks for extractability.",
                "Add FAQPage schema covering the top follow-up questions.",
            ],
            'commercial': [
                "Add a comparison table and an explicit recommendation/verdict block.",
                "Include pros and cons, alternatives, and pricing context near the top.",
                "Use schema.org Review/AggregateRating where reviews are genuinely present.",
            ],
            'transactional': [
                "Place primary CTAs above the fold and repeat them at decision points.",
                "Keep the title/meta action-oriented (buy, book, sign up, get started).",
                "Reduce friction: clear pricing, trust signals, and a single dominant action.",
            ],
            'navigational': [
                "Keep brand/product name first in the title tag and H1.",
                "Ensure the target destination is one click from the main navigation.",
                "Add Organization/WebSite schema so brand entities resolve cleanly.",
            ],
        }

        for line in intent_playbooks.get(primary, intent_playbooks['informational']):
            items.append(f"[{primary}] {line}")

        if secondary:
            items.append(f"Secondary intent ({', '.join(secondary)}): acknowledge it in an H2 section without diluting the primary focus.")

        if alignment < 7:
            items.append(f"Intent alignment is {alignment}/12 - rewrite title, H1, and meta description to match {primary} intent signals.")
        else:
            items.append(f"Intent alignment is strong ({alignment}/12) - maintain format consistency on future updates.")

        if self.results.get('search_visibility', 0) < 50:
            items.append("Search visibility is under 50% - fix snippet/PAA gaps first; they compound fastest for intent capture.")

        self.results['intent_optimization'] = items[:6]

    def _build_content_strategy(self):
        items = []
        gap = self.results.get('content_gap', {})
        cannibalization = self.results.get('cannibalization', {})
        snippet = self.results.get('featured_snippet', {})
        paa = self.results.get('people_also_ask', {})
        authority = self.results.get('topic_authority', 0)
        visibility = self.results.get('search_visibility', 0)
        primary = self.results.get('search_intent', 'informational')

        missing = gap.get('missing_subtopics', [])
        if missing:
            items.append("Subtopics to cover next: " + ", ".join(missing[:6]) + ".")
        if gap.get('word_gap', 0) > 400:
            items.append(f"Expand depth by ~{gap.get('word_gap', 0):,} words to match the competitive benchmark.")
        if gap.get('missing_schema'):
            items.append("Add missing structured data: " + ", ".join(gap['missing_schema']) + ".")
        if cannibalization.get('issues'):
            items.append("Cannibalization cleanup: " + "; ".join(cannibalization['issues'][:2]) + ".")
        if int(snippet.get('score', 0)) < 6:
            items.append("Reformat key answers into 20-90 word blocks under question headings to target featured snippets.")
        if int(paa.get('score', 0)) < 5:
            items.append("Add 5+ question-form subheadings with direct answers and FAQPage schema for PAA coverage.")
        if float(authority) < 60:
            items.append("Publish 2-3 supporting cluster pages and interlink them to raise topic authority.")
        if float(visibility) < 50:
            items.append("Search visibility is the growth bottleneck: prioritize ranking-factor fixes flagged in priority actions.")
        if primary == 'commercial':
            items.append("Commercial intent: add comparison tables, verdict blocks, and updated review dates.")
        elif primary == 'transactional':
            items.append("Transactional intent: tighten CTA placement, schema (Product/Offer), and trust elements.")

        img = self.results.get('image_search', {})
        if int(img.get('score', 0)) and int(img.get('score', 0)) < 6:
            items.append("Image search: add alt text, descriptive filenames, captions, and image markup.")
        vid = self.results.get('video_search', {})
        if int(vid.get('videos', 0)) > 0 and int(vid.get('score', 0)) < 6:
            items.append("Video search: add VideoObject schema with thumbnail, duration, and transcript.")

        seen = set()
        unique = []
        for item in items:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        self.results['content_strategy'] = unique[:8]

    def _print_intent_optimization(self):
        items = self.results.get('intent_optimization', [])
        primary = self.results.get('search_intent', 'unknown')
        if not items:
            return
        print(f"    |{Fore.WHITE}{Style.BRIGHT}              SEARCH INTENT OPTIMIZATION ({primary.upper()}){Style.RESET_ALL}{' ' * max(0, 47 - len(primary))}|")
        print(f"    |{'-'*70}|")
        for i, item in enumerate(items, 1):
            words = item.split()
            lines = []
            current = ''
            for word in words:
                candidate = (current + ' ' + word).strip()
                if len(candidate) > 64 and current:
                    lines.append(current)
                    current = word
                else:
                    current = candidate
            if current:
                lines.append(current)
            for line_i, chunk in enumerate(lines):
                if line_i == 0:
                    print(f"    | {Fore.CYAN}{i}.{Style.RESET_ALL} {chunk}")
                else:
                    print(f"    |    {chunk}")
        print(f"    +================================================================+")

    def _print_competitive_position(self):
        pos = self.results.get('competitive_position', {})
        if not pos:
            return
        label = pos.get('label', 'Unknown')
        composite = pos.get('composite', 0)
        if label == 'Leader':
            label_color = Fore.GREEN
        elif label == 'Challenger':
            label_color = Fore.CYAN
        elif label == 'Competitor':
            label_color = Fore.YELLOW
        else:
            label_color = Fore.RED
        print(f"    |{Fore.WHITE}{Style.BRIGHT}                 COMPETITIVE POSITION ANALYSIS{Style.RESET_ALL}{' ' * 15}|")
        print(f"    |{'-'*70}|")
        print(f"    | Position: {label_color}{label:<14}{Style.RESET_ALL} Composite: {self._pct_color(composite)}{composite:.1f}%{Style.RESET_ALL}")
        bar = self._gauge(composite)
        print(f"    | STANDING {self._pct_color(composite)}{bar}{Style.RESET_ALL} {composite:3.0f}%")
        for point in pos.get('points', [])[:5]:
            words = point.split()
            lines = []
            current = ''
            for word in words:
                candidate = (current + ' ' + word).strip()
                if len(candidate) > 64 and current:
                    lines.append(current)
                    current = word
                else:
                    current = candidate
            if current:
                lines.append(current)
            for line_i, chunk in enumerate(lines):
                if line_i == 0:
                    print(f"    | - {chunk}")
                else:
                    print(f"    |   {chunk}")
        print(f"    +================================================================+")

    def _print_content_strategy(self):
        items = self.results.get('content_strategy', [])
        if not items:
            return
        print(f"    |{Fore.WHITE}{Style.BRIGHT}                 CONTENT STRATEGY RECOMMENDATIONS{Style.RESET_ALL}{' ' * 12}|")
        print(f"    |{'-'*70}|")
        for i, item in enumerate(items, 1):
            words = item.split()
            lines = []
            current = ''
            for word in words:
                candidate = (current + ' ' + word).strip()
                if len(candidate) > 64 and current:
                    lines.append(current)
                    current = word
                else:
                    current = candidate
            if current:
                lines.append(current)
            for line_i, chunk in enumerate(lines):
                if line_i == 0:
                    print(f"    | {Fore.YELLOW}{i}.{Style.RESET_ALL} {chunk}")
                else:
                    print(f"    |    {chunk}")
        print(f"    +================================================================+")

    def run(self):
        print(BANNER)
        print(f"    {Fore.YELLOW}[*] Analyzing: {self.url}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

        if not self.fetch_page():
            print(f"\n    {Fore.RED}[-] Cannot fetch page. Check URL and try again.{Style.RESET_ALL}")
            return self.results

        print(f"\n    {Fore.YELLOW}[*] Running SEO Checks...{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}{'-'*70}{Style.RESET_ALL}")

        self.check_ssl()
        self.check_title()
        self.check_meta_description()
        self.check_meta_keywords()
        self.check_headings()
        self.check_images()
        self.check_image_seo()
        self.check_links()
        self.check_internal_link_structure()
        self.check_anchor_text_distribution()
        self.check_outbound_link_quality()
        self.check_og_tags()
        self.check_twitter_card()
        self.check_social_media_completeness()
        self.check_robots_meta()
        self.check_canonical()
        self.check_viewport()
        self.check_lang()
        self.check_favicon()
        self.check_word_count()
        self.check_content_length_analysis()
        self.check_page_size()
        self.check_load_time()
        self.check_core_web_vitals()
        self.check_url_structure()
        self.check_content_quality()
        self.check_structured_data()
        self.check_schema_validation()
        self.check_sitemap()
        self.check_robots_txt()
        self.check_https_redirect()
        self.check_readability()
        self.check_keyword_density()
        self.check_html_validation()
        self.check_hreflang()
        self.check_accelerated_mobile()
        self.check_mobile_first_indexing()
        self.check_voice_search_optimization()
        self.check_eeat_signals()
        self.check_hidden_text()
        self.check_semantic_html()
        self.check_accessibility_basics()
        self.check_page_hints()
        self.check_lazy_loading()

        print(f"\n    {Fore.YELLOW}[*] Running v6.0 Advanced Checks...{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}{'-'*70}{Style.RESET_ALL}")
        self.check_content_freshness()
        self.check_content_depth_competition()
        self.check_seasonal_content()
        self.check_content_quality_index()
        self.check_ai_llm_readiness()
        self.check_internal_linking_architecture()
        self.check_topic_clusters()
        self.check_entity_recognition()
        self.check_knowledge_graph_signals()

        print(f"\n    {Fore.YELLOW}[*] Running Search Intelligence Checks...{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}{'-'*70}{Style.RESET_ALL}")
        self.check_search_intent_analysis()
        self.check_featured_snippet_optimization()
        self.check_people_also_ask_optimization()
        self.check_knowledge_panel_optimization()
        self.check_image_search_optimization()
        self.check_video_search_optimization()
        self.check_keyword_cannibalization()
        self.check_content_gap_analysis()
        self.check_topic_authority()

        print(f"\n    {Fore.YELLOW}[*] Running v8.0 Deep Optimization Checks...{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}{'-'*70}{Style.RESET_ALL}")
        self.check_voice_search_deep_analysis()
        self.check_visual_search_optimization()
        self.check_video_featured_snippet_optimization()
        self.check_image_featured_snippet_optimization()
        self.check_local_pack_optimization()

        if self.check_links_enabled and (self.internal_links or self.external_links):
            self.check_broken_links()

        total_penalty = sum(p['penalty'] for p in self.results['penalties'])
        total_bonus = sum(b['bonus'] for b in self.results['bonuses'])
        self.results['penalty_total'] = total_penalty
        self.results['bonus_total'] = total_bonus
        self.results['final_score'] = max(0, self.results['score'] - total_penalty + total_bonus)

        self._compute_ranking_factors()
        self._compute_technical_health()
        self._compute_search_visibility()
        self._compute_content_competitiveness()
        self._compute_ranking_potential()
        self._build_priority_actions()
        self._build_strategy()
        self._build_competitive_position()
        self._build_intent_optimization()
        self._build_content_strategy()

        if total_penalty > 0:
            print(f"\n    {Fore.RED}[*] Penalties applied: -{total_penalty} points{Style.RESET_ALL}")
        if total_bonus > 0:
            print(f"    {Fore.GREEN}[*] Bonuses earned: +{total_bonus} points{Style.RESET_ALL}")

        print(f"\n    {Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        self._print_health_dashboard()
        self._print_summary()
        self._print_priority_actions()
        self._print_intent_optimization()
        self._print_competitive_position()
        self._print_strategy()
        self._print_content_strategy()
        return self.results

    def _get_grade(self, pct):
        if pct >= 80:
            return 'A', f"{Fore.GREEN}A", "EXCELLENT - Great SEO!"
        elif pct >= 60:
            return 'B', f"{Fore.YELLOW}B", "GOOD - Some improvements needed"
        elif pct >= 40:
            return 'C', f"{Fore.YELLOW}C", "FAIR - Significant improvements needed"
        elif pct >= 20:
            return 'D', f"{Fore.RED}D", "POOR - Major SEO issues"
        else:
            return 'F', f"{Fore.RED}F", "FAILING - Critical SEO problems"

    def _print_summary(self):
        score = self.results['score']
        max_score = self.results['max_score']
        pct = (score / max_score * 100) if max_score > 0 else 0
        final_score = self.results.get('final_score', score)
        final_pct = (final_score / max_score * 100) if max_score > 0 else 0

        grade_letter, grade_color, verdict = self._get_grade(final_pct)

        cat_lines = ''
        for cat, data in sorted(self.results['category_scores'].items()):
            cat_pct = (data['score'] / data['max'] * 100) if data['max'] > 0 else 0
            if cat_pct >= 80:
                color = Fore.GREEN
                letter = 'A'
            elif cat_pct >= 60:
                color = Fore.CYAN
                letter = 'B'
            elif cat_pct >= 40:
                color = Fore.YELLOW
                letter = 'C'
            elif cat_pct >= 20:
                color = Fore.RED
                letter = 'D'
            else:
                color = Fore.RED
                letter = 'F'
            cat_lines += f"    |  {color}{cat.upper():<16}{Style.RESET_ALL} [{letter}] {data['score']:>3}/{data['max']:<3} ({cat_pct:.0f}%){' '*(25-len(cat))}|\n"

        print(f"""
    +================================================================+
    |                      SEO SCORE SUMMARY                         |
    +================================================================+
    |  {Fore.WHITE}URL:{Style.RESET_ALL}         {self.url[:53]:<53}  |
    |  {Fore.WHITE}Raw Score:{Style.RESET_ALL}    {grade_color}{score}/{max_score} ({pct:.0f}%){Style.RESET_ALL}{' '*(34-len(f'{score}/{max_score} ({pct:.0f}%)'))}|
    |  {Fore.WHITE}Final Score:{Style.RESET_ALL}  {grade_color}{final_score}/{max_score} ({final_pct:.0f}%){Style.RESET_ALL}{' '*(32-len(f'{final_score}/{max_score} ({final_pct:.0f}%)'))}|
    |  {Fore.WHITE}Grade:{Style.RESET_ALL}       {grade_color}{grade_letter}{Style.RESET_ALL} - {verdict}{' '*(34-len(verdict))}|
    |  {Fore.WHITE}Penalties:{Style.RESET_ALL}   {Fore.RED}-{self.results.get('penalty_total', 0)} pts{Style.RESET_ALL}{' '*(48-len(f'-{self.results.get("penalty_total", 0)} pts'))}|
    |  {Fore.WHITE}Bonuses:{Style.RESET_ALL}     {Fore.GREEN}+{self.results.get('bonus_total', 0)} pts{Style.RESET_ALL}{' '*(50-len(f'+{self.results.get("bonus_total", 0)} pts'))}|
    +================================================================+
    |  {Fore.WHITE}{Style.BRIGHT}CATEGORY BREAKDOWN{Style.RESET_ALL}{' '*(50)}|
    |{'-'*70}|
{cat_lines}    +================================================================+""")

        if self.results['penalties']:
            print(f"    |  {Fore.RED}PENALTIES:{Style.RESET_ALL}{' '*57}|")
            print(f"    |{'-'*70}|")
            for p in self.results['penalties']:
                print(f"    |  {Fore.RED}- {p['detail'][:64]:<64}{Style.RESET_ALL}  |")

        if self.results['bonuses']:
            print(f"    |  {Fore.GREEN}BONUSES:{Style.RESET_ALL}{' '*60}|")
            print(f"    |{'-'*70}|")
            for b in self.results['bonuses']:
                print(f"    |  {Fore.GREEN}+ {b['detail'][:64]:<64}{Style.RESET_ALL}  |")

        if self.results['warnings']:
            print(f"    |  {Fore.YELLOW}WARNINGS:{Style.RESET_ALL}{' '*59}|")
            print(f"    |{'-'*70}|")
            for w in self.results['warnings'][:8]:
                print(f"    |  {Fore.YELLOW}{w[:66]:<66}{Style.RESET_ALL}  |")
            if len(self.results['warnings']) > 8:
                print(f"    |  {Fore.YELLOW}... and {len(self.results['warnings'])-8} more{Style.RESET_ALL}{' '*43}|")

        if self.results['quick_wins']:
            print(f"\n    {Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}QUICK WINS (High Impact){Style.RESET_ALL}{' '*(39)}|")
            print(f"    |{'-'*70}|")
            sorted_wins = sorted(self.results['quick_wins'], key=lambda x: ({'high': 0, 'medium': 1, 'low': 2}.get(x['impact'], 1), {'low': 0, 'medium': 1, 'high': 2}.get(x.get('effort', 'low'), 1)))
            shown = 0
            for win in sorted_wins:
                if shown >= 6:
                    break
                impact_color = Fore.RED if win['impact'] == 'high' else (Fore.YELLOW if win['impact'] == 'medium' else Fore.WHITE)
                effort = win.get('effort', 'low')
                print(f"    |  {impact_color}[{win['impact'].upper()}]{Style.RESET_ALL} {win['title'][:44]:<44} Eff:{effort[:1]} |")
                if win['description']:
                    print(f"    |    {Fore.CYAN}{win['description'][:62]:<62}{Style.RESET_ALL}  |")
                shown += 1
            if len(self.results['quick_wins']) > 6:
                print(f"    |  {Fore.CYAN}... and {len(self.results['quick_wins'])-6} more quick wins{Style.RESET_ALL}{' '*(30)}|")

        if self.results['recommendations']:
            sorted_recs = sorted(self.results['recommendations'], key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x['priority'], 1))
            high_impact = [r for r in sorted_recs if r['priority'] == 'high'][:5]
            if high_impact:
                print(f"\n    {Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                print(f"    |  {Fore.WHITE}{Style.BRIGHT}TOP RECOMMENDATIONS{Style.RESET_ALL}{' '*(46)}|")
                print(f"    |{'-'*70}|")
                for rec in high_impact:
                    detail_short = rec['detail'][:55] if rec['detail'] else 'No detail'
                    print(f"    |  {Fore.RED}[HIGH]{Style.RESET_ALL} {rec['check']:<25} {detail_short:<35}  |")

        print(f"\n    +================================================================+\n")

    def export_json(self, path):
        with open(path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"    {Fore.GREEN}[+] JSON report saved: {path}{Style.RESET_ALL}")

    def export_csv(self, path):
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Check', 'Category', 'Passed', 'Score', 'Max Score', 'Weight', 'Detail'])
            for c in self.results['checks']:
                writer.writerow([c['name'], c.get('category', ''), c['passed'], c['points'], c['max_points'], c.get('weight', 1.0), c['detail']])
            writer.writerow([])
            writer.writerow(['Total Score', '', '', f"{self.results['score']}/{self.results['max_score']}"])
            writer.writerow(['Weighted Score', '', '', f"{self.results.get('weighted_score', 0):.1f}/{self.results.get('weighted_max', 0):.1f}"])
            writer.writerow(['Final Score', '', '', f"{self.results.get('final_score', 0)}/{self.results['max_score']}"])
            writer.writerow(['Penalties', '', '', f"-{self.results.get('penalty_total', 0)}"])
            writer.writerow(['Bonuses', '', '', f"+{self.results.get('bonus_total', 0)}"])
            writer.writerow(['Ranking Weighted Pct', '', '', f"{self.results.get('ranking_weighted_pct', 0)}%"])
            writer.writerow(['Search Visibility', '', '', f"{self.results.get('search_visibility', 0)}%"])
            rp = self.results.get('ranking_potential', {})
            writer.writerow(['Ranking Potential', '', '', f"{rp.get('potential', 0)}% ({rp.get('label', 'n/a')})"])
            th = self.results.get('technical_health', {})
            writer.writerow(['Technical Health', '', '', f"{th.get('pct', 0)}% (grade {th.get('grade', 'n/a')})"])
            cc = self.results.get('content_competitiveness', {})
            writer.writerow(['Content Competitiveness', '', '', f"{cc.get('score', 0)}% ({cc.get('label', 'n/a')})"])
            vd = self.results.get('voice_search_deep', {})
            writer.writerow(['Voice Search Deep', '', '', f"{vd.get('score', 0)}/{vd.get('max', 12)}"])
            vs = self.results.get('visual_search', {})
            writer.writerow(['Visual Search', '', '', f"{vs.get('score', 0)}/{vs.get('max', 10)}"])
            vsn = self.results.get('video_featured_snippet', {})
            writer.writerow(['Video Featured Snippet', '', '', f"{vsn.get('score', 0)}/{vsn.get('max', 10)}"])
            isn = self.results.get('image_featured_snippet', {})
            writer.writerow(['Image Featured Snippet', '', '', f"{isn.get('score', 0)}/{isn.get('max', 10)}"])
            lp = self.results.get('local_pack', {})
            writer.writerow(['Local Pack', '', '', f"{lp.get('score', 0)}/{lp.get('max', 10)}"])
            writer.writerow(['Search Intent', '', '', str(self.results.get('search_intent', 'unknown'))])
            writer.writerow(['Intent Alignment', '', '', f"{self.results.get('intent_alignment', 0)}/12"])
            writer.writerow(['Topic Authority', '', '', f"{self.results.get('topic_authority', 0)}%"])
            writer.writerow(['Competitive Position', '', '', str(self.results.get('competitive_position', {}).get('label', 'n/a'))])
            writer.writerow(['Content Coverage', '', '', f"{self.results.get('content_gap', {}).get('coverage_pct', 0)}%"])
            for strategy_item in self.results.get('content_strategy', []):
                writer.writerow(['Content Strategy', '', '', strategy_item])
            for factor_name, factor_data in self.results.get('ranking_factors', {}).items():
                writer.writerow([f'Factor: {factor_name}', '', '', f"{factor_data.get('pct', 0)}% (weight {factor_data.get('weight', 0)})"])
        print(f"    {Fore.GREEN}[+] CSV report saved: {path}{Style.RESET_ALL}")

    def export_html(self, path):
        checks_by_category = {}
        for check in self.results['checks']:
            cat = check.get('category', 'general')
            if cat not in checks_by_category:
                checks_by_category[cat] = []
            checks_by_category[cat].append(check)

        categories_html = ''
        cat_order = ['meta', 'content', 'freshness', 'intent', 'snippet', 'competitive', 'visibility', 'technical', 'performance', 'security', 'mobile', 'social', 'links', 'entities', 'eeat', 'voice', 'visual', 'local', 'ai', 'general']
        for cat in cat_order:
            if cat not in checks_by_category:
                continue
            checks = checks_by_category[cat]
            cat_data = self.results['category_scores'].get(cat, {'score': 0, 'max': 0})
            cat_pct = (cat_data['score'] / cat_data['max'] * 100) if cat_data['max'] > 0 else 0
            if cat_pct >= 80:
                cat_color = '#3fb950'
                cat_grade = 'A'
            elif cat_pct >= 60:
                cat_color = '#58a6ff'
                cat_grade = 'B'
            elif cat_pct >= 40:
                cat_color = '#d29922'
                cat_grade = 'C'
            elif cat_pct >= 20:
                cat_color = '#f85149'
                cat_grade = 'D'
            else:
                cat_color = '#f85149'
                cat_grade = 'F'

            checks_rows = ''
            for check in checks:
                color = '#3fb950' if check['passed'] else '#f85149'
                status = 'PASS' if check['passed'] else 'FAIL'
                checks_rows += f'<tr><td style="color:{color};font-weight:700">{status}</td><td>{check["name"]}</td><td>{check["points"]}/{check["max_points"]}</td><td>{check["detail"][:80]}</td></tr>\n'

            categories_html += f'''<details style="margin:10px 0">
<summary style="cursor:pointer;padding:12px 16px;background:#161b22;border:1px solid #30363d;border-radius:6px;font-size:1.05em">
<span style="color:{cat_color};font-weight:700">[{cat_grade}]</span> <span style="color:#c9d1d9;text-transform:capitalize">{cat}</span>
<span style="float:right;color:#8b949e">{cat_data['score']}/{cat_data['max']} ({cat_pct:.0f}%)</span>
</summary>
<div style="padding:0 16px 16px;background:#0d1117;border:1px solid #30363d;border-top:0;border-radius:0 0 6px 6px">
<table style="width:100%;border-collapse:collapse;margin-top:8px">
<tr style="border-bottom:1px solid #30363d"><th style="color:#8b949e;text-align:left;padding:6px 8px">Status</th><th style="color:#8b949e;text-align:left;padding:6px 8px">Check</th><th style="color:#8b949e;text-align:left;padding:6px 8px">Score</th><th style="color:#8b949e;text-align:left;padding:6px 8px">Detail</th></tr>
{checks_rows}</table>
</div>
</details>\n'''

        score = self.results['score']
        max_score = self.results['max_score']
        final_score = self.results.get('final_score', score)
        pct = (final_score / max_score * 100) if max_score > 0 else 0
        grade_letter, _, _ = self._get_grade(pct)

        penalties_html = ''
        for p in self.results['penalties']:
            penalties_html += f'<li style="color:#f85149">{p["detail"]} (-{p["penalty"]} pts)</li>\n'

        bonuses_html = ''
        for b in self.results['bonuses']:
            bonuses_html += f'<li style="color:#3fb950">{b["detail"]} (+{b["bonus"]} pts)</li>\n'

        quick_wins_html = ''
        sorted_wins = sorted(self.results['quick_wins'], key=lambda x: ({'high': 0, 'medium': 1, 'low': 2}.get(x['impact'], 1), {'low': 0, 'medium': 1, 'high': 2}.get(x.get('effort', 'low'), 1)))
        for win in sorted_wins[:10]:
            impact_color = '#f85149' if win['impact'] == 'high' else ('#d29922' if win['impact'] == 'medium' else '#c9d1d9')
            effort_val = win.get('effort', 'low')
            quick_wins_html += f'''<div style="padding:8px 12px;margin:4px 0;background:#161b22;border-left:3px solid {impact_color};border-radius:0 4px 4px 0">
<strong style="color:{impact_color}">[{win["impact"].upper()}]</strong> {win["title"]} <span style="color:#8b949e;font-size:0.85em">(effort: {effort_val})</span>
<div style="color:#8b949e;font-size:0.9em;margin-top:2px">{win["description"]}</div>
</div>\n'''

        recs_html = ''
        sorted_recs = sorted(self.results['recommendations'], key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x['priority'], 1))
        for rec in sorted_recs[:10]:
            pcolor = '#f85149' if rec['priority'] == 'high' else ('#d29922' if rec['priority'] == 'medium' else '#c9d1d9')
            recs_html += f'<tr><td style="color:{pcolor};font-weight:700">{rec["priority"].upper()}</td><td>{rec["check"]}</td><td>{rec["category"]}</td><td>{rec["detail"][:60]}</td></tr>\n'

        factor_rows = ''
        for factor_name, factor_data in self.results.get('ranking_factors', {}).items():
            fpct = factor_data.get('pct', 0)
            fcolor = '#3fb950' if fpct >= 80 else '#58a6ff' if fpct >= 60 else '#d29922' if fpct >= 40 else '#f85149'
            factor_rows += f'<div style="margin:10px 0"><div style="display:flex;justify-content:space-between;font-size:0.92em;margin-bottom:3px"><span>{factor_name.capitalize()} (weight {factor_data.get("weight", 0):.0%})</span><span style="color:{fcolor};font-weight:700">{fpct:.0f}%</span></div><div style="background:#21262d;border-radius:4px;height:12px"><div style="width:{fpct:.0f}%;background:{fcolor};height:12px;border-radius:4px"></div></div></div>'

        eeat_html = ''
        eeat = self.results.get('eeat_breakdown', {})
        if eeat:
            for pillar, pdata in eeat.items():
                ppct = (pdata.get('score', 0) / pdata.get('max', 1) * 100) if pdata.get('max', 0) > 0 else 0
                pcolor = '#3fb950' if ppct >= 80 else '#58a6ff' if ppct >= 60 else '#d29922' if ppct >= 40 else '#f85149'
                eeat_html += f'<div style="margin:8px 0"><div style="display:flex;justify-content:space-between;font-size:0.9em"><span style="text-transform:capitalize">{pillar}</span><span style="color:{pcolor}">{pdata.get("score", 0)}/{pdata.get("max", 0)}</span></div><div style="background:#21262d;border-radius:4px;height:10px;margin-top:3px"><div style="width:{ppct:.0f}%;background:{pcolor};height:10px;border-radius:4px"></div></div></div>'

        priority_html = ''
        for act in self.results.get('priority_actions', [])[:10]:
            pcolor = '#f85149' if act['priority'] in ('critical', 'high') else '#d29922'
            effort_val = act.get('effort', 'med')
            priority_html += f'<tr><td style="color:{pcolor};font-weight:700">{act["priority"].upper()}</td><td>{act["action"]}</td><td style="color:#3fb950">+{act["potential_gain"]}</td><td>{effort_val}</td><td>{act["detail"][:70]}</td></tr>\n'

        strategy_html = ''
        for strat_i, strat_item in enumerate(self.results.get('strategy', []), 1):
            strategy_html += f'<li style="margin:8px 0;color:#c9d1d9">{strat_i}. {strat_item}</li>\n'

        sv = float(self.results.get('search_visibility', 0) or 0)
        sv_color = '#3fb950' if sv >= 80 else '#58a6ff' if sv >= 60 else '#d29922' if sv >= 40 else '#f85149'
        intent = str(self.results.get('search_intent', 'unknown'))
        secondary_intents = self.results.get('secondary_intents', [])
        ta = float(self.results.get('topic_authority', 0) or 0)
        ta_color = '#3fb950' if ta >= 80 else '#58a6ff' if ta >= 60 else '#d29922' if ta >= 40 else '#f85149'

        rp = self.results.get('ranking_potential', {})
        rp_val = float(rp.get('potential', 0) or 0)
        rp_color = '#3fb950' if rp_val >= 80 else '#58a6ff' if rp_val >= 60 else '#d29922' if rp_val >= 40 else '#f85149'
        th = self.results.get('technical_health', {})
        th_val = float(th.get('pct', 0) or 0)
        th_color = '#3fb950' if th_val >= 80 else '#58a6ff' if th_val >= 60 else '#d29922' if th_val >= 40 else '#f85149'
        cc = self.results.get('content_competitiveness', {})
        cc_val = float(cc.get('score', 0) or 0)
        cc_color = '#3fb950' if cc_val >= 80 else '#58a6ff' if cc_val >= 60 else '#d29922' if cc_val >= 40 else '#f85149'

        v_deep = self.results.get('voice_search_deep', {})
        vis_s = self.results.get('visual_search', {})
        vsn = self.results.get('video_featured_snippet', {})
        isn = self.results.get('image_featured_snippet', {})
        lp = self.results.get('local_pack', {})

        sv_components_html = ''
        for comp_name, comp_data in self.results.get('search_visibility_breakdown', {}).items():
            cv = comp_data.get('value', 0)
            cweight = comp_data.get('weight', 0)
            ccolor = '#3fb950' if cv >= 80 else '#58a6ff' if cv >= 60 else '#d29922' if cv >= 40 else '#f85149'
            sv_components_html += f'<div style="margin:8px 0"><div style="display:flex;justify-content:space-between;font-size:0.9em"><span>{comp_name.replace("_", " ").capitalize()} (weight {cweight:.0%})</span><span style="color:{ccolor}">{cv:.0f}%</span></div><div style="background:#21262d;border-radius:4px;height:10px;margin-top:3px"><div style="width:{cv:.0f}%;background:{ccolor};height:10px;border-radius:4px"></div></div></div>\n'

        intent_items_html = ''
        for it in self.results.get('intent_optimization', []):
            intent_items_html += f'<li style="margin:6px 0;color:#c9d1d9">{it}</li>\n'

        pos = self.results.get('competitive_position', {})
        pos_label = pos.get('label', 'Unknown')
        pos_composite = pos.get('composite', 0)
        pos_points_html = ''
        for pt in pos.get('points', []):
            pos_points_html += f'<li style="margin:6px 0;color:#c9d1d9">{pt}</li>\n'

        content_strategy_html = ''
        for cs_i, cs_item in enumerate(self.results.get('content_strategy', []), 1):
            content_strategy_html += f'<li style="margin:8px 0;color:#c9d1d9">{cs_i}. {cs_item}</li>\n'

        gap = self.results.get('content_gap', {})
        gap_rows = ''
        if gap:
            gap_rows = f'''<tr><th>Analysis mode</th><td>{gap.get("mode", "n/a")}</td></tr>
<tr><th>Competitors analyzed</th><td>{gap.get("competitors_analyzed", 0)} (failed: {gap.get("competitors_failed", 0)})</td></tr>
<tr><th>Word gap</th><td>{gap.get("word_gap", 0):,}</td></tr>
<tr><th>Subtopic coverage</th><td>{gap.get("coverage_pct", 0):.0f}%</td></tr>
<tr><th>Missing subtopics</th><td>{", ".join(gap.get("missing_subtopics", [])[:8]) or "none"}</td></tr>
<tr><th>Missing schema</th><td>{", ".join(gap.get("missing_schema", [])) or "none"}</td></tr>'''

        cann = self.results.get('cannibalization', {})
        cann_html = ''
        if cann.get('issues'):
            for issue in cann['issues']:
                cann_html += f'<li style="color:#f85149">{issue}</li>\n'
        else:
            cann_html = '<li style="color:#3fb950">No within-page cannibalization signals detected</li>'

        snippet = self.results.get('featured_snippet', {})
        paa = self.results.get('people_also_ask', {})
        kp = self.results.get('knowledge_panel', {})
        img_s = self.results.get('image_search', {})
        vid_s = self.results.get('video_search', {})

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SEO Report v8.0 - {self.url}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; line-height: 1.5; }}
h1 {{ color: #3fb950; border-bottom: 2px solid #30363d; padding-bottom: 10px; font-size: 1.5em; }}
h2 {{ color: #58a6ff; font-size: 1.15em; margin: 0 0 10px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 15px 0; }}
.stat {{ display: inline-block; text-align: center; padding: 12px 20px; margin: 4px; background: #0d1117; border-radius: 6px; border: 1px solid #30363d; min-width: 90px; }}
.stat .val {{ font-size: 1.8em; font-weight: 700; color: #58a6ff; }}
.stat .lbl {{ font-size: 0.82em; color: #8b949e; margin-top: 2px; }}
.green {{ color: #3fb950 !important; }}
.red {{ color: #f85149 !important; }}
.yellow {{ color: #d29922 !important; }}
.score-ring {{ width: 130px; height: 130px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2.2em; font-weight: 700; margin: 0 auto 12px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 7px 10px; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.92em; }}
th {{ color: #8b949e; font-weight: 600; }}
.grade-badge {{ display: inline-block; width: 36px; height: 36px; border-radius: 50%; text-align: center; line-height: 36px; font-weight: 700; font-size: 1.1em; margin-right: 8px; }}
</style></head><body>
<h1>SEO Analysis Report v8.0</h1>
<div class="card">
<h2>Score Overview</h2>
<div style="text-align:center">
<div class="score-ring" style="border: 8px solid {'#3fb950' if pct >= 80 else '#d29922' if pct >= 50 else '#f85149'}">{pct:.0f}%</div>
<p style="font-size:1.1em;font-weight:600">{final_score}/{max_score} points | Grade: {grade_letter}</p>
<p style="color:#8b949e;font-size:0.9em">Raw: {score}/{max_score} | Penalties: -{self.results.get('penalty_total', 0)} | Bonuses: +{self.results.get('bonus_total', 0)}</p>
</div>
<div style="text-align:center;margin-top:12px">
<div class="stat"><div class="val">{len([c for c in self.results['checks'] if c['passed']])}</div><div class="lbl">Passed</div></div>
<div class="stat"><div class="val red">{len([c for c in self.results['checks'] if not c['passed']])}</div><div class="lbl">Failed</div></div>
<div class="stat"><div class="val yellow">{len(self.results['warnings'])}</div><div class="lbl">Warnings</div></div>
<div class="stat"><div class="val">{len(self.results['checks'])}</div><div class="lbl">Total Checks</div></div>
</div>
</div>

<div class="card">
<h2>v8.0 Scoring Models</h2>
<div style="text-align:center">
<div class="stat"><div class="val" style="color:{rp_color}">{rp_val:.0f}%</div><div class="lbl">Ranking Potential ({rp.get('label', 'n/a')})</div></div>
<div class="stat"><div class="val" style="color:{th_color}">{th_val:.0f}%</div><div class="lbl">Technical Health ({th.get('grade', 'n/a')})</div></div>
<div class="stat"><div class="val" style="color:{cc_color}">{cc_val:.0f}%</div><div class="lbl">Content Competitiveness ({cc.get('label', 'n/a')})</div></div>
</div>
<p style="color:#8b949e;font-size:0.9em;margin-top:8px">Limiting factors: {', '.join(rp.get('limiting_factors', [])) or 'none under threshold'}</p>
</div>

<div class="card">
<h2>Target Information</h2>
<table>
<tr><th>URL</th><td>{self.url}</td></tr>
<tr><th>Status Code</th><td>{self.results.get('status_code', 'N/A')}</td></tr>
<tr><th>Load Time</th><td>{self.results.get('load_time', 'N/A')}s</td></tr>
<tr><th>Page Size</th><td>{self.results.get('content_length', 0)/1024:.1f} KB</td></tr>
<tr><th>Version</th><td>SEOChecker v8.0</td></tr>
</table></div>

{f'''<div class="card">
<h2>Penalties</h2>
<ul style="padding-left:20px">{penalties_html}</ul>
</div>''' if self.results['penalties'] else ''}

{f'''<div class="card">
<h2>Bonuses Earned</h2>
<ul style="padding-left:20px">{bonuses_html}</ul>
</div>''' if self.results['bonuses'] else ''}

<div class="card">
<h2>Search Visibility &amp; Intent</h2>
<div style="text-align:center">
<div class="stat"><div class="val" style="color:{sv_color}">{sv:.0f}%</div><div class="lbl">Search Visibility</div></div>
<div class="stat"><div class="val">{intent}</div><div class="lbl">Primary Intent</div></div>
<div class="stat"><div class="val" style="color:{ta_color}">{ta:.0f}%</div><div class="lbl">Topic Authority</div></div>
<div class="stat"><div class="val">{self.results.get("intent_alignment", 0)}/12</div><div class="lbl">Intent Alignment</div></div>
</div>
<p style="color:#8b949e;font-size:0.9em;margin-top:8px">Secondary intents: {", ".join(secondary_intents) if secondary_intents else "none detected"} | Freshness: {self.results.get("freshness", 0)}/10 (decay {self.results.get("freshness_decay_pct", 0):.0f}%)</p>
{sv_components_html}
</div>

<div class="card">
<h2>Content Strategy Recommendations</h2>
{f'<ol style="padding-left:20px">{content_strategy_html}</ol>' if content_strategy_html else '<p style="color:#8b949e">No content strategy items generated.</p>'}
</div>

<div class="card">
<h2>Competitive Position Analysis</h2>
<p style="font-size:1.15em"><strong style="color:{'#3fb950' if pos_label == 'Leader' else '#58a6ff' if pos_label == 'Challenger' else '#d29922' if pos_label == 'Competitor' else '#f85149'}">{pos_label}</strong> — composite {pos_composite:.1f}%</p>
<ul style="padding-left:20px">{pos_points_html}</ul>
</div>

<div class="card">
<h2>Content Gap Analysis</h2>
<table>{gap_rows or '<tr><td>No gap data</td></tr>'}</table>
</div>

<div class="card">
<h2>Keyword Cannibalization</h2>
<ul style="padding-left:20px">{cann_html}</ul>
</div>

<div class="card">
<h2>Search Intent Optimization</h2>
{f'<ul style="padding-left:20px">{intent_items_html}</ul>' if intent_items_html else '<p style="color:#8b949e">No intent optimization items.</p>'}
</div>

<div class="card">
<h2>Snippet / PAA / Knowledge / Media / v8 Scores</h2>
<table>
<tr><th>Featured Snippet</th><td>{snippet.get("score", 0)}/{snippet.get("max", 10)} (Q&amp;A blocks: {snippet.get("ready_answer_blocks", 0)}, lists: {snippet.get("list_blocks", 0)}, tables: {snippet.get("tables", 0)})</td></tr>
<tr><th>People Also Ask</th><td>{paa.get("score", 0)}/{paa.get("max", 10)} (questions: {paa.get("question_headings", 0)}, answers: {paa.get("direct_answers", 0)})</td></tr>
<tr><th>Knowledge Panel</th><td>{kp.get("score", 0)}/{kp.get("max", 10)} (sameAs: {kp.get("sameas", 0)}, KG links: {kp.get("kg_links", 0)})</td></tr>
<tr><th>Image Search</th><td>{img_s.get("score", 0)}/{img_s.get("max", 10)} (images: {img_s.get("images", 0)}, alt: {img_s.get("alt_coverage", 0)}%)</td></tr>
<tr><th>Video Search</th><td>{vid_s.get("score", 0)}/{vid_s.get("max", 10)} (videos: {vid_s.get("videos", 0)})</td></tr>
<tr><th>Voice Deep</th><td>{v_deep.get("score", 0)}/{v_deep.get("max", 12)} (openers: {v_deep.get("question_openers", 0)}, speakable: {v_deep.get("speakable_sentences", 0)})</td></tr>
<tr><th>Visual Search</th><td>{vis_s.get("score", 0)}/{vis_s.get("max", 10)} (images: {vis_s.get("images", 0)}, alt: {vis_s.get("alt_coverage", 0)}%)</td></tr>
<tr><th>Video Featured Snippet</th><td>{vsn.get("score", 0)}/{vsn.get("max", 10)} (videos: {vsn.get("videos", 0)}, clip: {vsn.get("clip_markup", False)})</td></tr>
<tr><th>Image Featured Snippet</th><td>{isn.get("score", 0)}/{isn.get("max", 10)} (images: {isn.get("images", 0)}, captions: {isn.get("captions", 0)})</td></tr>
<tr><th>Local Pack</th><td>{lp.get("score", 0)}/{lp.get("max", 10)} (schema: {lp.get("local_schema", False)}, address: {lp.get("address", False)}, phone: {lp.get("phone", False)})</td></tr>
</table>
</div>

<div class="card">
<h2>Quick Wins</h2>
{quick_wins_html if quick_wins_html else '<p style="color:#8b949e">No quick wins identified - great job!</p>'}
</div>

<div class="card">
<h2>Top Recommendations</h2>
<table><tr><th>Priority</th><th>Check</th><th>Category</th><th>Detail</th></tr>
{recs_html}</table>
</div>

{f'''<div class="card">
<h2>Ranking Factor Weighting</h2>
{factor_rows}
<p style="color:#8b949e;font-size:0.88em;margin-top:8px">Weighted SEO score: {self.results.get("ranking_weighted_pct", 0):.1f}% — content 35% / links 25% / technical 25% / UX 15% | Ranking potential: {rp_val:.0f}% | Technical health: {th_val:.0f}% | Competitiveness: {cc_val:.0f}%</p>
</div>''' if factor_rows else ''}

{f'''<div class="card">
<h2>E-E-A-T Breakdown</h2>
{eeat_html}
</div>''' if eeat_html else ''}

<div class="card">
<h2>Priority Action Items</h2>
{f'''<table><tr><th>Priority</th><th>Action</th><th>Gain</th><th>Effort</th><th>Detail</th></tr>
{priority_html}</table>''' if priority_html else '<p style="color:#8b949e">No critical actions - keep maintaining.</p>'}
</div>

<div class="card">
<h2>Long-Term Strategy</h2>
{f'''<ol style="padding-left:20px">{strategy_html}</ol>''' if strategy_html else '<p style="color:#8b949e">No strategy items generated.</p>'}
</div>

<div class="card">
<h2>Detailed Results by Category</h2>
{categories_html}
</div>

<p style="color:#8b949e;text-align:center;font-size:0.85em">Generated by SEOChecker v8.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</body></html>"""

        with open(path, 'w') as f:
            f.write(html)
        print(f"    {Fore.GREEN}[+] HTML report saved: {path}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        prog='seocheck',
        description=f'{Fore.GREEN}{Style.BRIGHT}SEOChecker v8.0 - Ultimate Website SEO Analyzer{Style.RESET_ALL}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{Fore.CYAN}Examples:{Style.RESET_ALL}
  {Fore.GREEN}# Basic check{Style.RESET_ALL}
  python seocheck.py -u https://example.com

  {Fore.GREEN}# Check with broken link detection{Style.RESET_ALL}
  python seocheck.py -u https://example.com --check-links

  {Fore.GREEN}# Content gap analysis against competitors{Style.RESET_ALL}
  python seocheck.py -u https://example.com --competitors https://rival1.com,https://rival2.com

  {Fore.GREEN}# Export all reports{Style.RESET_ALL}
  python seocheck.py -u https://example.com --export all

  {Fore.GREEN}# Custom timeout{Style.RESET_ALL}
  python seocheck.py -u https://example.com -t 30
"""
    )

    parser.add_argument('-u', '--url', required=True, help='URL to analyze')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Request timeout (default: 15)')
    parser.add_argument('--export', default='none', choices=['all', 'json', 'csv', 'html', 'none'],
                        help='Export format (default: none)')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    parser.add_argument('--check-links', action='store_true', help='Check for broken links (slower)')
    parser.add_argument('--batch', help='File with URLs to analyze (one per line)')
    parser.add_argument('--competitors', default='',
                        help='Comma-separated competitor URLs for content gap analysis')

    args = parser.parse_args()

    if args.no_color:
        _disable_colors()

    competitors = [u.strip() for u in args.competitors.split(',') if u.strip()]

    urls = []
    if args.batch and os.path.exists(args.batch):
        with open(args.batch, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if args.url:
        urls.insert(0, args.url)

    if not urls:
        print(f"{Fore.RED}No URLs provided{Style.RESET_ALL}")
        return

    for i, url in enumerate(urls):
        if len(urls) > 1:
            print(f"\n{'='*70}")
            print(f"  Analyzing URL {i+1}/{len(urls)}: {url}")
            print(f"{'='*70}")

        checker = SEOChecker(url, timeout=args.timeout, check_links=args.check_links,
                             competitors=competitors)
        results = checker.run()

        if args.export in ('all', 'json'):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix = f"_{i}" if len(urls) > 1 else ""
            checker.export_json(f"seo_report_{ts}{suffix}.json")
        if args.export in ('all', 'csv'):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix = f"_{i}" if len(urls) > 1 else ""
            checker.export_csv(f"seo_report_{ts}{suffix}.csv")
        if args.export in ('all', 'html'):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix = f"_{i}" if len(urls) > 1 else ""
            checker.export_html(f"seo_report_{ts}{suffix}.html")


if __name__ == '__main__':
    main()
