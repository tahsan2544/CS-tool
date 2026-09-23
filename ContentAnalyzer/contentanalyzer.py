#!/usr/bin/env python3
"""ContentAnalyzer v6.0 - Deep content originality, uniqueness, quality, engagement and conversion intelligence."""
import sys
import os
import argparse
import json
import csv
import io
import re
import math
import unicodedata
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    os.system("pip install requests")
    import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    os.system("pip install beautifulsoup4")
    from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# RTL language codes
# ---------------------------------------------------------------------------
RTL_LANGS = frozenset({
    "ar", "he", "fa", "ur", "ps", "sd", "yi", "ku", "ckb", "ug",
    "syr", "dv", "ha", "rn", "mzn", "glk", "azb", "bgn",
})

RTL_SCRIPT_RANGES = (
    (0x0590, 0x05FF), (0x0600, 0x06FF), (0x0700, 0x074F),
    (0x0750, 0x077F), (0x0780, 0x07BF), (0x07C0, 0x07FF),
    (0x0800, 0x083F), (0x0840, 0x085F), (0x08A0, 0x08FF),
    (0xFB1D, 0xFDFF), (0xFE70, 0xFEFF), (0x10E60, 0x10E7F),
    (0x1EE00, 0x1EEFF),
)

UNICODE_SCRIPT_MAP = {
    "LATIN": "Latin", "CYRILLIC": "Cyrillic", "ARABIC": "Arabic",
    "HEBREW": "Hebrew", "DEVANAGARI": "Devanagari", "BENGALI": "Bengali",
    "TAMIL": "Tamil", "TELUGU": "Telugu", "THAI": "Thai",
    "GEORGIAN": "Georgian", "ARMENIAN": "Armenian", "HANGUL": "Hangul",
    "HIRAGANA": "Hiragana", "KATAKANA": "Katakana", "HAN": "CJK",
    "GREEK": "Greek", "ETHIOPIC": "Ethiopic", "MYANMAR": "Myanmar",
    "KHMER": "Khmer", "LAO": "Lao", "TIBETAN": "Tibetan",
    "GUJARATI": "Gujarati", "GURMUKHI": "Gurmukhi", "KANNADA": "Kannada",
    "MALAYALAM": "Malayalam", "SINHALA": "Sinhala", "CHEROKEE": "Cherokee",
    "CANADIAN_ABORIGINAL": "Canadian Syllabics", "OGHAM": "Ogham",
    "RUNIC": "Runic", "COPTIC": "Coptic", "SYRIAC": "Syriac",
    "THAANA": "Thaana", "NKO": "NKo", "BALI": "Balinese",
}

LANGUAGE_READABILITY_FACTORS = {
    "en": 1.0, "es": 0.95, "de": 1.1, "fr": 1.05, "pt": 0.95,
    "it": 0.95, "nl": 1.05, "ru": 1.15, "ja": 1.2, "zh": 1.15,
    "ar": 1.1, "ko": 1.1, "hi": 1.1, "bn": 1.1, "ta": 1.15,
    "te": 1.15, "th": 1.2, "vi": 1.0, "pl": 1.1, "cs": 1.1,
    "sv": 0.95, "da": 0.95, "no": 0.95, "fi": 1.2, "tr": 1.0,
    "el": 1.05, "hu": 1.2, "ro": 1.0, "uk": 1.15, "id": 0.9,
    "ms": 0.9, "he": 1.1, "fa": 1.1, "ur": 1.1,
}

SCRIPT_LANGUAGE_RANGES = {
    "ko": ((0xAC00, 0xD7AF), (0x1100, 0x11FF)),
    "hi": ((0x0900, 0x097F),),
    "bn": ((0x0980, 0x09FF),),
    "ta": ((0x0B80, 0x0BFF),),
    "te": ((0x0C00, 0x0C7F),),
    "th": ((0x0E00, 0x0E7F),),
    "el": ((0x0370, 0x03FF),),
    "ka": ((0x10A0, 0x10FF),),
    "hy": ((0x0530, 0x058F),),
    "my": ((0x1000, 0x109F),),
    "km": ((0x1780, 0x17FF),),
    "lo": ((0x0E80, 0x0EFF),),
    "bo": ((0x0F00, 0x0FFF),),
    "gu": ((0x0A80, 0x0AFF),),
    "pa": ((0x0A00, 0x0A7F),),
    "kn": ((0x0C80, 0x0CFF),),
    "ml": ((0x0D00, 0x0D7F),),
    "si": ((0x0D80, 0x0DFF),),
}


class Colors:
    def __init__(self, no_color=False):
        self.enabled = not no_color
        self.RED = "\033[91m" if self.enabled else ""
        self.GREEN = "\033[92m" if self.enabled else ""
        self.YELLOW = "\033[93m" if self.enabled else ""
        self.BLUE = "\033[94m" if self.enabled else ""
        self.MAGENTA = "\033[95m" if self.enabled else ""
        self.CYAN = "\033[96m" if self.enabled else ""
        self.WHITE = "\033[97m" if self.enabled else ""
        self.BRIGHT_WHITE = "\033[1;97m" if self.enabled else ""
        self.BRIGHT_RED = "\033[1;91m" if self.enabled else ""
        self.BRIGHT_GREEN = "\033[1;92m" if self.enabled else ""
        self.BRIGHT_YELLOW = "\033[1;93m" if self.enabled else ""
        self.BRIGHT_BLUE = "\033[1;94m" if self.enabled else ""
        self.BRIGHT_MAGENTA = "\033[1;95m" if self.enabled else ""
        self.BRIGHT_CYAN = "\033[1;96m" if self.enabled else ""
        self.BOLD = "\033[1m" if self.enabled else ""
        self.DIM = "\033[2m" if self.enabled else ""
        self.UNDERLINE = "\033[4m" if self.enabled else ""
        self.RESET = "\033[0m" if self.enabled else ""

    def colorize(self, text, color):
        return f"{color}{text}{self.RESET}"


def print_banner(colors):
    c = colors
    lines = [
        f"{c.BRIGHT_CYAN}+=============================================================================+",
        f"{c.BRIGHT_CYAN}|{c.BRIGHT_WHITE}  _______                    ______                          {c.BRIGHT_CYAN}|",
        f"{c.BRIGHT_CYAN}|{c.BRIGHT_WHITE} |   ____|____  _____  ____ |   ___|_____  _____  ____        {c.BRIGHT_CYAN}|",
        f"{c.BRIGHT_CYAN}|{c.BRIGHT_WHITE} |____   /  _ \\/     \\|    \\|   __||  ___|/     \\|  _ \\       {c.BRIGHT_CYAN}|",
        f"{c.BRIGHT_CYAN}|{c.BRIGHT_WHITE} |       (  < <  <  ) |  |  |  |  | |   |  <  )  | | | |      {c.BRIGHT_CYAN}|",
        f"{c.BRIGHT_CYAN}|{c.BRIGHT_WHITE} |_______/\\____/__/__\\|____/|__|  |__|   \\____/|____/       {c.BRIGHT_CYAN}|",
        f"{c.BRIGHT_CYAN}|{c.BRIGHT_YELLOW}            Content Quality Analyzer  v6.0                      {c.BRIGHT_CYAN}|",
        f"{c.BRIGHT_CYAN}|{c.DIM}  Deep originality, engagement & conversion intelligence     {c.BRIGHT_CYAN}|",
        f"{c.BRIGHT_CYAN}+=============================================================================+{c.RESET}",
    ]
    for line in lines:
        print(line)
    print()


# ---------------------------------------------------------------------------
# Syllable / word helpers
# ---------------------------------------------------------------------------
def syllable_count(word):
    word = word.lower().strip()
    if len(word) <= 3:
        return 1
    vowels = "aeiouy"
    count = 0
    prev_vowel = False
    for char in word:
        is_vowel = char in vowels
        if is_vowel and not prev_vowel:
            count += 1
        prev_vowel = is_vowel
    if word.endswith("e"):
        count -= 1
    if word.endswith("le") and len(word) > 2 and word[-3] not in vowels:
        count += 1
    return max(count, 1)


def is_complex_word(word):
    return syllable_count(word) > 3


def is_passive_voice(sentence):
    passive_patterns = [
        r"\b(is|are|was|were|be|been|being)\s+\w+ed\b",
        r"\b(is|are|was|were|be|been|being)\s+\w+en\b",
        r"\b(is|are|was|were|be|been|being)\s+\w+wn\b",
    ]
    for pattern in passive_patterns:
        if re.search(pattern, sentence, re.IGNORECASE):
            return True
    return False


def count_adverbs(words):
    adverbs = {
        "very", "really", "quite", "just", "also", "too", "so", "then",
        "now", "here", "there", "where", "when", "how", "why", "always",
        "never", "sometimes", "often", "usually", "already", "still",
        "even", "only", "almost", "enough", "perhaps", "probably",
        "certainly", "definitely", "absolutely", "completely", "totally",
        "highly", "extremely", "particularly", "especially", "generally",
        "normally", "typically", "previously", "subsequently", "however",
        "therefore", "moreover", "furthermore", "additionally", "meanwhile",
        "fortunately", "unfortunately", "basically", "simply", "merely",
        "hardly", "barely", "quickly", "slowly", "suddenly", "gradually",
        "immediately", "directly", "finally", "recently", "lately",
    }
    count = 0
    for w in words:
        cleaned = w.lower().strip(".,!?;:\"'")
        if cleaned in adverbs:
            count += 1
    return count


# ---------------------------------------------------------------------------
# Readability indices
# ---------------------------------------------------------------------------
def _split_sentences(text):
    sentences = re.split(r"[.!?]+", text)
    return [s.strip() for s in sentences if s.strip()]


def _get_words(text):
    return re.findall(r"\b[a-zA-Z]+\b", text)


def flesch_reading_ease(text):
    sentences = _split_sentences(text)
    words = _get_words(text)
    if not sentences or not words:
        return 0.0
    asl = len(words) / len(sentences)
    asw = sum(syllable_count(w) for w in words) / len(words)
    score = 206.835 - 1.015 * asl - 84.6 * asw
    return max(0.0, min(100.0, score))


def flesch_kincaid_grade(text):
    sentences = _split_sentences(text)
    words = _get_words(text)
    if not sentences or not words:
        return 0.0
    asl = len(words) / len(sentences)
    asw = sum(syllable_count(w) for w in words) / len(words)
    grade = 0.39 * asl + 11.8 * asw - 15.59
    return max(0.0, grade)


def gunning_fog_index(text):
    sentences = _split_sentences(text)
    words = _get_words(text)
    if not sentences or not words:
        return 0.0
    asl = len(words) / len(sentences)
    complex_words = sum(1 for w in words if syllable_count(w) >= 3)
    pct_complex = complex_words / len(words) * 100
    score = 0.4 * (asl + pct_complex)
    return max(0.0, score)


def coleman_liau_index(text):
    sentences = _split_sentences(text)
    words = _get_words(text)
    if not sentences or not words:
        return 0.0
    chars = sum(len(w) for w in words)
    asl = len(words) / len(sentences)
    cl = 0.0588 * (chars / len(words) * 100) - 0.296 * (len(sentences) / len(words) * 100) - 15.8
    return max(0.0, cl)


def automated_readability_index(text):
    sentences = _split_sentences(text)
    words = _get_words(text)
    if not sentences or not words:
        return 0.0
    chars = sum(len(w) for w in words)
    ari = 4.71 * (chars / len(words)) + 0.5 * (len(words) / len(sentences)) - 21.43
    return max(0.0, ari)


def linsear_write_formula(text):
    sentences = _split_sentences(text)
    words = _get_words(text)
    if not sentences or not words:
        return 0.0
    easy = 0
    hard = 0
    for word in words:
        syl = syllable_count(word)
        if syl <= 2:
            easy += 1
        else:
            hard += syl
    total = easy + hard
    if total == 0:
        return 0.0
    number = easy - hard
    if number > 0:
        lwf = 100 - number / total * 100
    else:
        lwf = 20 - number / total * 100
    return max(0.0, lwf)


def smog_index(text):
    sentences = _split_sentences(text)
    words = _get_words(text)
    if not sentences or not words:
        return 0.0
    complex_words = sum(1 for w in words if syllable_count(w) >= 3)
    score = 1.0430 * math.sqrt(complex_words * (30.0 / len(sentences))) + 3.1291
    return max(0.0, score)


def text_standard_score(readability_indices):
    grades = []
    for idx in readability_indices:
        g = readability_indices[idx]
        if g >= 0:
            grades.append(g)
    if not grades:
        return 0.0
    return round(sum(grades) / len(grades), 1)


def readability_label(score):
    if score >= 90:
        return "5th grade (very easy)"
    elif score >= 80:
        return "6th grade (easy)"
    elif score >= 70:
        return "7th grade (fairly easy)"
    elif score >= 60:
        return "8th-9th grade (standard)"
    elif score >= 50:
        return "10th-12th grade (fairly difficult)"
    elif score >= 30:
        return "College level (difficult)"
    else:
        return "College graduate (very difficult)"


def grade_level_label(grade):
    if grade < 1:
        return "Before Grade 1"
    elif grade < 2:
        return "1st Grade"
    elif grade < 3:
        return "2nd Grade"
    elif grade < 4:
        return "3rd Grade"
    elif grade < 13:
        return "Grade " + str(int(round(grade)))
    elif grade < 16:
        return "College"
    elif grade < 19:
        return "Post-Graduate"
    else:
        return "Professional"



# ---------------------------------------------------------------------------
# Language & encoding helpers
# ---------------------------------------------------------------------------
def detect_language_from_meta(soup):
    html_tag = soup.find("html")
    if html_tag:
        lang = html_tag.get("lang") or html_tag.get("xml:lang")
        if lang:
            return lang.strip().split("-")[0].strip()
    meta_tag = soup.find("meta", attrs={"http-equiv": re.compile(r"content-language", re.IGNORECASE)})
    if meta_tag:
        content = meta_tag.get("content", "")
        if content:
            return content.strip().split("-")[0].strip()
    meta_tag = soup.find("meta", attrs={"name": re.compile(r"language", re.IGNORECASE)})
    if meta_tag:
        content = meta_tag.get("content", "")
        if content:
            return content.strip().split("-")[0].strip()
    return None


def detect_language_from_content(text):
    words = _get_words(text)
    if len(words) < 10:
        return None
    lang_samples = {
        "en": {"the", "be", "to", "of", "and", "a", "in", "that", "have", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "her", "she", "or", "an", "will", "my", "one", "all", "would", "there", "their", "what", "so", "up", "out", "if", "about", "who", "get", "which", "go", "me"},
        "es": {"el", "la", "de", "en", "los", "las", "del", "que", "por", "con", "una", "para", "es", "al", "se", "lo", "como", "pero", "su", "le", "ya", "o", "este", "ha", "si", "porque", "esta", "son", "entre", "cuando", "muy", "sin", "sobre", "tambien", "me", "hasta", "hay", "donde", "quien", "desde", "todo", "nos", "durante", "todos", "uno", "les", "ni", "contra", "otros", "ese", "eso", "ante", "ellos", "esto", "mi", "antes", "algunos", "unos", "yo", "otro", "otras", "otra", "el", "tanto", "esa", "estos", "mucho", "quienes", "nada", "muchos", "cual", "poco", "ella", "estar", "estas", "algunas", "algo", "nosotros"},
        "de": {"der", "die", "und", "in", "den", "von", "zu", "das", "mit", "sich", "des", "auf", "fur", "ist", "im", "dem", "nicht", "ein", "eine", "als", "auch", "es", "an", "werden", "aus", "er", "hat", "dass", "sie", "nach", "wird", "bei", "einer", "um", "am", "sind", "noch", "wie", "einem", "uber", "einen", "so", "zum", "war", "haben", "aber", "vor", "oder", "nur", "ihr", "uns", "ihm", "diese", "dieser", "mich", "keine", "kann", "dir", "man", "da", "was", "dort", "ob"},
        "fr": {"le", "la", "de", "les", "des", "un", "une", "et", "en", "que", "qui", "dans", "du", "est", "pour", "pas", "sur", "au", "ce", "il", "ne", "se", "plus", "par", "je", "avec", "tout", "faire", "son", "mais", "comme", "on", "elle", "nous", "aussi", "bien", "cette", "ces", "vous", "nos", "ses", "dont", "leur", "va", "aux", "entre", "meme", "mon", "peut", "sont", "mes", "cet", "toi", "moi", "non", "oui", "si"},
        "pt": {"de", "a", "que", "e", "do", "da", "em", "um", "para", "e", "com", "uma", "os", "no", "se", "na", "por", "mais", "dos", "como", "mas", "foi", "ao", "ele", "das", "tem", "seu", "sua", "ou", "ser", "quando", "muito", "ha", "nos", "ja", "esta", "eu", "tambem", "so", "pelo", "pela", "ate", "isso", "ela", "entre", "era", "depois", "sem", "mesmo", "aos", "ter", "seus", "quem", "nas", "me", "esse", "eles", "estao", "voce", "tinha", "foram", "essa", "num", "nem", "suas", "meu", "minha"},
        "it": {"di", "che", "la", "il", "un", "a", "in", "del", "una", "da", "per", "con", "non", "sono", "si", "lo", "al", "le", "ma", "come", "anche", "ci", "ha", "no", "ne", "piu", "o", "su", "alla", "dei", "nella", "nel", "quando", "molto", "hanno", "stato", "questo", "loro", "della", "delle", "suo", "sua", "furono", "essere", "aveva", "fece", "noi", "voi", "tutti", "tutto", "gia", "ancora", "dopo", "prima"},
        "nl": {"de", "het", "van", "een", "en", "in", "is", "dat", "op", "te", "zijn", "voor", "met", "niet", "ook", "aan", "er", "maar", "om", "als", "dan", "bij", "nog", "zo", "uit", "kan", "door", "dit", "naar", "hij", "was", "ze", "we", "wat", "worden", "die", "haar", "hen", "hun", "wij", "geen", "veel", "meer", "tot", "daar", "heeft", "had", "hem", "mijn", "men"},
        "ru": {"и", "в", "не", "на", "я", "что", "он", "как", "это", "она", "так", "его", "но", "да", "ты", "к", "у", "же", "вы", "за", "бы", "по", "только", "её", "мне", "было", "вот", "от", "меня", "ещё", "нет", "о", "из", "ему", "теперь", "когда", "даже", "ну", "вдруг", "ли", "если", "или", "ни", "быть", "был", "него", "вас", "нибудь", "опять", "уж", "вам", "ведь", "там", "потом", "себя", "ничего", "ей", "может", "они", "тут", "где", "есть", "надо", "ней", "для", "мы", "тебя", "их", "чем", "была", "сам", "чтоб", "без", "будто", "чего", "раз", "тоже", "себе", "под", "будет", "тогда", "кто", "этот", "того", "потому", "этого", "какой", "совсем", "ним", "здесь", "один", "почти", "мой", "тем", "чтобы", "нее", "сейчас", "были", "куда", "зачем", "всех", "никогда", "можно", "при", "наконец", "два", "об", "другой", "хоть", "после", "над", "больше", "тот", "через", "эти", "нас", "про", "всего", "них", "какая", "много", "разве", "три", "эту", "моя", "впрочем", "хорошо", "свою", "этой", "перед", "иногда", "лучше", "чуть", "том", "нельзя", "такой", "им", "более", "всегда", "уже", "конечно", "всю", "между"},
        "ja": {"の", "に", "は", "を", "た", "が", "で", "て", "と", "し", "れ", "さ", "ある", "いる", "も", "する", "から", "な", "こと", "い", "や", "など", "ない", "この", "ため", "その", "よう", "また", "もの", "という", "あり", "まで", "られ", "なる", "へ", "か", "だ", "これ", "により", "おり", "より", "ず", "なかっ", "なく", "しかし", "について", "だっ"},
        "zh": {"的", "一", "是", "在", "不", "了", "有", "和", "人", "这", "中", "大", "为", "上", "个", "国", "我", "以", "要", "他", "时", "来", "用", "们", "生", "到", "作", "地", "于", "出", "就", "分", "对", "成", "会", "可", "主", "发", "年", "动", "同", "工", "也", "能", "下", "过", "子", "说", "产", "种", "面", "而", "方", "后", "多", "定", "行", "学", "法", "所", "民", "得", "经", "十", "三", "之", "进", "着", "等", "部", "度", "家", "电", "力", "里", "如", "水", "化", "高", "自", "二", "理", "起", "小", "物", "现", "实", "加", "量", "都", "两", "体", "制", "机", "当", "使", "点", "从", "业", "本", "去", "把", "性", "好", "应", "开", "它", "合", "还", "因", "由", "其", "些", "然", "前", "外", "天", "政", "四", "日", "那", "社", "义", "事", "平", "形", "相", "全", "表", "间", "样", "与", "关", "各", "重", "新", "线", "内", "数", "正", "心", "反", "你", "明", "看", "原", "又", "么", "利", "比", "或", "但", "质", "气", "第", "向", "道", "命", "此", "变", "条", "只", "没", "结", "解", "问", "意", "建", "月", "公", "无", "系", "军", "很", "情", "者", "最", "立", "代", "想", "已", "通", "并", "提", "直", "题", "党", "程", "展", "五", "果", "料", "象", "员", "革", "位", "入", "常", "文", "总", "次", "品", "式", "活", "设", "及", "管", "特", "件", "长", "求", "老", "头", "基", "资", "边", "流", "路", "级", "少", "图", "山", "统", "接", "知", "较", "将", "组", "见", "计", "别", "她", "手", "角", "期", "根", "论", "运", "农", "指", "几", "九", "区", "强", "放", "决", "西", "被", "干", "做", "必", "战", "先", "回", "则", "任", "据", "处", "队", "南", "给", "色", "光", "门", "即", "保", "治", "北", "造", "百", "规", "热", "领", "七", "海", "口", "东", "导", "器", "压", "志", "世", "金", "增", "争", "济", "阶", "油", "思", "术", "极", "交", "受", "联", "什", "认", "六", "共", "权", "收", "证", "改", "清", "己", "美", "再", "采", "传", "更", "白", "风", "转", "打", "造", "儿", "容", "近", "代", "价", "买", "议", "走", "效", "报", "程", "感", "族", "非", "更", "住", "统", "红", "太", "许", "变", "造", "测", "持", "状", "拉", "失", "陈", "快", "怎", "整", "注", "支", "却", "流", "空", "格", "名", "土", "标", "血", "死", "场", "仍", "片", "响", "且", "竞", "群", "包", "抓", "准", "午", "装", "境", "害", "紧", "办", "左", "右", "骨", "玉", "怕", "站", "然", "弹", "评", "含", "拿", "继", "盛", "竹", "欢", "帮", "落"},
        "ar": {"من", "في", "على", "أن", "هذا", "إلى", "عن", "عند", "وقد", "ولم", "كل", "بل", "قد", "ولا", "بين", "يكون", "وقد", "ذلك", "يكون", "كما", "أيضا", "بعد", "قبل", "حتى", "خلال", "دون", "عندما", "حيث", "وإن", "ولكن", "إنما", "إذا", "ثم", "منذ", "أي", "أو", "بل", "غير", " handedness", "بها", "فيه", "منها", "عليها", "إليها", "لها", "عنها", "معها", "وهي", "وكان", "وقال", "أنه", "التي", "الذي", "فيما", "إلا", "بما", "له", "عليه", "منه", "فيها", "upon"},
        "ko": {"이", "그", "저", "것", "수", "등", "들", "및", "앱", "또한", "대한", "으로", "에서", "와의", "과의", "위한", "까지", "부터", "에게", "한테", "에서의", "으로의", "부터의", "까지의", "而言", "의해", "위하여", "대하여", "따르면", "의하면", "보면", "경우", "때문", "하에", "위하여", "하여", "있어", "대해", "으로써"},
        "hi": {"के", "में", "है", "की", "को", "से", "पर", "ने", "यह", "था", "कि", "एक", "या", "और", "इस", "भी", "पर", "तो", "क्या", "जो", "कर", "लिए", "अपने", "मैं", "हम", "तुम", "वह", "इसे", "उन्हें", "हो", "गया", "थे", "हैं", "रहा", "करता", "किया", "रहे", "करें", "होगा", "होंगे"},
        "bn": {"এর", "এই", "ও", "একটি", "এবং", "যে", "তার", "সে", "তিনি", "আমি", "আমরা", "আপনি", "তুমি", "সে", "এটি", "হয়", "করা", "হবে", "করে", "থেকে", "সাথে", "মধ্যে", "পর", "আগে", "কাছে", "নিকটে", "উপর", "নিচে", "ভিতরে", "বাইরে"},
        "ta": {"மற்றும்", "ஒரு", "இது", "அது", "இதில்", "அதில்", "இவை", "அவை", "தான்", "மிக", "மிகவும்", "போல", "போன்ற", "வரை", "வரையில்", "சுமார்", "சுமார்", "கிட்டத்தட்ட", "அன்று", "பின்", "முன்", "மேலும்", "கீழும்"},
        "te": {"మరియు", "ఒక", "ఇది", "అది", "వారు", "మేము", "మీరు", "నేను", "అతను", "ఆమె", "అవి", "వాటి", "ఇవి", "కూడా", "లో", "నుండి", "కి", "చేత", "చేసి", "ఉన్న", "ఉంది", "చేయడం", "చేస్తుంది"},
        "th": {"ของ", "ใน", "และ", "เป็น", "ที่", "มี", "ได้", "จะ", "ให้", "ไป", "มา", "กับ", "แต่", "ก็", "คือ", "ไม่", "มี", "อยู่", "แล้ว", "นี้", "นั้น", "ทำ", "ใช้", "ว่า", "จาก", "ถ้า", "ต้อง", "หรือ", "เท่า", "วัน", "ปี", "เดือน", "ครั้ง"},
        "vi": {"cua", "la", "va", "trong", "co", "la", "cho", "cac", "mot", "cung", "nhu", "nay", "do", "theo", "tu", "den", "tai", "dau", "viet", "nam", "ngay", "thang", "gio", "phut", "giay", "khong", "nao", "day", "do", "ay", "no", "nhung", "hay", "hoac", "neu", "vi", "vi du"},
        "pl": {"w", "na", "nie", "do", "to", "jest", "ze", "za", "jak", "co", "czy", "ale", "od", "po", "tak", "jeszcze", "tylko", "juz", "tez", "sobie", "przy", "tego", "ktore", "ktory", "ta", "ten", "te", "tym", "tych", "tym", "moze", "bardzo", "są", "bedzie", "byl", "byla", "bede", "beda", "miec", "zostal", "przez", "uzywac"},
        "cs": {"v", "a", "na", "je", "se", "to", "z", "do", "jako", "ale", "za", "jsem", "jste", "jsme", "tak", "byl", "byla", "bylo", "byly", "bude", "budou", "mit", "tento", "tato", "toto", "ten", "ta", "to", "ty", "ti", "kteří", "která", "které", "již", "nebo", "podle", "mezi", "před", "po", "při", "od", "když", "kde", "kdo", "co", "jak", "velmi", "taky", "také", "jen", "právě"},
        "sv": {"och", "att", "det", "i", "en", "som", "har", "för", "av", "med", "den", "till", "på", "är", "av", "ett", "om", "men", "var", "jag", "han", "hon", "vi", "de", "du", "så", "kan", "ska", "skulle", "hade", "var", "ska", "efter", "vid", "mot", "alla", "över", "bara", "nu", "här", "där", "också", "redan", "än", "när", "alltså"},
        "da": {"og", "i", "at", "er", "en", "den", "til", "det", "de", "af", "for", "med", "har", "som", "var", "ikke", "kan", "vil", "skal", "der", "men", "om", "jeg", "han", "hun", "vi", "du", "så", "da", "også", "allerede", "bare", "lige", "når", "hvor", "efter", "ved", "over", "under", "mellem", "fra", "ud", "ind", "op", "ned", "før", "siden", "igen", "nu", "her", "der"},
        "no": {"og", "i", "er", "at", "en", "for", "det", "til", "som", "med", "den", "av", "har", "de", "var", "ikke", "kan", "vil", "skal", "der", "men", "om", "jeg", "han", "hun", "vi", "du", "så", "også", "bare", "når", "hvor", "etter", "ved", "over", "under", "mellom", "fra", "ut", "inn", "opp", "ned", "før", "siden", "igjen", "nå", "her", "der", "ble", "ha", "få"},
        "fi": {"ja", "on", "ei", "se", "ett", "yks", "kak", "oli", "olla", "tai", "kuin", "myös", "vain", "niin", "näin", "siis", "jos", "kun", "sill", "kuten", "mutta", "vaikka", "koska", "mikä", "mitä", "missä", "milloin", "kuinka", "miksi", "millä", "minä", "sinä", "hän", "me", "te", "he", "tämä", "tuo", "se", "nämä", "nuo", "ne", "tässä", "tuossa", "siinä", "tällä", "tuolla", "sillä", "tänä", "tuona", "sinä"},
        "tr": {"bir", "ve", "bu", "da", "de", "için", "ile", "çok", "var", "ama", "olan", "olarak", "daha", "bile", "sonra", "önce", "gibi", "kadar", "böyle", "şöyle", "nasıl", "neden", "niçin", "her", "hiç", "tüm", "bütün", "başka", "diğer", "kendi", "ben", "sen", "biz", "siz", "onlar", "o", "şu", "benim", "senin", "bizim", "sizin", "onların", "onun", "mı", "mi", "mu", "mü", "değil", "olmak", "etmek", "yapmak", "gelmek", "gitmek", "almak", "vermek", "demek", "bilmek", "istemek", "görmek", "bilmek"},
        "el": {"και", "το", "τα", "τη", "της", "τον", "το", "με", "σε", "από", "για", "ως", "αλλά", "ή", "που", "πολύ", "μπορεί", "να", "είναι", "θα", "έχει", "αυτό", "αυτά", "εδώ", "εκεί", "πως", "τι", "ποιος", "πόσο", "γιατί", "πώς", "όταν", "αν", "όμως", "επίσης", "μόνο", "ακόμα", "ήδη", "σχεδόν", "πάντα", "ποτέ", "συχνά", "σπάνια"},
        "hu": {"és", "a", "az", "egy", "nem", "is", "hogy", "ez", "van", "volt", "lesz", "csak", "meg", "már", "még", "de", "ha", "mint", "vagy", "után", "előtt", "között", "felé", "által", "mögött", "mellett", "számára", "szerint", "által", "igen", "nagyon", "itt", "ott", "akkor", "most", "mindig", "soha", "néha", "gyakran", "ritkán", "továbbá", "azonban", "ezért", "mivel", "pedig", "bár", "habár", "miután", "mielőtt"},
        "ro": {"și", "de", "în", "la", "cu", "pe", "un", "o", "este", "sunt", "au", "care", "că", "pentru", "din", "mai", "sau", "dar", "ca", "să", "nu", "fost", "fi", "va", "voi", "ei", "ele", "noi", "voi", "ei", "acest", "această", "acestea", "aceștia", "aceste", "unde", "când", "cum", "de ce", "cine", "ce", "după", "între", "prin", "sub", "peste", "lângă", "contra", "fără", "chiar", "doar", "deja", "încă", "totuși", "iar", "apoi", "atunci", "aici", "acolo", "astăzi", "ieri", "mâine"},
        "uk": {"і", "на", "в", "не", "що", "з", "як", "але", "він", "вона", "воно", "вони", "ми", "ви", "ти", "я", "цей", "ця", "це", "ці", "той", "та", "те", "ті", "бути", "є", "був", "була", "було", "були", "буде", "будуть", "мав", "мала", "мало", "мали", "має", "мають", "може", "можуть", "також", "тільки", "ще", "вже", "ні", "так", "якщо", "коли", "де", "чому", "як", "хто", "щоб", "бо", "адже", "оскільки", "після", "перед", "між", "через", "без", "для", "про", "від", "до", "за", "під", "над", "при"},
        "id": {"dan", "di", "yang", "untuk", "dengan", "ini", "itu", "pada", "dari", "adalah", "akan", "juga", "telah", "sudah", "oleh", "karena", "seperti", "atau", "hanya", "ada", "tidak", "bisa", "mereka", "kami", "kita", "anda", "saya", "dia", "ia", "hal", "bagi", "serta", "bahwa", "setelah", "sebelum", "ketika", "sementara", "meskipun", "walaupun", "namun", "tetapi", "maka", "kemudian", "selain", "lagi", "lebih", "paling", "sangat", "sekali", "jika", "apabila", "sebagai", "dalam", "melalui", "mengenai", "antara", "seluruh", "semua", "setiap", "lain", "baru", "lainnya", "lain kali"},
        "ms": {"dan", "di", "yang", "untuk", "dengan", "ini", "itu", "pada", "dari", "adalah", "akan", "juga", "telah", "sudah", "oleh", "kerana", "seperti", "atau", "hanya", "ada", "tidak", "boleh", "mereka", "kami", "kita", "anda", "saya", "dia", "ia", "hal", "bagi", "serta", "bahawa", "selepas", "sebelum", "ketika", "sementara", "walaupun", "namun", "tetapi", "maka", "kemudian", "selain", "lagi", "lebih", "paling", "sangat", "sekali", "jika", "apabila", "sebagai", "dalam", "melalui", "mengenai", "antara", "seluruh", "semua", "setiap", "lain", "baru", "lainnya"},
    }
    word_set = set(w.lower() for w in words)
    scores = {}
    for lang, samples in lang_samples.items():
        overlap = word_set & samples
        scores[lang] = len(overlap)
    if not scores:
        return None
    best_lang = max(scores, key=scores.get)
    if scores[best_lang] < 3:
        return None
    return best_lang


def detect_encoding(raw_bytes):
    if not raw_bytes:
        return "utf-8"
    boms = [
        (b"\xef\xbb\xbf", "utf-8-sig"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
        (b"\x00\x00\xfe\xff", "utf-32-be"),
        (b"\xff\xfe\x00\x00", "utf-32-le"),
    ]
    for bom, enc in boms:
        if raw_bytes[:len(bom)] == bom:
            return enc
    has_high_bytes = any(b > 127 for b in raw_bytes[:4096])
    if not has_high_bytes:
        return "ascii"
    utf8_valid = True
    try:
        raw_bytes.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        utf8_valid = False
    if utf8_valid:
        return "utf-8"
    for enc in ("utf-16", "windows-1252", "iso-8859-1", "latin-1"):
        try:
            raw_bytes.decode(enc)
            return enc
        except (UnicodeDecodeError, ValueError):
            continue
    return "latin-1"


def is_rtl_text(text):
    rtl_count = 0
    total_count = 0
    for char in text:
        if char.isspace():
            continue
        total_count += 1
        cp = ord(char)
        for start, end in RTL_SCRIPT_RANGES:
            if start <= cp <= end:
                rtl_count += 1
                break
    if total_count == 0:
        return False, 0.0
    ratio = rtl_count / total_count
    return ratio > 0.3, round(ratio * 100, 1)


def detect_rtl_lang(lang_code):
    if lang_code and lang_code.lower() in RTL_LANGS:
        return True
    return False


def detect_unicode_script(char):
    try:
        name = unicodedata.name(char, "")
        if name:
            parts = name.split()
            if parts:
                script_key = parts[0]
                return UNICODE_SCRIPT_MAP.get(script_key, script_key)
    except ValueError:
        pass
    return "Unknown"


def get_script_distribution(text):
    scripts = Counter()
    for char in text:
        if char.isspace():
            continue
        script = detect_unicode_script(char)
        scripts[script] += 1
    return dict(scripts)


def detect_language_by_script(text):
    script_counts = Counter()
    for char in text:
        if char.isspace():
            continue
        cp = ord(char)
        for lang, ranges in SCRIPT_LANGUAGE_RANGES.items():
            for start, end in ranges:
                if start <= cp <= end:
                    script_counts[lang] += 1
                    break
    if script_counts:
        return script_counts.most_common(1)[0][0]
    return None


def analyze_unicode_content(text):
    categories = Counter()
    for char in text:
        if char.isspace():
            continue
        cat = unicodedata.category(char)
        categories[cat] += 1
    total = sum(categories.values()) or 1
    result = {
        "total_characters": total,
        "letter_count": sum(v for k, v in categories.items() if k.startswith("L")),
        "number_count": sum(v for k, v in categories.items() if k.startswith("N")),
        "punctuation_count": sum(v for k, v in categories.items() if k.startswith("P")),
        "symbol_count": sum(v for k, v in categories.items() if k.startswith("S")),
        "non_ascii_count": sum(1 for c in text if ord(c) > 127),
    }
    result["non_ascii_pct"] = round(result["non_ascii_count"] / max(len(text), 1) * 100, 1)
    scripts = get_script_distribution(text)
    result["script_distribution"] = scripts
    result["unique_scripts_detected"] = len(scripts)
    return result


def detect_language_segments(text, segment_size=200):
    segments = []
    words = text.split()
    for i in range(0, len(words), segment_size):
        segment = " ".join(words[i:i + segment_size])
        lang = detect_language_from_content(segment)
        if not lang:
            lang = detect_language_by_script(segment)
        preview = segment[:80] + "..." if len(segment) > 80 else segment
        segments.append({
            "text_preview": preview,
            "language": lang,
            "word_count": len(segment.split()),
        })
    return segments


def translation_quality_hints(text):
    hints = []
    if re.search(r"[.!?]\s*[.!?]", text):
        hints.append("Inconsistent punctuation spacing detected")
    if re.search(r"\b(\w+)\s+\1\b", text, re.IGNORECASE):
        hints.append("Repeated words detected")
    scripts = get_script_distribution(text)
    if len(scripts) > 3:
        hints.append("Multiple scripts detected; possible mixed language content")
    sentences = _split_sentences(text)
    if sentences:
        avg_len = sum(len(s.split()) for s in sentences) / len(sentences)
        if avg_len > 40:
            hints.append("Very long average sentences; may indicate translation artifacts")
    filler_patterns = [
        r"\bhow to\b.*\bstep by step\b",
        r"\bin this article\b.*\bwe will\b",
        r"\bit is worth noting\b",
        r"\bneedless to say\b",
        r"\bit goes without saying\b",
    ]
    for pattern in filler_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            hints.append("Common filler phrase detected: " + pattern.replace("\\b", "").replace("\b", ""))
            break
    return hints


def language_readability_adjustment(score, lang_code):
    factor = LANGUAGE_READABILITY_FACTORS.get(lang_code, 1.0)
    adjusted = score / factor if factor > 0 else score
    return round(max(0.0, min(100.0, adjusted)), 1)


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------
def score_color(score, max_val, colors):
    pct = score / max_val if max_val > 0 else 0
    if pct >= 0.7:
        return colors.BRIGHT_GREEN
    elif pct >= 0.5:
        return colors.BRIGHT_YELLOW
    else:
        return colors.BRIGHT_RED


def grade_from_score(total, max_score=100):
    pct = total / max_score * 100 if max_score > 0 else 0
    if pct >= 90:
        return "A", "[1;92m"
    elif pct >= 70:
        return "B", "[1;94m"
    elif pct >= 50:
        return "C", "[1;93m"
    elif pct >= 30:
        return "D", "[1;91m"
    else:
        return "F", "[1;91m"


def wcag_level(accessibility_score, max_score):
    pct = accessibility_score / max_score if max_score > 0 else 0
    if pct >= 0.9:
        return "AAA"
    elif pct >= 0.7:
        return "AA"
    elif pct >= 0.5:
        return "A"
    else:
        return "Non-Compliant"


# ---------------------------------------------------------------------------
# v6.0 category registry
# ---------------------------------------------------------------------------
CATEGORY_MAX = {
    "structure": 15, "readability": 15, "accessibility": 15,
    "links": 10, "images": 10, "freshness": 10,
    "social_seo": 10, "multimedia": 5, "depth": 10,
    "content_strategy": 10, "code_blocks": 5, "blockquotes": 3,
    "originality": 10, "uniqueness": 10, "quality_signals": 10,
    "engagement": 10, "conversion": 10,
    "flow": 5, "scannability": 5, "hierarchy": 5,
}

CATEGORY_LABELS = {
    "structure": "Content Structure",
    "readability": "Readability",
    "accessibility": "Accessibility",
    "links": "Link Quality",
    "images": "Image Quality",
    "freshness": "Content Freshness",
    "social_seo": "Social & SEO",
    "multimedia": "Multimedia",
    "depth": "Content Depth",
    "content_strategy": "Content Strategy",
    "code_blocks": "Code Blocks",
    "blockquotes": "Blockquotes",
    "originality": "Originality",
    "uniqueness": "Uniqueness",
    "quality_signals": "Quality Signals",
    "engagement": "Engagement",
    "conversion": "Conversion",
    "flow": "Content Flow",
    "scannability": "Scannability",
    "hierarchy": "Hierarchy",
}

QUALITY_INDEX_WEIGHTS = {
    "structure": 10, "readability": 10, "accessibility": 10, "links": 6,
    "images": 4, "freshness": 6, "social_seo": 9, "multimedia": 3,
    "depth": 8, "content_strategy": 7, "code_blocks": 2, "blockquotes": 2,
    "originality": 6, "uniqueness": 5, "quality_signals": 6,
    "engagement": 5, "conversion": 5, "flow": 3, "scannability": 3,
    "hierarchy": 3,
}

DASHBOARD_GROUPS = [
    ("Core Content", ["structure", "readability", "depth", "hierarchy", "flow", "scannability"]),
    ("Discovery & SEO", ["social_seo", "links", "freshness", "images", "multimedia"]),
    ("Originality & Quality", ["originality", "uniqueness", "quality_signals"]),
    ("Engagement & Conversion", ["engagement", "conversion", "content_strategy"]),
    ("Accessibility & Craft", ["accessibility", "code_blocks", "blockquotes"]),
]


# ---------------------------------------------------------------------------
# v6.0 analysis lexicons
# ---------------------------------------------------------------------------
TRANSITION_WORDS = frozenset({
    "however", "therefore", "moreover", "furthermore", "additionally",
    "meanwhile", "consequently", "nevertheless", "nonetheless", "thus",
    "hence", "accordingly", "otherwise", "besides", "similarly",
    "likewise", "conversely", "instead", "first", "second", "third",
    "next", "then", "finally", "later", "firstly", "secondly",
    "lastly", "afterward", "subsequently", "specifically", "indeed",
    "also", "because", "since", "although", "while", "until",
    "unless", "after", "before",
})

TRANSITION_PHRASES = (
    "for example", "for instance", "in addition", "on the other hand",
    "as a result", "in contrast", "in conclusion", "in summary",
    "for this reason", "in other words", "to sum up", "as mentioned",
    "in fact", "even so", "that said", "by contrast", "in short",
)

CONTENT_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "but", "if", "then", "else", "of",
    "to", "in", "on", "for", "with", "as", "by", "at", "from", "is",
    "are", "was", "were", "be", "been", "it", "this", "that", "these",
    "those", "you", "your", "we", "our", "they", "their", "he", "she",
    "his", "her", "not", "no", "do", "does", "did", "have", "has",
    "had", "will", "would", "can", "could", "should", "may", "might",
    "must", "than", "what", "which", "who", "whom", "when", "where",
    "why", "how", "all", "each", "every", "so", "into", "over",
    "under", "about", "after", "before", "between", "through",
    "during", "its", "up", "out", "just", "than", "too", "very",
    "can", "now", "get", "got", "one", "two", "also",
})

FORMULAIC_OPENERS = (
    "in today's world", "in today's digital age", "in the digital age",
    "since the dawn of", "have you ever wondered", "in this article we",
    "in this blog post", "welcome to our", "unlock the", "delve into",
    "when it comes to", "it's no secret", "look no further",
    "in a world where", "picture this", "let's face it",
    "at the end of the day", "navigating the world of",
)

EVIDENCE_TERMS = (
    "study", "research", "survey", "data", "statistics", "report",
    "analysis", "findings", "percent", "evidence", "benchmark",
    "measured", "recorded", "sample size",
)

EXAMPLE_MARKERS = (
    "example", "for instance", "such as", "e.g.", "case study",
    "for example", "consider the following", "imagine",
)

AUTHORITY_MARKERS = (
    "according to", "research shows", "study", "source",
    "reported by", "citation", "peer-reviewed", "published in",
)

CREDENTIAL_MARKERS = (
    "expert", "phd", "professor", "certified", "specialist",
    "analyst", "researcher", "years of experience", "doctor",
)

CURIOSITY_WORDS = (
    "secret", "surprising", "unexpected", "mistake", "truth",
    "unlock", "discover", "mistakes", "myths", "hidden",
    "proven", "essential", "ultimate", "surprisingly",
)

EMOTIONAL_WORDS = (
    "love", "hate", "fear", "exciting", "frustrating", "delight",
    "shocking", "pain", "gain", "struggle", "win", "loss", "amazing",
    "incredible", "powerful", "transform",
)

CTA_PHRASES = (
    "sign up", "get started", "start free", "try it", "download",
    "subscribe", "buy now", "purchase", "book a", "request a",
    "contact us", "join now", "apply now", "upgrade", "claim",
    "schedule a", "talk to", "see pricing", "free trial",
)

BENEFIT_WORDS = (
    "free", "save", "guarantee", "instantly", "easily", "proven",
    "faster", "better", "results", "reduce", "increase", "boost",
    "shortcut", "effortless", "risk-free",
)

SOCIAL_PROOF_MARKERS = (
    "testimonial", "review", "rated", "trusted by", "customers",
    "clients", "stars", "case study", "as seen on", "award",
    "5-star", "feedback",
)

URGENCY_WORDS = (
    "limited", "today only", "now", "deadline", "hurry", "expires",
    "last chance", "only", "spots", "ends soon", "acting",
)

FRICTION_REDUCERS = (
    "no credit card", "cancel anytime", "no commitment", "free trial",
    "money-back", "no obligation", "guaranteed", "secure",
)


# ---------------------------------------------------------------------------
# v6.0 text-analysis helpers
# ---------------------------------------------------------------------------
def type_token_ratio(words):
    if not words:
        return 0.0
    return len(set(w.lower() for w in words)) / len(words)


def hapax_ratio(words):
    if not words:
        return 0.0
    counts = Counter(w.lower() for w in words)
    if not counts:
        return 0.0
    hapax = sum(1 for v in counts.values() if v == 1)
    return hapax / len(counts)


def word_entropy(words):
    if not words:
        return 0.0
    counts = Counter(w.lower() for w in words)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def sentence_length_stdev(sentences):
    lengths = [len(_get_words(s)) for s in sentences]
    if len(lengths) < 2:
        return 0.0
    mean = sum(lengths) / len(lengths)
    variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)
    return math.sqrt(variance)


def duplicate_sentence_ratio(sentences):
    if not sentences:
        return 0.0
    normalized = [re.sub(r"\s+", " ", s.strip().lower()) for s in sentences if len(s.strip()) > 10]
    if not normalized:
        return 0.0
    counts = Counter(normalized)
    dup = sum(c for c in counts.values() if c > 1)
    return dup / len(normalized)


def repeated_ngram_ratio(text, n=5):
    tokens = [w.lower() for w in _get_words(text)]
    if len(tokens) < n:
        return 0.0
    grams = Counter(tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1))
    total = sum(grams.values())
    if total == 0:
        return 0.0
    repeated = sum(c for c in grams.values() if c > 1)
    return repeated / total


def distinct_phrase_ratio(words, n=3):
    tokens = [w.lower() for w in words]
    if len(tokens) < n:
        return 0.0
    grams = Counter(tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1))
    if not grams:
        return 0.0
    once = sum(1 for c in grams.values() if c == 1)
    return once / len(grams)


def reading_time_minutes(words, wpm=225):
    if not words:
        return 0.0
    return round(len(words) / wpm, 1)


def transition_ratio(sentences):
    if not sentences:
        return 0.0
    hits = 0
    for s in sentences:
        lower = s.lower()
        if any(p in lower for p in TRANSITION_PHRASES):
            hits += 1
            continue
        tokens = [w.lower().strip(".,!?;:'\"") for w in _get_words(s)]
        if any(w in TRANSITION_WORDS for w in tokens):
            hits += 1
    return hits / len(sentences)


def paragraph_continuity(paragraphs):
    def content_words(p):
        return set(
            w.lower() for w in _get_words(p)
            if w.lower() not in CONTENT_STOPWORDS and len(w) > 2
        )
    sets = [s for s in (content_words(p) for p in paragraphs) if s]
    if len(sets) < 2:
        return 1.0
    overlaps = []
    for i in range(len(sets) - 1):
        inter = sets[i] & sets[i + 1]
        union = sets[i] | sets[i + 1]
        if union:
            overlaps.append(len(inter) / len(union))
    return sum(overlaps) / len(overlaps) if overlaps else 0.0


def compute_readability_index(details):
    if not details:
        return 0.0
    fre = details.get("language_adjusted_fre", details.get("flesch_reading_ease", 0)) or 0
    asl = details.get("avg_sentence_length", 20) or 20
    complex_pct = details.get("complex_word_pct", 20) or 0
    passive_pct = details.get("passive_voice_pct", 10) or 0
    adverb_pct = details.get("adverb_pct", 5) or 0
    refinement = details.get("readability_refinement", {}) or {}
    sl_sd = float(refinement.get("sentence_length_stdev", 9.0) or 9.0)
    question_pct = float(refinement.get("question_cadence_pct", 8.0) or 8.0)
    smog = float(refinement.get("smog_index", details.get("smog_index", 8.0)) or 8.0)
    variety_term = max(0.0, 100.0 - abs(sl_sd - 9.0) * 8.0)
    cadence_term = max(0.0, 100.0 - abs(question_pct - 8.0) * 10.0)
    smog_term = max(0.0, (12.0 - min(smog, 20.0)) / 12.0 * 100.0)
    score = 0.0
    score += max(0.0, min(float(fre), 100.0)) * 0.40
    score += max(0.0, (30.0 - min(float(asl), 60.0))) / 30.0 * 100.0 * 0.15
    score += max(0.0, (30.0 - min(float(complex_pct), 60.0))) / 30.0 * 100.0 * 0.12
    score += max(0.0, (25.0 - min(float(passive_pct), 50.0))) / 25.0 * 100.0 * 0.08
    score += max(0.0, (6.0 - min(float(adverb_pct), 12.0))) / 6.0 * 100.0 * 0.07
    score += variety_term * 0.08
    score += cadence_term * 0.05
    score += smog_term * 0.05
    return max(0.0, min(100.0, score))


def compute_content_quality_index(scores, results=None):
    total_weight = 0.0
    acc = 0.0
    for key, weight in QUALITY_INDEX_WEIGHTS.items():
        mx = CATEGORY_MAX.get(key, 0)
        if mx <= 0:
            continue
        acc += (scores.get(key, 0) / mx) * weight
        total_weight += weight
    if total_weight <= 0:
        return 0.0
    base = max(0.0, min(100.0, acc / total_weight * 100.0))
    if not results:
        return base
    refinement_terms = []
    orig_deep = results.get("originality", {}).get("originality_deep", {}) or {}
    if "deep_originality_index" in orig_deep:
        refinement_terms.append(float(orig_deep.get("deep_originality_index", 0) or 0))
    qual_ref = results.get("quality_signals", {}).get("quality_refinement", {}) or {}
    if "refined_quality_index" in qual_ref:
        refinement_terms.append(float(qual_ref.get("refined_quality_index", 0) or 0))
    eng_ref = results.get("engagement", {}).get("engagement_refinement", {}) or {}
    if "refined_engagement_index" in eng_ref:
        refinement_terms.append(float(eng_ref.get("refined_engagement_index", 0) or 0))
    conv_ref = results.get("conversion", {}).get("conversion_refinement", {}) or {}
    if "refined_conversion_index" in conv_ref:
        refinement_terms.append(float(conv_ref.get("refined_conversion_index", 0) or 0))
    struct_ref = results.get("structure", {}).get("structure_refinement", {}) or {}
    if "section_balance_score" in struct_ref:
        refinement_terms.append(float(struct_ref.get("section_balance_score", 0) or 0))
    flow_ref = results.get("flow", {}).get("flow_refinement", {}) or {}
    if "narrative_arc_ok" in flow_ref:
        refinement_terms.append(85.0 if flow_ref.get("narrative_arc_ok") else 45.0)
    if not refinement_terms:
        return base
    refinement_avg = sum(refinement_terms) / len(refinement_terms)
    blended = base * 0.85 + refinement_avg * 0.15
    return max(0.0, min(100.0, blended))


def compute_seo_content_score(scores, results):
    def category_pct(key):
        mx = CATEGORY_MAX.get(key, 0)
        if mx <= 0:
            return 0.0
        return scores.get(key, 0) / mx * 100.0
    base = (
        category_pct("social_seo") * 0.35
        + category_pct("structure") * 0.20
        + category_pct("links") * 0.20
        + category_pct("freshness") * 0.10
        + category_pct("depth") * 0.15
    )
    bonus = 0.0
    social = results.get("social_seo", {})
    if social.get("canonical_url"):
        bonus += 2.0
    desc_len = social.get("meta_description_length", 0) or 0
    if 120 <= desc_len <= 160:
        bonus += 2.0
    og_tags = social.get("og_tags", {}) or {}
    if "og:title" in og_tags and "og:description" in og_tags:
        bonus += 1.0
    if social.get("json_ld_structured_data"):
        bonus += 1.0
    social_align = social.get("title_h1_alignment_pct", 0) or 0
    if social_align >= 40:
        bonus += 2.0
    depth_words = (results.get("depth", {}) or {}).get("word_count", 0) or 0
    if depth_words >= 600:
        bonus += 2.0
    elif depth_words >= 300:
        bonus += 1.0
    internal_ratio = (results.get("links", {}) or {}).get("internal_ratio", 0) or 0
    if 30 <= internal_ratio <= 80:
        bonus += 1.5
    img_alt = (results.get("images", {}) or {}).get("alt_completeness_pct", 0) or 0
    if img_alt >= 90:
        bonus += 1.5
    hier_ref = (results.get("hierarchy", {}) or {}).get("hierarchy_refinement", {}) or {}
    title_cov = hier_ref.get("title_term_coverage_pct", 0) or 0
    if title_cov >= 40:
        bonus += 1.5
    return max(0.0, min(100.0, base + bonus))


def accessibility_quality_percentage(details):
    if not details:
        return 0.0
    points = 0.0
    alt_ratio = float(details.get("alt_text_ratio", 100) or 0)
    points += max(0.0, min(alt_ratio, 100.0)) / 100.0 * 25.0
    if details.get("lang_attribute"):
        points += 15.0
    aria_signal = float(details.get("aria_labels", 0) or 0) + float(details.get("aria_roles", 0) or 0)
    points += min(aria_signal / 5.0, 1.0) * 15.0
    label_ratio = float(details.get("labeled_inputs_ratio", 100) or 100)
    points += max(0.0, min(label_ratio, 100.0)) / 100.0 * 15.0
    landmark_types = details.get("landmark_types", []) or []
    points += min(len(landmark_types) / 4.0, 1.0) * 15.0
    if details.get("skip_navigation"):
        points += 7.5
    if details.get("focus_indicators_detected"):
        points += 7.5
    if details.get("heading_order_ok"):
        points += 5.0
    generic_links = float(details.get("generic_link_texts", 0) or 0)
    points -= min(generic_links * 2.0, 10.0)
    if details.get("table_captions"):
        points += 2.5
    return max(0.0, min(100.0, points))



# ---------------------------------------------------------------------------
# ContentAnalyzer
# ---------------------------------------------------------------------------
class ContentAnalyzer:
    def __init__(self, url, timeout=15, verbose=False, no_color=False):
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.colors = Colors(no_color)
        self.soup = None
        self.html = ""
        self.headers = {}
        self.results = {}
        self.scores = {}
        self.recommendations = []
        self.base_domain = urlparse(url).netloc
        self.all_words = []
        self.all_sentences = []
        self.detected_language = None
        self.is_rtl = False
        self.rtl_pct = 0.0
        self.encoding = "utf-8"

    def fetch_content(self):
        c = self.colors
        try:
            print(c.colorize("  [*] Fetching: " + self.url, c.CYAN))
            resp = requests.get(
                self.url,
                timeout=self.timeout,
                headers={"User-Agent": "ContentAnalyzer/6.0"},
                allow_redirects=True,
            )
            resp.raise_for_status()
            self.html = resp.text
            self.headers = dict(resp.headers)
            self.encoding = detect_encoding(resp.content[:4096])
            self.soup = BeautifulSoup(self.html, "html.parser")
            byte_count = len(self.html)
            print(c.colorize("  [+] OK - " + str(byte_count) + " bytes, status " + str(resp.status_code), c.GREEN))
            return True
        except requests.exceptions.RequestException as e:
            print(c.colorize("  [!] Failed: " + str(e), c.RED))
            return False

    def get_visible_text(self):
        if not self.soup:
            return ""
        clone = BeautifulSoup(str(self.soup), "html.parser")
        for tag in clone(["script", "style", "noscript", "head"]):
            tag.decompose()
        return clone.get_text(separator=" ", strip=True)

    def detect_language(self):
        c = self.colors
        print(c.colorize("  [>] Detecting language...", c.YELLOW))
        meta_lang = detect_language_from_meta(self.soup) if self.soup else None
        text = self.get_visible_text()
        content_lang = detect_language_from_content(text)
        script_lang = detect_language_by_script(text)
        self.detected_language = meta_lang or content_lang or script_lang or "en"
        self.is_rtl = detect_rtl_lang(self.detected_language)
        text_rtl, text_rtl_pct = is_rtl_text(text)
        if text_rtl:
            self.is_rtl = True
            self.rtl_pct = text_rtl_pct
        details = {
            "language": self.detected_language,
            "source": "meta" if meta_lang else ("content" if content_lang else ("script" if script_lang else "default")),
            "is_rtl": self.is_rtl,
            "rtl_text_percentage": self.rtl_pct,
            "encoding": self.encoding,
        }
        self.results["language"] = details
        lang_display = self.detected_language.upper()
        if self.is_rtl:
            lang_display += " (RTL)"
        print(c.colorize("  [+] Language: " + lang_display + " | Encoding: " + self.encoding, c.GREEN))

    def check_structure(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing content structure...", c.YELLOW))
        score = 0
        details = {}

        h1_tags = self.soup.find_all("h1")
        details["h1_count"] = len(h1_tags)
        if len(h1_tags) == 1:
            score += 2
        elif len(h1_tags) == 0:
            self.recommendations.append("Add exactly one H1 tag for the main title")
        else:
            self.recommendations.append("Found " + str(len(h1_tags)) + " H1 tags; use exactly one")
            score += 0.5

        all_headings = []
        heading_texts = []
        for level in range(1, 7):
            for tag in self.soup.find_all("h" + str(level)):
                all_headings.append(level)
                heading_texts.append({"level": level, "text": tag.get_text(strip=True)})
        details["heading_levels"] = all_headings
        details["heading_outline"] = heading_texts

        hierarchy_ok = True
        skipped_levels = 0
        for i in range(1, len(all_headings)):
            if all_headings[i] > all_headings[i - 1] + 1:
                hierarchy_ok = False
                skipped_levels += 1
        if hierarchy_ok and len(all_headings) > 0:
            score += 2
        elif len(all_headings) == 0:
            self.recommendations.append("Add heading tags (H2-H6) to structure content")
        else:
            score += 0.5
            self.recommendations.append("Fix heading hierarchy (found " + str(skipped_levels) + " skipped level(s))")
        details["skipped_levels"] = skipped_levels

        paragraphs = self.soup.find_all("p")
        details["paragraph_count"] = len(paragraphs)
        if len(paragraphs) >= 3:
            score += 1.5
        elif len(paragraphs) > 0:
            score += 0.5
        else:
            self.recommendations.append("Add paragraphs to break up text content")

        para_lengths = [len(p.get_text(strip=True).split()) for p in paragraphs if p.get_text(strip=True)]
        if para_lengths:
            avg_para = sum(para_lengths) / len(para_lengths)
            details["avg_paragraph_words"] = round(avg_para, 1)
            if 30 <= avg_para <= 150:
                score += 1
            elif avg_para > 150:
                self.recommendations.append("Paragraphs are too long; aim for 30-150 words")
        else:
            details["avg_paragraph_words"] = 0

        lists = self.soup.find_all(["ul", "ol"])
        details["list_count"] = len(lists)
        if lists:
            score += 1

        tables = self.soup.find_all("table")
        details["table_count"] = len(tables)
        if tables:
            score += 0.5

        semantic_tags = ["article", "section", "nav", "main", "aside", "header", "footer"]
        semantic = self.soup.find_all(semantic_tags)
        details["semantic_elements"] = len(semantic)
        semantic_breakdown = {}
        for tag_name in semantic_tags:
            count = len(self.soup.find_all(tag_name))
            if count > 0:
                semantic_breakdown[tag_name] = count
        details["semantic_breakdown"] = semantic_breakdown
        if len(semantic) >= 3:
            score += 2
        elif len(semantic) >= 1:
            score += 1
        else:
            self.recommendations.append("Use semantic HTML5 elements (article, section, nav, main)")

        total_headings = len(all_headings)
        if total_headings >= 3:
            score += 1.5
        elif total_headings >= 1:
            score += 0.5

        dl_tags = self.soup.find_all("dl")
        details["definition_list_count"] = len(dl_tags)
        if dl_tags:
            score += 0.5

        bq_tags = self.soup.find_all("blockquote")
        details["blockquote_count"] = len(bq_tags)
        if bq_tags:
            score += 0.5

        toc_candidates = self.soup.find_all("nav", attrs={"aria-label": re.compile(r"table of contents|toc", re.IGNORECASE)})
        toc_candidates += self.soup.find_all(id=re.compile(r"toc|table-of-contents", re.IGNORECASE))
        toc_candidates += self.soup.find_all(class_=re.compile(r"toc|table-of-contents", re.IGNORECASE))
        details["toc_hints"] = len(toc_candidates)
        if toc_candidates:
            score += 0.5

        score = min(score, 15)

        optimization = {}
        heading_word_counts = [len(_get_words(h["text"])) for h in heading_texts if h["text"]]
        good_headings = [n for n in heading_word_counts if 2 <= n <= 8]
        if heading_word_counts:
            optimized_ratio = len(good_headings) / len(heading_word_counts)
        else:
            optimized_ratio = 0.0
        optimization["optimized_heading_ratio"] = round(optimized_ratio * 100, 1)
        optimization["heading_length_optimized"] = optimized_ratio >= 0.7
        empty_headings = sum(1 for h in heading_texts if not h["text"])
        optimization["empty_headings"] = empty_headings
        overlong_headings = sum(1 for h in heading_texts if len(h["text"]) > 70)
        optimization["overlong_headings"] = overlong_headings
        h2_count = all_headings.count(2)
        words_local = _get_words(self.get_visible_text())
        words_per_h2 = len(words_local) / max(h2_count, 1)
        optimization["h2_section_count"] = h2_count
        optimization["words_per_h2_section"] = round(words_per_h2, 1)
        if optimized_ratio >= 0.7 and empty_headings == 0 and overlong_headings == 0:
            score += 0.5
        elif overlong_headings:
            self.recommendations.append("Shorten headings to under 70 characters")
        elif empty_headings:
            self.recommendations.append("Remove or fill empty heading elements")
        if h2_count >= 3 and 100 <= words_per_h2 <= 500:
            score += 0.5
        elif h2_count < 3 and len(words_local) >= 500:
            self.recommendations.append("Break long content into more H2 sections (aim for one H2 per 100-500 words)")

        paras_text = [p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True)]
        structure_refinement = {}
        intro_present = bool(paras_text) and len(_get_words(paras_text[0])) <= 100
        structure_refinement["intro_section_present"] = intro_present
        closing_markers_struct = ("conclusion", "in summary", "to summarize", "next steps", "final thoughts", "faq")
        conclusion_present = False
        for para in paras_text[-4:]:
            para_lower = para.lower()
            if any(marker in para_lower for marker in closing_markers_struct):
                conclusion_present = True
                break
        structure_refinement["conclusion_section_present"] = conclusion_present
        section_buckets = []
        current_bucket = None
        for el in self.soup.find_all(["h1", "h2", "p", "li"]):
            if el.name in ("h1", "h2"):
                current_bucket = []
                section_buckets.append(current_bucket)
            if current_bucket is None:
                current_bucket = []
                section_buckets.append(current_bucket)
            current_bucket.append(len(_get_words(el.get_text())))
        section_sizes = [sum(b) for b in section_buckets if b]
        structure_refinement["section_count"] = len(section_sizes)
        if len(section_sizes) >= 2:
            section_mean = sum(section_sizes) / len(section_sizes)
            section_var = sum((x - section_mean) ** 2 for x in section_sizes) / len(section_sizes)
            cv = math.sqrt(section_var) / section_mean if section_mean else 1.0
            balance = max(0.0, 1.0 - cv)
        elif len(section_sizes) == 1:
            balance = 0.5
        else:
            balance = 0.0
        structure_refinement["section_balance_score"] = round(balance * 100, 1)
        structure_refinement["media_in_sections"] = bool(self.soup.find_all(["img", "video"])) and len(section_sizes) >= 2
        details["structure_refinement"] = structure_refinement
        if intro_present:
            score += 0.25
        if conclusion_present:
            score += 0.25
        if balance >= 0.6:
            score += 0.25
        elif balance < 0.3 and len(section_sizes) >= 3:
            self.recommendations.append("Section lengths are uneven; rebalance content across H2 sections")
        score = min(score, 15)
        details["optimization"] = optimization
        details["total_headings"] = total_headings
        self.results["structure"] = details
        self.scores["structure"] = round(score, 1)

    def check_readability(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing readability...", c.YELLOW))
        score = 0
        details = {}
        text = self.get_visible_text()
        words = _get_words(text)
        sentences = _split_sentences(text)
        self.all_words = words
        self.all_sentences = sentences

        details["total_words"] = len(words)
        details["total_sentences"] = len(sentences)

        if not words:
            details["readability_index"] = 0.0
            self.results["readability"] = details
            self.scores["readability"] = 0
            return

        fre = flesch_reading_ease(text)
        fkg = flesch_kincaid_grade(text)
        gf = gunning_fog_index(text)
        cli = coleman_liau_index(text)
        ari = automated_readability_index(text)
        lwf = linsear_write_formula(text)
        smog = smog_index(text)

        all_indices = {
            "flesch_kincaid_grade": fkg,
            "gunning_fog_index": gf,
            "coleman_liau_index": cli,
            "automated_readability_index": ari,
            "linsear_write_formula": lwf,
        }
        ts = text_standard_score(all_indices)

        lang_code = self.detected_language or "en"
        adjusted_fre = language_readability_adjustment(fre, lang_code)
        adjusted_ts = language_readability_adjustment(ts, lang_code)

        details["flesch_reading_ease"] = round(fre, 1)
        details["flesch_kincaid_grade"] = round(fkg, 1)
        details["gunning_fog_index"] = round(gf, 1)
        details["coleman_liau_index"] = round(cli, 1)
        details["automated_readability_index"] = round(ari, 1)
        details["linsear_write_formula"] = round(lwf, 1)
        details["smog_index"] = round(smog, 1)
        details["text_standard"] = round(ts, 1)
        details["readability_level"] = readability_label(fre)
        details["text_standard_level"] = grade_level_label(ts)
        details["language_adjusted_fre"] = adjusted_fre
        details["language_adjusted_ts"] = adjusted_ts
        details["language_readability_factor"] = LANGUAGE_READABILITY_FACTORS.get(lang_code, 1.0)

        if fre >= 60:
            score += 3
        elif fre >= 40:
            score += 1.5
        else:
            self.recommendations.append("Improve readability: use shorter sentences and simpler words")

        avg_sentence_len = len(words) / max(len(sentences), 1)
        details["avg_sentence_length"] = round(avg_sentence_len, 1)
        if avg_sentence_len <= 20:
            score += 2
        elif avg_sentence_len <= 30:
            score += 1
        else:
            self.recommendations.append("Average sentence length is " + str(round(avg_sentence_len)) + " words; aim for under 20")

        avg_word_len = sum(len(w) for w in words) / len(words)
        details["avg_word_length"] = round(avg_word_len, 1)
        if avg_word_len <= 5:
            score += 1.5
        elif avg_word_len <= 7:
            score += 0.5

        complex_words = [w for w in words if is_complex_word(w)]
        complex_pct = len(complex_words) / len(words) * 100
        details["complex_word_count"] = len(complex_words)
        details["complex_word_pct"] = round(complex_pct, 1)
        if complex_pct <= 15:
            score += 2
        elif complex_pct <= 30:
            score += 1
        else:
            self.recommendations.append(str(round(complex_pct)) + "% complex words; reduce jargon")

        passive_count = sum(1 for s in sentences if is_passive_voice(s))
        passive_pct = passive_count / max(len(sentences), 1) * 100
        details["passive_voice_pct"] = round(passive_pct, 1)
        if passive_pct <= 10:
            score += 1.5
        elif passive_pct <= 25:
            score += 0.5
        else:
            self.recommendations.append("Reduce passive voice usage")

        adverb_count = count_adverbs(words)
        adverb_pct = adverb_count / len(words) * 100
        details["adverb_count"] = adverb_count
        details["adverb_pct"] = round(adverb_pct, 1)
        if adverb_pct <= 3:
            score += 1.5
        elif adverb_pct <= 6:
            score += 0.5
        else:
            self.recommendations.append("Reduce adverb usage for stronger writing")

        para_lengths = [len(p.get_text(strip=True).split()) for p in self.soup.find_all("p") if p.get_text(strip=True)]
        if para_lengths:
            avg_para = sum(para_lengths) / len(para_lengths)
            details["avg_paragraph_words"] = round(avg_para, 1)
            details["max_paragraph_words"] = max(para_lengths)
            if 30 <= avg_para <= 150:
                score += 1.5
            elif avg_para > 200:
                self.recommendations.append("Some paragraphs are very long; break them up")
        else:
            details["avg_paragraph_words"] = 0

        score = min(score, 15)

        sl_sd = sentence_length_stdev(sentences)
        question_sentences = sum(1 for s in sentences if "?" in s)
        question_pct = question_sentences / max(len(sentences), 1) * 100
        short_sentences = sum(1 for s in sentences if 1 <= len(_get_words(s)) <= 12)
        long_sentences = sum(1 for s in sentences if len(_get_words(s)) > 30)
        short_sentence_pct = short_sentences / max(len(sentences), 1) * 100
        long_sentence_pct = long_sentences / max(len(sentences), 1) * 100
        readability_refinement = {
            "smog_index": round(smog, 1),
            "sentence_length_stdev": round(sl_sd, 2),
            "question_cadence_pct": round(question_pct, 1),
            "short_sentence_pct": round(short_sentence_pct, 1),
            "long_sentence_pct": round(long_sentence_pct, 1),
        }
        ref_points = 0.0
        if 5.0 <= sl_sd <= 14.0:
            ref_points += 0.3
        elif sl_sd < 3.0:
            self.recommendations.append("Sentence lengths are uniform; vary short and long sentences for rhythm")
        if 3.0 <= question_pct <= 15.0:
            ref_points += 0.2
        if long_sentence_pct <= 15.0:
            ref_points += 0.2
        elif long_sentence_pct > 25.0:
            self.recommendations.append("More than a quarter of sentences exceed 30 words; split the long ones")
            ref_points -= 0.2
        if smog <= 10.0:
            ref_points += 0.3
        elif smog > 14.0:
            self.recommendations.append("SMOG index is high; simplify multi-syllable terms for general audiences")
        readability_refinement["refinement_points"] = round(ref_points, 2)
        details["readability_refinement"] = readability_refinement
        score = max(0.0, min(15.0, score + ref_points))

        transition_tr = transition_ratio(sentences)
        details["transition_sentence_pct"] = round(transition_tr * 100, 1)
        ideal_sentences = 0
        for s in sentences:
            sl = len(_get_words(s))
            if 8 <= sl <= 22:
                ideal_sentences += 1
        ideal_sentence_pct = ideal_sentences / max(len(sentences), 1) * 100
        details["ideal_sentence_pct"] = round(ideal_sentence_pct, 1)
        readability_index = compute_readability_index(details)
        details["readability_index"] = round(readability_index, 1)
        if transition_tr >= 0.15:
            score += 0.5
        elif transition_tr < 0.05 and len(sentences) > 8:
            self.recommendations.append("Add transition words (however, therefore, for example) to connect ideas")
        if ideal_sentence_pct >= 60:
            score += 0.5
        score = min(score, 15)
        self.results["readability"] = details
        self.scores["readability"] = round(score, 1)

    def check_accessibility(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing accessibility...", c.YELLOW))
        score = 0
        details = {}

        images = self.soup.find_all("img")
        details["total_images"] = len(images)
        images_with_alt = [img for img in images if img.get("alt") is not None]
        images_empty_alt = [img for img in images_with_alt if img.get("alt", "").strip() == ""]
        details["images_with_alt"] = len(images_with_alt)
        details["images_empty_alt"] = len(images_empty_alt)
        if images:
            alt_ratio = len(images_with_alt) / len(images)
            details["alt_text_ratio"] = round(alt_ratio * 100, 1)
            if alt_ratio >= 0.9:
                score += 2.5
            elif alt_ratio >= 0.5:
                score += 1
                self.recommendations.append("Some images missing alt text")
            else:
                self.recommendations.append("Most images missing alt text; add descriptive alt attributes")
        else:
            details["alt_text_ratio"] = 100.0
            score += 2.5

        aria_labels = self.soup.find_all(attrs={"aria-label": True})
        aria_roles = self.soup.find_all(attrs={"role": True})
        aria_describedby = self.soup.find_all(attrs={"aria-describedby": True})
        aria_hidden = self.soup.find_all(attrs={"aria-hidden": True})
        details["aria_labels"] = len(aria_labels)
        details["aria_roles"] = len(aria_roles)
        details["aria_describedby"] = len(aria_describedby)
        details["aria_hidden"] = len(aria_hidden)
        if len(aria_labels) + len(aria_roles) >= 3:
            score += 1.5
        elif len(aria_labels) + len(aria_roles) >= 1:
            score += 0.5

        forms = self.soup.find_all("form")
        labels = self.soup.find_all("label")
        inputs = self.soup.find_all(["input", "textarea", "select"])
        details["forms"] = len(forms)
        details["labels"] = len(labels)
        inputs_with_label = 0
        for inp in inputs:
            inp_id = inp.get("id", "")
            if inp_id and self.soup.find("label", attrs={"for": inp_id}):
                inputs_with_label += 1
            elif inp.get("aria-label") or inp.get("aria-labelledby"):
                inputs_with_label += 1
            elif inp.get("title"):
                inputs_with_label += 1
        if inputs:
            label_ratio = inputs_with_label / len(inputs)
            details["labeled_inputs_ratio"] = round(label_ratio * 100, 1)
            if label_ratio >= 0.9:
                score += 1.5
            elif label_ratio >= 0.5:
                score += 0.5
                self.recommendations.append("Some form inputs missing labels")
            else:
                self.recommendations.append("Most form inputs missing labels for screen readers")
        else:
            score += 1.5

        html_tag = self.soup.find("html")
        has_lang = html_tag and html_tag.get("lang")
        details["lang_attribute"] = bool(has_lang)
        if has_lang:
            score += 1.5
        else:
            self.recommendations.append("Add lang attribute to html element")

        landmark_roles = ["banner", "contentinfo", "navigation", "main", "complementary", "region", "search"]
        landmark_elements = ["header", "footer", "nav", "main", "aside"]
        landmarks_found = []
        for elem in self.soup.find_all(landmark_elements):
            tag_name = elem.name
            if tag_name not in landmarks_found:
                landmarks_found.append(tag_name)
        aria_landmarks = self.soup.find_all(attrs={"role": landmark_roles})
        details["semantic_landmarks"] = len(self.soup.find_all(landmark_elements))
        details["aria_landmarks"] = len(aria_landmarks)
        details["landmark_types"] = landmarks_found
        landmark_score = len(landmarks_found) + len(aria_landmarks)
        if landmark_score >= 3:
            score += 1.5
        elif landmark_score >= 1:
            score += 0.5

        skip_link = self.soup.find("a", href=re.compile(r"^#"))
        details["skip_navigation"] = bool(skip_link)
        if skip_link:
            score += 0.5

        focus_styles = False
        style_tags = self.soup.find_all("style")
        for style in style_tags:
            style_text = style.get_text()
            if ":focus" in style_text or "focus-visible" in style_text:
                focus_styles = True
                break
        if not focus_styles:
            details["focus_indicators_detected"] = False
        else:
            details["focus_indicators_detected"] = True
            score += 0.5

        tabindex_elements = self.soup.find_all(attrs={"tabindex": True})
        positive_tabindex = [e for e in tabindex_elements if (e.get("tabindex", "0").lstrip("-")).isdigit() and int(e.get("tabindex", 0)) > 0]
        details["tabindex_elements"] = len(tabindex_elements)
        details["positive_tabindex_count"] = len(positive_tabindex)
        if positive_tabindex:
            self.recommendations.append("Avoid positive tabindex values; use 0 or -1 instead")

        color_issues = 0
        for elem in self.soup.find_all(style=True):
            style = elem.get("style", "")
            if "color" in style and "background" not in style:
                color_issues += 1
        details["inline_color_styles"] = color_issues

        tables = self.soup.find_all("table")
        tables_with_headers = sum(1 for t in tables if t.find("th"))
        details["data_tables"] = len(tables)
        details["tables_with_headers"] = tables_with_headers
        if tables:
            if tables_with_headers == len(tables):
                score += 1
            else:
                self.recommendations.append("Add <th> headers to data tables for screen readers")

        figures = self.soup.find_all("figure")
        figcaptions = self.soup.find_all("figcaption")
        details["figures"] = len(figures)
        details["figcaption_count"] = len(figcaptions)
        if figcaptions:
            score += 0.5
        elif figures:
            self.recommendations.append("Add <figcaption> descriptions to figures")

        videos = self.soup.find_all("video")
        caption_tracks = self.soup.find_all("track", attrs={"kind": re.compile(r"captions|subtitles", re.IGNORECASE)})
        details["captioned_media"] = len(caption_tracks)
        if videos:
            if caption_tracks:
                score += 0.5
            else:
                self.recommendations.append("Add captions or subtitle tracks to video content")

        empty_link_text = 0
        generic_link_text = 0
        generic_link_words = {"click here", "here", "read more", "more", "link", "learn more", "this", "go"}
        for anchor in self.soup.find_all("a", href=True):
            label = anchor.get_text(strip=True)
            if not label and not anchor.get("aria-label") and not anchor.find("img"):
                empty_link_text += 1
            elif label.lower() in generic_link_words:
                generic_link_text += 1
        details["empty_link_names"] = empty_link_text
        details["generic_link_texts"] = generic_link_text
        if empty_link_text:
            self.recommendations.append("Give every link accessible text; avoid empty links")

        ordered_headings = self.soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        heading_order_ok = True
        heading_order_skips = 0
        for i in range(1, len(ordered_headings)):
            prev_level = int(ordered_headings[i - 1].name[1])
            cur_level = int(ordered_headings[i].name[1])
            if cur_level > prev_level + 1:
                heading_order_ok = False
                heading_order_skips += 1
        details["heading_order_ok"] = heading_order_ok if ordered_headings else True
        details["heading_order_skips"] = heading_order_skips
        if ordered_headings and heading_order_ok:
            score += 0.5
        elif not heading_order_ok:
            self.recommendations.append("Fix heading order for assistive tech: never skip levels (H2 -> H4)")

        table_captions = len(self.soup.find_all("caption"))
        details["table_captions"] = table_captions
        if tables and table_captions:
            score += 0.5
        elif tables:
            self.recommendations.append("Add <caption> elements to data tables for screen readers")

        score = min(score, 15)
        details["accessibility_percentage"] = round(score / 15 * 100, 1)
        self.results["accessibility"] = details
        self.scores["accessibility"] = round(score, 1)

    def check_links(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing link quality...", c.YELLOW))
        score = 0
        details = {}

        links = self.soup.find_all("a", href=True)
        details["total_links"] = len(links)
        if not links:
            details["internal"] = 0
            details["external"] = 0
            details["internal_ratio"] = 0
            details["nofollow_count"] = 0
            details["empty_anchor_text"] = 0
            self.results["links"] = details
            self.scores["links"] = 5
            return

        internal = 0
        external = 0
        nofollow = 0
        empty_text = 0
        generic_text = 0
        generic_words = {"click here", "here", "read more", "more", "link", "learn more", "this", "go"}

        for link in links:
            href = link.get("href", "")
            text = link.get_text(strip=True).lower()
            parsed = urlparse(href)
            if parsed.netloc and parsed.netloc != self.base_domain:
                external += 1
            else:
                internal += 1
            rel = link.get("rel", [])
            if "nofollow" in rel:
                nofollow += 1
            if not text:
                empty_text += 1
            elif text in generic_words:
                generic_text += 1

        details["internal"] = internal
        details["external"] = external
        details["nofollow_count"] = nofollow
        details["empty_anchor_text"] = empty_text
        details["generic_anchor_text"] = generic_text

        total = len(links)
        internal_ratio = internal / total
        details["internal_ratio"] = round(internal_ratio * 100, 1)

        if 0.3 <= internal_ratio <= 0.8:
            score += 2
        elif internal_ratio > 0.8:
            score += 1
        else:
            score += 0.5

        link_density = total / max(len(self.all_words), 1) * 100
        details["link_density_pct"] = round(link_density, 2)
        if link_density <= 5:
            score += 2
        elif link_density <= 10:
            score += 1
        else:
            self.recommendations.append("Link density too high; reduce number of links")

        good_anchor = total - empty_text - generic_text
        anchor_quality = good_anchor / total * 100
        details["anchor_quality_pct"] = round(anchor_quality, 1)
        if anchor_quality >= 80:
            score += 2
        elif anchor_quality >= 50:
            score += 1
        else:
            self.recommendations.append("Improve anchor text: use descriptive text instead of generic phrases")

        if nofollow > 0:
            score += 1
        if total > 0:
            score += 1

        if total > 200:
            self.recommendations.append("Very high link count; consider reducing")
            score -= 1

        score = max(0, min(score, 10))
        self.results["links"] = details
        self.scores["links"] = round(score, 1)

    def check_images(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing image quality...", c.YELLOW))
        score = 0
        details = {}

        images = self.soup.find_all("img")
        details["total_images"] = len(images)
        if not images:
            self.results["images"] = details
            self.scores["images"] = 5
            return

        with_alt = [img for img in images if img.get("alt") and img.get("alt").strip()]
        details["with_descriptive_alt"] = len(with_alt)
        alt_ratio = len(with_alt) / len(images)
        details["alt_completeness_pct"] = round(alt_ratio * 100, 1)
        if alt_ratio >= 0.9:
            score += 2.5
        elif alt_ratio >= 0.5:
            score += 1
        else:
            self.recommendations.append("Add descriptive alt text to all images")

        lazy_count = sum(1 for img in images if img.get("loading") == "lazy")
        details["lazy_loaded"] = lazy_count
        if lazy_count > 0:
            score += 1

        with_srcset = sum(1 for img in images if img.get("srcset"))
        details["responsive_images"] = with_srcset
        if with_srcset > 0:
            score += 1

        formats = {}
        for img in images:
            src = img.get("src", "")
            ext = src.split(".")[-1].split("?")[0].lower() if "." in src else "unknown"
            formats[ext] = formats.get(ext, 0) + 1
        details["formats"] = formats
        modern_formats = {"webp", "avif", "svg"}
        modern_count = sum(v for k, v in formats.items() if k in modern_formats)
        if modern_count > 0:
            score += 0.5

        decorative = sum(1 for img in images if img.get("alt", "").strip() == "" or img.get("role") == "presentation")
        details["decorative_images"] = decorative

        score = min(score, 10)
        self.results["images"] = details
        self.scores["images"] = round(score, 1)

    def check_freshness(self):
        c = self.colors
        print(c.colorize("  [>] Checking content freshness...", c.YELLOW))
        score = 0
        details = {}

        last_modified = self.headers.get("Last-Modified", "")
        details["last_modified_header"] = last_modified
        if last_modified:
            score += 2

        meta_dates = []
        for meta in self.soup.find_all("meta"):
            name = (meta.get("name") or "").lower()
            content = meta.get("content", "")
            if any(kw in name for kw in ["date", "modified", "publish", "updated"]):
                meta_dates.append(content)
        details["meta_dates"] = meta_dates
        if meta_dates:
            score += 1.5

        copyright_text = ""
        footer = self.soup.find("footer")
        if footer:
            copyright_text = footer.get_text()
        if not copyright_text:
            for elem in self.soup.find_all(string=re.compile(r"copyright|\u00a9|\(c\)", re.IGNORECASE)):
                copyright_text += " " + str(elem)
        details["copyright_found"] = bool(copyright_text)
        current_year = datetime.now().year
        if str(current_year) in copyright_text:
            score += 2
        elif str(current_year - 1) in copyright_text:
            score += 1

        text = self.get_visible_text()
        date_patterns = [
            r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b",
            r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
            r"\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b",
        ]
        date_refs = []
        for pattern in date_patterns:
            date_refs.extend(re.findall(pattern, text))
        details["date_references_found"] = len(date_refs)
        if date_refs:
            score += 1.5
        else:
            self.recommendations.append("Add dates to content for freshness signals")

        time_tag = self.soup.find("time")
        details["time_element"] = bool(time_tag)
        if time_tag:
            score += 1

        score = min(score, 10)
        self.results["freshness"] = details
        self.scores["freshness"] = round(score, 1)

    def check_social_seo(self):
        c = self.colors
        print(c.colorize("  [>] Checking social & SEO tags...", c.YELLOW))
        score = 0
        details = {}

        og_tags = {}
        for meta in self.soup.find_all("meta", attrs={"property": re.compile(r"^og:")}):
            og_tags[meta.get("property")] = meta.get("content", "")
        details["og_tags"] = og_tags
        og_required = ["og:title", "og:description", "og:image", "og:url"]
        og_found = sum(1 for t in og_required if t in og_tags)
        details["og_completeness"] = str(og_found) + "/" + str(len(og_required))
        if og_found >= 4:
            score += 2
        elif og_found >= 2:
            score += 1
        else:
            self.recommendations.append("Add Open Graph tags for social sharing")

        twitter_tags = {}
        for meta in self.soup.find_all("meta", attrs={"name": re.compile(r"^twitter:")}):
            twitter_tags[meta.get("name")] = meta.get("content", "")
        details["twitter_tags"] = twitter_tags
        if twitter_tags:
            score += 1

        meta_desc = self.soup.find("meta", attrs={"name": "description"})
        if meta_desc:
            desc_content = meta_desc.get("content", "")
            details["meta_description_length"] = len(desc_content)
            if 120 <= len(desc_content) <= 160:
                score += 2
            elif 50 <= len(desc_content) <= 200:
                score += 1
            else:
                self.recommendations.append("Optimize meta description to 120-160 characters")
        else:
            details["meta_description_length"] = 0
            self.recommendations.append("Add a meta description tag")

        keywords_tag = self.soup.find("meta", attrs={"name": "keywords"})
        details["keywords_tag"] = bool(keywords_tag)
        if keywords_tag:
            score += 0.5

        canonical = self.soup.find("link", rel="canonical")
        details["canonical_url"] = canonical.get("href", "") if canonical else None
        if canonical:
            score += 1.5

        robots_meta = self.soup.find("meta", attrs={"name": "robots"})
        details["robots_meta"] = robots_meta.get("content", "") if robots_meta else None
        if robots_meta:
            score += 0.5

        title_tag = self.soup.find("title")
        if title_tag:
            title_text = title_tag.get_text(strip=True)
            details["title_length"] = len(title_text)
            if 30 <= len(title_text) <= 60:
                score += 1.5
            elif 10 <= len(title_text) <= 80:
                score += 0.5
        else:
            title_text = ""
            details["title_length"] = 0
            self.recommendations.append("Add a page title tag")

        ld_json = self.soup.find("script", type=re.compile(r"ld\+json", re.IGNORECASE))
        details["json_ld_structured_data"] = bool(ld_json)
        if ld_json:
            score += 0.5

        hreflang_tags = self.soup.find_all("link", rel="alternate", hreflang=True)
        details["hreflang_tags"] = len(hreflang_tags)
        if hreflang_tags:
            score += 0.5

        title_words = set(w.lower() for w in _get_words(title_text)) if title_text else set()
        h1_words = set()
        for h1 in self.soup.find_all("h1"):
            h1_words.update(w.lower() for w in _get_words(h1.get_text()))
        if title_words and h1_words:
            alignment = len(title_words & h1_words) / max(len(title_words | h1_words), 1)
        else:
            alignment = 0.0
        details["title_h1_alignment_pct"] = round(alignment * 100, 1)
        if alignment >= 0.4:
            score += 0.5
        elif title_words and h1_words:
            self.recommendations.append("Align the H1 heading with the page title keywords")

        score = min(score, 10)
        self.results["social_seo"] = details
        self.scores["social_seo"] = round(score, 1)

    def check_multimedia(self):
        c = self.colors
        print(c.colorize("  [>] Checking multimedia elements...", c.YELLOW))
        score = 0
        details = {}

        videos = self.soup.find_all("video")
        iframes = self.soup.find_all("iframe")
        audios = self.soup.find_all("audio")
        canvases = self.soup.find_all("canvas")
        svgs = self.soup.find_all("svg")
        embeds = self.soup.find_all("embed")
        objects = self.soup.find_all("object")

        details["videos"] = len(videos)
        details["iframes"] = len(iframes)
        details["audio"] = len(audios)
        details["canvas"] = len(canvases)
        details["svg"] = len(svgs)
        details["embeds"] = len(embeds)
        details["objects"] = len(objects)

        if videos:
            score += 1.5
            for vid in videos:
                if vid.get("preload") or vid.get("poster"):
                    score += 0.25

        if iframes:
            good_iframes = 0
            for iframe in iframes:
                title = iframe.get("title", "")
                if title:
                    good_iframes += 1
            details["iframes_with_title"] = good_iframes
            if good_iframes == len(iframes):
                score += 1.5
            elif good_iframes > 0:
                score += 0.75
            else:
                self.recommendations.append("Add title attributes to iframes for accessibility")

        if audios:
            score += 0.5

        if canvases or svgs:
            score += 1

        score = min(score, 5)
        self.results["multimedia"] = details
        self.scores["multimedia"] = round(score, 1)

    def check_depth(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing content depth...", c.YELLOW))
        score = 0
        details = {}

        text = self.get_visible_text()
        words = _get_words(text)
        word_count = len(words)
        details["word_count"] = word_count

        if word_count >= 1000:
            score += 3
        elif word_count >= 500:
            score += 2.5
        elif word_count >= 300:
            score += 2
        elif word_count >= 100:
            score += 1
        else:
            self.recommendations.append("Content is very thin; aim for 300+ words")

        code_chars = 0
        for tag in self.soup.find_all(["script", "style"]):
            code_chars += len(tag.get_text())
        html_len = len(self.html)
        text_chars = len(text)
        if html_len > 0:
            ratio = text_chars / html_len
        else:
            ratio = 0
        details["content_to_code_ratio"] = round(ratio * 100, 1)
        if ratio >= 0.3:
            score += 2
        elif ratio >= 0.15:
            score += 1
        else:
            self.recommendations.append("Low content-to-code ratio; reduce script/style size")

        unique_words = set(w.lower() for w in words)
        details["unique_words"] = len(unique_words)
        if word_count > 0:
            unique_ratio = len(unique_words) / word_count
            details["vocabulary_richness"] = round(unique_ratio * 100, 1)
            if unique_ratio >= 0.6:
                score += 2
            elif unique_ratio >= 0.4:
                score += 1

        headings = []
        for level in range(2, 7):
            for h in self.soup.find_all("h" + str(level)):
                headings.append(h.get_text(strip=True))
        details["subheading_count"] = len(headings)
        if len(headings) >= 5:
            score += 2
        elif len(headings) >= 3:
            score += 1.5
        elif len(headings) >= 1:
            score += 0.5

        info_density = word_count / max(html_len, 1) * 1000
        details["info_density_per_1k_chars"] = round(info_density, 1)

        score = min(score, 10)
        self.results["depth"] = details
        self.scores["depth"] = round(score, 1)

    def check_unicode(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing Unicode content...", c.YELLOW))
        text = self.get_visible_text()
        details = analyze_unicode_content(text)

        rtl_info = is_rtl_text(text)
        details["rtl_text_percentage"] = rtl_info[1]
        details["is_rtl_content"] = rtl_info[0]

        if details["non_ascii_pct"] > 10:
            details["multilingual_indicator"] = True
        else:
            details["multilingual_indicator"] = False

        self.results["unicode"] = details
        self.scores["unicode"] = 0

    def check_multilingual(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing multilingual content...", c.YELLOW))
        text = self.get_visible_text()
        details = {}

        segments = detect_language_segments(text)
        details["language_segments"] = segments
        detected_langs = set(s["language"] for s in segments if s["language"])
        details["language_count"] = len(detected_langs)
        details["detected_languages"] = list(detected_langs)

        if details["language_count"] > 1:
            details["is_multilingual"] = True
            self.recommendations.append("Content appears to be multilingual; consider separating by language for better SEO")
        else:
            details["is_multilingual"] = False

        hints = translation_quality_hints(text)
        details["translation_hints"] = hints
        if hints:
            details["possible_machine_translation"] = len(hints) >= 2
        else:
            details["possible_machine_translation"] = False

        lang_code = self.detected_language or "en"
        details["language_adjustment_factor"] = LANGUAGE_READABILITY_FACTORS.get(lang_code, 1.0)

        self.results["multilingual"] = details
        self.scores["multilingual"] = 0

    def check_content_strategy(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing content strategy...", c.YELLOW))
        score = 0
        details = {}

        text = self.get_visible_text()
        words = _get_words(text)
        text_lower = text.lower()

        freshness_signals = {}
        meta_dates = []
        for meta in self.soup.find_all("meta"):
            name = (meta.get("name") or "").lower()
            content = meta.get("content", "")
            if any(kw in name for kw in ["date", "modified", "publish", "updated"]):
                meta_dates.append(content)
        freshness_signals["meta_dates"] = meta_dates

        current_year = datetime.now().year
        year_refs = re.findall(r"\b(20\d{2})\b", text)
        freshness_signals["year_references"] = year_refs

        recent_indicators = ["updated", "revised", "new", "latest", "current", "recent"]
        found_recent = [ind for ind in recent_indicators if ind in text_lower]
        freshness_signals["recent_indicators_found"] = found_recent
        freshness_signals["has_recent_dates"] = bool(meta_dates) or str(current_year) in year_refs
        details["freshness_signals"] = freshness_signals

        depth_analysis = {}
        word_count = len(words)
        depth_analysis["word_count"] = word_count
        unique_words = set(w.lower() for w in words)
        depth_analysis["unique_words"] = len(unique_words)
        if word_count > 0:
            depth_analysis["vocabulary_richness"] = round(len(unique_words) / word_count * 100, 1)
        paragraphs = self.soup.find_all("p")
        para_lengths = [len(p.get_text(strip=True).split()) for p in paragraphs if p.get_text(strip=True)]
        if para_lengths:
            depth_analysis["avg_paragraph_length"] = round(sum(para_lengths) / len(para_lengths), 1)
            depth_analysis["max_paragraph_length"] = max(para_lengths)
        details["depth_analysis"] = depth_analysis

        uniqueness = {}
        filler_phrases = [
            "in conclusion", "in summary", "to sum up", "in closing",
            "as a result", "it is important to note", "it should be noted",
            "in this article", "in this post", "in this guide",
        ]
        found_fillers = [phrase for phrase in filler_phrases if phrase in text_lower]
        uniqueness["filler_phrases_found"] = found_fillers
        template_indicators = ["lorem ipsum", "placeholder", "sample text", "insert text here"]
        found_templates = [ind for ind in template_indicators if ind in text_lower]
        uniqueness["template_indicators"] = found_templates
        uniqueness_score = 100
        uniqueness_score -= len(found_fillers) * 5
        uniqueness_score -= len(found_templates) * 20
        uniqueness["uniqueness_score"] = max(0, uniqueness_score)
        details["uniqueness"] = uniqueness

        gaps = {}
        has_faq = "faq" in text_lower or "frequently asked" in text_lower
        has_examples = "example" in text_lower or "for instance" in text_lower
        has_conclusion = "conclusion" in text_lower or "in summary" in text_lower
        has_cta = any(kw in text_lower for kw in ["sign up", "get started", "learn more", "contact us"])
        gap_list = []
        if not has_faq:
            gap_list.append("No FAQ section detected")
        if not has_examples:
            gap_list.append("No examples or use cases found")
        if not has_conclusion:
            gap_list.append("No conclusion or summary section")
        if not has_cta:
            gap_list.append("No call-to-action found")
        gaps["gaps"] = gap_list
        gaps["has_faq"] = has_faq
        gaps["has_examples"] = has_examples
        gaps["has_conclusion"] = has_conclusion
        gaps["has_cta"] = has_cta
        details["gap_analysis"] = gaps

        update_freq = {}
        version_pattern = r"[vV]ersion\s*[\d.]+|v\d+\.\d+"
        versions = re.findall(version_pattern, text)
        update_freq["version_references"] = versions
        changelog_indicators = ["changelog", "what\'s new", "release notes", "update history"]
        update_freq["changelog_found"] = any(ind in text_lower for ind in changelog_indicators)
        date_pattern = r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"
        dates_found = re.findall(date_pattern, text)
        update_freq["date_patterns_found"] = len(dates_found)
        details["update_frequency"] = update_freq

        engagement = {}
        forms = self.soup.find_all("form")
        engagement["forms"] = len(forms)
        social_links = self.soup.find_all("a", href=re.compile(r"(facebook|twitter|linkedin|share|social)"))
        engagement["social_sharing_links"] = len(social_links)
        engagement["has_social_sharing"] = len(social_links) > 0
        cta_keywords = ["sign up", "get started", "try", "download", "subscribe", "buy", "purchase", "contact"]
        engagement["has_cta"] = any(kw in text_lower for kw in cta_keywords)
        images = self.soup.find_all("img")
        videos = self.soup.find_all("video")
        engagement["images"] = len(images)
        engagement["videos"] = len(videos)
        engagement["has_multimedia"] = len(images) > 0 or len(videos) > 0
        comments = self.soup.find_all(class_=re.compile(r"comment|discussion|review"))
        engagement["comment_sections"] = len(comments)
        details["engagement_potential"] = engagement

        if freshness_signals.get("has_recent_dates"):
            score += 2
        if depth_analysis.get("word_count", 0) >= 500:
            score += 2
        if uniqueness.get("uniqueness_score", 0) >= 70:
            score += 2
        if engagement.get("has_cta"):
            score += 1
        if engagement.get("has_social_sharing"):
            score += 1
        if not gaps.get("gaps"):
            score += 2

        score = min(score, 10)
        self.results["content_strategy"] = details
        self.scores["content_strategy"] = round(score, 1)

    def check_code_blocks(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing code blocks...", c.YELLOW))
        score = 0
        details = {}

        code_blocks = self.soup.find_all("code")
        pre_blocks = self.soup.find_all("pre")

        details["code_elements"] = len(code_blocks)
        details["pre_elements"] = len(pre_blocks)

        highlighted = 0
        for code in code_blocks:
            classes = " ".join(code.get("class", []))
            if any(kw in classes.lower() for kw in ["highlight", "language", "lang-", "hljs", "prism", "brush"]):
                highlighted += 1
        details["syntax_highlighted"] = highlighted

        lang_annotated = 0
        for code in code_blocks:
            classes = code.get("class", [])
            for cls in classes:
                if cls.startswith("language-") or cls.startswith("lang-"):
                    lang_annotated += 1
                    break
        details["language_annotated"] = lang_annotated

        line_numbers = len(self.soup.find_all(class_=re.compile(r"line-numbers|linenumber|line-number|linenums")))
        details["line_numbers_found"] = line_numbers

        text = self.get_visible_text()
        words = _get_words(text)
        code_words = 0
        for pre in pre_blocks:
            code_words += len(_get_words(pre.get_text()))
        for code in code_blocks:
            if code.parent and code.parent.name != "pre":
                code_words += len(_get_words(code.get_text()))

        if words:
            code_ratio = code_words / len(words) * 100
            details["code_word_ratio_pct"] = round(code_ratio, 1)
        else:
            details["code_word_ratio_pct"] = 0

        code_block_langs = set()
        for code in code_blocks:
            classes = code.get("class", [])
            for cls in classes:
                if cls.startswith("language-"):
                    code_block_langs.add(cls[9:])
                elif cls.startswith("lang-"):
                    code_block_langs.add(cls[5:])
        details["detected_languages"] = list(code_block_langs)

        if code_blocks or pre_blocks:
            score += 2
        if highlighted > 0:
            score += 1
        if lang_annotated > 0:
            score += 1
        if line_numbers > 0:
            score += 0.5

        score = min(score, 5)
        self.results["code_blocks"] = details
        self.scores["code_blocks"] = round(score, 1)

    def check_blockquotes(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing blockquotes...", c.YELLOW))
        score = 0
        details = {}

        blockquotes = self.soup.find_all("blockquote")
        details["total_blockquotes"] = len(blockquotes)

        if not blockquotes:
            self.results["blockquotes"] = details
            self.scores["blockquotes"] = 0
            return

        with_cite = [bq for bq in blockquotes if bq.get("cite")]
        details["with_cite_attribute"] = len(with_cite)

        with_attribution = 0
        for bq in blockquotes:
            if bq.find("footer") or bq.find("cite") or bq.find(class_=re.compile(r"attribution|source|author")):
                with_attribution += 1
        details["with_attribution"] = with_attribution

        with_links = 0
        for bq in blockquotes:
            if bq.find("a"):
                with_links += 1
        details["with_linked_sources"] = with_links

        avg_bq_length = 0
        bq_lengths = [len(bq.get_text(strip=True).split()) for bq in blockquotes if bq.get_text(strip=True)]
        if bq_lengths:
            avg_bq_length = sum(bq_lengths) / len(bq_lengths)
        details["avg_blockquote_words"] = round(avg_bq_length, 1)

        if blockquotes:
            score += 1
        if with_cite:
            score += 1
        if with_attribution:
            score += 1
        if with_links:
            score += 0.5

        score = min(score, 3)
        self.results["blockquotes"] = details
        self.scores["blockquotes"] = round(score, 1)

    def check_originality(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing content originality...", c.YELLOW))
        score = 0
        details = {}

        text = self.get_visible_text()
        text_lower = text.lower()
        sentences = self.all_sentences or _split_sentences(text)
        words = self.all_words or _get_words(text)

        found_formulaic = [p for p in FORMULAIC_OPENERS if p in text_lower]
        details["formulaic_openers_found"] = found_formulaic
        if not found_formulaic:
            score += 2
        elif len(found_formulaic) <= 2:
            score += 1
            self.recommendations.append("Replace generic/filler openers with a concrete hook")
        else:
            self.recommendations.append("Content leans on formulaic openers; rewrite the opening section")

        template_indicators = ["lorem ipsum", "placeholder text", "sample text", "insert text here"]
        found_templates = [t for t in template_indicators if t in text_lower]
        details["template_indicators"] = found_templates
        if not found_templates:
            score += 2
        else:
            self.recommendations.append("Remove leftover template/placeholder text")

        dup_ratio = duplicate_sentence_ratio(sentences)
        details["duplicate_sentence_pct"] = round(dup_ratio * 100, 1)
        if dup_ratio <= 0.02:
            score += 1.5
        elif dup_ratio <= 0.08:
            score += 0.5
        else:
            self.recommendations.append("Sentences repeat internally; rewrite duplicated passages")

        ngram_rep = repeated_ngram_ratio(text, n=5)
        details["repeated_5gram_pct"] = round(ngram_rep * 100, 1)
        if ngram_rep <= 0.05:
            score += 1.5
        elif ngram_rep <= 0.15:
            score += 0.5
        else:
            self.recommendations.append("Repeated 5-word phrases detected; vary phrasing and syntax")

        attribution_hits = [m for m in AUTHORITY_MARKERS if m in text_lower]
        external_sources = 0
        for anchor in self.soup.find_all("a", href=True):
            host = urlparse(anchor.get("href", "")).netloc
            if host and host != self.base_domain and anchor.get_text(strip=True):
                external_sources += 1
        details["attribution_markers"] = attribution_hits
        details["external_source_links"] = external_sources
        if attribution_hits or external_sources >= 3:
            score += 1.5
        elif external_sources >= 1:
            score += 0.75
        else:
            self.recommendations.append("Add citations and source links to support claims")

        first_person = sum(1 for w in words if w.lower() in {"i", "we", "our", "my", "us"})
        details["first_person_markers"] = first_person
        if first_person >= 4:
            score += 1
        elif first_person >= 1:
            score += 0.5
        else:
            self.recommendations.append("Add first-hand perspective (experience, process, data) to boost originality")

        if self.soup.find_all("blockquote"):
            score += 0.5

        deep = {}
        para_texts = [re.sub(r"\s+", " ", p.get_text(strip=True).lower()) for p in self.soup.find_all("p")]
        para_texts = [p for p in para_texts if len(p) > 40]
        para_counts = Counter(para_texts)
        boiler_dup = sum(c for c in para_counts.values() if c > 1) / max(len(para_texts), 1)
        deep["boilerplate_paragraph_pct"] = round(boiler_dup * 100, 1)
        quote_words_count = sum(len(_get_words(b.get_text())) for b in self.soup.find_all("blockquote"))
        deep["quote_word_pct"] = round(quote_words_count / max(len(words), 1) * 100, 1)
        firsthand_markers = [
            m for m in ("we found", "our data", "in our tests", "we measured",
                        "based on our", "when we", "our analysis", "we tested")
            if m in text_lower
        ]
        deep["firsthand_insight_markers"] = firsthand_markers
        claim_patterns = [
            r"\bbest\s+\w+", r"\b#\s?1\b", r"\bleading\b", r"\bnumber one\b",
            r"\bworld['’]s\s+(?:best|most)\b",
        ]
        generic_claims = 0
        for pattern in claim_patterns:
            generic_claims += len(re.findall(pattern, text, re.IGNORECASE))
        local_stat_count = len(re.findall(r"\d+(?:\.\d+)?\s*%|\b\d[\d,]{1,}\b", text))
        unsupported = 0
        if local_stat_count == 0 and not attribution_hits:
            unsupported = generic_claims
        elif generic_claims > local_stat_count:
            unsupported = generic_claims - local_stat_count
        deep["generic_claim_count"] = generic_claims
        deep["unsupported_claims"] = unsupported
        if unsupported > 0:
            self.recommendations.append("Unsupported superlative claims detected; back them with data or soften the wording")
        sub_scores = {
            "anti_formulaic": 100 - min(len(found_formulaic) * 20, 100),
            "anti_boilerplate": 100 - min(boiler_dup * 200, 100),
            "attribution": min(len(attribution_hits) * 25 + min(external_sources, 4) * 10, 100),
            "perspective": min(first_person * 10 + len(firsthand_markers) * 20, 100),
            "claim_support": max(
                0,
                100 - unsupported * 15 - (0 if local_stat_count >= 3 else (3 - local_stat_count) * 15),
            ),
        }
        deep_index = round(sum(sub_scores.values()) / len(sub_scores), 1)
        deep["sub_scores"] = sub_scores
        deep["deep_originality_index"] = deep_index
        details["originality_deep"] = deep

        score = max(0.0, min(score, 10))
        base_index = round(score / 10 * 100, 1)
        details["originality_index"] = round(base_index * 0.7 + deep_index * 0.3, 1)
        self.results["originality"] = details
        self.scores["originality"] = round(score, 1)

    def check_uniqueness(self):
        c = self.colors
        print(c.colorize("  [>] Scoring content uniqueness...", c.YELLOW))
        score = 0
        details = {}

        text = self.get_visible_text()
        sentences = self.all_sentences or _split_sentences(text)
        words = self.all_words or _get_words(text)

        ttr = type_token_ratio(words)
        details["type_token_ratio"] = round(ttr * 100, 1)
        if ttr >= 0.55:
            score += 2.5
        elif ttr >= 0.40:
            score += 1.5
        elif ttr >= 0.25:
            score += 0.75
        else:
            self.recommendations.append("Vocabulary is repetitive; broaden word choice (low type-token ratio)")

        hapax = hapax_ratio(words)
        details["hapax_legomena_ratio"] = round(hapax * 100, 1)
        if hapax >= 0.50:
            score += 2
        elif hapax >= 0.35:
            score += 1
        else:
            self.recommendations.append("Too many repeated words; introduce synonyms and domain terms")

        sl_sd = sentence_length_stdev(sentences)
        details["sentence_length_stdev"] = round(sl_sd, 2)
        if 5.0 <= sl_sd <= 14.0:
            score += 1.5
        elif sl_sd < 3.0:
            score += 0.5
            self.recommendations.append("Sentence lengths are uniform; vary short and long sentences")
        else:
            score += 0.75

        dup = duplicate_sentence_ratio(sentences)
        details["duplicate_sentence_pct"] = round(dup * 100, 1)
        if dup <= 0.02:
            score += 1.5
        elif dup <= 0.08:
            score += 0.5
        else:
            self.recommendations.append("Duplicate sentences reduce uniqueness; consolidate or rewrite")

        entropy = word_entropy(words)
        details["lexical_entropy"] = round(entropy, 2)
        if entropy >= 3.5:
            score += 1.5
        elif entropy >= 3.0:
            score += 1
        else:
            score += 0.25

        distinct = distinct_phrase_ratio(words, n=3)
        details["distinct_3gram_ratio"] = round(distinct * 100, 1)
        if distinct >= 0.85:
            score += 1
        elif distinct >= 0.70:
            score += 0.5

        uniqueness_refinement = {}
        para_norm = [
            re.sub(r"\s+", " ", p.get_text(strip=True).lower())
            for p in self.soup.find_all("p")
            if len(p.get_text(strip=True)) > 20
        ]
        para_unique = len(set(para_norm)) / max(len(para_norm), 1)
        uniqueness_refinement["unique_paragraph_pct"] = round(para_unique * 100, 1)
        openings = [tuple(w.lower() for w in _get_words(s)[:3]) for s in sentences if _get_words(s)]
        open_div = len(set(openings)) / max(len(openings), 1)
        uniqueness_refinement["sentence_opening_diversity_pct"] = round(open_div * 100, 1)
        word_counts = Counter(w.lower() for w in words)
        content_terms = [w for w in word_counts if w not in CONTENT_STOPWORDS and len(w) > 3]
        distinctive = sum(1 for w in content_terms if word_counts[w] == 1)
        distinctive_ratio = distinctive / max(len(content_terms), 1)
        uniqueness_refinement["distinctive_term_count"] = distinctive
        uniqueness_refinement["distinctive_term_ratio_pct"] = round(distinctive_ratio * 100, 1)
        bonus = 0.0
        if para_unique >= 0.9:
            bonus += 0.4
        elif para_unique < 0.7 and para_norm:
            bonus -= 0.3
            self.recommendations.append("Paragraphs repeat; rewrite duplicated blocks to raise uniqueness")
        if open_div >= 0.75:
            bonus += 0.3
        if distinctive_ratio >= 0.5:
            bonus += 0.3
        uniqueness_refinement["refinement_bonus"] = round(bonus, 2)
        score = max(0.0, min(10.0, score + bonus))
        uniqueness_refinement["refined_uniqueness_score"] = round(score / 10 * 100, 1)
        details["uniqueness_refinement"] = uniqueness_refinement
        details["uniqueness_score"] = round(score / 10 * 100, 1)
        self.results["uniqueness"] = details
        self.scores["uniqueness"] = round(score, 1)

    def check_quality_signals(self):
        c = self.colors
        print(c.colorize("  [>] Evaluating content quality signals...", c.YELLOW))
        score = 0
        details = {}

        text = self.get_visible_text()
        text_lower = text.lower()

        evidence_hits = [t for t in EVIDENCE_TERMS if t in text_lower]
        details["evidence_markers"] = evidence_hits
        if len(evidence_hits) >= 4:
            score += 2
        elif len(evidence_hits) >= 2:
            score += 1
        elif evidence_hits:
            score += 0.5
        else:
            self.recommendations.append("Back claims with research, data, or cited evidence")

        stat_count = len(re.findall(r"\d+(?:\.\d+)?\s*%|\b\d[\d,]{1,}\b", text))
        details["statistical_references"] = stat_count
        if stat_count >= 5:
            score += 1.5
        elif stat_count >= 2:
            score += 0.75
        else:
            self.recommendations.append("Include concrete statistics or data points")

        example_hits = [t for t in EXAMPLE_MARKERS if t in text_lower]
        details["example_markers"] = example_hits
        if len(example_hits) >= 2:
            score += 1.5
        elif example_hits:
            score += 0.75
        else:
            self.recommendations.append("Add examples or use cases to illustrate key points")

        blockquotes = self.soup.find_all("blockquote")
        with_cite = [b for b in blockquotes if b.get("cite") or b.find("footer") or b.find("cite")]
        details["sourced_quotes"] = len(with_cite)
        quote_words = ["said", "explains", "argues", "notes", "according"]
        quoted = bool(blockquotes) and any(q in text_lower for q in quote_words)
        if with_cite or quoted:
            score += 1.5
        elif blockquotes:
            score += 0.75
            self.recommendations.append("Attribute quotes with <cite>, footer, or source links")

        credential_hits = [t for t in CREDENTIAL_MARKERS if t in text_lower]
        details["credential_markers"] = credential_hits
        if credential_hits:
            score += 1

        authoritative_links = 0
        for anchor in self.soup.find_all("a", href=True):
            host = urlparse(anchor.get("href", "")).netloc.lower()
            if host.endswith(".edu") or host.endswith(".gov") or host.endswith(".org"):
                authoritative_links += 1
        details["authoritative_links"] = authoritative_links
        if authoritative_links >= 2:
            score += 1
        elif authoritative_links >= 1:
            score += 0.5

        figcaptions = self.soup.find_all("figcaption")
        figures = self.soup.find_all("figure")
        details["captioned_figures"] = len(figcaptions)
        if figcaptions:
            score += 1
        elif figures:
            score += 0.25

        tables = self.soup.find_all("table")
        details["data_tables"] = len(tables)
        if tables:
            score += 0.5

        quality_refinement = {}
        words_for_ref = self.all_words or _get_words(text)
        year_refs = len(re.findall(r"\b(?:19|20)\d{2}\b", text))
        specificity = min(100.0, stat_count * 8 + min(year_refs, 10) * 4)
        quality_refinement["statistical_references"] = stat_count
        quality_refinement["year_references"] = year_refs
        quality_refinement["specificity_score"] = round(specificity, 1)
        hedge_words = ("maybe", "perhaps", "might", "possibly", "somewhat", "arguably", "likely", "probably", "seems", "appears")
        hedge_hits = [h for h in hedge_words if re.search(r"\b" + re.escape(h) + r"\b", text_lower)]
        quality_refinement["hedging_markers"] = hedge_hits
        quality_refinement["hedge_density_pct"] = round(len(hedge_hits) / max(len(words_for_ref), 1) * 100, 2)
        if len(hedge_hits) > 4:
            self.recommendations.append("Reduce hedging language; state findings with supported confidence")
        step_matches = len(re.findall(r"\bstep\s+\d+\b|\bstep\s+by\s+step\b", text_lower, re.IGNORECASE))
        quality_refinement["actionable_steps_detected"] = step_matches
        quality_refinement["actionable_advice"] = step_matches >= 1 or "how to" in text_lower
        claim_evidence_ratio = round(len(evidence_hits) / max(1, min(stat_count, 10)), 2)
        quality_refinement["claim_evidence_ratio"] = claim_evidence_ratio
        ref_bonus = 0.0
        if specificity >= 50:
            ref_bonus += 3
        elif specificity >= 25:
            ref_bonus += 1.5
        if len(hedge_hits) <= 2:
            ref_bonus += 2
        if quality_refinement["actionable_advice"]:
            ref_bonus += 2
        quality_refinement["refinement_bonus"] = round(ref_bonus, 2)
        score = max(0.0, min(10.0, score + ref_bonus))
        quality_refinement["refined_quality_index"] = round(score / 10 * 100, 1)
        details["quality_refinement"] = quality_refinement
        details["quality_signal_index"] = round(score / 10 * 100, 1)
        self.results["quality_signals"] = details
        self.scores["quality_signals"] = round(score, 1)

    def check_flow(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing content flow...", c.YELLOW))
        score = 0
        details = {}

        text = self.get_visible_text()
        sentences = self.all_sentences or _split_sentences(text)

        tr = transition_ratio(sentences)
        details["transition_sentence_pct"] = round(tr * 100, 1)
        if tr >= 0.18:
            score += 1.5
        elif tr >= 0.08:
            score += 0.75
        else:
            self.recommendations.append("Add transition words/phrases between ideas (e.g., however, therefore, for example)")

        paragraphs = [p.get_text(strip=True) for p in self.soup.find_all("p") if p.get_text(strip=True)]
        continuity = paragraph_continuity(paragraphs)
        details["paragraph_continuity_pct"] = round(continuity * 100, 1)
        if continuity >= 0.12:
            score += 1.5
        elif continuity >= 0.06:
            score += 0.75
        else:
            self.recommendations.append("Improve paragraph-to-paragraph continuity; carry key terms forward")

        sl_sd = sentence_length_stdev(sentences)
        details["sentence_length_stdev"] = round(sl_sd, 2)
        if 5.0 <= sl_sd <= 14.0:
            score += 1
        elif sl_sd < 3.0:
            score += 0.25
            self.recommendations.append("Vary sentence lengths; long runs of equal-length sentences read monotonous")
        else:
            score += 0.5

        opening_hook = False
        if paragraphs:
            first_words = len(_get_words(paragraphs[0]))
            has_question = bool(sentences) and "?" in sentences[0]
            opening_hook = first_words <= 60 or has_question
        details["opening_hook"] = opening_hook
        if opening_hook:
            score += 0.5

        closing_markers = ["in conclusion", "in summary", "to summarize", "finally", "next steps", "bottom line"]
        has_closing = False
        if paragraphs:
            last_para = paragraphs[-1].lower()
            last_word_count = len(_get_words(paragraphs[-1]))
            has_closing = any(m in last_para for m in closing_markers) or last_word_count <= 80
        details["closing_signal"] = bool(has_closing)
        if has_closing:
            score += 0.5

        flow_refinement = {}
        paras_for_flow = [p for p in paragraphs if p]
        total_flow_words = sum(len(_get_words(p)) for p in paras_for_flow)
        if paras_for_flow and total_flow_words:
            third = max(1, len(paras_for_flow) // 3)
            opening_words = sum(len(_get_words(p)) for p in paras_for_flow[:third])
            closing_words = sum(len(_get_words(p)) for p in paras_for_flow[-third:])
            opening_share = opening_words / total_flow_words
            closing_share = closing_words / total_flow_words
            flow_refinement["opening_word_share_pct"] = round(opening_share * 100, 1)
            flow_refinement["closing_word_share_pct"] = round(closing_share * 100, 1)
            arc_ok = 0.10 <= opening_share <= 0.50 and closing_share >= 0.08
        else:
            arc_ok = False
            flow_refinement["opening_word_share_pct"] = 0.0
            flow_refinement["closing_word_share_pct"] = 0.0
        flow_refinement["narrative_arc_ok"] = arc_ok
        words_for_flow = self.all_words or _get_words(text)
        connective_hits = sum(1 for w in words_for_flow if w.lower().strip(".,!?;:'\"") in TRANSITION_WORDS)
        flow_refinement["connective_density_per_100"] = round(connective_hits / max(len(words_for_flow), 1) * 100, 2)
        starts = [tuple(w.lower() for w in _get_words(p)[:3]) for p in paras_for_flow if _get_words(p)]
        start_diversity = len(set(starts)) / max(len(starts), 1)
        flow_refinement["paragraph_start_diversity_pct"] = round(start_diversity * 100, 1)
        flow_refinement["topic_drift_pct"] = round(max(0.0, 1.0 - continuity) * 100, 1)
        details["flow_refinement"] = flow_refinement
        if arc_ok:
            score = min(5.0, score + 0.2)
        if start_diversity >= 0.8 and starts:
            score = min(5.0, score + 0.15)
        if start_diversity < 0.5 and len(starts) >= 4:
            self.recommendations.append("Paragraphs open with the same words; vary topic-sentence openings")

        score = max(0.0, min(score, 5))
        details["flow_index"] = round(score / 5 * 100, 1)
        self.results["flow"] = details
        self.scores["flow"] = round(score, 1)

    def check_scannability(self):
        c = self.colors
        print(c.colorize("  [>] Analyzing content scannability...", c.YELLOW))
        score = 0
        details = {}

        words = self.all_words or _get_words(self.get_visible_text())
        word_count = max(len(words), 1)

        headings = []
        for level in range(1, 7):
            headings.extend(self.soup.find_all("h" + str(level)))
        headings_with_text = [h for h in headings if h.get_text(strip=True)]
        headings_per_100 = len(headings_with_text) / word_count * 100
        details["headings_per_100_words"] = round(headings_per_100, 2)
        if headings_per_100 >= 0.5:
            score += 1.2
        elif headings_per_100 >= 0.25:
            score += 0.6
        else:
            self.recommendations.append("Add more subheadings; aim for one heading every 200-300 words")

        list_items = self.soup.find_all("li")
        bullets_per_100 = len(list_items) / word_count * 100
        details["bullets_per_100_words"] = round(bullets_per_100, 2)
        if bullets_per_100 >= 0.5:
            score += 1.0
        elif bullets_per_100 >= 0.2:
            score += 0.5
        elif len(list_items) == 0 and word_count >= 400:
            self.recommendations.append("Break long prose blocks into bulleted lists for skimming")

        paragraphs = [p for p in self.soup.find_all("p") if p.get_text(strip=True)]
        short_paras = [p for p in paragraphs if len(p.get_text(strip=True).split()) < 80]
        short_para_pct = len(short_paras) / max(len(paragraphs), 1) * 100
        details["short_paragraph_pct"] = round(short_para_pct, 1)
        if short_para_pct >= 60:
            score += 1.3
        elif short_para_pct >= 35:
            score += 0.65
        else:
            self.recommendations.append("Shorten paragraphs; keep most paragraphs under 80 words")

        emphasis = len(self.soup.find_all(["strong", "b", "em", "i"]))
        emphasis_per_100 = emphasis / word_count * 100
        details["emphasis_per_100_words"] = round(emphasis_per_100, 2)
        if emphasis_per_100 >= 0.4:
            score += 0.5
        elif emphasis_per_100 >= 0.15:
            score += 0.25

        blocks = len(paragraphs) + len(list_items) + len(headings_with_text)
        blocks_per_100 = blocks / word_count * 100
        details["block_elements_per_100_words"] = round(blocks_per_100, 2)
        if blocks_per_100 >= 3:
            score += 0.5
        elif blocks_per_100 >= 1.5:
            score += 0.25

        scannability_refinement = {}
        title_tag_s = self.soup.find("title")
        keyword_terms = set()
        if title_tag_s:
            keyword_terms.update(
                w.lower() for w in _get_words(title_tag_s.get_text())
                if w.lower() not in CONTENT_STOPWORDS and len(w) > 2
            )
        keyword_emphasis_hits = 0
        for tag in self.soup.find_all(["strong", "b", "em", "i"]):
            tag_words = set(w.lower() for w in _get_words(tag.get_text()))
            keyword_emphasis_hits += len(tag_words & keyword_terms)
        scannability_refinement["keyword_emphasis_hits"] = keyword_emphasis_hits
        summary_boxes = len(self.soup.find_all(class_=re.compile(r"summary|callout|key-?takeaway|tldr", re.IGNORECASE)))
        summary_boxes += len(self.soup.find_all("aside"))
        scannability_refinement["summary_boxes"] = summary_boxes
        numbered_steps = 0
        for ol in self.soup.find_all("ol"):
            item_count = len(ol.find_all("li"))
            if 3 <= item_count <= 12:
                numbered_steps += 1
        scannability_refinement["numbered_step_lists"] = numbered_steps
        internal_jump_links = sum(
            1 for a in self.soup.find_all("a", href=True) if a.get("href", "").startswith("#")
        )
        scannability_refinement["internal_jump_links"] = internal_jump_links
        scannability_refinement["skim_tables"] = len(self.soup.find_all("table"))
        if summary_boxes:
            score = min(5.0, score + 0.2)
        if numbered_steps:
            score = min(5.0, score + 0.15)
        if internal_jump_links >= 3:
            score = min(5.0, score + 0.15)
        if keyword_emphasis_hits >= 3:
            score = min(5.0, score + 0.1)
        if summary_boxes == 0 and word_count >= 600:
            self.recommendations.append("Add a summary box or key-takeaways block near the top for skimmers")
        details["scannability_refinement"] = scannability_refinement

        score = max(0.0, min(score, 5))
        details["scannability_index"] = round(score / 5 * 100, 1)
        self.results["scannability"] = details
        self.scores["scannability"] = round(score, 1)

    def check_hierarchy(self):
        c = self.colors
        print(c.colorize("  [>] Optimizing content hierarchy...", c.YELLOW))
        score = 0
        details = {}

        heading_entries = []
        for level in range(1, 7):
            for tag in self.soup.find_all("h" + str(level)):
                heading_entries.append({"level": level, "text": tag.get_text(strip=True)})

        skipped_levels = 0
        orphan_h3_plus = 0
        h2_seen = False
        for i in range(1, len(heading_entries)):
            prev = heading_entries[i - 1]["level"]
            cur = heading_entries[i]["level"]
            if cur > prev + 1:
                skipped_levels += 1
            if cur >= 3 and not h2_seen:
                orphan_h3_plus += 1
            if cur == 2:
                h2_seen = True
        if heading_entries and heading_entries[0]["level"] >= 3:
            orphan_h3_plus += 1
        details["skipped_levels"] = skipped_levels
        details["orphan_subheadings"] = orphan_h3_plus
        if heading_entries and skipped_levels == 0 and orphan_h3_plus == 0:
            score += 1.5
        elif skipped_levels <= 1:
            score += 0.75
        else:
            self.recommendations.append("Repair heading hierarchy: never skip heading levels (H2 -> H4)")

        heading_lengths = [len(h["text"]) for h in heading_entries if h["text"]]
        if heading_lengths:
            avg_heading_len = sum(heading_lengths) / len(heading_lengths)
        else:
            avg_heading_len = 0.0
        details["avg_heading_length"] = round(avg_heading_len, 1)
        if 15 <= avg_heading_len <= 60:
            score += 1
        elif avg_heading_len > 80:
            score += 0.25
            self.recommendations.append("Headings run long; keep them between 15 and 60 characters")

        level_counts = Counter(h["level"] for h in heading_entries)
        details["heading_depth_distribution"] = {"H" + str(k): v for k, v in sorted(level_counts.items())}
        h2_count = level_counts.get(2, 0)
        h3_count = level_counts.get(3, 0)
        depth_balance = 1.0
        if h2_count > 0 and h3_count > 0:
            ratio = h3_count / h2_count
            depth_balance = 1.0 if 0.5 <= ratio <= 4.0 else 0.5
        elif h2_count > 0:
            depth_balance = 0.75
        details["depth_balance"] = depth_balance
        if depth_balance >= 1.0:
            score += 1
        elif depth_balance >= 0.75:
            score += 0.5

        outline_words = 0
        words_after_heading = False
        current_heading = None
        total_words = 0
        for element in self.soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6", "p", "li"]):
            text = element.get_text(strip=True)
            if not text:
                continue
            wc = len(_get_words(text))
            total_words += wc
            if element.name and element.name.startswith("h"):
                current_heading = element.name
                words_after_heading = True
            elif words_after_heading and current_heading:
                outline_words += wc
        completeness = outline_words / max(total_words, 1)
        details["outline_coverage_pct"] = round(completeness * 100, 1)
        if completeness >= 0.8:
            score += 1
        elif completeness >= 0.5:
            score += 0.5
        else:
            self.recommendations.append("Place most body content under headings so the outline covers the page")

        breadcrumb = self.soup.find_all(class_=re.compile(r"breadcrumb|breadcrumbl", re.I))
        breadcrumb += self.soup.find_all("nav", attrs={"aria-label": re.compile(r"breadcrumb", re.I)})
        details["breadcrumb_present"] = bool(breadcrumb)
        if breadcrumb:
            score += 0.5

        hierarchy_refinement = {}
        title_terms = set()
        title_tag_for_terms = self.soup.find("title")
        if title_tag_for_terms:
            title_terms.update(
                w.lower() for w in _get_words(title_tag_for_terms.get_text())
                if w.lower() not in CONTENT_STOPWORDS and len(w) > 2
            )
        for h1 in self.soup.find_all("h1"):
            title_terms.update(
                w.lower() for w in _get_words(h1.get_text())
                if w.lower() not in CONTENT_STOPWORDS and len(w) > 2
            )
        heading_terms = set()
        for h in heading_entries:
            heading_terms.update(
                w.lower() for w in _get_words(h["text"])
                if w.lower() not in CONTENT_STOPWORDS and len(w) > 2
            )
        coverage = len(title_terms & heading_terms) / max(len(title_terms), 1)
        hierarchy_refinement["title_term_coverage_pct"] = round(coverage * 100, 1)
        text_headings = [h["text"].lower() for h in heading_entries if h["text"]]
        unique_ratio = len(set(text_headings)) / max(len(text_headings), 1)
        hierarchy_refinement["unique_heading_ratio_pct"] = round(unique_ratio * 100, 1)
        level_counts_h = Counter(h["level"] for h in heading_entries)
        levels_used = len(level_counts_h)
        hierarchy_refinement["levels_used"] = levels_used
        hierarchy_refinement["depth_utilization_pct"] = round(levels_used / 6 * 100, 1)
        hierarchy_refinement["single_h1"] = level_counts_h.get(1, 0) == 1
        details["hierarchy_refinement"] = hierarchy_refinement
        if coverage >= 0.4:
            score += 0.25
        elif title_terms and coverage < 0.2:
            self.recommendations.append("Reuse title keywords in subheadings so the outline matches search intent")
        if unique_ratio >= 0.9 and text_headings:
            score += 0.15
        if hierarchy_refinement["single_h1"]:
            score += 0.1

        score = max(0.0, min(score, 5))
        details["hierarchy_index"] = round(score / 5 * 100, 1)
        self.results["hierarchy"] = details
        self.scores["hierarchy"] = round(score, 1)

    def check_engagement_prediction(self):
        c = self.colors
        print(c.colorize("  [>] Predicting content engagement...", c.YELLOW))
        score = 0
        details = {}

        text = self.get_visible_text()
        text_lower = text.lower()
        sentences = self.all_sentences or _split_sentences(text)
        words = self.all_words or _get_words(text)

        question_count = sum(1 for s in sentences if "?" in s)
        details["question_count"] = question_count
        hook = False
        if sentences:
            opening = " ".join(sentences[:2]).lower()
            hook = ("?" in opening) or any(w in opening for w in ("you", "your", "why", "how", "imagine", "what if"))
        details["opening_hook"] = hook
        if hook:
            score += 1.5
        elif question_count >= 3:
            score += 1
        else:
            self.recommendations.append("Open with a hook: a question, statistic, or bold claim")

        word_total = max(len(words), 1)
        you_count = sum(1 for w in words if w.lower() in {"you", "your", "yours", "yourself"})
        you_pct = you_count / word_total * 100
        details["second_person_pct"] = round(you_pct, 1)
        if you_pct >= 1.5:
            score += 1.5
        elif you_pct >= 0.5:
            score += 0.75
        else:
            self.recommendations.append("Address the reader directly (use \"you\") to raise engagement")

        curiosity_hits = [w for w in CURIOSITY_WORDS if w in text_lower]
        details["curiosity_markers"] = curiosity_hits
        if len(curiosity_hits) >= 4:
            score += 1.5
        elif len(curiosity_hits) >= 2:
            score += 0.75

        emotional_hits = [w for w in EMOTIONAL_WORDS if w in text_lower]
        details["emotional_markers"] = emotional_hits
        if len(emotional_hits) >= 3:
            score += 1
        elif emotional_hits:
            score += 0.5

        interactive = 0
        interactive += len(self.soup.find_all("form"))
        interactive += len(self.soup.find_all(class_=re.compile(r"quiz|poll|survey|tab|accordion", re.IGNORECASE)))
        details["interactive_elements"] = interactive
        if interactive >= 2:
            score += 1
        elif interactive >= 1:
            score += 0.5

        media = len(self.soup.find_all(["img", "video"])) + len(self.soup.find_all("svg"))
        details["media_elements"] = media
        if media >= 3:
            score += 1
        elif media >= 1:
            score += 0.5

        read_min = reading_time_minutes(words)
        details["estimated_reading_minutes"] = read_min
        if 2.0 <= read_min <= 9.0:
            score += 1
        elif read_min > 9.0:
            score += 0.25
            self.recommendations.append("Content runs long for typical web attention; add summaries or split pages")
        else:
            score += 0.25

        lists = self.soup.find_all(["ul", "ol"])
        details["list_blocks"] = len(lists)
        if lists:
            score += 0.5

        comment_sections = len(self.soup.find_all(class_=re.compile(r"comment|discussion|review", re.IGNORECASE)))
        details["comment_sections"] = comment_sections
        if comment_sections:
            score += 0.5

        engagement_refinement = {}
        total_sentences = max(len(sentences), 1)
        zone = max(1, total_sentences // 3)
        open_q = any("?" in s for s in sentences[:zone])
        mid_q = any("?" in s for s in sentences[zone:2 * zone])
        close_q = any("?" in s for s in sentences[2 * zone:])
        hook_depth = sum(1 for z in (open_q, mid_q, close_q) if z)
        engagement_refinement["question_zones"] = {"opening": open_q, "middle": mid_q, "closing": close_q}
        engagement_refinement["hook_depth"] = hook_depth
        hook_headings = 0
        for lvl in range(1, 7):
            for h in self.soup.find_all("h" + str(lvl)):
                heading_text = h.get_text(strip=True).lower()
                if (
                    re.match(r"^\d+", heading_text)
                    or heading_text.startswith(("how", "why", "what", "can", "should"))
                    or "?" in heading_text
                ):
                    hook_headings += 1
        engagement_refinement["hook_headings"] = hook_headings
        stat_count_eng = len(re.findall(r"\d+(?:\.\d+)?\s*%|\b\d[\d,]{1,}\b", text))
        share_score = 0
        if lists:
            share_score += 20
        if stat_count_eng >= 2:
            share_score += 20
        if len(curiosity_hits) >= 2:
            share_score += 20
        if self.soup.find_all("blockquote"):
            share_score += 15
        if media >= 2:
            share_score += 15
        if hook:
            share_score += 10
        engagement_refinement["shareability_score"] = min(100, share_score)
        base_eng = score / 10 * 100
        refined_eng = (
            base_eng * 0.70
            + engagement_refinement["shareability_score"] * 0.15
            + (hook_depth / 3 * 100) * 0.15
        )
        refined_eng = max(0.0, min(100.0, refined_eng))
        engagement_refinement["refined_engagement_index"] = round(refined_eng, 1)
        details["engagement_refinement"] = engagement_refinement
        if hook_depth >= 2:
            score = min(10.0, score + 0.25)
        if engagement_refinement["shareability_score"] >= 60:
            score = min(10.0, score + 0.25)

        score = max(0.0, min(score, 10))
        engagement_index = engagement_refinement["refined_engagement_index"]
        if engagement_index >= 75:
            prediction = "High"
        elif engagement_index >= 50:
            prediction = "Moderate"
        elif engagement_index >= 30:
            prediction = "Low-Moderate"
        else:
            prediction = "Low"
        details["engagement_index"] = engagement_index
        details["engagement_prediction"] = prediction
        self.results["engagement"] = details
        self.scores["engagement"] = round(score, 1)

    def check_conversion_potential(self):
        c = self.colors
        print(c.colorize("  [>] Evaluating conversion potential...", c.YELLOW))
        score = 0
        details = {}

        text = self.get_visible_text()
        text_lower = text.lower()

        cta_hits = [p for p in CTA_PHRASES if p in text_lower]
        details["cta_phrases"] = cta_hits
        cta_links = []
        for anchor in self.soup.find_all("a", href=True):
            label = anchor.get_text(strip=True)
            if label and any(p in label.lower() for p in CTA_PHRASES):
                cta_links.append(label)
        buttons = [b.get_text(strip=True) for b in self.soup.find_all("button")]
        cta_buttons = [b for b in buttons if b and any(p in b.lower() for p in CTA_PHRASES)]
        details["cta_links"] = cta_links[:10]
        details["cta_buttons"] = cta_buttons[:10]
        cta_count = len(cta_hits) + len(cta_links) + len(cta_buttons)
        details["cta_count"] = cta_count
        if cta_count >= 3:
            score += 2.5
        elif cta_count >= 1:
            score += 1.5
            self.recommendations.append("Add more calls-to-action; place one mid-content and one at the end")
        else:
            self.recommendations.append("No call-to-action found; add a clear primary CTA")

        placement_points = 0.0
        if cta_hits:
            positions = [text_lower.find(p) for p in cta_hits]
            positions = [p for p in positions if p >= 0]
            if positions:
                first_pos = min(positions) / max(len(text_lower), 1)
                last_pos = max(positions) / max(len(text_lower), 1)
                details["first_cta_position_pct"] = round(first_pos * 100, 1)
                details["last_cta_position_pct"] = round(last_pos * 100, 1)
                if last_pos >= 0.6:
                    placement_points += 0.5
                if first_pos <= 0.3:
                    placement_points += 0.5
        score += placement_points

        benefit_hits = [w for w in BENEFIT_WORDS if w in text_lower]
        details["benefit_markers"] = benefit_hits
        if len(benefit_hits) >= 4:
            score += 1.5
        elif len(benefit_hits) >= 2:
            score += 0.75
        else:
            self.recommendations.append("Use benefit-driven language (save, free, proven, instant results)")

        proof_hits = [w for w in SOCIAL_PROOF_MARKERS if w in text_lower]
        ld_text = ""
        for script in self.soup.find_all("script", type=re.compile(r"ld\+json", re.IGNORECASE)):
            ld_text += script.get_text()
        has_review_schema = "aggregateRating" in ld_text or '"Review"' in ld_text
        details["social_proof_markers"] = proof_hits
        details["review_schema"] = has_review_schema
        if has_review_schema or len(proof_hits) >= 3:
            score += 1.5
        elif proof_hits:
            score += 0.75
        else:
            self.recommendations.append("Add social proof: testimonials, reviews, or customer counts")

        urgency_hits = [w for w in URGENCY_WORDS if w in text_lower]
        details["urgency_markers"] = urgency_hits
        if len(urgency_hits) >= 2:
            score += 1
        elif urgency_hits:
            score += 0.5

        friction_hits = [w for w in FRICTION_REDUCERS if w in text_lower]
        details["friction_reducers"] = friction_hits
        if friction_hits:
            score += 1
        elif cta_count >= 1:
            score += 0.25

        h1_tag = self.soup.find("h1")
        h1_text = h1_tag.get_text(strip=True) if h1_tag else ""
        meta_desc = self.soup.find("meta", attrs={"name": "description"})
        desc_text = meta_desc.get("content", "") if meta_desc else ""
        value_words = set(w.lower() for w in BENEFIT_WORDS)
        h1_lower = h1_text.lower()
        value_prop_clear = bool(h1_text) and any(v in h1_lower for v in value_words)
        if not value_prop_clear and h1_text and any(
            w in h1_lower for w in ("how", "why", "guide", "best", "top", "free")
        ):
            value_prop_clear = True
        details["value_proposition_clear"] = value_prop_clear
        details["meta_description_present"] = bool(desc_text)
        if value_prop_clear:
            score += 1
        elif h1_text:
            score += 0.5
            self.recommendations.append("Sharpen the H1 so it states a concrete benefit or outcome")

        inputs = self.soup.find_all(["input", "textarea", "select"])
        visible_inputs = [i for i in inputs if i.get("type") not in ("hidden", "submit", "button")]
        details["form_fields"] = len(visible_inputs)
        if len(visible_inputs) == 0:
            score += 0.5
        elif len(visible_inputs) <= 6:
            score += 0.5
        elif len(visible_inputs) > 12:
            score += 0.0
            self.recommendations.append("Forms are heavy; reduce fields to lower conversion friction")
        else:
            score += 0.25

        conversion_refinement = {}
        email_fields = sum(1 for i in inputs if i.get("type") == "email")
        checkboxes = sum(1 for i in inputs if i.get("type") == "checkbox")
        conversion_refinement["email_fields"] = email_fields
        conversion_refinement["checkboxes"] = checkboxes
        conversion_refinement["micro_commitment_present"] = email_fields >= 1 or checkboxes >= 1
        objection_markers = [
            m for m in ("what if", "is it worth", "how much", "alternative", "why should", "is this for", "vs ", "versus")
            if m in text_lower
        ]
        conversion_refinement["objection_markers"] = objection_markers
        conversion_refinement["objection_handling"] = len(objection_markers) >= 1
        conversion_refinement["risk_reversal_count"] = len(friction_hits)
        generic_cta = {"learn more", "click here", "submit", "read more", "more"}
        specific_cta = [p for p in cta_hits if p not in generic_cta]
        conversion_refinement["specific_cta_phrases"] = specific_cta
        conversion_refinement["cta_specificity_pct"] = round(len(specific_cta) / max(len(cta_hits), 1) * 100, 1)
        if conversion_refinement["objection_handling"]:
            pass
        elif cta_count >= 1 and not objection_markers:
            self.recommendations.append("Address buyer objections in-content (what if, how much, alternatives)")
        conv_bonus = 0.0
        if conversion_refinement["micro_commitment_present"]:
            conv_bonus += 0.4
        if conversion_refinement["objection_handling"]:
            conv_bonus += 0.4
        if len(specific_cta) >= 2:
            conv_bonus += 0.3
        if len(friction_hits) >= 2:
            conv_bonus += 0.3
        conversion_refinement["refinement_bonus"] = round(conv_bonus, 2)

        score = max(0.0, min(score + conv_bonus, 10))
        conversion_index = round(score / 10 * 100, 1)
        conversion_refinement["refined_conversion_index"] = conversion_index
        details["conversion_refinement"] = conversion_refinement
        if conversion_index >= 75:
            band = "Strong"
        elif conversion_index >= 50:
            band = "Moderate"
        elif conversion_index >= 30:
            band = "Weak"
        else:
            band = "Very Weak"
        details["conversion_index"] = conversion_index
        details["conversion_band"] = band
        self.results["conversion"] = details
        self.scores["conversion"] = round(score, 1)

    def compute_composite_indices(self):
        cqi = compute_content_quality_index(self.scores, self.results)
        readability_index = self.results.get("readability", {}).get("readability_index", 0.0)
        a11y_points = self.scores.get("accessibility", 0)
        a11y_max = CATEGORY_MAX.get("accessibility", 15)
        a11y_pct = a11y_points / a11y_max * 100 if a11y_max else 0.0
        a11y_quality = accessibility_quality_percentage(self.results.get("accessibility", {}))
        seo_score = compute_seo_content_score(self.scores, self.results)

        orig_deep = self.results.get("originality", {}).get("originality_deep", {}) or {}
        deep_originality = float(orig_deep.get("deep_originality_index", 0) or 0)
        qual_ref = self.results.get("quality_signals", {}).get("quality_refinement", {}) or {}
        quality_refinement_index = float(qual_ref.get("refined_quality_index", 0) or 0)
        eng_ref = self.results.get("engagement", {}).get("engagement_refinement", {}) or {}
        engagement_refinement_index = float(eng_ref.get("refined_engagement_index", 0) or 0)
        conv_ref = self.results.get("conversion", {}).get("conversion_refinement", {}) or {}
        conversion_refinement_index = float(conv_ref.get("refined_conversion_index", 0) or 0)

        eng_second_person = float(self.results.get("engagement", {}).get("second_person_pct", 0) or 0)
        depth_words = int(self.results.get("depth", {}).get("word_count", 0) or 0)
        qs_idx = float(self.results.get("quality_signals", {}).get("quality_signal_index", 0) or 0)
        uniq_idx = float(self.results.get("uniqueness", {}).get("uniqueness_score", 0) or 0)
        orig_idx = float(self.results.get("originality", {}).get("originality_index", 0) or 0)
        eng_idx = float(self.results.get("engagement", {}).get("engagement_index", 0) or 0)
        conv_idx = float(self.results.get("conversion", {}).get("conversion_index", 0) or 0)

        audience_clarity = 0.6 * readability_index + 0.4 * min(eng_second_person * 40.0, 100.0)
        funnel_fit = 0.6 * conv_idx + 0.4 * eng_idx
        topic_authority = 0.5 * qs_idx + 0.5 * min(depth_words / 10.0, 100.0)
        differentiation = 0.5 * orig_idx + 0.5 * uniq_idx
        strategy_index = (audience_clarity + funnel_fit + topic_authority + differentiation) / 4.0
        strategy_refinement = {
            "audience_clarity": round(max(0.0, min(100.0, audience_clarity)), 1),
            "funnel_fit": round(max(0.0, min(100.0, funnel_fit)), 1),
            "topic_authority": round(max(0.0, min(100.0, topic_authority)), 1),
            "differentiation": round(max(0.0, min(100.0, differentiation)), 1),
            "content_strategy_index": round(max(0.0, min(100.0, strategy_index)), 1),
        }
        if "content_strategy" in self.results:
            self.results["content_strategy"]["strategy_refinement"] = strategy_refinement

        self.results["indices"] = {
            "content_quality_index": round(cqi, 1),
            "readability_index": round(readability_index, 1),
            "accessibility_score": round(a11y_pct, 1),
            "accessibility_quality_score": round(a11y_quality, 1),
            "seo_content_score": round(seo_score, 1),
            "deep_originality_index": round(deep_originality, 1),
            "quality_refinement_index": round(quality_refinement_index, 1),
            "engagement_refinement_index": round(engagement_refinement_index, 1),
            "conversion_refinement_index": round(conversion_refinement_index, 1),
            "content_strategy_index": strategy_refinement["content_strategy_index"],
        }

    def generate_content_outline(self):
        outline = []
        for level in range(1, 7):
            for tag in self.soup.find_all("h" + str(level)):
                text = tag.get_text(strip=True)
                if text:
                    tag_id = tag.get("id", "")
                    anchor = "#" + tag_id if tag_id else ""
                    outline.append({
                        "level": level,
                        "text": text,
                        "id": tag_id,
                        "anchor": anchor,
                    })
        return outline

    def run_all_checks(self):
        self.fetch_content()
        if not self.soup:
            print(self.colors.colorize("  [!] Cannot proceed without content", self.colors.RED))
            return False
        self.detect_language()
        self.check_structure()
        self.check_readability()
        self.check_accessibility()
        self.check_links()
        self.check_images()
        self.check_freshness()
        self.check_social_seo()
        self.check_multimedia()
        self.check_depth()
        self.check_unicode()
        self.check_multilingual()
        self.check_content_strategy()
        self.check_code_blocks()
        self.check_blockquotes()
        self.check_originality()
        self.check_uniqueness()
        self.check_quality_signals()
        self.check_flow()
        self.check_scannability()
        self.check_hierarchy()
        self.check_engagement_prediction()
        self.check_conversion_potential()
        self.compute_composite_indices()
        return True

    def get_total_score(self):
        return sum(self.scores.values())

    def get_max_score(self):
        return sum(CATEGORY_MAX.values())

    def print_category_bar(self, label, score, max_score, width=30):
        c = self.colors
        filled = int(score / max_score * width) if max_score > 0 else 0
        pct = score / max_score if max_score > 0 else 0
        if pct >= 0.7:
            bar_color = c.BRIGHT_GREEN
        elif pct >= 0.5:
            bar_color = c.BRIGHT_YELLOW
        else:
            bar_color = c.BRIGHT_RED
        bar = bar_color + "=" * filled + c.DIM + "-" * (width - filled) + c.RESET
        print("    " + label.ljust(22) + " [" + bar + "] " + str(score).rjust(5) + "/" + str(max_score))

    def _render_gauge(self, value, max_val, width=20):
        c = self.colors
        pct = value / max_val if max_val > 0 else 0
        filled = int(round(pct * width))
        filled = max(0, min(width, filled))
        if pct >= 0.7:
            color = c.BRIGHT_GREEN
        elif pct >= 0.5:
            color = c.BRIGHT_YELLOW
        else:
            color = c.BRIGHT_RED
        return color + "[" + "=" * filled + " " * (width - filled) + "]" + c.RESET

    def _print_quality_dashboard(self):
        c = self.colors
        total = self.get_total_score()
        max_score = self.get_max_score()
        grade, grade_color = grade_from_score(total, max_score)
        indices = self.results.get("indices", {})

        print(c.colorize("  CONTENT QUALITY DASHBOARD", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        overall_pct = total / max_score if max_score else 0
        print(
            "    Overall  " + self._render_gauge(total, max_score, 28)
            + "  " + c.BOLD + str(round(total, 1)) + "/" + str(max_score)
            + "  (" + str(round(overall_pct * 100, 1)) + "%)"
            + "  [Grade: " + grade_color + grade + c.RESET + "]"
        )
        print()

        for group_name, keys in DASHBOARD_GROUPS:
            g_score = sum(self.scores.get(k, 0) for k in keys)
            g_max = sum(CATEGORY_MAX[k] for k in keys)
            print("    " + c.BRIGHT_CYAN + group_name + c.RESET + "  "
                  + str(round(g_score, 1)) + "/" + str(g_max))
            for key in keys:
                sc = self.scores.get(key, 0)
                mx = CATEGORY_MAX[key]
                self.print_category_bar(CATEGORY_LABELS[key], sc, mx)
            print()

        print(c.colorize("  KEY INDICES", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        index_rows = [
            ("Content Quality Index", indices.get("content_quality_index", 0), 100),
            ("Readability Index", indices.get("readability_index", 0), 100),
            ("Accessibility Score", indices.get("accessibility_score", 0), 100),
            ("SEO Content Score", indices.get("seo_content_score", 0), 100),
            ("Engagement Prediction", self.results.get("engagement", {}).get("engagement_index", 0), 100),
            ("Conversion Potential", self.results.get("conversion", {}).get("conversion_index", 0), 100),
            ("Originality Index", self.results.get("originality", {}).get("originality_index", 0), 100),
            ("Uniqueness Score", self.results.get("uniqueness", {}).get("uniqueness_score", 0), 100),
            ("Deep Originality", indices.get("deep_originality_index", 0), 100),
            ("Quality Refinement", indices.get("quality_refinement_index", 0), 100),
            ("Engagement Refinement", indices.get("engagement_refinement_index", 0), 100),
            ("Conversion Refinement", indices.get("conversion_refinement_index", 0), 100),
            ("Strategy Index", indices.get("content_strategy_index", 0), 100),
        ]
        for label, value, mx in index_rows:
            print("    " + label.ljust(24) + " " + self._render_gauge(value, mx, 18)
                  + " " + str(value).rjust(6) + "/100")
        print()

        print(c.colorize("  " + "-" * 60, c.DIM))
        total_line = "    " + c.BOLD + "TOTAL".ljust(22) + c.RESET + "  " + grade_color + str(round(total, 1)).rjust(5) + "/" + str(max_score) + "  [Grade: " + grade + "]" + c.RESET
        print(total_line)
        print(c.colorize("  " + "-" * 60, c.DIM))
        print()

    def _print_readability_details(self):
        c = self.colors
        if self.scores.get("readability", 0) <= 0:
            return
        r = self.results.get("readability", {})
        print(c.colorize("  READABILITY METRICS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    Flesch Reading Ease:     " + c.BRIGHT_GREEN + str(r.get("flesch_reading_ease", 0)) + c.RESET + " (" + str(r.get("readability_level", "N/A")) + ")")
        print("    Flesch-Kincaid Grade:    " + c.BRIGHT_GREEN + str(r.get("flesch_kincaid_grade", 0)) + c.RESET + " (" + grade_level_label(r.get("flesch_kincaid_grade", 0)) + ")")
        print("    Gunning Fog Index:       " + c.BRIGHT_GREEN + str(r.get("gunning_fog_index", 0)) + c.RESET + " (" + grade_level_label(r.get("gunning_fog_index", 0)) + ")")
        print("    Coleman-Liau Index:      " + c.BRIGHT_GREEN + str(r.get("coleman_liau_index", 0)) + c.RESET + " (" + grade_level_label(r.get("coleman_liau_index", 0)) + ")")
        print("    Automated Readability:   " + c.BRIGHT_GREEN + str(r.get("automated_readability_index", 0)) + c.RESET + " (" + grade_level_label(r.get("automated_readability_index", 0)) + ")")
        print("    Linsear Write Formula:   " + c.BRIGHT_GREEN + str(r.get("linsear_write_formula", 0)) + c.RESET + " (" + grade_level_label(r.get("linsear_write_formula", 0)) + ")")
        print("    SMOG Index:              " + c.BRIGHT_GREEN + str(r.get("smog_index", 0)) + c.RESET + " (" + grade_level_label(r.get("smog_index", 0)) + ")")
        print("    Text Standard (avg):     " + c.BRIGHT_CYAN + str(r.get("text_standard", 0)) + c.RESET + " (" + str(r.get("text_standard_level", "N/A")) + ")")
        print()
        print("    Avg Sentence Length:     " + c.BRIGHT_CYAN + str(r.get("avg_sentence_length", 0)) + c.RESET + " words")
        print("    Avg Word Length:         " + c.BRIGHT_CYAN + str(r.get("avg_word_length", 0)) + c.RESET + " chars")
        print("    Complex Words:           " + c.BRIGHT_YELLOW + str(r.get("complex_word_pct", 0)) + "%" + c.RESET)
        print("    Passive Voice:           " + c.BRIGHT_YELLOW + str(r.get("passive_voice_pct", 0)) + "%" + c.RESET)
        print("    Adverb Usage:            " + c.BRIGHT_YELLOW + str(r.get("adverb_pct", 0)) + "%" + c.RESET)
        ri = r.get("readability_index", 0)
        ri_color = c.BRIGHT_GREEN if ri >= 70 else c.BRIGHT_YELLOW if ri >= 45 else c.BRIGHT_RED
        print()
        print("    " + c.BOLD + "Readability Index (v6):    " + c.RESET + ri_color + str(ri) + "/100" + c.RESET
              + "  " + self._render_gauge(ri, 100, 14))
        print("    Ideal Sentence Band:     " + c.BRIGHT_CYAN + str(r.get("ideal_sentence_pct", 0)) + "%" + c.RESET + " (8-22 words)")
        print("    Transition Coverage:     " + c.BRIGHT_CYAN + str(r.get("transition_sentence_pct", 0)) + "%" + c.RESET + " of sentences")
        read_ref = r.get("readability_refinement", {}) or {}
        if read_ref:
            print()
            print("    " + c.DIM + "--- Readability Refinement (v6) ---" + c.RESET)
            print("    Sentence Length Stdev:   " + c.BRIGHT_CYAN + str(read_ref.get("sentence_length_stdev", 0)) + c.RESET)
            print("    Question Cadence:        " + c.BRIGHT_CYAN + str(read_ref.get("question_cadence_pct", 0)) + "%" + c.RESET)
            print("    Short Sentences (<=12):  " + c.BRIGHT_CYAN + str(read_ref.get("short_sentence_pct", 0)) + "%" + c.RESET)
            print("    Long Sentences (>30):    " + c.BRIGHT_YELLOW + str(read_ref.get("long_sentence_pct", 0)) + "%" + c.RESET)
        adj_fre = r.get("language_adjusted_fre")
        adj_ts = r.get("language_adjusted_ts")
        if adj_fre is not None and adj_ts is not None:
            print()
            print("    " + c.DIM + "--- Language-Adjusted Scores (" + str(r.get("language", self.detected_language or "en")).upper() + ") ---" + c.RESET)
            print("    Adj. Flesch Reading Ease:" + c.BRIGHT_CYAN + str(adj_fre) + c.RESET)
            print("    Adj. Text Standard:      " + c.BRIGHT_CYAN + str(adj_ts) + c.RESET)
            print("    Adjustment Factor:       " + c.DIM + str(r.get("language_readability_factor", 1.0)) + c.RESET)
        print()

    def _print_audience_grades(self):
        c = self.colors
        if self.scores.get("readability", 0) <= 0:
            return
        r = self.results.get("readability", {})
        ts = r.get("text_standard", 0)
        print(c.colorize("  READABILITY FOR DIFFERENT AUDIENCES", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))

        audiences = [
            ("General Public", 6, 8),
            ("High School Students", 9, 12),
            ("College Students", 13, 16),
            ("Technical Audience", 16, 19),
            ("Academic/Professional", 19, 22),
        ]
        for name, low, high in audiences:
            if low <= ts <= high:
                indicator = c.BRIGHT_GREEN + "[IDEAL]"
            elif ts < low:
                indicator = c.BRIGHT_YELLOW + "[EASIER]"
            else:
                indicator = c.BRIGHT_RED + "[HARDER]"
            print("    " + name.ljust(25) + " Grade " + str(low) + "-" + str(high).ljust(4) + indicator + c.RESET)
        print()

    def _print_accessibility_details(self):
        c = self.colors
        if self.scores.get("accessibility", 0) <= 0:
            return
        a = self.results.get("accessibility", {})
        acc_max = 15
        acc_score = self.scores.get("accessibility", 0)
        wcag = wcag_level(acc_score, acc_max)
        wcag_color = c.BRIGHT_GREEN if wcag == "AAA" else c.BRIGHT_YELLOW if wcag in ("AA", "A") else c.BRIGHT_RED

        print(c.colorize("  ACCESSIBILITY COMPLIANCE", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    WCAG 2.1 Level:          " + wcag_color + wcag + c.RESET)
        print()
        print(c.colorize("  ACCESSIBILITY SUMMARY", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    Images with alt text:      " + str(a.get("alt_text_ratio", 0)) + "%")
        print("    Lang attribute:            " + ("Yes" if a.get("lang_attribute") else "No"))
        print("    ARIA labels:               " + str(a.get("aria_labels", 0)))
        print("    ARIA roles:                " + str(a.get("aria_roles", 0)))
        print("    ARIA describedby:          " + str(a.get("aria_describedby", 0)))
        print("    Semantic landmarks:        " + str(a.get("semantic_landmarks", 0)))
        print("    Landmark types:            " + (", ".join(a.get("landmark_types", [])) or "None"))
        print("    Form labels:               " + str(a.get("labels", 0)))
        print("    Skip navigation:           " + ("Yes" if a.get("skip_navigation") else "No"))
        print("    Focus indicators:          " + ("Yes" if a.get("focus_indicators_detected") else "No"))
        print("    Tabindex elements:         " + str(a.get("tabindex_elements", 0)))
        if a.get("positive_tabindex_count", 0) > 0:
            print("    " + c.BRIGHT_RED + "Positive tabindex:        " + str(a.get("positive_tabindex_count", 0)) + " (avoid)!" + c.RESET)
        print()

    def _print_language_info(self):
        c = self.colors
        lang = self.results.get("language", {})
        if not lang:
            return
        print(c.colorize("  LANGUAGE & ENCODING", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    Detected Language:       " + c.BRIGHT_CYAN + str(lang.get("language", "N/A")).upper() + c.RESET + " (source: " + str(lang.get("source", "N/A")) + ")")
        print("    RTL Language:            " + ("Yes" if lang.get("is_rtl") else "No"))
        if lang.get("rtl_text_percentage", 0) > 0:
            print("    RTL Text Percentage:     " + str(lang.get("rtl_text_percentage", 0)) + "%")
        print("    Character Encoding:      " + c.BRIGHT_CYAN + str(lang.get("encoding", "N/A")) + c.RESET)
        print()

    def _print_structure_details(self):
        c = self.colors
        s = self.results.get("structure", {})
        if not s:
            return
        print(c.colorize("  CONTENT STRUCTURE DETAILS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    H1 Tags:                 " + str(s.get("h1_count", 0)))
        print("    Total Headings:          " + str(s.get("total_headings", 0)))
        print("    Paragraphs:              " + str(s.get("paragraph_count", 0)))
        print("    Lists:                   " + str(s.get("list_count", 0)))
        print("    Tables:                  " + str(s.get("table_count", 0)))
        print("    Definition Lists:        " + str(s.get("definition_list_count", 0)))
        print("    Blockquotes:             " + str(s.get("blockquote_count", 0)))
        print("    Semantic Elements:       " + str(s.get("semantic_elements", 0)))
        print("    TOC Hints:               " + str(s.get("toc_hints", 0)))
        if s.get("semantic_breakdown"):
            parts = ", ".join(k + ":" + str(v) for k, v in s["semantic_breakdown"].items())
            print("    Semantic Breakdown:      " + parts)
        print()

        outline = s.get("heading_outline", [])
        if outline:
            print(c.colorize("  HEADING HIERARCHY", c.BOLD))
            print(c.colorize("  " + "-" * 60, c.DIM))
            for item in outline:
                level = item["level"]
                text = item["text"]
                indent = "  " * (level - 1)
                print("    " + indent + "H" + str(level) + ": " + text[:55])
            print()

    def _print_unicode_info(self):
        c = self.colors
        u = self.results.get("unicode", {})
        if not u:
            return
        print(c.colorize("  UNICODE ANALYSIS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    Total Characters:        " + str(u.get("total_characters", 0)))
        print("    Letters:                 " + str(u.get("letter_count", 0)))
        print("    Numbers:                 " + str(u.get("number_count", 0)))
        print("    Punctuation:             " + str(u.get("punctuation_count", 0)))
        print("    Symbols:                 " + str(u.get("symbol_count", 0)))
        print("    Non-ASCII Characters:    " + str(u.get("non_ascii_count", 0)) + " (" + str(u.get("non_ascii_pct", 0)) + "%)")
        print("    Scripts Detected:        " + str(u.get("unique_scripts_detected", 0)))
        scripts = u.get("script_distribution", {})
        if scripts:
            script_str = ", ".join(k + ":" + str(v) for k, v in sorted(scripts.items(), key=lambda x: -x[1])[:8])
            print("    Script Distribution:     " + c.DIM + script_str + c.RESET)
        if u.get("is_rtl_content"):
            print("    RTL Content:             Yes (" + str(u.get("rtl_text_percentage", 0)) + "%)")
        print()

    def _print_multilingual_info(self):
        c = self.colors
        m = self.results.get("multilingual", {})
        if not m:
            return
        print(c.colorize("  MULTILINGUAL ANALYSIS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    Languages Detected:     " + c.BRIGHT_CYAN + str(m.get("language_count", 1)) + c.RESET)
        if m.get("is_multilingual"):
            print("    Multilingual Content:   " + c.BRIGHT_YELLOW + "Yes" + c.RESET)
            langs = m.get("detected_languages", [])
            if langs:
                print("    Detected Languages:     " + ", ".join(str(l).upper() for l in langs))
        else:
            print("    Multilingual Content:   No")
        hints = m.get("translation_hints", [])
        if hints:
            print("    Translation Hints:")
            for hint in hints:
                print("      - " + hint)
        if m.get("possible_machine_translation"):
            print("    " + c.BRIGHT_YELLOW + "Possible machine translation detected" + c.RESET)
        print("    Language Factor:        " + str(m.get("language_adjustment_factor", 1.0)))
        print()

    def _print_content_strategy(self):
        c = self.colors
        cs = self.results.get("content_strategy", {})
        if not cs:
            return
        print(c.colorize("  CONTENT STRATEGY ANALYSIS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))

        freshness = cs.get("freshness_signals", {})
        if freshness.get("has_recent_dates"):
            print("    Freshness:              " + c.BRIGHT_GREEN + "Recent content detected" + c.RESET)
        else:
            print("    Freshness:              " + c.BRIGHT_YELLOW + "No recent dates found" + c.RESET)

        depth = cs.get("depth_analysis", {})
        print("    Word Count:             " + str(depth.get("word_count", 0)))
        vr = depth.get("vocabulary_richness", 0)
        print("    Vocabulary Richness:    " + str(vr) + "%")

        uniqueness = cs.get("uniqueness", {})
        us = uniqueness.get("uniqueness_score", 0)
        us_color = c.BRIGHT_GREEN if us >= 70 else c.BRIGHT_YELLOW if us >= 50 else c.BRIGHT_RED
        print("    Uniqueness Score:       " + us_color + str(us) + "%" + c.RESET)

        gaps = cs.get("gap_analysis", {})
        gap_list = gaps.get("gaps", [])
        if gap_list:
            print("    Content Gaps:")
            for gap in gap_list:
                print("      - " + gap)

        engagement = cs.get("engagement_potential", {})
        print("    Social Sharing:         " + ("Yes" if engagement.get("has_social_sharing") else "No"))
        print("    Call-to-Action:         " + ("Yes" if engagement.get("has_cta") else "No"))
        print("    Forms:                  " + str(engagement.get("forms", 0)))
        print("    Comment Sections:       " + str(engagement.get("comment_sections", 0)))

        strat_ref = cs.get("strategy_refinement", {}) or {}
        if strat_ref:
            print()
            print("    " + c.DIM + "--- Strategy Pillars (v6) ---" + c.RESET)
            pillar_specs = [
                ("Audience Clarity", strat_ref.get("audience_clarity", 0)),
                ("Funnel Fit", strat_ref.get("funnel_fit", 0)),
                ("Topic Authority", strat_ref.get("topic_authority", 0)),
                ("Differentiation", strat_ref.get("differentiation", 0)),
                ("Strategy Index", strat_ref.get("content_strategy_index", 0)),
            ]
            for pillar_name, pillar_value in pillar_specs:
                pillar_color = c.BRIGHT_GREEN if pillar_value >= 70 else c.BRIGHT_YELLOW if pillar_value >= 45 else c.BRIGHT_RED
                print("    " + pillar_name.ljust(25) + pillar_color + str(pillar_value) + "/100" + c.RESET
                      + "  " + self._render_gauge(pillar_value, 100, 12))
        print()

    def _print_code_block_analysis(self):
        c = self.colors
        cb = self.results.get("code_blocks", {})
        if not cb:
            return
        if cb.get("code_elements", 0) == 0 and cb.get("pre_elements", 0) == 0:
            return
        print(c.colorize("  CODE BLOCK ANALYSIS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    Code Elements:          " + str(cb.get("code_elements", 0)))
        print("    Pre Elements:           " + str(cb.get("pre_elements", 0)))
        print("    Syntax Highlighted:     " + str(cb.get("syntax_highlighted", 0)))
        print("    Language Annotated:     " + str(cb.get("language_annotated", 0)))
        print("    Line Numbers:           " + str(cb.get("line_numbers_found", 0)))
        print("    Code Word Ratio:        " + str(cb.get("code_word_ratio_pct", 0)) + "%")
        langs = cb.get("detected_languages", [])
        if langs:
            print("    Detected Languages:     " + ", ".join(langs))
        print()

    def _print_blockquote_analysis(self):
        c = self.colors
        bq = self.results.get("blockquotes", {})
        if not bq or bq.get("total_blockquotes", 0) == 0:
            return
        print(c.colorize("  BLOCKQUOTE ANALYSIS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    Total Blockquotes:      " + str(bq.get("total_blockquotes", 0)))
        print("    With Cite Attribute:    " + str(bq.get("with_cite_attribute", 0)))
        print("    With Attribution:       " + str(bq.get("with_attribution", 0)))
        print("    With Linked Sources:    " + str(bq.get("with_linked_sources", 0)))
        print("    Avg Blockquote Length:  " + str(bq.get("avg_blockquote_words", 0)) + " words")
        print()

    def _print_content_outline(self):
        c = self.colors
        outline = self.generate_content_outline()
        if not outline:
            return
        print(c.colorize("  CONTENT OUTLINE", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        for item in outline:
            level = item["level"]
            text = item["text"]
            indent = "  " * (level - 1)
            anchor = ""
            if item["anchor"]:
                anchor = " " + c.DIM + item["anchor"] + c.RESET
            print("    " + indent + "H" + str(level) + ": " + text[:50] + anchor)
        print()

    def _print_originality_uniqueness(self):
        c = self.colors
        orig = self.results.get("originality", {})
        uniq = self.results.get("uniqueness", {})
        qs = self.results.get("quality_signals", {})
        if not orig and not uniq and not qs:
            return
        print(c.colorize("  ORIGINALITY & UNIQUENESS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        oi = orig.get("originality_index", 0)
        oi_color = c.BRIGHT_GREEN if oi >= 70 else c.BRIGHT_YELLOW if oi >= 45 else c.BRIGHT_RED
        print("    Originality Index:       " + oi_color + str(oi) + "/100" + c.RESET
              + "  " + self._render_gauge(oi, 100, 14))
        print("    Duplicate Sentences:     " + str(orig.get("duplicate_sentence_pct", 0)) + "%")
        print("    Repeated 5-grams:        " + str(orig.get("repeated_5gram_pct", 0)) + "%")
        print("    External Source Links:   " + str(orig.get("external_source_links", 0)))
        if orig.get("formulaic_openers_found"):
            print("    " + c.BRIGHT_YELLOW + "Formulaic openers:         " + str(len(orig.get("formulaic_openers_found", []))) + " found" + c.RESET)
        deep = orig.get("originality_deep", {}) or {}
        if deep:
            doi = deep.get("deep_originality_index", 0)
            doi_color = c.BRIGHT_GREEN if doi >= 70 else c.BRIGHT_YELLOW if doi >= 45 else c.BRIGHT_RED
            print("    Deep Originality:        " + doi_color + str(doi) + "/100" + c.RESET
                  + "  " + self._render_gauge(doi, 100, 14))
            print("    Boilerplate Paragraphs:  " + str(deep.get("boilerplate_paragraph_pct", 0)) + "%")
            print("    Quote Word Share:        " + str(deep.get("quote_word_pct", 0)) + "%")
            print("    First-hand Markers:      " + str(len(deep.get("firsthand_insight_markers", []))))
            print("    Unsupported Claims:      " + str(deep.get("unsupported_claims", 0)))
        print()
        us = uniq.get("uniqueness_score", 0)
        us_color = c.BRIGHT_GREEN if us >= 70 else c.BRIGHT_YELLOW if us >= 50 else c.BRIGHT_RED
        print("    Uniqueness Score:        " + us_color + str(us) + "/100" + c.RESET
              + "  " + self._render_gauge(us, 100, 14))
        print("    Type-Token Ratio:        " + str(uniq.get("type_token_ratio", 0)) + "%")
        print("    Hapax Legomena:          " + str(uniq.get("hapax_legomena_ratio", 0)) + "%")
        print("    Lexical Entropy:         " + str(uniq.get("lexical_entropy", 0)))
        print("    Sentence Length Stdev:   " + str(uniq.get("sentence_length_stdev", 0)))
        uniq_ref = uniq.get("uniqueness_refinement", {}) or {}
        if uniq_ref:
            print("    Unique Paragraphs:       " + str(uniq_ref.get("unique_paragraph_pct", 0)) + "%")
            print("    Opening Diversity:       " + str(uniq_ref.get("sentence_opening_diversity_pct", 0)) + "%")
            print("    Distinctive Terms:       " + str(uniq_ref.get("distinctive_term_count", 0))
                  + " (" + str(uniq_ref.get("distinctive_term_ratio_pct", 0)) + "%)")
        print()
        qsi = qs.get("quality_signal_index", 0)
        qsi_color = c.BRIGHT_GREEN if qsi >= 70 else c.BRIGHT_YELLOW if qsi >= 45 else c.BRIGHT_RED
        print("    Quality Signal Index:    " + qsi_color + str(qsi) + "/100" + c.RESET
              + "  " + self._render_gauge(qsi, 100, 14))
        print("    Statistical References:  " + str(qs.get("statistical_references", 0)))
        print("    Evidence Markers:        " + str(len(qs.get("evidence_markers", []))))
        print("    Example Markers:         " + str(len(qs.get("example_markers", []))))
        print("    Credential Markers:      " + str(len(qs.get("credential_markers", []))))
        print("    Authoritative Links:     " + str(qs.get("authoritative_links", 0)))
        qual_ref = qs.get("quality_refinement", {}) or {}
        if qual_ref:
            print("    Specificity Score:       " + str(qual_ref.get("specificity_score", 0)) + "/100")
            print("    Hedging Markers:         " + str(len(qual_ref.get("hedging_markers", []))))
            print("    Actionable Steps:        " + str(qual_ref.get("actionable_steps_detected", 0)))
        print()

    def _print_flow_scannability_hierarchy(self):
        c = self.colors
        flow = self.results.get("flow", {})
        scan = self.results.get("scannability", {})
        hier = self.results.get("hierarchy", {})
        if not flow and not scan and not hier:
            return
        print(c.colorize("  FLOW, SCANNABILITY & HIERARCHY", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        fi = flow.get("flow_index", 0)
        print("    Flow Index:              " + str(fi) + "/100"
              + "  " + self._render_gauge(fi, 100, 14))
        print("    Transition Coverage:     " + str(flow.get("transition_sentence_pct", 0)) + "%")
        print("    Paragraph Continuity:    " + str(flow.get("paragraph_continuity_pct", 0)) + "%")
        print("    Opening Hook:            " + ("Yes" if flow.get("opening_hook") else "No"))
        print("    Closing Signal:          " + ("Yes" if flow.get("closing_signal") else "No"))
        print()
        si = scan.get("scannability_index", 0)
        print("    Scannability Index:      " + str(si) + "/100"
              + "  " + self._render_gauge(si, 100, 14))
        print("    Headings / 100 words:    " + str(scan.get("headings_per_100_words", 0)))
        print("    Bullets / 100 words:     " + str(scan.get("bullets_per_100_words", 0)))
        print("    Short Paragraphs:        " + str(scan.get("short_paragraph_pct", 0)) + "%")
        print("    Emphasis / 100 words:    " + str(scan.get("emphasis_per_100_words", 0)))
        print()
        hi = hier.get("hierarchy_index", 0)
        print("    Hierarchy Index:         " + str(hi) + "/100"
              + "  " + self._render_gauge(hi, 100, 14))
        print("    Skipped Levels:          " + str(hier.get("skipped_levels", 0)))
        print("    Orphan Subheadings:      " + str(hier.get("orphan_subheadings", 0)))
        print("    Avg Heading Length:      " + str(hier.get("avg_heading_length", 0)) + " chars")
        print("    Outline Coverage:        " + str(hier.get("outline_coverage_pct", 0)) + "%")
        print("    Breadcrumb:              " + ("Yes" if hier.get("breadcrumb_present") else "No"))
        dist = hier.get("heading_depth_distribution", {})
        if dist:
            parts = ", ".join(k + ":" + str(v) for k, v in dist.items())
            print("    Heading Distribution:    " + c.DIM + parts + c.RESET)
        hier_ref = hier.get("hierarchy_refinement", {}) or {}
        if hier_ref:
            print("    Title Term Coverage:     " + str(hier_ref.get("title_term_coverage_pct", 0)) + "%")
            print("    Unique Headings:         " + str(hier_ref.get("unique_heading_ratio_pct", 0)) + "%")
            print("    Depth Utilization:       " + str(hier_ref.get("depth_utilization_pct", 0)) + "%")
        struct_ref = self.results.get("structure", {}).get("structure_refinement", {}) or {}
        if struct_ref:
            print()
            print("    " + c.DIM + "--- Structure Refinement (v6) ---" + c.RESET)
            print("    Intro Section:           " + ("Yes" if struct_ref.get("intro_section_present") else "No"))
            print("    Conclusion Section:      " + ("Yes" if struct_ref.get("conclusion_section_present") else "No"))
            print("    Sections Detected:       " + str(struct_ref.get("section_count", 0)))
            print("    Section Balance:         " + str(struct_ref.get("section_balance_score", 0)) + "/100")
        scan_ref = self.results.get("scannability", {}).get("scannability_refinement", {}) or {}
        if scan_ref:
            print()
            print("    " + c.DIM + "--- Scannability Refinement (v6) ---" + c.RESET)
            print("    Keyword Emphasis Hits:   " + str(scan_ref.get("keyword_emphasis_hits", 0)))
            print("    Summary Boxes:           " + str(scan_ref.get("summary_boxes", 0)))
            print("    Numbered Step Lists:     " + str(scan_ref.get("numbered_step_lists", 0)))
            print("    Internal Jump Links:     " + str(scan_ref.get("internal_jump_links", 0)))
        flow_ref = flow.get("flow_refinement", {}) or {}
        if flow_ref:
            print()
            print("    " + c.DIM + "--- Flow Refinement (v6) ---" + c.RESET)
            print("    Opening Word Share:      " + str(flow_ref.get("opening_word_share_pct", 0)) + "%")
            print("    Closing Word Share:      " + str(flow_ref.get("closing_word_share_pct", 0)) + "%")
            print("    Narrative Arc:           " + ("OK" if flow_ref.get("narrative_arc_ok") else "Needs work"))
            print("    Start Diversity:         " + str(flow_ref.get("paragraph_start_diversity_pct", 0)) + "%")
            print("    Topic Drift:             " + str(flow_ref.get("topic_drift_pct", 0)) + "%")
        print()

    def _print_engagement_conversion(self):
        c = self.colors
        eng = self.results.get("engagement", {})
        conv = self.results.get("conversion", {})
        if not eng and not conv:
            return
        print(c.colorize("  ENGAGEMENT & CONVERSION", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        ei = eng.get("engagement_index", 0)
        ei_color = c.BRIGHT_GREEN if ei >= 70 else c.BRIGHT_YELLOW if ei >= 45 else c.BRIGHT_RED
        print("    Engagement Index:        " + ei_color + str(ei) + "/100" + c.RESET
              + "  " + self._render_gauge(ei, 100, 14))
        print("    Prediction:              " + c.BRIGHT_CYAN + str(eng.get("engagement_prediction", "N/A")) + c.RESET)
        print("    Opening Hook:            " + ("Yes" if eng.get("opening_hook") else "No"))
        print("    Second-Person Usage:     " + str(eng.get("second_person_pct", 0)) + "%")
        print("    Curiosity Markers:       " + str(len(eng.get("curiosity_markers", []))))
        print("    Emotional Markers:       " + str(len(eng.get("emotional_markers", []))))
        print("    Interactive Elements:    " + str(eng.get("interactive_elements", 0)))
        print("    Est. Reading Time:       " + str(eng.get("estimated_reading_minutes", 0)) + " min")
        print()
        ci = conv.get("conversion_index", 0)
        ci_color = c.BRIGHT_GREEN if ci >= 70 else c.BRIGHT_YELLOW if ci >= 45 else c.BRIGHT_RED
        print("    Conversion Index:        " + ci_color + str(ci) + "/100" + c.RESET
              + "  " + self._render_gauge(ci, 100, 14))
        print("    Band:                    " + c.BRIGHT_CYAN + str(conv.get("conversion_band", "N/A")) + c.RESET)
        print("    CTA Count:               " + str(conv.get("cta_count", 0)))
        print("    Benefit Markers:         " + str(len(conv.get("benefit_markers", []))))
        print("    Social Proof Markers:    " + str(len(conv.get("social_proof_markers", []))))
        print("    Urgency Markers:         " + str(len(conv.get("urgency_markers", []))))
        print("    Friction Reducers:       " + str(len(conv.get("friction_reducers", []))))
        print("    Value Proposition:       " + ("Clear" if conv.get("value_proposition_clear") else "Unclear"))
        print("    Form Fields:             " + str(conv.get("form_fields", 0)))
        cta_phrase_preview = conv.get("cta_phrases", [])[:4]
        if cta_phrase_preview:
            print("    CTA Phrases:             " + c.DIM + ", ".join(cta_phrase_preview) + c.RESET)
        eng_ref = eng.get("engagement_refinement", {}) or {}
        if eng_ref:
            print()
            print("    " + c.DIM + "--- Engagement Refinement (v6) ---" + c.RESET)
            print("    Hook Depth:              " + str(eng_ref.get("hook_depth", 0)) + "/3 zones")
            print("    Hook Headings:           " + str(eng_ref.get("hook_headings", 0)))
            print("    Shareability Score:      " + str(eng_ref.get("shareability_score", 0)) + "/100")
            print("    Refined Engagement:      " + str(eng_ref.get("refined_engagement_index", 0)) + "/100")
        conv_ref = conv.get("conversion_refinement", {}) or {}
        if conv_ref:
            print()
            print("    " + c.DIM + "--- Conversion Refinement (v6) ---" + c.RESET)
            print("    Micro-commitment:        " + ("Yes" if conv_ref.get("micro_commitment_present") else "No"))
            print("    Objection Handling:      " + ("Yes" if conv_ref.get("objection_handling") else "No"))
            print("    Risk Reversal Count:     " + str(conv_ref.get("risk_reversal_count", 0)))
            print("    CTA Specificity:         " + str(conv_ref.get("cta_specificity_pct", 0)) + "%")
            print("    Refined Conversion:      " + str(conv_ref.get("refined_conversion_index", 0)) + "/100")
        print()

    def _print_strategy_recommendations(self):
        c = self.colors
        indices = self.results.get("indices", {})
        strategy = self.results.get("content_strategy", {})
        engagement = self.results.get("engagement", {})
        conversion = self.results.get("conversion", {})
        originality = self.results.get("originality", {})
        gaps = strategy.get("gap_analysis", {})
        print(c.colorize("  CONTENT STRATEGY RECOMMENDATIONS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        directives = []
        cqi = indices.get("content_quality_index", 0)
        if cqi < 70:
            directives.append(("Raise content quality index",
                               "Close the lowest-scoring categories first; target a quality index above 70.",
                               "Content Quality Index"))
        else:
            directives.append(("Protect quality standards",
                               "Quality index is healthy; keep the current editorial checklist in the publishing flow.",
                               "Content Quality Index"))
        seo = indices.get("seo_content_score", 0)
        if seo < 70:
            directives.append(("Tighten SEO fundamentals",
                               "Fix title/meta/canonical/heading alignment and internal linking gaps.",
                               "SEO Content Score"))
        if conversion.get("conversion_index", 0) < 60:
            directives.append(("Strengthen conversion path",
                               "Add a primary CTA above and below the fold, plus one proof element (testimonial or stat).",
                               "Conversion Index"))
        if engagement.get("engagement_index", 0) < 60:
            directives.append(("Lift engagement signals",
                               "Open with a hook, address the reader as 'you', and break content with lists and media.",
                               "Engagement Index"))
        if originality.get("originality_index", 0) < 70:
            directives.append(("Differentiate the content",
                               "Add first-hand examples, data, and citations so the piece could not be swapped for a competitor's.",
                               "Originality Index"))
        if gaps.get("gaps"):
            directives.append(("Close content gaps",
                               "Missing pieces: " + "; ".join(gaps.get("gaps", [])[:3]) + ".",
                               "Gap Analysis"))
        freshness = strategy.get("freshness_signals", {})
        if not freshness.get("has_recent_dates"):
            directives.append(("Signal freshness",
                               "Publish or display visible dates and update older pages on a schedule.",
                               "Freshness"))
        if self.results.get("multilingual", {}).get("is_multilingual"):
            directives.append(("Consolidate language targeting",
                               "Split or tag content per language (hreflang) so each language ranks on its own.",
                               "Multilingual SEO"))
        strategy_idx = indices.get("content_strategy_index", 0)
        if strategy_idx and strategy_idx < 60:
            directives.append(("Sharpen strategy pillars",
                               "Weakest pillars decide the fix: clarity (reader language), funnel fit (CTA path), authority (evidence), or differentiation (first-hand insight).",
                               "Content Strategy Index"))
        deep_orig = indices.get("deep_originality_index", 0)
        if deep_orig and deep_orig < 60:
            directives.append(("Deepen originality",
                               "Reduce boilerplate, add first-hand insight, and support superlative claims with data.",
                               "Deep Originality Index"))
        if len(directives) > 8:
            directives = directives[:8]
        for i, (title, body, metric) in enumerate(directives, 1):
            print("    " + c.BRIGHT_YELLOW + str(i) + "." + c.RESET + " " + c.BOLD + title + c.RESET)
            print("       " + body)
            print("       " + c.DIM + "Metric: " + metric + c.RESET)
        print()

    def _print_improvement_roadmap(self):
        c = self.colors
        total = self.get_total_score()
        max_score = self.get_max_score()
        grade, grade_color = grade_from_score(total, max_score)
        indices = self.results.get("indices", {})

        deficits = []
        for key, mx in CATEGORY_MAX.items():
            sc = self.scores.get(key, 0)
            deficit = mx - sc
            if deficit > 0.05:
                weight = QUALITY_INDEX_WEIGHTS.get(key, 1)
                impact = round(deficit / mx * weight * 1.5, 2) if mx else 0.0
                ratio = deficit / mx if mx else 0.0
                if ratio >= 0.5 and weight >= 6:
                    priority = "High"
                elif ratio >= 0.3:
                    priority = "Medium"
                else:
                    priority = "Low"
                deficits.append((impact, deficit, key, sc, mx, priority))
        deficits.sort(reverse=True)
        deficits = deficits[:9]

        phase1_keywords = ("h1", "meta description", "alt text", "lang attribute", "title tag",
                           "canonical", "add exactly one", "add a meta", "add dates",
                           "placeholder", "template", "empty link", "th>", "figcaption",
                           "heading hierarchy", "empty heading")
        phase3_keywords = ("faq", "multilingual", "hreflang", "schema", "structured data",
                           "case stud", "first-hand", "original research", "video",
                           "comment", "split pages")

        entries = []
        for impact, deficit, key, sc, mx, priority in deficits:
            label_lower = CATEGORY_LABELS[key].lower()
            related = []
            for rec in self.recommendations:
                rec_lower = rec.lower()
                if key.split("_")[0] in rec_lower or label_lower.split()[0] in rec_lower:
                    related.append(rec)
            joined = (" ".join(related) + " " + label_lower).lower()
            if any(k in joined for k in phase1_keywords):
                phase = 1
            elif any(k in joined for k in phase3_keywords):
                phase = 3
            else:
                phase = 2
            entries.append({
                "phase": phase,
                "category": CATEGORY_LABELS[key],
                "deficit": round(deficit, 1),
                "score": sc,
                "max": mx,
                "recs": related[:2],
                "impact": impact,
                "priority": priority,
            })
        if entries and not any(e["phase"] == 1 for e in entries):
            entries[0]["phase"] = 1
        if len(entries) >= 4 and not any(e["phase"] == 3 for e in entries):
            entries[-1]["phase"] = 3
        phase1 = [e for e in entries if e["phase"] == 1]
        phase2 = [e for e in entries if e["phase"] == 2]
        phase3 = [e for e in entries if e["phase"] == 3]

        print(c.colorize("  CONTENT IMPROVEMENT ROADMAP", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))
        print("    Current: " + str(round(total, 1)) + "/" + str(max_score)
              + "  Grade " + grade_color + grade + c.RESET
              + "  Quality Index " + str(indices.get("content_quality_index", 0)) + "/100")
        print()

        phase_defs = [
            ("Phase 1 - Quick Wins (hours)", phase1, c.BRIGHT_GREEN),
            ("Phase 2 - Structural Fixes (days)", phase2, c.BRIGHT_YELLOW),
            ("Phase 3 - Strategic Upgrades (weeks)", phase3, c.BRIGHT_CYAN),
        ]
        step = 1
        for title, phase_entries, color in phase_defs:
            if not phase_entries:
                continue
            print("    " + color + c.BOLD + title + c.RESET)
            for entry in phase_entries:
                priority_color = c.BRIGHT_RED if entry.get("priority") == "High" else c.BRIGHT_YELLOW if entry.get("priority") == "Medium" else c.DIM
                print("      " + c.BOLD + str(step) + "." + c.RESET + " "
                      + entry["category"] + "  (-" + str(entry["deficit"]) + " pts, currently "
                      + str(entry["score"]) + "/" + str(entry["max"]) + ")"
                      + "  " + priority_color + "[" + str(entry.get("priority", "Medium")) + "]" + c.RESET
                      + c.DIM + " impact~" + str(entry.get("impact", 0)) + c.RESET)
                for rec in entry["recs"]:
                    print("         " + c.DIM + "- " + rec + c.RESET)
                step += 1
            print()
        if step == 1:
            print("    " + c.BRIGHT_GREEN + "No outstanding items; content is in strong shape." + c.RESET)
            print()

    def _print_recommendations_with_examples(self):
        c = self.colors
        if not self.recommendations:
            return
        print(c.colorize("  RECOMMENDATIONS", c.BOLD))
        print(c.colorize("  " + "-" * 60, c.DIM))

        example_map = {
            "Add exactly one H1 tag": "  <h1>Page Title</h1>",
            "heading tags (H2-H6)": "  <h2>Section</h2> ... <h3>Subsection</h3>",
            "semantic HTML5 elements": "  Use <article>, <section>, <nav>, <main> instead of <div>",
            "alt text to all images": '  <img src="photo.jpg" alt="A red bicycle on a trail">',
            "Add a meta description": '  <meta name="description" content="120-160 char summary">',
            "Add lang attribute": '  <html lang="en">',
            "paragraphs are very long": "  Break paragraphs at 3-4 sentences (30-150 words each)",
            "Reduce passive voice": "  Change 'The ball was thrown by John' to 'John threw the ball'",
            "Reduce adverb usage": "  Change 'ran quickly' to 'sprinted' or 'dashed'",
            "complex words": "  Replace jargon: 'utilize' -> 'use', 'facilitate' -> 'help'",
            "Anchor text": "  Instead of 'click here', use 'Read our pricing guide'",
            "Add dates to content": '  <time datetime="2026-01-15">January 15, 2026</time>',
            "Open Graph tags": '  <meta property="og:title" content="Page Title">',
            "title attributes to iframes": '  <iframe title="Google Maps location" ...>',
            "Add heading tags": "  Structure content: <h2>Topic</h2> ... <h3>Subtopic</h3>",
            "Link density": "  Reduce links per paragraph; aim for 2-5 links per 100 words",
            "content-to-code ratio": "  Move scripts to external files; inline CSS sparingly",
            "very thin": "  Aim for 300+ words of substantive content per page",
            "multilingual": "  Use hreflang tags: <link rel='alternate' hreflang='es' href='...'>",
            "machine translation": "  Review translated content for natural phrasing and accuracy",
            "FAQ section": "  Add structured FAQ: <section itemscope itemtype='https://schema.org/FAQPage'>",
            "call-to-action": "  Add clear CTA buttons with action-oriented text",
            "call-to-action found": "  <a class=\"btn\" href=\"/signup\">Start your free trial</a>",
            "content gaps": "  Consider adding examples, case studies, or an FAQ section",
            "transition words": "  Join ideas: 'However, ...' / 'For example, ...' / 'Therefore, ...'",
            "paragraph-to-paragraph continuity": "  Echo the key term from paragraph N at the start of paragraph N+1",
            "bulleted lists": "  Convert dense prose blocks into <ul><li> lists of 3-7 items",
            "Shorten paragraphs": "  Split any paragraph longer than 80 words into two",
            "formulaic openers": "  Replace 'In today's world...' with a concrete statistic or anecdote",
            "citations and source links": "  Support claims: <a href='https://source.example'>Study (2025)</a>",
            "first-hand perspective": "  Add 'In our tests...' / 'When we shipped...' sections with real data",
            "Sentence lengths": "  Alternate short punchy sentences with longer explanatory ones",
            "Vocabulary is repetitive": "  Swap repeated terms for precise synonyms or domain vocabulary",
            "statistics or data points": "  Include numbers: 'Teams cut onboarding time by 34% in 6 weeks'",
            "Add examples or use cases": "  Show a worked example or mini case study per major point",
            "social proof": "  Add a testimonial block or customer logos near the CTA",
            "benefit-driven language": "  Lead with outcomes: 'Save 5 hours a week', not feature lists",
            "value proposition": "  H1 pattern: 'Get [outcome] without [pain] in [timeframe]'",
            "opening with a hook": "  Start with: 'What if you could [outcome] by [time]?'",
            "Address the reader": "  Rewrite 'Users can' as 'You can' throughout",
            "open with a hook": "  Start with a question, surprising stat, or bold claim",
            "reduce conversion friction": "  Trim form fields; show 'No credit card required' near the button",
            "Add more calls-to-action": "  Place CTAs after the intro, mid-article, and at the close",
            "No call-to-action": "  Add a primary CTA button with a specific verb: 'Start free trial'",
            "<th> headers": "  <table><tr><th scope=\"col\">Metric</th>...</tr></table>",
            "figcaption": "  <figure><img src=\"...\" alt=\"...\"><figcaption>What it shows</figcaption></figure>",
            "subtitle tracks": "  <video><track kind=\"captions\" src=\"captions.vtt\" srclang=\"en\"></video>",
            "empty links": "  Wrap descriptive text or aria-label around every anchor",
            "heading hierarchy": "  Keep the sequence H1 -> H2 -> H3; never skip levels",
            "Shorten headings": "  Use 3-7 word headings that state the section's takeaway",
            "more H2 sections": "  One H2 every 100-500 words keeps the outline navigable",
            "JSON-LD": "  <script type=\"application/ld+json\">{ \"@type\": \"Article\", ... }</script>",
            "align the H1": "  Make the H1 reuse the page title's core keywords",
            "split pages": "  Break the piece into a series with intro/summary linking",
            "form fields": "  Keep lead forms to <= 6 visible fields; progressive-profile the rest",
        }
        for i, rec in enumerate(self.recommendations, 1):
            print("    " + c.BRIGHT_YELLOW + str(i) + "." + c.RESET + " " + rec)
            for key, example in example_map.items():
                if key.lower() in rec.lower():
                    print("       " + c.DIM + "Example: " + example + c.RESET)
                    break
        print()

    def print_results(self):
        c = self.colors
        total = self.get_total_score()
        max_score = self.get_max_score()
        grade, grade_color = grade_from_score(total, max_score)

        print()
        print(c.colorize("=" * 78, c.BRIGHT_CYAN))
        print(c.colorize("                         ANALYSIS RESULTS", c.BOLD))
        print(c.colorize("=" * 78, c.BRIGHT_CYAN))
        print()

        self._print_quality_dashboard()
        self._print_readability_details()
        self._print_audience_grades()
        self._print_accessibility_details()
        self._print_language_info()
        self._print_multilingual_info()
        self._print_structure_details()
        self._print_content_outline()
        self._print_unicode_info()
        self._print_originality_uniqueness()
        self._print_flow_scannability_hierarchy()
        self._print_engagement_conversion()
        self._print_content_strategy()
        self._print_strategy_recommendations()
        self._print_code_block_analysis()
        self._print_blockquote_analysis()
        self._print_improvement_roadmap()
        self._print_recommendations_with_examples()

        print(c.colorize("=" * 78, c.BRIGHT_CYAN))

    def export_json(self, filepath):
        data = {
            "url": self.url,
            "timestamp": datetime.now().isoformat(),
            "version": "6.0",
            "total_score": round(self.get_total_score(), 1),
            "max_score": self.get_max_score(),
            "grade": grade_from_score(self.get_total_score(), self.get_max_score())[0],
            "scores": self.scores,
            "results": self.results,
            "content_outline": self.generate_content_outline(),
            "recommendations": self.recommendations,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        print(self.colors.colorize("  [+] JSON exported to: " + filepath, self.colors.GREEN))

    def export_csv(self, filepath):
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Score", "Max Score", "Percentage"])
            for key, max_val in CATEGORY_MAX.items():
                sc = self.scores.get(key, 0)
                pct_str = "{:.1f}%".format(sc / max_val * 100) if max_val else "0%"
                writer.writerow([key, sc, max_val, pct_str])
            writer.writerow([])
            total = round(self.get_total_score(), 1)
            max_sc = self.get_max_score()
            total_pct = "{:.1f}%".format(total / max_sc * 100) if max_sc else "0%"
            writer.writerow(["Total", total, max_sc, total_pct])
            writer.writerow(["Grade", grade_from_score(total, max_sc)[0]])
            writer.writerow([])
            writer.writerow(["Key", "Value"])
            r = self.results.get("readability", {})
            writer.writerow(["Flesch Reading Ease", r.get("flesch_reading_ease", "")])
            writer.writerow(["Flesch-Kincaid Grade", r.get("flesch_kincaid_grade", "")])
            writer.writerow(["Gunning Fog Index", r.get("gunning_fog_index", "")])
            writer.writerow(["Coleman-Liau Index", r.get("coleman_liau_index", "")])
            writer.writerow(["Automated Readability Index", r.get("automated_readability_index", "")])
            writer.writerow(["Linsear Write Formula", r.get("linsear_write_formula", "")])
            writer.writerow(["SMOG Index", r.get("smog_index", "")])
            writer.writerow(["Text Standard", r.get("text_standard", "")])
            writer.writerow(["Adjusted FRE", r.get("language_adjusted_fre", "")])
            writer.writerow(["Adjusted Text Standard", r.get("language_adjusted_ts", "")])
            lang = self.results.get("language", {})
            writer.writerow(["Language", lang.get("language", "")])
            writer.writerow(["RTL", lang.get("is_rtl", "")])
            writer.writerow(["Encoding", lang.get("encoding", "")])
            writer.writerow(["WCAG Level", wcag_level(self.scores.get("accessibility", 0), 15)])
            ml = self.results.get("multilingual", {})
            writer.writerow(["Languages Detected", ml.get("language_count", 1)])
            writer.writerow(["Is Multilingual", ml.get("is_multilingual", False)])
            cs = self.results.get("content_strategy", {})
            writer.writerow(["Uniqueness Score (strategy)", cs.get("uniqueness", {}).get("uniqueness_score", "")])
            indices = self.results.get("indices", {})
            writer.writerow(["Content Quality Index", indices.get("content_quality_index", "")])
            writer.writerow(["Readability Index", indices.get("readability_index", "")])
            writer.writerow(["Accessibility Score", indices.get("accessibility_score", "")])
            writer.writerow(["SEO Content Score", indices.get("seo_content_score", "")])
            writer.writerow(["Originality Index", self.results.get("originality", {}).get("originality_index", "")])
            writer.writerow(["Uniqueness Score", self.results.get("uniqueness", {}).get("uniqueness_score", "")])
            writer.writerow(["Quality Signal Index", self.results.get("quality_signals", {}).get("quality_signal_index", "")])
            writer.writerow(["Engagement Prediction", self.results.get("engagement", {}).get("engagement_prediction", "")])
            writer.writerow(["Engagement Index", self.results.get("engagement", {}).get("engagement_index", "")])
            writer.writerow(["Conversion Index", self.results.get("conversion", {}).get("conversion_index", "")])
            writer.writerow(["Conversion Band", self.results.get("conversion", {}).get("conversion_band", "")])
            writer.writerow(["Flow Index", self.results.get("flow", {}).get("flow_index", "")])
            writer.writerow(["Scannability Index", self.results.get("scannability", {}).get("scannability_index", "")])
            writer.writerow(["Hierarchy Index", self.results.get("hierarchy", {}).get("hierarchy_index", "")])
            writer.writerow(["Deep Originality Index", indices.get("deep_originality_index", "")])
            writer.writerow(["Quality Refinement Index", indices.get("quality_refinement_index", "")])
            writer.writerow(["Engagement Refinement Index", indices.get("engagement_refinement_index", "")])
            writer.writerow(["Conversion Refinement Index", indices.get("conversion_refinement_index", "")])
            writer.writerow(["Content Strategy Index", indices.get("content_strategy_index", "")])
            writer.writerow([])
            writer.writerow(["Recommendation #", "Message"])
            for i, rec in enumerate(self.recommendations, 1):
                writer.writerow([i, rec])
        print(self.colors.colorize("  [+] CSV exported to: " + filepath, self.colors.GREEN))
    def export_html(self, filepath):
        c = self.colors
        total = self.get_total_score()
        max_sc = self.get_max_score()
        grade, _ = grade_from_score(total, max_sc)
        cat_labels = CATEGORY_LABELS
        cat_max = CATEGORY_MAX
        rows = ""
        for key in cat_labels:
            sc = self.scores.get(key, 0)
            mx = cat_max[key]
            pct = sc / mx * 100 if mx else 0
            color = "#4caf50" if pct >= 70 else "#ff9800" if pct >= 50 else "#f44336"
            rows += "<tr><td>" + cat_labels[key] + "</td>"
            rows += '<td><div class="bar-bg"><div class="bar-fill" style="width:' + str(pct) + '%;background:' + color + '"></div></div></td>'
            rows += "<td>{:.1f} / ".format(sc) + str(mx) + "</td>"
            rows += "<td>{:.1f}%</td></tr>".format(pct)
        recs = ""
        for i, rec in enumerate(self.recommendations, 1):
            recs += "<li>" + rec + "</li>\n"
        r = self.results.get("readability", {})
        lang = self.results.get("language", {})
        ml = self.results.get("multilingual", {})
        a = self.results.get("accessibility", {})
        cs = self.results.get("content_strategy", {})
        indices = self.results.get("indices", {})
        orig = self.results.get("originality", {})
        uniq = self.results.get("uniqueness", {})
        eng = self.results.get("engagement", {})
        conv = self.results.get("conversion", {})
        flow = self.results.get("flow", {})
        scan = self.results.get("scannability", {})
        hier = self.results.get("hierarchy", {})
        wcag = wcag_level(self.scores.get("accessibility", 0), 15)
        grade_color = "#4caf50" if total >= max_sc * 0.7 else "#ff9800" if total >= max_sc * 0.5 else "#f44336"
        wcag_bg = "#4caf50" if wcag == "AAA" else "#ff9800" if wcag in ("AA", "A") else "#f44336"
        outline = self.generate_content_outline()
        outline_html = ""
        for item in outline:
            indent = "&nbsp;" * (item["level"] * 4)
            outline_html += '<div>' + indent + '<strong>H' + str(item["level"]) + ':</strong> ' + item["text"][:60] + '</div>\n'
        us = cs.get("uniqueness", {}).get("uniqueness_score", 0)
        us_color = "#4caf50" if us >= 70 else "#ff9800" if us >= 50 else "#f44336"
        p = []
        p.append("<!DOCTYPE html>")
        p.append('<html lang="en">')
        p.append("<head>")
        p.append('<meta charset="UTF-8">')
        p.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        p.append("<title>ContentAnalyzer v6.0 Report - " + self.url + "</title>")
        p.append("<style>")
        p.append("* { margin: 0; padding: 0; box-sizing: border-box; }")
        p.append("body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }")
        p.append(".container { max-width: 900px; margin: 0 auto; }")
        p.append("h1 { color: #58a6ff; margin-bottom: 0.5rem; font-size: 1.8rem; }")
        p.append("h2 { color: #58a6ff; margin: 1.5rem 0 0.75rem 0; font-size: 1.2rem; }")
        p.append("h3 { color: #8b949e; margin: 1rem 0 0.5rem 0; font-size: 1rem; }")
        p.append(".subtitle { color: #8b949e; margin-bottom: 2rem; }")
        p.append(".score-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; text-align: center; }")
        p.append(".score-big { font-size: 3rem; font-weight: bold; color: #58a6ff; }")
        p.append(".grade { font-size: 2rem; margin-left: 1rem; }")
        p.append("table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; margin-bottom: 2rem; }")
        p.append("th { background: #1f2937; color: #58a6ff; padding: 0.75rem 1rem; text-align: left; }")
        p.append("td { padding: 0.75rem 1rem; border-bottom: 1px solid #21262d; }")
        p.append(".bar-bg { background: #21262d; border-radius: 4px; height: 12px; width: 200px; }")
        p.append(".bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }")
        p.append(".recs { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }")
        p.append(".recs h2 { color: #f0883e; margin-bottom: 1rem; }")
        p.append(".recs li { margin-bottom: 0.5rem; color: #c9d1d9; }")
        p.append(".a11y { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }")
        p.append(".a11y h2 { color: #3fb950; margin-bottom: 1rem; }")
        p.append(".wcag-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: bold; color: #fff; margin-left: 0.5rem; }")
        p.append("a { color: #58a6ff; }")
        p.append("</style>")
        p.append("</head>")
        p.append("<body>")
        p.append('<div class="container">')
        p.append("<h1>ContentAnalyzer v6.0 Report</h1>")
        p.append('<p class="subtitle">URL: <a href="' + self.url + '">' + self.url + '</a><br>Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '</p>')
        p.append('<div class="score-box">')
        p.append('    <span class="score-big">' + "{:.1f}".format(total) + '</span><span class="grade" style="color:' + grade_color + '">Grade: ' + grade + '</span>')
        p.append('    <br><small style="color:#8b949e">WCAG 2.1 Level: <span class="wcag-badge" style="background:' + wcag_bg + '">' + wcag + '</span></small>')
        p.append("</div>")
        p.append('<table><thead><tr><th>Category</th><th>Score Bar</th><th>Score</th><th>Percentage</th></tr></thead><tbody>' + rows + "</tbody></table>")
        p.append('<div class="a11y"><h2>Readability Indices</h2>')
        p.append('<table><thead><tr><th>Index</th><th>Score</th><th>Grade Level</th></tr></thead><tbody>')
        p.append("<tr><td>Flesch Reading Ease</td><td>" + str(r.get('flesch_reading_ease', 0)) + "</td><td>" + str(r.get('readability_level', 'N/A')) + "</td></tr>")
        p.append("<tr><td>Flesch-Kincaid Grade</td><td>" + str(r.get('flesch_kincaid_grade', 0)) + "</td><td>" + grade_level_label(r.get('flesch_kincaid_grade', 0)) + "</td></tr>")
        p.append("<tr><td>Gunning Fog Index</td><td>" + str(r.get('gunning_fog_index', 0)) + "</td><td>" + grade_level_label(r.get('gunning_fog_index', 0)) + "</td></tr>")
        p.append("<tr><td>Coleman-Liau Index</td><td>" + str(r.get('coleman_liau_index', 0)) + "</td><td>" + grade_level_label(r.get('coleman_liau_index', 0)) + "</td></tr>")
        p.append("<tr><td>Automated Readability</td><td>" + str(r.get('automated_readability_index', 0)) + "</td><td>" + grade_level_label(r.get('automated_readability_index', 0)) + "</td></tr>")
        p.append("<tr><td>Linsear Write Formula</td><td>" + str(r.get('linsear_write_formula', 0)) + "</td><td>" + grade_level_label(r.get('linsear_write_formula', 0)) + "</td></tr>")
        p.append("<tr><td>SMOG Index</td><td>" + str(r.get('smog_index', 0)) + "</td><td>" + grade_level_label(r.get('smog_index', 0)) + "</td></tr>")
        p.append("<tr><td><strong>Text Standard (avg)</strong></td><td><strong>" + str(r.get('text_standard', 0)) + "</strong></td><td><strong>" + str(r.get('text_standard_level', 'N/A')) + "</strong></td></tr>")
        p.append("<tr><td><strong>Readability Index (v6)</strong></td><td><strong>" + str(r.get('readability_index', 0)) + "/100</strong></td><td><strong>" + str(indices.get('readability_index', 0)) + "/100</strong></td></tr>")
        p.append("</tbody></table></div>")
        p.append('<div class="a11y"><h2>Accessibility Summary</h2><table><tbody>')
        p.append('<tr><td>WCAG 2.1 Level</td><td><span class="wcag-badge" style="background:' + wcag_bg + '">' + wcag + '</span></td></tr>')
        p.append("<tr><td>Images with alt text</td><td>" + str(a.get('alt_text_ratio', 0)) + "%</td></tr>")
        p.append("<tr><td>Lang attribute</td><td>" + ("Yes" if a.get('lang_attribute') else "No") + "</td></tr>")
        p.append("<tr><td>ARIA labels</td><td>" + str(a.get('aria_labels', 0)) + "</td></tr>")
        p.append("<tr><td>ARIA roles</td><td>" + str(a.get('aria_roles', 0)) + "</td></tr>")
        p.append("<tr><td>Semantic landmarks</td><td>" + str(a.get('semantic_landmarks', 0)) + "</td></tr>")
        p.append("<tr><td>Skip navigation</td><td>" + ("Yes" if a.get('skip_navigation') else "No") + "</td></tr>")
        p.append("<tr><td>Focus indicators</td><td>" + ("Yes" if a.get('focus_indicators_detected') else "No") + "</td></tr>")
        p.append("</tbody></table></div>")
        p.append('<div class="a11y"><h2>Language &amp; Encoding</h2><table><tbody>')
        p.append("<tr><td>Language</td><td>" + str(lang.get('language', 'N/A')).upper() + " (source: " + str(lang.get('source', 'N/A')) + ")</td></tr>")
        p.append("<tr><td>RTL Language</td><td>" + ("Yes" if lang.get('is_rtl') else "No") + "</td></tr>")
        p.append("<tr><td>Encoding</td><td>" + str(lang.get('encoding', 'N/A')) + "</td></tr>")
        p.append("<tr><td>Languages Detected</td><td>" + str(ml.get('language_count', 1)) + "</td></tr>")
        p.append("</tbody></table></div>")
        p.append('<div class="a11y"><h2>Content Strategy</h2><table><tbody>')
        p.append('<tr><td>Uniqueness Score</td><td><span style="color:' + us_color + '">' + str(us) + '%</span></td></tr>')
        p.append("<tr><td>Has FAQ</td><td>" + ("Yes" if cs.get('gap_analysis', {}).get('has_faq') else "No") + "</td></tr>")
        p.append("<tr><td>Has Examples</td><td>" + ("Yes" if cs.get('gap_analysis', {}).get('has_examples') else "No") + "</td></tr>")
        p.append("<tr><td>Has CTA</td><td>" + ("Yes" if cs.get('engagement_potential', {}).get('has_cta') else "No") + "</td></tr>")
        p.append("</tbody></table></div>")
        p.append('<div class="a11y"><h2>Key Indices (v6.0)</h2><table><tbody>')
        p.append("<tr><td>Content Quality Index</td><td>" + str(indices.get('content_quality_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Readability Index</td><td>" + str(indices.get('readability_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Accessibility Score</td><td>" + str(indices.get('accessibility_score', 0)) + "/100</td></tr>")
        p.append("<tr><td>Accessibility Quality Score</td><td>" + str(indices.get('accessibility_quality_score', 0)) + "/100</td></tr>")
        p.append("<tr><td>SEO Content Score</td><td>" + str(indices.get('seo_content_score', 0)) + "/100</td></tr>")
        p.append("<tr><td>Deep Originality Index</td><td>" + str(indices.get('deep_originality_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Quality Refinement Index</td><td>" + str(indices.get('quality_refinement_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Engagement Refinement Index</td><td>" + str(indices.get('engagement_refinement_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Conversion Refinement Index</td><td>" + str(indices.get('conversion_refinement_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Content Strategy Index</td><td>" + str(indices.get('content_strategy_index', 0)) + "/100</td></tr>")
        p.append("</tbody></table></div>")
        p.append('<div class="a11y"><h2>Originality &amp; Uniqueness</h2><table><tbody>')
        p.append("<tr><td>Originality Index</td><td>" + str(orig.get('originality_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Duplicate Sentences</td><td>" + str(orig.get('duplicate_sentence_pct', 0)) + "%</td></tr>")
        p.append("<tr><td>Repeated 5-grams</td><td>" + str(orig.get('repeated_5gram_pct', 0)) + "%</td></tr>")
        p.append("<tr><td>Uniqueness Score</td><td>" + str(uniq.get('uniqueness_score', 0)) + "/100</td></tr>")
        p.append("<tr><td>Type-Token Ratio</td><td>" + str(uniq.get('type_token_ratio', 0)) + "%</td></tr>")
        p.append("<tr><td>Lexical Entropy</td><td>" + str(uniq.get('lexical_entropy', 0)) + "</td></tr>")
        p.append("</tbody></table></div>")
        p.append('<div class="a11y"><h2>Engagement &amp; Conversion</h2><table><tbody>')
        p.append("<tr><td>Engagement Prediction</td><td>" + str(eng.get('engagement_prediction', 'N/A')) + " (" + str(eng.get('engagement_index', 0)) + "/100)</td></tr>")
        p.append("<tr><td>Conversion Band</td><td>" + str(conv.get('conversion_band', 'N/A')) + " (" + str(conv.get('conversion_index', 0)) + "/100)</td></tr>")
        p.append("<tr><td>CTA Count</td><td>" + str(conv.get('cta_count', 0)) + "</td></tr>")
        p.append("<tr><td>Second-Person Usage</td><td>" + str(eng.get('second_person_pct', 0)) + "%</td></tr>")
        p.append("<tr><td>Est. Reading Time</td><td>" + str(eng.get('estimated_reading_minutes', 0)) + " min</td></tr>")
        p.append("</tbody></table></div>")
        p.append('<div class="a11y"><h2>Flow, Scannability &amp; Hierarchy</h2><table><tbody>')
        p.append("<tr><td>Flow Index</td><td>" + str(flow.get('flow_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Transition Coverage</td><td>" + str(flow.get('transition_sentence_pct', 0)) + "%</td></tr>")
        p.append("<tr><td>Paragraph Continuity</td><td>" + str(flow.get('paragraph_continuity_pct', 0)) + "%</td></tr>")
        p.append("<tr><td>Scannability Index</td><td>" + str(scan.get('scannability_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Hierarchy Index</td><td>" + str(hier.get('hierarchy_index', 0)) + "/100</td></tr>")
        p.append("<tr><td>Outline Coverage</td><td>" + str(hier.get('outline_coverage_pct', 0)) + "%</td></tr>")
        p.append("</tbody></table></div>")
        p.append('<div class="a11y"><h2>Content Outline</h2>' + outline_html + "</div>")
        p.append('<div class="recs"><h2>Recommendations (' + str(len(self.recommendations)) + ')</h2><ol>' + recs + "</ol></div>")
        p.append("</div></body></html>")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(p))
        print(c.colorize("  [+] HTML exported to: " + filepath, c.GREEN))

    def export(self, fmt):
        if fmt == "none":
            return
        base = "contentanalyzer_" + datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt in ("all", "json"):
            self.export_json(base + ".json")
        if fmt in ("all", "csv"):
            self.export_csv(base + ".csv")
        if fmt in ("all", "html"):
            self.export_html(base + ".html")


def main():
    parser = argparse.ArgumentParser(
        description="ContentAnalyzer v6.0 - Deep content originality, uniqueness, quality, engagement and conversion intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--export", choices=["all", "json", "csv", "html", "none"], default="none", help="Export format (default: none)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    colors = Colors(args.no_color)
    print_banner(colors)

    analyzer = ContentAnalyzer(
        url=args.url,
        timeout=args.timeout,
        verbose=args.verbose,
        no_color=args.no_color,
    )

    if analyzer.run_all_checks():
        analyzer.print_results()
        analyzer.export(args.export)
    else:
        print(colors.colorize("  [!] Analysis failed. Check the URL and try again.", colors.RED))
        sys.exit(1)


if __name__ == "__main__":
    main()
