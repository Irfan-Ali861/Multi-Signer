# conftest.py
import warnings
from urllib3.exceptions import NotOpenSSLWarning

# Silence the macOS LibreSSL warning during test collection & execution
warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
