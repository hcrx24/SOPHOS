"""
sophos_client/main.py
Application entrypoint for the SOPHOS SSE PyQt6 GUI client.
"""
import sys
import os

# Add client root to sys.path so imports like "from core.crypto import ..."
# work regardless of working directory.
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont
from ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SOPHOS SSE")
    app.setOrganizationName("SophosSSE Demo")

    # Prefer Inter font if available, fall back gracefully
    app.setFont(QFont("Inter", 12))

    window = MainWindow()
    window.show()

    # Load existing keys on startup (if already generated)
    window._load_keys()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
