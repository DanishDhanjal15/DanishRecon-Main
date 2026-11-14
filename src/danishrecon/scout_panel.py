#!/usr/bin/env python3
"""
Scout Panel - PyQt5 Widget for Scout AI Integration
Provides a UI panel within DanishRecon for interacting with Scout AI chatbot.
"""

import os
import sys
import json
import atexit
import subprocess
import requests
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
    QLineEdit, QLabel, QScrollArea, QFrame, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl, QTimer
from PyQt5.QtGui import QFont


class ScoutPanel(QWidget):
    """PyQt5 widget for Scout AI chatbot integration within DanishRecon."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = parent
        self.scout_url = "http://localhost:8765"
        self.session_id = "cyberrecon-session"
        self.scout_available = False  # Will be set to True only if backend responds
        self._backend_proc = None     # auto-started backend subprocess (if any)
        self._poll_timer = None
        self._poll_count = 0
        atexit.register(self.stop_backend)  # clean up the backend on app exit
        self._check_scout_availability()  # Non-blocking check
        self.init_ui()

    def _find_scout_backend(self):
        """Locate scout_chatbot/scout.py relative to this file."""
        here = os.path.dirname(os.path.abspath(__file__))
        for c in [
            os.path.join(here, "..", "scout_chatbot", "scout.py"),
            os.path.join(here, "scout_chatbot", "scout.py"),
        ]:
            if os.path.exists(c):
                return os.path.abspath(c)
        return None

    def ensure_backend(self):
        """If the Scout backend isn't running, launch it automatically (non-blocking)."""
        self._check_scout_availability()
        if self.scout_available:
            self.status_label.setText("Scout AI ready")
            return
        if self._backend_proc is not None and self._backend_proc.poll() is None:
            return  # a launch is already in progress
        script = self._find_scout_backend()
        if not script:
            self.status_label.setText("Scout backend not found (scout_chatbot/scout.py missing)")
            return
        try:
            self._backend_proc = subprocess.Popen(
                [sys.executable, script],
                cwd=os.path.dirname(script),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self.status_label.setText("Starting Scout AI backend... (a few seconds)")
            self.chat_display.append("\n⏳ <b>Starting Scout AI backend...</b> please wait a few seconds.")
            self._poll_count = 0
            if self._poll_timer is None:
                self._poll_timer = QTimer(self)
                self._poll_timer.timeout.connect(self._poll_backend_ready)
            self._poll_timer.start(1500)
        except Exception as e:
            self.status_label.setText(f"Could not start Scout backend: {str(e)[:60]}")

    def _poll_backend_ready(self):
        """Poll backend health after auto-start (driven by a QTimer, non-blocking)."""
        self._poll_count += 1
        self._check_scout_availability()
        if self.scout_available:
            self._poll_timer.stop()
            self.status_label.setText("Scout AI ready")
            self.chat_display.append("\n✅ <b>Scout AI is ready!</b> Ask a question below.")
        elif self._poll_count >= 20:  # ~30s of polling
            self._poll_timer.stop()
            self.status_label.setText("Scout backend did not start in time — try scout_chatbot/START_Scout.bat")

    def stop_backend(self):
        """Terminate the auto-started backend when the app exits."""
        try:
            if self._backend_proc is not None and self._backend_proc.poll() is None:
                self._backend_proc.terminate()
        except Exception:
            pass
        
    def init_ui(self):
        """Initialize the Scout Panel UI."""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🤖 Scout AI Security Assistant")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Chat display area
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setPlaceholderText("Scout AI responses will appear here...")
        layout.addWidget(self.chat_display)
        
        # Input area
        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Ask Scout about security vulnerabilities, scanning, or best practices...")
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)
        
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_button)
        
        layout.addLayout(input_layout)
        
        # Status
        self.status_label = QLabel("Scout AI ready" if self.scout_available else "Scout AI offline - operating in standalone mode")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        
    def _check_scout_availability(self):
        """Non-blocking check if Scout backend is available."""
        try:
            response = requests.get(f"{self.scout_url}/health", timeout=2)
            self.scout_available = response.status_code == 200
        except:
            self.scout_available = False
        
    def send_message(self):
        """Send a message to Scout AI."""
        message = self.message_input.text().strip()
        if not message:
            return
        
        # Check if Scout is available (non-blocking); if not, auto-start the backend
        if not self.scout_available:
            self._check_scout_availability()
            if not self.scout_available:
                # Auto-launch the backend and keep the typed message so the user can retry
                self.ensure_backend()
                self.chat_display.append(
                    "\n⏳ <b>Scout AI is starting…</b> your message is kept — "
                    "click <b>Send</b> again in a few seconds."
                )
                return

        self.message_input.clear()
        self.status_label.setText("Sending message...")
        self.send_button.setEnabled(False)
        
        # Display user message
        self.chat_display.append(f"\n<b>You:</b> {message}")
        
        try:
            # Send to Scout backend
            response = requests.post(
                f"{self.scout_url}/chat",
                json={"session_id": self.session_id, "message": message},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # Backend (/chat) returns {"reply": ...}; keep "response" as a fallback
                scout_response = data.get("reply") or data.get("response") or "No response from Scout."
                self.chat_display.append(f"\n<b>Scout:</b> {scout_response}")
                self.status_label.setText("Message received from Scout")
            else:
                self.chat_display.append(f"\n<b>Info:</b> Scout returned status {response.status_code}")
                self.status_label.setText(f"Scout status: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            self.scout_available = False
            self.chat_display.append(
                "\n⚠️ <b>Scout Connection Lost</b>\n"
                f"Could not reach Scout backend at {self.scout_url}\n"
                "Scout is optional - CyberRecon continues normally."
            )
            self.status_label.setText("Scout offline - continuing without AI analysis")
        except requests.exceptions.Timeout:
            self.chat_display.append("\n⚠️ <b>Info:</b> Request to Scout timed out.")
            self.status_label.setText("Scout request timed out")
        except Exception as e:
            self.chat_display.append(f"\n⚠️ <b>Info:</b> {str(e)[:100]}")
            self.status_label.setText(f"Scout unavailable")
        finally:
            self.send_button.setEnabled(True)
    
    def inject_scan_target(self, target):
        """Inject a scan target into Scout for analysis."""
        if not target:
            return
        
        # Auto-generate a helpful prompt for Scout about this target
        message = f"Can you analyze security for {target}?"
        
        self.message_input.setText(message)
        self.chat_display.append(f"\n✓ <b>Scan Target:</b> {target} (injected)")
        
        # Check if Scout is available
        if not self.scout_available:
            self._check_scout_availability()
            if not self.scout_available:
                self.chat_display.append(
                    "\n⚠️ Scout AI is offline, but CyberRecon is running normally.\n"
                    "You can still send the message above if Scout becomes available, "
                    "or continue without it."
                )
                self.status_label.setText("Scout offline - Click Send if Scout backend starts")
                return
        
        self.status_label.setText(f"Ready to analyze {target} with Scout AI")
    
    def clear_chat(self):
        """Clear the chat history."""
        self.chat_display.clear()
        self.status_label.setText("Chat cleared")
    
    def set_scout_url(self, url):
        """Set the Scout backend URL."""
        self.scout_url = url
