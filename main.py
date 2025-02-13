# main.py

import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QStackedWidget, QTableWidget, 
    QTableWidgetItem, QHeaderView, QMessageBox, QListWidget, 
    QGraphicsOpacityEffect, QInputDialog
)
from PySide6.QtGui import QAction, QIcon, QClipboard
from PySide6.QtCore import QSize, Qt, QTimer, QPropertyAnimation, QRect

from database import save_password, get_all_passwords, delete_password as del_password, search_passwords, verify_pin, set_pin
from encryption import encrypt_password, decrypt_password

class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(200, 100, 700, 500)
        self.setStyleSheet("""
            background-color: #2b2b2b;
            color: white;
            font-family: Arial;
            font-size: 14px;
        """)
        self.init_ui()
    
    def init_ui(self):
        """Setup the modern UI layout."""
        main_layout = QHBoxLayout()

        # Left Sidebar Navigation
        self.sidebar = QListWidget()
        self.sidebar.addItem("🔒 Add Password")
        self.sidebar.addItem("📂 View Passwords")
        self.sidebar.setFixedWidth(180)
        self.sidebar.setStyleSheet("""
            QListWidget {
                background-color: #333;
                color: white;
                border: none;
            }
            QListWidget::item:selected {
                background-color: #555;
                font-weight: bold;
            }
        """)
        self.sidebar.currentRowChanged.connect(self.switch_screen)

        # Stacked Widget (Switchable UI Panels)
        self.stack = QStackedWidget()

        # Page 1 - Add Password Form
        self.add_password_widget = QWidget()
        self.add_password_layout = QVBoxLayout()

        self.account_label = QLabel("Account Name:")
        self.account_input = QLineEdit()
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        # Save Password Button
        self.save_button = QPushButton("Save Password")
        self.save_button.setFixedHeight(40)
        self.save_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-size: 14px;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.save_button.clicked.connect(self.save_password)

        # Adding widgets to layout
        self.add_password_layout.addWidget(self.account_label)
        self.add_password_layout.addWidget(self.account_input)
        self.add_password_layout.addWidget(self.username_label)
        self.add_password_layout.addWidget(self.username_input)
        self.add_password_layout.addWidget(self.password_label)
        self.add_password_layout.addWidget(self.password_input)
        self.add_password_layout.addStretch()
        self.add_password_layout.addWidget(self.save_button)
        self.add_password_layout.addStretch()
        self.add_password_widget.setLayout(self.add_password_layout)

        # Page 2 - View Passwords
        self.view_password_widget = QWidget()
        self.view_password_layout = QVBoxLayout()

        self.search_label = QLabel("🔍 Search Account:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter account name...")
        self.search_input.textChanged.connect(self.search_password)

        # Passwords Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Account", "Username", "Password", "Copy", "Delete"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setStyleSheet("background-color: white; color: black;")

        # Show Passwords Toggle Button
        self.show_passwords_button = QPushButton("Show Passwords")
        self.show_passwords_button.setFixedHeight(40)
        self.show_passwords_button.setCheckable(True)
        self.show_passwords_button.clicked.connect(self.toggle_password_visibility)

        self.logout_button = QPushButton("🔒 Logout")
        self.logout_button.setFixedHeight(40)
        self.logout_button.setStyleSheet("background-color: #FFAA00; color: white; border-radius: 5px; padding: 10px;")
        self.logout_button.clicked.connect(self.lock_app)

        self.view_password_layout.addWidget(self.search_label)
        self.view_password_layout.addWidget(self.search_input)
        self.view_password_layout.addWidget(self.results_table)
        self.view_password_layout.addStretch()
        self.view_password_layout.addWidget(self.show_passwords_button)
        self.view_password_layout.addStretch()
        self.view_password_layout.addWidget(self.logout_button)
        self.view_password_widget.setLayout(self.view_password_layout)

        # Add pages to stack
        self.stack.addWidget(self.add_password_widget)
        self.stack.addWidget(self.view_password_widget)

        # Add widgets to main layout
        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.stack)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)


    def switch_screen(self, index):
        """Switch between Add Password and View Password screens with animation."""
        animation = QPropertyAnimation(self.stack, b"geometry")
        animation.setDuration(400)
        animation.setStartValue(self.stack.geometry())
        animation.setEndValue(self.stack.geometry())
        animation.start()
        self.stack.setCurrentIndex(index)
        if index == 1:
            self.fetch_all_passwords()

    def save_password(self):
        """Save encrypted password to the database."""
        account = self.account_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if not account or not username or not password:
            QMessageBox.warning(self, "Error", "All fields are required!")
            return

        encrypted_password = encrypt_password(password)
        save_password(account, username, encrypted_password)

        QMessageBox.information(self, "Success", "Password saved successfully!")


        # Clear input fields
        self.account_input.clear()
        self.username_input.clear()
        self.password_input.clear()

    def search_password(self):
        """Search passwords and update table with animation."""
        query = self.search_input.text()
        records = search_passwords(query)

        self.results_table.setRowCount(0)
        self.hidden_passwords = {}

        for row_index, (account, username, encrypted_password) in enumerate(records):
            decrypted_password = decrypt_password(encrypted_password)
            self.hidden_passwords[row_index] = decrypted_password

            self.results_table.insertRow(row_index)
            self.results_table.setItem(row_index, 0, QTableWidgetItem(account))
            self.results_table.setItem(row_index, 1, QTableWidgetItem(username))
            self.results_table.setItem(row_index, 2, QTableWidgetItem("••••••••"))

            # Copy Button
            copy_button = QPushButton("📋 Copy")
            copy_button.clicked.connect(lambda _, pwd=decrypted_password: self.copy_to_clipboard(pwd))
            self.results_table.setCellWidget(row_index, 3, copy_button)

            # Delete Button (added for search results)
            delete_button = QPushButton("🗑 Delete")
            delete_button.setFixedSize(80, 30)
            delete_button.setStyleSheet("background-color: #FF4C4C; color: white; border-radius: 5px; padding: 5px;")
            delete_button.clicked.connect(lambda _, acc=account: self.delete_password(acc))
            self.results_table.setCellWidget(row_index, 4, delete_button)

    def toggle_password_visibility(self):
        """Show or hide passwords with a smooth transition."""
        show = self.show_passwords_button.isChecked()
        for row_index in range(self.results_table.rowCount()):
            # Note: Using a simple approach without animation for table items.
            if show:
                self.results_table.setItem(row_index, 2, QTableWidgetItem(self.hidden_passwords[row_index]))
            else:
                self.results_table.setItem(row_index, 2, QTableWidgetItem("••••••••"))
        self.show_passwords_button.setText("Hide Passwords" if show else "Show Passwords")

    def copy_to_clipboard(self, password):
        """Copy password to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(password)
        QMessageBox.information(self, "Copied", "Password copied! Auto-clearing in 20s.")
        QTimer.singleShot(20000, self.clear_clipboard)

    def clear_clipboard(self):
        """Clear clipboard after timeout."""
        clipboard = QApplication.clipboard()
        clipboard.clear()
        QMessageBox.information(self, "Clipboard Cleared", "Clipboard content cleared.")

    def fetch_all_passwords(self):
        """Fetch and display all stored passwords after verifying the PIN."""
        if not self.prompt_for_pin("view saved passwords"):
            return

        records = get_all_passwords()
        self.results_table.setRowCount(0)
        self.hidden_passwords = {}

        for row_index, (account, username, encrypted_password) in enumerate(records):
            decrypted_password = decrypt_password(encrypted_password)
            self.hidden_passwords[row_index] = decrypted_password

            self.results_table.insertRow(row_index)
            self.results_table.setItem(row_index, 0, QTableWidgetItem(account))
            self.results_table.setItem(row_index, 1, QTableWidgetItem(username))
            self.results_table.setItem(row_index, 2, QTableWidgetItem("••••••••"))

            copy_button = QPushButton("📋 Copy")
            copy_button.setFixedSize(80, 30)
            copy_button.clicked.connect(lambda _, pwd=decrypted_password: self.copy_to_clipboard(pwd))
            self.results_table.setCellWidget(row_index, 3, copy_button)

            delete_button = QPushButton("🗑 Delete")
            delete_button.setFixedSize(80, 30)
            delete_button.setStyleSheet("background-color: #FF4C4C; color: white; border-radius: 5px; padding: 5px;")
            delete_button.clicked.connect(lambda _, acc=account: self.delete_password(acc))
            self.results_table.setCellWidget(row_index, 4, delete_button)

    def delete_password(self, account):
        """Delete a password entry from the database after PIN verification."""
        if not self.prompt_for_pin(f"delete the password for '{account}'"):
            return

        confirmation = QMessageBox.question(
            self, "Delete Password", f"Are you sure you want to delete the password for '{account}'?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if confirmation == QMessageBox.Yes:
            del_password(account)
            QMessageBox.information(self, "Deleted", f"Password for '{account}' has been deleted.")
            self.fetch_all_passwords()

    def prompt_for_pin(self, action):
        """
        Prompt the user to enter a PIN before performing sensitive actions.
        If the user cancels or enters an incorrect PIN, switch back to the home screen.
        """
        pin, ok = QInputDialog.getText(self, "Enter PIN", f"Enter your PIN to {action}:", QLineEdit.Password)
        if not ok or not pin:
            QMessageBox.warning(self, "Error", "PIN is required! Returning to Home screen.")
            # Switch to a safe page 
            self.switch_screen(0)
            return False

        if not verify_pin(pin):
            QMessageBox.warning(self, "Error", "Incorrect PIN! Returning to Home screen.")
            self.switch_screen(0)
            return False

        return True

    
    def set_new_pin(self):
        """Allow the user to set a new PIN."""
        new_pin, ok = QInputDialog.getText(self, "Set PIN", "Enter a new PIN:", QLineEdit.Password)
        if ok and new_pin:
            set_pin(new_pin)
            QMessageBox.information(self, "Success", "PIN updated successfully!")

    def lock_app(self):
        """Lock the app by requiring PIN entry before accessing passwords."""
        QMessageBox.information(self, "Logged Out", "You have been logged out. Please re-enter your PIN.")
        if not self.prompt_for_pin("access the app"):
            self.close()  # Close the app if PIN is incorrect

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())
