import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QTextEdit, QFileDialog, QMessageBox
)
from eclib import EC, DiffieHellman
from Crypto.Cipher import AES
import base64
import hashlib
class ECCWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Elliptic Curve Cryptography")
        self.setGeometry(100, 100, 500, 400)

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # Elliptic Curve Parameters
        self.label_a = QLabel("Value of a:")
        self.input_a = QLineEdit()
        self.label_b = QLabel("Value of b:")
        self.input_b = QLineEdit()
        self.label_q = QLabel("Value of q (prime):")
        self.input_q = QLineEdit()

        layout.addWidget(self.label_a)
        layout.addWidget(self.input_a)
        layout.addWidget(self.label_b)
        layout.addWidget(self.input_b)
        layout.addWidget(self.label_q)
        layout.addWidget(self.input_q)

        # Private Keys
        self.label_privA = QLabel("Private Key of A:")
        self.input_privA = QLineEdit()
        self.label_privB = QLabel("Private Key of B:")
        self.input_privB = QLineEdit()

        layout.addWidget(self.label_privA)
        layout.addWidget(self.input_privA)
        layout.addWidget(self.label_privB)
        layout.addWidget(self.input_privB)

        # Buttons
        self.button_import = QPushButton("Import File")
        self.button_import.clicked.connect(self.import_file)
        self.button_encrypt = QPushButton("Encrypt")
        self.button_encrypt.clicked.connect(self.ecdh_encrypt)
        self.button_decrypt = QPushButton("Decrypt")
        self.button_decrypt.clicked.connect(self.ecdh_decrypt)

        layout.addWidget(self.button_import)
        layout.addWidget(self.button_encrypt)
        layout.addWidget(self.button_decrypt)

        # Text Area
        self.text_edit = QTextEdit()
        layout.addWidget(self.text_edit)

        self.setLayout(layout)

    def import_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open File', '', 'Text files (*.txt)')
        if file_path:
            with open(file_path, 'r') as file:
                self.text_edit.setText(file.read())

    def ecdh_encrypt(self):
        A = int(self.input_a.text())
        B = int(self.input_b.text())
        C = int(self.input_q.text())
        PrivA = int(self.input_privA.text())
        PrivB = int(self.input_privB.text())
        data = self.text_edit.toPlainText()


        print("1")
        ec = EC(A, B, C)
        print("2")
        g, _ = ec.at(0)
        print(g)
        print("3")
        dh = DiffieHellman(ec, g)
        print("4")
        apub = dh.gen(PrivA)
        print("5")
        bpub = dh.gen(PrivB)
        print("6")
        shared_secret_A = dh.secret(PrivA, bpub)
        print("7")
        shared_secret_B = dh.secret(PrivB, apub)
        print("8")
        secret = hashlib.md5(str(shared_secret_A + shared_secret_B).encode()).digest()
        print("9")
        cipher = AES.new(secret, AES.MODE_ECB)
        print("10")
        padded_data = data.ljust((len(data) // 16 + 1) * 16)
        print("11")
        encrypted_data = cipher.encrypt(padded_data.encode())
        print("12")
        encoded_data = base64.b64encode(encrypted_data).decode()
        print("13")
        self.text_edit.setText(encoded_data)
        print("14")

    def ecdh_decrypt(self):
        A = int(self.input_a.text())
        B = int(self.input_b.text())
        C = int(self.input_q.text())
        PrivA = int(self.input_privA.text())
        PrivB = int(self.input_privB.text())
        data = self.text_edit.toPlainText()

        ec = EC(A, B, C)
        g, _ = ec.at(0)
        dh = DiffieHellman(ec, g)
        apub = dh.gen(PrivA)
        bpub = dh.gen(PrivB)
        shared_secret_A = dh.secret(PrivA, bpub)
        shared_secret_B = dh.secret(PrivB, apub)

        secret = hashlib.md5(str(shared_secret_A + shared_secret_B).encode()).digest()
        cipher = AES.new(secret, AES.MODE_ECB)
        decrypted_data = cipher.decrypt(base64.b64decode(data)).decode().rstrip()
        self.text_edit.setText(decrypted_data)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ECCWindow()
    window.show()
    sys.exit(app.exec_())
