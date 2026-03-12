# phish_urlPhishing URL Checker

Aplikasi web sederhana berbasis Machine Learning untuk mendeteksi apakah sebuah URL termasuk phishing atau aman. Aplikasi ini menggunakan model yang telah dilatih dan ditampilkan melalui dashboard Streamlit untuk melakukan pengecekan URL secara langsung.

1. Fitur

- Mengecek apakah sebuah URL berpotensi phishing

- Menampilkan probabilitas hasil prediksi

- Menampilkan informasi dasar domain seperti IP, lokasi, dan redirect

- Antarmuka sederhana berbasis web menggunakan Streamlit

2. Teknologi yang Digunakan

- Python

- Scikit-learn

- Pandas & NumPy

- Streamlit

3. Instalasi

Clone repository:

git clone https://github.com/username/nama-repository.git

Masuk ke folder project:

cd nama-repository

Install dependency:

pip install -r requirements.txt

Menjalankan Aplikasi

Jalankan perintah berikut:

streamlit run streamlit_phishing_dashboard.py

Setelah itu buka alamat lokal yang muncul di terminal (biasanya http://localhost:8501).

Cara Penggunaan

Masukkan URL yang ingin diperiksa.

Klik tombol Cek URL.

Sistem akan menampilkan hasil prediksi serta informasi dasar dari domain tersebut.

Catatan

Project ini dibuat untuk tujuan pembelajaran dan penelitian.
