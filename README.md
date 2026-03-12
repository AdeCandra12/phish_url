# Phishing URL Checker

Aplikasi web sederhana berbasis **Machine Learning** untuk mendeteksi apakah sebuah **URL termasuk phishing atau aman**.
Aplikasi ini menggunakan model yang telah dilatih dan ditampilkan melalui **dashboard Streamlit** untuk melakukan pengecekan URL secara langsung.

---

## Fitur

- Mengecek apakah sebuah URL berpotensi phishing
- Menampilkan probabilitas hasil prediksi
- Menampilkan informasi dasar domain seperti IP, lokasi, dan redirect
- Antarmuka web sederhana menggunakan Streamlit

---

## Teknologi yang Digunakan

- Python
- Scikit-learn
- Pandas
- NumPy
- Streamlit

---

## Instalasi

Clone repository:

git clone https://github.com/username/nama-repository.git

Masuk ke folder project:

```bash
cd nama-repository
```

Install dependency:

```bash
pip install -r requirements.txt
```

---

## Menjalankan Aplikasi

Jalankan aplikasi dengan perintah berikut:

```bash
streamlit run streamlit_phishing_dashboard.py
```

Setelah itu buka alamat lokal yang muncul di terminal (biasanya):

```
http://localhost:8501
```

---

## Cara Penggunaan

1. Masukkan URL yang ingin diperiksa.
2. Klik tombol **Cek URL**.
3. Sistem akan menampilkan hasil prediksi serta informasi dasar dari domain tersebut.

---

## Catatan

Project ini dibuat untuk **tujuan pembelajaran dan penelitian**.
