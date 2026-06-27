# Authorized Lab Emulation Console With WSL + Windows OS

<p align="center">
  <img src="logo.png" alt="Authorized Lab Emulation Console With WSL + Windows OS" width="220">
</p>

<p align="center">
  <strong>Console kerja untuk pentester yang memakai Windows dan WSL Kali Linux</strong><br>
  Menyatukan module catalog, live console, timeline, evidence, dan HTML report dalam satu dashboard internal.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688" alt="FastAPI">
  <img src="https://img.shields.io/badge/Frontend-HTML%20%2B%20CSS%20%2B%20JS-1E88E5" alt="Frontend">
  <img src="https://img.shields.io/badge/Environment-Windows%20%2B%20WSL%20Kali-3949AB" alt="Windows plus WSL Kali">
  <img src="https://img.shields.io/badge/Scope-Authorized%20Lab-C62828" alt="Authorized Lab">
</p>

---

## Overview

Repository ini dibuat sebagai console kerja untuk tim pentest internal yang menjalankan tool dari **Kali Linux di WSL**, tetapi tetap ingin memakai **browser dan workflow harian di Windows**.

Tujuan utamanya:

- memberi antarmuka yang lebih rapi untuk menjalankan asesmen lab yang terotorisasi;
- membatasi target ke subnet yang disetujui;
- merangkum hasil scan menjadi evidence, timeline, severity, dan report;
- memudahkan operator melakukan validasi cepat tanpa harus berpindah-pindah terminal.

Repo ini bukan shell bebas untuk menjalankan command arbitrer dari UI. Semua alur dirancang tetap berada dalam guardrail backend.

---

## Cocok Untuk Siapa

Console ini cocok untuk:

- pentester yang bekerja di Windows tetapi tool utamanya ada di WSL Kali Linux;
- operator lab internal yang butuh alur scan terarah;
- tim red team yang ingin menyatukan hasil beberapa tool ke panel evidence;
- pengajar, lab engineer, atau assessor yang ingin menyiapkan workflow pentest yang lebih konsisten.

---

## Konsep Kerja

Alur kerja repo ini sederhana:

1. operator membuka UI dari browser Windows;
2. backend berjalan dari lingkungan WSL Kali Linux;
3. modul menjalankan tool yang tersedia di Kali;
4. output tool diproses menjadi:
   - live console
   - module timeline
   - evidence highlights
   - severity summary
   - HTML report

Dengan pola ini, Windows dipakai untuk pengalaman UI dan dokumentasi, sedangkan WSL Kali dipakai untuk tool execution.

---

## Fitur Utama

- Guardrail target berdasarkan approved ranges atau subnet yang diizinkan.
- Module catalog berbasis fase kill chain.
- Full simulation chain sesuai execution profile.
- Live Console, Timeline, dan Evidence dalam panel terpisah.
- Severity summary yang mengikuti evidence yang benar-benar ditampilkan.
- View Report untuk membuka report HTML dari job aktif.
- Perlindungan password untuk aksi `Simpan Ranges`.
- Launcher `start-console` dan `stop-console` dari Windows ke WSL Kali.

---

## Struktur Repository

```text
redteam-console/
|-- backend/
|   |-- assets.py
|   |-- catalog.py
|   |-- lab_config.py
|   |-- main.py
|   |-- store.py
|   |-- workflow.py
|   |-- wahidin_check_headers.py
|   `-- data/
|-- .runtime/
|-- index.html
|-- script.js
|-- styles.css
|-- lab-ranges.json
|-- requirements.txt
|-- start-console.cmd
|-- start-console.sh
|-- stop-console.cmd
|-- stop-console.sh
`-- README.md
```

Ringkasnya:

- `backend/main.py` adalah entry point backend FastAPI.
- `backend/catalog.py` memuat definisi modul dan profile eksekusi.
- `backend/store.py` menangani penyimpanan job.
- `backend/lab_config.py` mengelola konfigurasi approved ranges.
- `backend/wahidin_check_headers.py` menjadi source checker untuk audit security header.
- `index.html`, `script.js`, dan `styles.css` menangani UI dashboard.

---

## Kebutuhan Lingkungan

Minimum yang disarankan:

- Windows 10/11
- WSL2
- distro `kali-linux`
- Python 3 di WSL
- browser di Windows

Tool yang dianjurkan tersedia di Kali agar modul lebih optimal:

- `nmap`
- `ffuf`
- `gobuster`
- `nikto`
- `whatweb`
- `nuclei`
- `dnsx`
- `httpx`
- `amass`
- `sslyze`
- `sqlmap`
- `hydra`
- `john`
- `hashcat`
- `impacket`
- `smbclient`
- `ldapsearch`
- `tcpdump`
- `jq`
- `pandoc`
- `graphviz`
- `git`
- `wget`
- `curl`

Repo ini tetap bisa berjalan walau sebagian tool belum tersedia, tetapi modul terkait bisa di-skip atau hasilnya tidak sekaya lingkungan yang lengkap.

---

## Menjalankan Console

### Opsi 1: dari Windows

Gunakan launcher berikut:

- [start-console.cmd](C:/Users/gufroni/Documents/GitHub/redteam-console/start-console.cmd)
- [stop-console.cmd](C:/Users/gufroni/Documents/GitHub/redteam-console/stop-console.cmd)

Alurnya:

1. klik `start-console.cmd`;
2. script Windows memanggil `kali-linux` di WSL;
3. backend dijalankan dari repo ini;
4. buka `http://localhost:4080` dari browser Windows.

Untuk menghentikan backend:

1. klik `stop-console.cmd`;
2. script akan menghentikan proses uvicorn aktif milik console ini.

### Opsi 2: langsung dari terminal WSL

```bash
cd /mnt/c/Users/gufroni/Documents/GitHub/redteam-console
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn backend.main:app --host 0.0.0.0 --port 4080
```

Lalu akses:

```text
http://localhost:4080
```

---

## Workflow Penggunaan

Urutan pakai yang disarankan:

1. pastikan console sudah aktif;
2. isi target IP yang berada dalam approved ranges;
3. pilih `Module Profile`:
   - `fast` untuk validasi cepat;
   - `balanced` untuk baseline yang lebih umum;
   - `deep` untuk observasi lebih lengkap;
4. jalankan modul tunggal atau `Run Full Simulation Chain`;
5. pantau hasil di tab:
   - `Console`
   - `Timeline`
   - `Evidence`
6. buka `View Report` jika ingin melihat report HTML.

---

## Approved Ranges

Target dibatasi agar operator hanya bekerja pada subnet yang diotorisasi.

File utama:

- [lab-ranges.json](C:/Users/gufroni/Documents/GitHub/redteam-console/lab-ranges.json)

Contoh isi:

```json
{
  "allowed_subnets": [
    "10.10.10.0/24",
    "192.168.56.0/24"
  ]
}
```

Catatan:

- tombol `Simpan Ranges` dilindungi password;
- backend tetap punya fallback konfigurasi jika file range bermasalah;
- ini penting agar repo aman dipakai bersama dalam lab.

---

## Modul dan Tooling

Repo ini dirancang untuk memetakan output tool menjadi evidence yang lebih mudah dibaca operator. Beberapa contoh area modul:

- service discovery
- host discovery
- DNS dan vhost enumeration
- web fingerprinting
- web security header audit
- content discovery
- misconfiguration review
- TLS dan DNS baseline review
- sensitive file discovery

Khusus untuk audit security header, repo ini sudah memakai source checker internal:

- [backend/wahidin_check_headers.py](C:/Users/gufroni/Documents/GitHub/redteam-console/backend/wahidin_check_headers.py)

Ini bisa menjadi fondasi untuk memperkaya modul web-hardening dan web-misconfiguration ke depan.

---

## Cara Mengoptimalkan Penggunaan

Agar console ini terasa maksimal untuk pentester yang bekerja di Windows + WSL Kali:

- pastikan tool inti di Kali sudah terpasang dan bisa dipanggil dari terminal;
- gunakan profile `fast` untuk cek awal, lalu lanjutkan `balanced` atau `deep` saat butuh detail;
- jaga approved ranges tetap sesuai ruang lab;
- gunakan `Evidence` untuk ringkasan cepat, lalu cek `Console` saat ingin melihat command dan output mentah;
- gunakan `View Report` untuk menyusun narasi laporan dari hasil yang sudah terkumpul.

Kalau lingkungan Kali makin lengkap, hasil modul live juga akan makin kaya.

---

## Pengembangan Lanjutan

Repo ini bisa terus diperkaya agar lebih powerful untuk kebutuhan red team. Arah pengembangan yang masuk akal misalnya:

- menambah modul baru berbasis tool Kali yang sudah umum dipakai pentester;
- memperluas parser evidence untuk Nmap, Nikto, Nuclei, ffuf, dan tool lain;
- memperkaya report HTML agar lebih komprehensif;
- menambah korelasi antar temuan lintas modul;
- menambah hardening checklist, cookie audit, dan review security header yang lebih detail;
- menambah kontrol operator, audit trail, dan export tambahan.

Semakin matang mapping modul ke tool, semakin dekat hasil console ini dengan workflow pentest manual yang biasa dilakukan operator.

---

## Troubleshooting Singkat

Jika `http://localhost:4080` tidak terbuka:

- pastikan backend sudah dijalankan;
- cek log di `.runtime/console.log`;
- cek apakah port 4080 sedang dipakai proses lain;
- jalankan `stop-console.cmd`, lalu coba `start-console.cmd` lagi.

Jika modul tidak menghasilkan data yang lengkap:

- cek apakah tool terkait tersedia di Kali;
- cek apakah target berada di subnet yang diizinkan;
- cek `Console` untuk melihat command yang dijalankan dan error yang muncul.

---

## Catatan Penggunaan

- Gunakan repo ini hanya untuk lab yang telah diotorisasi.
- Jangan memperluas target di luar approved ranges tanpa persetujuan yang jelas.
- Jangan menganggap UI ini sebagai pengganti analisis manual; ini adalah akselerator workflow.
- Simpan pengembangan modul dengan pendekatan yang bertanggung jawab dan terukur.

---

<p align="center">
  developed with love by cakgup
</p>
