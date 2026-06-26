# Authorized Lab Emulation Console

Starter project untuk **Kali Linux di WSL** yang menampilkan dashboard console seperti POC attacker-emulation, tetapi dengan guardrail yang ketat:

- **simulation-only** secara default
- **tanpa input command mentah**
- **target dibatasi ke daftar subnet lab yang disetujui**
- **job dicatat dan ditampilkan di live console**

Project ini cocok sebagai pondasi untuk:

- dashboard internal lab exercise
- tabletop / validation workflow
- orchestration UI untuk modul yang nantinya Anda sambungkan sendiri
- browser Windows + backend Linux/WSL

## Arsitektur

```text
redteam-console/
|-- backend/
|   |-- __init__.py
|   |-- catalog.py
|   |-- main.py
|   `-- store.py
|-- index.html
|-- script.js
|-- styles.css
|-- requirements.txt
`-- README.md
```

## Fitur Starter

- Dashboard frontend bergaya console
- Backend `FastAPI`
- Catalog modul per fase
- Endpoint job tunggal dan full chain
- Target validation dengan subnet lock
- Penyimpanan job sederhana berbasis `SQLite`
- Polling live log dari browser
- Tema terang/gelap
- Progress bar per job
- Severity summary dan evidence highlights
- Export evidence JSON
- Live-safe adapter terbatas untuk beberapa modul recon/baseline

## Mode Aman Saat Ini

Build awal ini **tidak mengeksekusi tool ofensif nyata**. Semua modul masih berupa:

- validasi target
- pembuatan job
- simulasi langkah kerja
- emit log yang realistis untuk kebutuhan UI dan workflow

Ini sengaja dibuat aman dulu agar Anda bisa mengembangkan:

1. UI
2. backend
3. guardrail
4. observability

tanpa langsung membuka risiko eksekusi command arbitrer.

Modul tertentu sekarang memiliki **live-safe adapter** yang hanya melakukan pemeriksaan ringan dan dibatasi subnet:

- `recon-service-scan`
- `baseline-web-fingerprint`
- `baseline-content-discovery`
- `baseline-tls-dns-review`

Adapter ini hanya melakukan read-only probing sederhana untuk kebutuhan lab internal.

## Menjalankan di Kali WSL

Masuk ke folder repo dari terminal Kali WSL, lalu:

```bash
cd /mnt/c/Users/user/Documents/GitHub/redteam-console
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 4080 --reload
```

Lalu buka dari browser Windows:

```text
http://localhost:4080
```

## Menjalankan Otomatis dengan Launcher

Supaya lebih praktis setelah laptop menyala, gunakan file berikut dari Windows:

- [`start-console.cmd`](C:/Users/gufroni/Documents/GitHub/redteam-console/start-console.cmd)
- [`stop-console.cmd`](C:/Users/gufroni/Documents/GitHub/redteam-console/stop-console.cmd)

Alurnya:

1. Klik ganda `start-console.cmd`
2. Windows memanggil distro `kali-linux`
3. Script WSL menjalankan atau membuat `.venv` bila perlu
4. Backend start di background pada `http://localhost:4080`

Script WSL yang dipanggil:

- [`start-console.sh`](C:/Users/gufroni/Documents/GitHub/redteam-console/start-console.sh)
- [`stop-console.sh`](C:/Users/gufroni/Documents/GitHub/redteam-console/stop-console.sh)

Log runtime akan ditulis ke:

```text
.runtime/console.log
```

PID proses akan ditulis ke:

```text
.runtime/console.pid
```

## Kalau Ingin Auto Start Saat Login Windows

Anda bisa menaruh shortcut `start-console.cmd` ke folder Startup Windows:

```text
shell:startup
```

Dengan begitu, setelah login Windows, launcher akan mencoba menyalakan backend otomatis.

## Guardrail Default

- subnet lab default yang diizinkan:
  - `10.10.10.0/24`
  - `192.168.56.0/24`
  - `192.168.122.0/24`
  - `172.16.56.0/24`
- mode eksekusi: `simulation-only`
- target harus IP valid
- tidak ada field untuk command bebas
- modul hanya dapat dipilih dari catalog backend

Kalau Anda ingin ganti atau tambah range VM/lab, edit file:

[`lab-ranges.json`](C:/Users/gufroni/Documents/GitHub/redteam-console/lab-ranges.json)

Contoh jika VirtualBox Anda memakai `192.168.22.0/24`, cukup ubah:

```json
{
  "allowed_subnets": [
    "10.10.10.0/24",
    "192.168.22.0/24"
  ]
}
```

Lalu restart backend atau jalankan ulang launcher:

- [`stop-console.cmd`](C:/Users/gufroni/Documents/GitHub/redteam-console/stop-console.cmd)
- [`start-console.cmd`](C:/Users/gufroni/Documents/GitHub/redteam-console/start-console.cmd)

Backend sekarang membaca subnet dari `lab-ranges.json` saat start. Jika file ini rusak atau tidak ada, sistem akan otomatis fallback ke default bawaan di [`backend/lab_config.py`](C:/Users/gufroni/Documents/GitHub/redteam-console/backend/lab_config.py).

## Endpoint Utama

- `GET /api/config`
- `GET /api/modules`
- `GET /api/jobs`
- `GET /api/jobs/{job_id}`
- `GET /api/jobs/{job_id}/evidence`
- `POST /api/jobs`
- `POST /api/jobs/full-chain`

## Langkah Pengembangan Berikutnya

Kalau fondasi ini sudah cocok, tahap berikut yang paling masuk akal:

1. Tambahkan adapter runner per modul
2. Pisahkan mode `simulation` dan `approved-live`
3. Tambahkan auth internal
4. Tambahkan audit trail yang lebih rinci
5. Tambahkan export evidence/report
6. Tambahkan WebSocket untuk live stream log

## Catatan Penting

Project ini ditujukan untuk **lab internal terotorisasi**. Jangan menambahkan eksekusi bebas atau target tanpa validasi subnet.
