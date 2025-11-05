import os
import datetime
from flask import Flask, render_template_string

# --- Konfigurasi ---
# Pastikan ini menunjuk ke file log yang benar
LOG_FILE = "security.log"
# --------------------

app = Flask(__name__)

def parse_log_report():
    """Membaca security.log dan mengurai laporan pemeriksaan TERAKHIR."""
    report_data = {
        'safe': 0,
        'corrupt': 0,
        'deleted': 0,
        'new': 0,
        'last_anomaly': "N/A",
        'last_check_time': "N/A",
        'status': "Belum ada log ditemukan."
    }

    if not os.path.exists(LOG_FILE):
        report_data['status'] = f"File log '{LOG_FILE}' tidak ditemukan."
        return report_data

    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        report_data['status'] = f"Gagal membaca log: {e}"
        return report_data

    # Temukan baris log untuk pemeriksaan terakhir
    last_check_lines = []
    last_check_start_index = -1
    
    # Cari mundur untuk menemukan "Memulai pemeriksaan" yang terakhir
    for i in range(len(lines) - 1, -1, -1):
        if "--- Memulai pemeriksaan integritas ---" in lines[i]:
            last_check_start_index = i
            # Ambil waktu pemeriksaan dari baris log ini
            try:
                report_data['last_check_time'] = lines[i].split(']')[0][1:]
            except Exception:
                pass # Biarkan N/A jika format gagal
            break
            
    if last_check_start_index == -1:
        report_data['status'] = "Belum ada sesi '--check' yang dijalankan."
        return report_data

    # Ambil semua log dari pemeriksaan terakhir
    last_check_lines = lines[last_check_start_index + 1:]
    anomaly_timestamps = []

    for line in last_check_lines:
        if "--- Pemeriksaan integritas selesai ---" in line:
            break  # Berhenti di akhir sesi pemeriksaan

        try:
            level_msg = line.split('] ')[1]
            level, message = level_msg.split(': ', 1)
        except (IndexError, ValueError):
            continue  # Lewati baris yang formatnya salah

        # Analisis log
        if level == "INFO" and "verified OK" in message:
            report_data['safe'] += 1
        elif level == "WARNING" and "integrity failed" in message:
            report_data['corrupt'] += 1
        elif level == "WARNING" and "DELETED" in message:
            report_data['deleted'] += 1
        elif level == "ALERT" and "Unknown file" in message:
            report_data['new'] += 1

        # Catat waktu anomali
        if level in ("WARNING", "ALERT"):
            try:
                timestamp_str = line.split(']')[0][1:]
                anomaly_timestamps.append(
                    datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                )
            except (IndexError, ValueError):
                continue
    
    if anomaly_timestamps:
        report_data['last_anomaly'] = max(anomaly_timestamps).strftime('%Y-%m-%d %H:%M:%S')

    total_anomalies = report_data['corrupt'] + report_data['deleted'] + report_data['new']
    if total_anomalies > 0:
        report_data['status'] = f"PERINGATAN: Terdeteksi {total_anomalies} anomali!"
    else:
        report_data['status'] = "Semua file aman dan terverifikasi."

    return report_data


# --- Template HTML ---
# (Disimpan di dalam string agar file tetap tunggal)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30"> <title>Dashboard Integritas File</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f4f7f6;
            color: #333;
            margin: 0;
            padding: 20px;
        }
        .container { 
            max-width: 800px; 
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        header {
            background-color: #2c3e50;
            color: white;
            padding: 20px 30px;
            border-bottom: 4px solid #3498db;
        }
        header h1 { margin: 0; font-size: 1.8em; }
        header p { margin: 5px 0 0; color: #ecf0f1; }
        .summary {
            padding: 30px;
            border-bottom: 1px solid #eee;
        }
        .summary h2 { 
            margin: 0 0 20px; 
            color: #34495e;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
        }
        .metric-card {
            background-color: #f9f9f9;
            border: 1px solid #eee;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        .metric-card .icon { font-size: 2.5em; }
        .metric-card .number { 
            font-size: 2.2em; 
            font-weight: 600; 
            margin: 10px 0;
            color: #2c3e50;
        }
        .metric-card .label { font-size: 0.9em; color: #7f8c8d; }
        
        /* Warna berdasarkan status */
        .metric-card.safe .icon { color: #2ecc71; }
        .metric-card.safe .number { color: #27ae60; }
        .metric-card.danger .icon { color: #e74c3c; }
        .metric-card.danger .number { color: #c0392b; }
        .metric-card.warning .icon { color: #f39c12; }
        .metric-card.warning .number { color: #d35400; }
        .metric-card.info .icon { color: #3498db; }
        .metric-card.info .number { color: #2980b9; }

        footer {
            padding: 20px 30px;
            background-color: #fdfdfd;
            border-top: 1px solid #eee;
            color: #95a5a6;
            font-size: 0.9em;
        }
        
        /* Status Bar */
        .status-bar {
            padding: 15px 30px;
            font-weight: 600;
            font-size: 1.1em;
        }
        .status-ok { background-color: #e8f5e9; color: #2e7d32; }
        .status-warn { background-color: #fff3e0; color: #e65100; }
        .status-error { background-color: #ffebee; color: #c62828; }

    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Dashboard Integritas File</h1>
            <p>Pemeriksaan terakhir: {{ last_check_time }}</p>
        </header>

        {% set total_anomalies = corrupt + deleted + new %}
        {% if status.startswith('Gagal') or status.startswith('Belum') %}
            <div class="status-bar status-error">{{ status }}</div>
        {% elif total_anomalies > 0 %}
            <div class="status-bar status-warn">{{ status }}</div>
        {% else %}
            <div class="status-bar status-ok">{{ status }}</div>
        {% endif %}

        <div class="summary">
            <h2>Ringkasan Pemeriksaan Terakhir</h2>
            <div class="metrics">
                <div class="metric-card safe">
                    <div class="icon">✅</div>
                    <div class="number">{{ safe }}</div>
                    <div class="label">File Aman</div>
                </div>
                <div class="metric-card {% if corrupt > 0 %}danger{% else %}info{% endif %}">
                    <div class="icon">❌</div>
                    <div class="number">{{ corrupt }}</div>
                    <div class="label">File Rusak</div>
                </div>
                <div class="metric-card {% if deleted > 0 %}warning{% else %}info{% endif %}">
                    <div class="icon">🚮</div>
                    <div class="number">{{ deleted }}</div>
                    <div class="label">File Dihapus</div>
                </div>
                <div class="metric-card {% if new > 0 %}danger{% else %}info{% endif %}">
                    <div class="icon">❓</div>
                    <div class="number">{{ new }}</div>
                    <div class="label">File Baru</div>
                </div>
            </div>
        </div>
        
        <footer>
            <strong>⏱️ Waktu Anomali Terakhir:</strong> {{ last_anomaly }}
        </footer>
    </div>
</body>
</html>
"""

# --- Route Flask ---
@app.route('/')
def dashboard():
    """Tampilkan halaman dashboard utama."""
    report_data = parse_log_report()
    return render_template_string(HTML_TEMPLATE, **report_data)

# --- Jalankan Aplikasi ---
if __name__ == '__main__':
    print("Menjalankan Flask Web Server di http://127.0.0.1:5000")
    print("Tekan CTRL+C untuk berhenti.")
    # 'host="0.0.0.0"' membuatnya bisa diakses dari jaringan (jika diinginkan)
    app.run(debug=True, port=5000, host="0.0.0.0")