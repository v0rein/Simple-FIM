import os
import sys
import json
import hashlib
import logging
import datetime

# --- Konfigurasi Sistem ---
TARGET_FOLDER = "./secure_files/"
BASELINE_DB = "hash_db.json"
LOG_FILE = "security.log"
# --------------------------

# Level log kustom untuk "ALERT"
# Kita akan memetakannya ke CRITICAL (level 50)
ALERT_LEVEL = logging.CRITICAL 
logging.addLevelName(ALERT_LEVEL, "ALERT")

def log_alert(logger_instance, message, *args, **kwargs):
    """Fungsi helper untuk logging ALERT."""
    if logger_instance.isEnabledFor(ALERT_LEVEL):
        logger_instance._log(ALERT_LEVEL, message, args, **kwargs)

# Menambahkan metode .alert() ke logger
logging.Logger.alert = log_alert

def setup_logging():
    """Menginisialisasi logger untuk file dan konsol."""
    logger = logging.getLogger('FileIntegrityMonitor')
    logger.setLevel(logging.INFO) # Tangkap semua level dari INFO

    # Cegah duplikasi handler jika skrip diimpor
    if logger.hasHandlers():
        logger.handlers.clear()

    # Format log yang diminta
    log_format = logging.Formatter(
        '[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 1. File Handler (mencatat semuanya ke security.log)
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(log_format)
    file_handler.setLevel(logging.INFO) # Catat INFO dan di atasnya ke file
    logger.addHandler(file_handler)

    # 2. Console Handler (hanya menampilkan peringatan/alert di konsol)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_format)
    console_handler.setLevel(logging.WARNING) # Hanya tampilkan WARNING/ALERT ke konsol
    logger.addHandler(console_handler)

    return logger

# Inisialisasi logger global
logger = setup_logging()

def get_file_hash(filepath):
    """Menghitung hash SHA-256 dari sebuah file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Baca file dalam chunk untuk efisiensi memori
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        logger.warning(f"File {filepath} tidak ditemukan saat hashing (mungkin terhapus).")
        return None
    except Exception as e:
        logger.error(f"Tidak dapat menghitung hash untuk {filepath}: {e}")
        return None

def create_baseline():
    """Membuat baseline hash awal dari TARGET_FOLDER."""
    logger.info("--- Memulai pembuatan baseline baru ---")
    baseline = {}
    try:
        if not os.listdir(TARGET_FOLDER):
            logger.warning(f"Folder {TARGET_FOLDER} kosong. Baseline akan kosong.")
            
        for filename in os.listdir(TARGET_FOLDER):
            filepath = os.path.join(TARGET_FOLDER, filename)
            if os.path.isfile(filepath):
                file_hash = get_file_hash(filepath)
                if file_hash:
                    baseline[filename] = file_hash
                    logger.info(f"File dibaseline: {filename}")
        
        with open(BASELINE_DB, 'w') as f:
            json.dump(baseline, f, indent=4)
        logger.info(f"Baseline berhasil disimpan ke {BASELINE_DB}")
        print(f"Baseline berhasil dibuat untuk {len(baseline)} file.")

    except FileNotFoundError:
        logger.error(f"Folder target tidak ditemukan: {TARGET_FOLDER}")
        print(f"Error: Folder {TARGET_FOLDER} tidak ada. Harap buat folder tersebut.")
    except Exception as e:
        logger.error(f"Gagal membuat baseline: {e}")

def load_baseline():
    """Memuat baseline hash dari file JSON."""
    try:
        with open(BASELINE_DB, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"File baseline {BASELINE_DB} tidak ditemukan. Jalankan --init.")
        print(f"Error: File baseline {BASELINE_DB} tidak ditemukan. Jalankan '--init' untuk membuat.")
        return None
    except json.JSONDecodeError:
        logger.error(f"File baseline {BASELINE_DB} korup atau format JSON salah.")
        return None

def check_integrity():
    """Memeriksa integritas file terhadap baseline."""
    logger.info("--- Memulai pemeriksaan integritas ---")
    baseline = load_baseline()
    if baseline is None:
        return # Error sudah dicatat oleh load_baseline

    baseline_files = set(baseline.keys())
    current_files_map = {}
    
    try:
        current_filenames = set(os.listdir(TARGET_FOLDER))
    except FileNotFoundError:
        logger.error(f"Folder target {TARGET_FOLDER} tidak ditemukan.")
        return

    # 1. Dapatkan status file saat ini
    for filename in current_filenames:
        filepath = os.path.join(TARGET_FOLDER, filename)
        if os.path.isfile(filepath):
            current_files_map[filename] = get_file_hash(filepath)

    current_files_set = set(current_files_map.keys())

    # 2. Periksa file yang dimodifikasi (ada di baseline DAN ada saat ini)
    for filename in baseline_files.intersection(current_files_set):
        if baseline[filename] == current_files_map[filename]:
            logger.info(f"File \"{filename}\" verified OK.")
        else:
            logger.warning(f"File \"{filename}\" integrity failed!")
            logger.alert(f"Integritas file \"{filename}\" gagal (Hash mismatch).")

    # 3. Periksa file yang dihapus (ada di baseline TAPI TIDAK ada saat ini)
    for filename in baseline_files - current_files_set:
        logger.warning(f"File \"{filename}\" has been DELETED.")

    # 4. Periksa file baru (TIDAK ada di baseline TAPI ada saat ini)
    for filename in current_files_set - baseline_files:
        # Ini adalah ALERT sesuai permintaan
        logger.alert(f"Unknown file \"{filename}\" detected.")

    logger.info("--- Pemeriksaan integritas selesai ---")
    print("Pemeriksaan integritas selesai. Lihat 'security.log' untuk detail.")

def show_report():
    """Membaca security.log dan menampilkan ringkasan."""
    print("\n--- 📜 Laporan Log Keamanan (Pemeriksaan Terakhir) ---")
    safe_count = 0
    corrupt_count = 0
    new_file_count = 0
    deleted_count = 0
    last_anomaly_time = "N/A"
    
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"File log {LOG_FILE} tidak ditemukan. Jalankan '--check' terlebih dahulu.")
        return

    # Temukan baris log untuk pemeriksaan terakhir
    last_check_lines = []
    for i in range(len(lines) - 1, -1, -1):
        if "--- Memulai pemeriksaan integritas ---" in lines[i]:
            last_check_lines = lines[i+1:] # Ambil semua baris *setelah* penanda
            break
    
    if not last_check_lines:
        print("Belum ada pemeriksaan ('--check') yang dijalankan.")
        return

    anomaly_timestamps = []

    for line in last_check_lines:
        if "--- Pemeriksaan integritas selesai ---" in line:
            break # Berhenti di akhir sesi pemeriksaan
        
        # Ekstrak pesan untuk analisis
        try:
            level_msg = line.split('] ')[1]
            level, message = level_msg.split(': ', 1)
        except (IndexError, ValueError):
            continue # Lewati baris yang formatnya salah

        # Analisis log
        if level == "INFO" and "verified OK" in message:
            safe_count += 1
        elif level == "WARNING" and "integrity failed" in message:
            corrupt_count += 1
        elif level == "WARNING" and "DELETED" in message:
            deleted_count += 1
        elif level == "ALERT" and "Unknown file" in message:
            new_file_count += 1
        
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
        last_anomaly_time = max(anomaly_timestamps).strftime('%Y-%m-%d %H:%M:%S')

    print(f"✅ File Aman (terverifikasi): {safe_count}")
    print(f"❌ File Rusak (termodifikasi): {corrupt_count}")
    print(f"🚮 File Dihapus:             {deleted_count}")
    print(f"❓ File Baru (mencurigakan): {new_file_count}")
    print("-------------------------------------------------")
    print(f"⏱️ Waktu Anomali Terakhir:   {last_anomaly_time}")

def main():
    """Fungsi utama untuk menangani argumen CLI."""
    # Buat folder target jika belum ada
    if not os.path.exists(TARGET_FOLDER):
        print(f"Membuat folder target: {TARGET_FOLDER}")
        os.makedirs(TARGET_FOLDER)
        print(f"Silakan tambahkan file ke {TARGET_FOLDER} lalu jalankan '--init'.")

    if len(sys.argv) < 2:
        print("\nPenggunaan: python monitor.py <perintah>")
        print("Perintah:")
        print("  --init    : Membuat/memperbarui baseline hash file.")
        print("  --check   : Menjalankan pemeriksaan integritas file.")
        print("  --report  : Menampilkan laporan dari log pemeriksaan terakhir.")
        return

    command = sys.argv[1]

    if command == "--init":
        create_baseline()
    elif command == "--check":
        check_integrity()
    elif command == "--report":
        show_report()
    else:
        print(f"Perintah tidak dikenal: {command}")
        print("Gunakan '--init', '--check', atau '--report'.")

if __name__ == "__main__":
    main()