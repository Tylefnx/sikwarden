import sqlite3
from contextlib import contextmanager

DB_FILE = "password_manager.db"

@contextmanager
def get_db_connection():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row 
        yield conn
    except sqlite3.Error as e:
        print(f"Veritabanı bağlantı hatası: {e}")
        if conn:
            conn.close()
    finally:
        if conn:
            conn.close()

def init_db():
    print("Veritabanı başlatılıyor...")
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username_enc TEXT NOT NULL,  -- Şifreli Kullanıcı Adı
                password_enc TEXT NOT NULL,  -- Şifreli Parola
                iv TEXT NOT NULL             -- Şifre çözme IV'si
            );
        """)
        conn.commit()
    print(f"Veritabanı ({DB_FILE}) hazır.")


def save_entry(site, username_enc, password_enc, iv):
    """Veritabanına yeni bir şifreli giriş kaydeder, aynı site+username kombinasyonu varsa eklemez."""
    with get_db_connection() as conn:
        # Aynı site ve username hash'i var mı kontrol et
        cursor = conn.execute(
            "SELECT id FROM entries WHERE site = ? AND username_enc = ?",
            (site, username_enc)
        )
        existing = cursor.fetchone()
        if existing:
            print(f"Hata: '{site}' ve bu kullanıcı adı için zaten bir kayıt mevcut.")
            return False

        # Yoksa kaydet
        conn.execute(
            "INSERT INTO entries (site, username_enc, password_enc, iv) VALUES (?, ?, ?, ?)",
            (site, username_enc, password_enc, iv)
        )
        conn.commit()
    print(f"'{site}' için şifreli giriş başarıyla kaydedildi.")
    return True



def get_entries_by_username(username_enc_key):
    """
    Verilen şifreli kullanıcı adına (anahtara) ait tüm girişleri döndürür.
    """
    with get_db_connection() as conn:
        entries = conn.execute(
            "SELECT id, site, username_enc, password_enc, iv FROM entries WHERE username_enc = ?",
            (username_enc_key,)
        ).fetchall()
        
        return [dict(row) for row in entries]


if __name__ == '__main__':
    init_db()
