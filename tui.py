# tui.py

import os
import base64
import time
from dotenv import load_dotenv

load_dotenv()
# password.py'dan tüm fonksiyonları, yeni eklenen hash_search_key dahil, import edin
from password import ( 
    hash_master_password,     
    check_master_password, 
    derive_key, 
    encrypt_data, 
    decrypt_data, 
    generate_secure_password,
    hash_search_key # YENİ HASH FONKSİYONUNU İÇE AKTARDIK
)

# database.py içindeki tüm gerekli fonksiyonları import edin
from database import init_db, save_entry, get_entries_by_username 

# Global Sabitler ve Değişkenler
MASTER_DATA_FILE = os.getenv("MASTER_DATA_LOCATION")
GLOBAL_AES_KEY = None 

# --- YARDIMCI VE KURULUM FONKSİYONLARI ---

def clear_screen():
    """Konsolu temizler."""
    os.system('cls' if os.name == 'nt' else 'clear')

def load_master_data():
    """Master hash'ini ve salt'ı dosyadan yükler."""
    if not os.path.exists(MASTER_DATA_FILE):
        return None, None
    try:
        with open(MASTER_DATA_FILE, 'r') as f:
            data = f.read().split('\n')
            hashed_pass = base64.b64decode(data[0].encode('utf-8'))
            salt = base64.b64decode(data[1].encode('utf-8'))
            return hashed_pass, salt
    except Exception:
        print("Hata: Ana veri dosyası okunamıyor veya bozuk.")
        return None, None

def save_master_data(hashed_pass, salt):
    """Master hash'ini ve salt'ı dosyaya kaydeder."""
    with open(MASTER_DATA_FILE, 'w') as f:
        f.write(base64.b64encode(hashed_pass).decode('utf-8') + '\n')
        f.write(base64.b64encode(salt).decode('utf-8'))
    print("Ana Şifre başarıyla kaydedildi.")

def setup_master_password():
    """İlk çalıştırma için Ana Şifre belirleme."""
    print("--- İLK KURULUM ---")
    password = input("Lütfen yeni bir Ana Şifre belirleyin (Min 8 karakter): ")
    if len(password) < 8:
        print("Hata: Şifre en az 8 karakter olmalıdır.")
        return setup_master_password()
        
    confirm = input("Şifreyi tekrar girin: ")
    if password != confirm:
        print("Hata: Şifreler eşleşmiyor.")
        return setup_master_password()

    salt = os.urandom(16)
    hashed = hash_master_password(password)
    
    save_master_data(hashed, salt)
    print("Kurulum tamamlandı. Yeniden Giriş Yapın.")
    time.sleep(2)

def login():
    """Ana Şifre girişi ve AES anahtarını türetme."""
    global GLOBAL_AES_KEY
    hashed_pass, salt = load_master_data()

    if hashed_pass is None:
        setup_master_password()
        return False

    print("--- PAROLA YÖNETİCİSİ GİRİŞ ---")
    password = input("Ana Şifrenizi girin: ")
    
    if check_master_password(password, hashed_pass):
        GLOBAL_AES_KEY = derive_key(password, salt)
        print("Giriş Başarılı!")
        time.sleep(1)
        return True
    else:
        print("Hata: Yanlış Ana Şifre.")
        time.sleep(2)
        return False

# --- ANA MENÜ İŞLEMLERİ ---

def add_password_entry():
    """Yeni bir parola kaydeder."""
    print("\n--- YENİ ŞİFRE EKLE ---")
    site = input("Site Adı (Title): ")
    username = input("Kullanıcı Adı: ")
    password_choice = input("Şifre (Boş bırakırsanız rastgele oluşturulur): ")

    if not password_choice:
        password_choice = generate_secure_password(length=20)
        print(f"Rastgele Şifre Oluşturuldu: {password_choice}")

    # ÖNEMLİ DÜZELTME: Kullanıcı adını arama için Hash'le
    username_enc = hash_search_key(username) 
    
    # Parolayı AES ile şifrele (bu hala rastgele IV kullanabilir, bu normaldir)
    password_enc, iv_placeholder = encrypt_data(password_choice, GLOBAL_AES_KEY)
    
    save_entry(site, username_enc, password_enc, iv_placeholder) 
    print(f"'{site}' kaydı başarıyla eklendi.")

def view_passwords():
    """Şifreli kullanıcı adına göre kayıtları getirir ve çözer."""
    print("\n--- ŞİFRELERİ GÖRÜNTÜLE ---")
    search_username = input("Hangi kullanıcı adına ait şifreleri görmek istiyorsunuz? ")
    
    # ÖNEMLİ DÜZELTME: Arama yapmak için kullanıcı adını da Hash'le
    search_username_enc = hash_search_key(search_username) 
    
    encrypted_entries = get_entries_by_username(search_username_enc)
    
    if not encrypted_entries:
        print(f"'{search_username}' adına ait kayıt bulunamadı.")
        return

    print("\n--- BULUNAN KAYITLAR ---")
    print(f"{'ID':<4} | {'Site/Title':<20} | {'Kullanıcı Adı':<20} | {'Şifre'}")
    print("-" * 75)

    for entry in encrypted_entries:
        # Not: username_enc artık hash'li olduğu için çözemeyiz, 
        # ancak parolayı çözebiliriz. Görüntüleme için kullanıcı adını tekrar alalım:
        
        # Kullanıcı Adı'nın çözülmesi gerekli değil, arama metnini kullanalım
        decrypted_password = decrypt_data(entry['password_enc'], GLOBAL_AES_KEY)
        
        print(f"{entry['id']:<4} | {entry['site']:<20} | {search_username:<20} | {decrypted_password}")
    print("-" * 75)

# --- TUI ANA DÖNGÜSÜ ---

def run_tui():
    init_db() 
    
    while not login():
        clear_screen()

    while True:
        clear_screen()
        print("\n=== PAROLA YÖNETİCİSİ TUI ===")
        print("1. Şifre Kaydet")
        print("2. Şifreleri Görüntüle (Kullanıcı Adına Göre)")
        print("0. Çıkış")
        print("-------------------------------")
        
        choice = input("Seçiminizi yapın (0-2): ")
        
        if choice == '1':
            add_password_entry()
            input("Devam etmek için Enter'a basın...")
        elif choice == '2':
            view_passwords()
            input("Devam etmek için Enter'a basın...")
        elif choice == '0':
            print("Çıkış yapılıyor...")
            break
        else:
            print("Geçersiz seçim.")
            input("Devam etmek için Enter'a basın...")

if __name__ == '__main__':
    run_tui()