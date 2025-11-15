import os
from dotenv import load_dotenv
from flask import Flask

# .env dosyasındaki değişkenleri yükler
load_dotenv()

# Flask uygulamasını başlatır
app = Flask(__name__)

@app.route('/')
def index():
    return "Password Manager - Local Server Running"

def main():
    host = os.getenv("APP_HOST")
    port = int(os.getenv("APP_PORT"))
    debug = os.getenv("APP_DEBUG").lower() in ('true', '1', 't')

    print("---------------------------------------")
    print(f"Server Başlatılıyor...")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Debug Modu: {debug}")
    print("---------------------------------------")

    app.run(
        host=host, 
        port=port, 
        debug=debug
    )

if __name__ == '__main__':
    main()
