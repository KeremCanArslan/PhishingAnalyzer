import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import email
from email import policy
from email.parser import BytesParser
import email.utils 
import re
import socket
import threading
import time
import os
import difflib
import requests
import base64
from urllib.parse import urlparse
import urllib3 
import pickle
from datetime import datetime

# SSL hata uyarılarını kapattma
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# HTML parçalamak için BeautifulSoup kullanıyoruz
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except:
    HAS_BS4 = False
    print("BeautifulSoup kütüphanesi yüklü değil")

# Domain yaşı sorgusu için
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    print("python-who kütüphanesi yok.")

#Gerekli dosyalar
DOMAIN_DOSYASI = "top_domains.txt"
API_DOSYASI = "virustotal_api.txt"

class EmailAnalyzer:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        
        # Eğer eğitilmiş yapay zeka modeli varsa onu yüklüyoruz
        if os.path.exists("spam_model.pkl") and os.path.exists("vectorizer.pkl"):
            try:
                with open("spam_model.pkl", "rb") as f: 
                    self.model = pickle.load(f)
                with open("vectorizer.pkl", "rb") as f: 
                    self.vectorizer = pickle.load(f)
            except: pass

        # Dolandırıcıların en çok kullandığı ücretsiz servisler
        # Bunlar normalde güvenli ama hackerlar çok kullanıyor.
        self.supheli_platformlar = [
            "kajabi.com", "herokuapp.com", "firebasestorage.googleapis.com", 
            "wixsite.com", "weebly.com", "forms.gle", "docs.google.com", 
            "drive.google.com", "dropbox.com", "s3.amazonaws.com", "ipfs.io",
            "pages.dev", "netlify.app", "vercel.app", "glitch.me"
        ]
        
        # Aciliyet belirten veya para/şifre isteyen kelimeler
        self.kritik_kelimeler = [
            "verify", "account", "suspended", "limit", "wallet", "password", 
            "security", "login", "update", "bank", "metamask", "coin", "crypto",
            "doğrula", "hesap", "askıya", "şifre", "güvenlik", "giriş", "cüzdan"
        ]

    # .eml dosyasını okuyan fonksiyon
    def load_email(self, dosya_yolu):
        try:
            with open(dosya_yolu, 'rb') as f:
                return BytesParser(policy=policy.default).parse(f)
        except: return None

    # spf kontrol
    def check_authentication(self, msg):
        headers = str(msg.get('Authentication-Results', '')).lower() + str(msg.get('Received-SPF', '')).lower()
        # fail kontrol
        if "fail" in headers or "softfail" in headers:
            return False 
        return True 
    # Spoofing kontrol
    def check_header_spoofing(self, msg):
        loglar = []
        suphelicheck = False
        
        gonderen = msg.get('From', '')
        yanit_adresi = msg.get('Reply-To', '')
        
        if yanit_adresi:
            try:
                # İsimleri atıp sadece mail adreslerini alıyoruz
                _, gonderen_mail = email.utils.parseaddr(gonderen)
                _, yanit_mail = email.utils.parseaddr(yanit_adresi)
                
                dom1 = gonderen_mail.split('@')[-1].lower().strip()
                dom2 = yanit_mail.split('@')[-1].lower().strip()
                
                if dom1 != dom2 and dom1 not in dom2 and dom2 not in dom1:
                    suphelicheck = True
                    loglar.append((2, f"[UYARI] Spoofing Tespiti: Gönderen '{dom1}' ama Yanıt Adresi '{dom2}'", 40))
                else:
                    loglar.append((4, f"[BİLGİ] Gönderen ve Yanıt domainleri uyumlu.", 0))
            except: pass
        return suphelicheck, loglar

    # Ek dosya kontrolü
    def scan_attachments(self, msg):
        loglar = []
        risk_var = False
        for part in msg.walk():
            dosya_adi = part.get_filename()
            if dosya_adi:
                uzanti = os.path.splitext(dosya_adi)[1].lower()
                # Exe gibi dosyalar virüs olabilir.
                if uzanti in ['.exe', '.bat', '.scr', '.vbs', '.js', '.jar', '.pdf']:
                    risk_var = True
                    loglar.append((1, f"[TEHLİKE] Riskli dosya eki tespit edildi: {dosya_adi}", 50))
        return risk_var, loglar

    # İçerik ve Linkleri ayıklama
    def extract_content_and_links(self, msg):
        metin = ""
        linkler = []
        sahte_linkler = [] 
        platform_abuse = []
        
        if msg.is_multipart():
            for part in msg.walk():
                # Sadece yazıları alıyoruz. Resim veya binary okumaya çalışınca program çöküyordu.
                if part.get_content_maintype() != 'text':
                    continue

                payload = part.get_payload(decode=True)
                if not payload: continue
                
                try:
                    decoded_text = payload.decode('utf-8', errors='ignore')
                    
                    if part.get_content_type() == "text/html" and HAS_BS4:
                        soup = BeautifulSoup(decoded_text, 'html.parser')
                        metin += soup.get_text() + " "
                        
                        for a in soup.find_all('a', href=True):
                            href = a['href']
                            linkler.append(href)
                            gorunen = a.get_text().strip().lower()
                            
                            # Çok kısa yazıları atla
                            if " " in gorunen or len(gorunen) < 4: continue 
                            
                            # URL Spoofing: Yazıda 'apple.com' yazıp arkada 'hacker.com'a gitmesi
                            if "." in gorunen:
                                gercek_domain = urlparse(href).netloc.lower()
                                if gercek_domain and gorunen not in href and "http" not in gorunen:
                                    if difflib.SequenceMatcher(None, gorunen, gercek_domain).ratio() < 0.4:
                                        sahte_linkler.append(f"Yazı: '{gorunen}' -> Link: '{gercek_domain}'")
                    else:
                        metin += decoded_text + " "
                        linkler.extend(re.findall(r'https?://[^\s<>"]+', decoded_text))
                except: pass 
        else:
            try:
                if msg.get_content_maintype() == 'text':
                    payload = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                    metin = payload
                    linkler = re.findall(r'https?://[^\s<>"]+', payload)
            except: pass
        
        # Platform Abuse Kontrolü
        bulunan_kelimeler = [k for k in self.kritik_kelimeler if k in metin.lower()]
        if bulunan_kelimeler:
            for link in linkler:
                domain = urlparse(link).netloc.lower()
                for platform in self.supheli_platformlar:
                    if platform in domain:
                        platform_abuse.append(f"Kritik kelime ({bulunan_kelimeler[0]}) ile riskli altyapı ({platform}) eşleşti!")
        
        return metin, linkler, sahte_linkler, list(set(platform_abuse))

    # AI tahmini
    def predict_phishing_score(self, text):
        if self.model and self.vectorizer:
            try:
                if not text or len(text) < 5: return 0
                vector_data = self.vectorizer.transform([text])
                return self.model.predict_proba(vector_data)[0][1] * 100
            except: return 0
        return 0

class NetworkManager:
    def __init__(self):
        self.whitelist = []
        self.api_key = None
        
        if os.path.exists(API_DOSYASI):
            try:
                with open(API_DOSYASI, "r") as f: self.api_key = f.read().strip()
            except: pass

        self.guvenilir_siteler = [
            "google", "facebook", "twitter", "instagram", "linkedin", "netflix",
            "paypal", "apple", "microsoft", "amazon", "whatsapp", "adobe",
            "garantibbva", "isbank", "akbank", "ziraatbank", "yapikredi",
            "turkiye", "enabiz", "gib", "egm", "sahibinden", "trendyol", "hepsiburada", "n11"
    
        ]
        self.whitelist_yukle()
    
    def whitelist_yukle(self):
        # Dosya yoksa internetten indiriyoruz
        if not os.path.exists(DOMAIN_DOSYASI):
            try:
                url = "https://raw.githubusercontent.com/scrapy/protego/master/tests/top-10000-websites.txt"
                r = requests.get(url, verify=False, timeout=5)
                if r.status_code == 200:
                    with open(DOMAIN_DOSYASI, "w", encoding="utf-8") as f: f.write(r.text)
            except: pass

        dosya_domainleri = []
        if os.path.exists(DOMAIN_DOSYASI):
            try:
                with open(DOMAIN_DOSYASI, "r", encoding="utf-8") as f:
                    for line in f:
                        temiz = line.strip().lower().replace("www.", "").split('.')[0]
                        if len(temiz) > 3: dosya_domainleri.append(temiz)
            except: pass
        
        self.whitelist = list(set(self.guvenilir_siteler + dosya_domainleri))
        print(f"Whitelist yüklendi: Toplam {len(self.whitelist)} güvenli site.")

    def extract_root_domain(self, url):
        try:
            domain = urlparse(url).netloc if "http" in url else url
            if not domain: return ""
            parcalar = domain.lower().replace("www.", "").split('.')
            # com.tr veya co.uk ayıklamak için
            if len(parcalar) >= 2:
                if parcalar[-1] in ['tr', 'uk', 'fr', 'de'] and len(parcalar) > 2:
                    return parcalar[-3] if parcalar[-2] in ['com', 'co', 'gov', 'org'] else parcalar[-2]
                return parcalar[-2]
            return parcalar[0]
        except: return ""

    # WHOIS SORGUSU
    def check_domain_age(self, domain):
        if not HAS_WHOIS:
            return None, "Kütüphane eksik"
            
        try:
            w = whois.whois(domain)
            tarih = w.creation_date
            
            if isinstance(tarih, list):
                tarih = tarih[0]
            
            if not tarih:
                return None, "Tarih bulunamadi"

            # Saat dilimi hatası
            if tarih.tzinfo is not None:
                tarih = tarih.replace(tzinfo=None)

            gun_sayisi = (datetime.now() - tarih).days
            
        
            LIMIT = 30 
            
            # BURADA DOMAIN ISMINI EKLEDIK
            if gun_sayisi < LIMIT:
                return False, f"Domain ({domain}) ÇOK YENİ: {gun_sayisi} günlük!"
            elif gun_sayisi < 180:
                return False, f"Domain ({domain}) YENİ: {gun_sayisi} günlük. Orta Risk"
            else:
                return True, f"Domain ({domain}) güvenilir: {gun_sayisi} gündür aktif."
                
        except Exception as e:
            # Whois sunucusu bazen ban atıyor veya cevap vermiyor
            return None, "Whois verisi alınamadı"

    def check_virustotal(self, url):
        if not self.api_key: return None, "API Key Yok", 0
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.api_key}
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
            if r.status_code == 200:
                stats = r.json()['data']['attributes']['last_analysis_stats']
                site_sayisi = stats['malicious']
                
                if site_sayisi > 0: 
                    return False, f"ZARARLI ({site_sayisi} motor tespit etti)", site_sayisi
                return True, "Temiz", 0
            return None, "Bilinmiyor", 0
        except: return None, "Hata", 0

    def check_dns_record(self, domain):
        try:
            # ping
            socket.gethostbyname(domain)
            return True
        except: return False

    def check_typosquatting(self, url):
        hedef = self.extract_root_domain("http://" + url)
        if hedef in self.whitelist: return False, None
        
        for orjinal in self.whitelist:
            if abs(len(hedef) - len(orjinal)) > 3: continue
            if hedef[0] != orjinal[0]: continue 

            # typo belirleme
            oran = difflib.SequenceMatcher(None, hedef, orjinal).ratio()
            if 0.85 < oran < 1.0:
                return True, orjinal
        return False, None

# 3. ARAYÜZ
class PhishingAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PHISHING ANALYZER")
        self.root.geometry("1000x850")
        
        tk.Label(root, text="PHISHING ANALYZER", font=("Helvetica", 22, "bold")).pack(pady=20)
        
        frame = tk.Frame(root)
        frame.pack(pady=10)
        
        tk.Label(frame, text="İncelenecek Mail Dosyası (.eml):", font=("Arial", 12)).pack(side=tk.LEFT, padx=5)
        self.entry_path = tk.Entry(frame, width=50, font=("Arial", 11))
        self.entry_path.pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Dosya Seç", font=("Arial", 10), command=self.browse_file).pack(side=tk.LEFT)
        
        self.btn_start = tk.Button(root, text="TARAMAYI BAŞLAT", font=("Arial", 14, "bold"), 
                                   bg="blue", fg="white", width=25, height=2, command=self.start_analysis)
        self.btn_start.pack(pady=15)
        
        self.lbl_status = tk.Label(root, text="Dosya bekleniyor", font=("Arial", 11), fg="gray")
        self.lbl_status.pack()
        
        # Sonuç ekranı
        self.txt_report = scrolledtext.ScrolledText(root, width=90, height=25, state='disabled', font=("Consolas", 12))
        self.txt_report.pack(pady=15, padx=15)

        # Renk Ayarları
        self.txt_report.tag_config("baslik", font=("Arial", 18, "bold"))
        self.txt_report.tag_config("danger", foreground="red", font=("Arial", 16, "bold"))
        self.txt_report.tag_config("warning", foreground="orange", font=("Arial", 16, "bold"))
        self.txt_report.tag_config("attention", foreground="blue", font=("Arial", 16, "bold"))
        self.txt_report.tag_config("safe", foreground="green", font=("Arial", 16, "bold"))
        self.txt_report.tag_config("normal", foreground="black", font=("Consolas", 12))

        tk.Label(root, text="Geliştirici: Kerem ARSLAN - 2026", font=("Arial", 10), fg="blue").pack(side=tk.BOTTOM, pady=10)

        self.email_analyzer = EmailAnalyzer()
        self.network_manager = NetworkManager()

    def browse_file(self):
        f = filedialog.askopenfilename(filetypes=[("Email Files", "*.eml")])
        if f:
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, f)

    def start_analysis(self):
        if not self.entry_path.get():
            messagebox.showwarning("Lütfen önce bir dosya seçin!")
            return
        
        self.lbl_status.config(text="Analiz yapılıyor, lütfen bekleyin", fg="blue")
        self.btn_start.config(state='disabled', text="İŞLENİYOR")
        self.txt_report.config(state='normal')
        self.txt_report.delete(1.0, tk.END)
        self.txt_report.config(state='disabled')
        
        threading.Thread(target=self.run_engine, args=(self.entry_path.get(),)).start()

    def run_engine(self, file_path):
        try:
            time.sleep(0.5)
            msg = self.email_analyzer.load_email(file_path)
            if not msg: raise Exception("Dosya okunamadı veya bozuk.")

            puan = 0
            loglar = []
            
            # HEADER KONTROLLERİ
            is_spoofed, l = self.email_analyzer.check_header_spoofing(msg)
            if is_spoofed: 
                puan += 40
                for _, txt, p in l: loglar.append((2, txt, p))
            else:
                if l: loglar.append((4, l[0][1], 0))
            
            if not self.email_analyzer.check_authentication(msg):
                puan += 60
                loglar.append((2, "[UYARI] SPF/DKIM Hatası kimlik doğrulanamadı", 60))
            else:
                loglar.append((4, "[BİLGİ] SPF/DKIM imzaları geçerli.", 0))

            has_virus, l = self.email_analyzer.scan_attachments(msg)
            if has_virus: 
                puan += 50
                for _, txt, p in l: loglar.append((1, txt, p))
            
            # İÇERİK KONTTROL
            content, links, spoofed_links, platform_abuse = self.email_analyzer.extract_content_and_links(msg)
            
            if spoofed_links:
                puan += 85
                for s in spoofed_links:
                    loglar.append((1, f"[KRİTİK] URL spoofing: {s}", 85))

            if platform_abuse:
                puan += 90
                for pa in platform_abuse:
                    loglar.append((1, f"[KRİTİK] {pa}", 90))
            
            ai_prob = self.email_analyzer.predict_phishing_score(content)
            ai_puan = 25 if ai_prob > 90 else 15 if ai_prob > 70 else 0
            puan += ai_puan
            if content:
                loglar.append((3, f"[AI] Phishing Olasılığı: %{ai_prob:.1f}", ai_puan))
            else:
                loglar.append((3, f"[AI] Metin içeriği bulunamadı", 0))

            #DOMAIN VE URL KONTROLÜ
            checked_domains = set()
            for link in list(set(links))[:5]:
                try:
                    parsed = urlparse(link)
                    domain = parsed.netloc
                    if not domain or domain in checked_domains: continue
                    checked_domains.add(domain)
                    
                    if "w3.org" in domain or "schema.org" in domain: continue

                    # IP Adresi kontrolü
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                        puan += 90
                        loglar.append((1, f"[KRİTİK] IP Adresi kullanımı: {domain}", 90))
                        continue
                    
                    # HTTP kontrolü
                    if parsed.scheme != 'https':
                        puan += 30
                        loglar.append((2, f"[DİKKAT] Güvensiz bağlantı (HTTP): {domain}", 30))
                    else:
                        loglar.append((4, f"[BİLGİ] Güvenli bağlantı (HTTPS): {domain}", 0))

                    # DNS kontrolü
                    if not self.network_manager.check_dns_record(domain):
                        puan += 50
                        loglar.append((2, f"[HATA] Siteye ulaşılamıyor: {domain}", 50))
                        continue

                    # WHOIS Kontrolü
                    if HAS_WHOIS:
                        is_old, age_msg = self.network_manager.check_domain_age(domain)
                        if is_old is False: 
                            if "YENİ" in age_msg: 
                                puan += 90
                                loglar.append((1, f"[KRİTİK] {age_msg}", 90))
                            else: 
                                puan += 40
                                loglar.append((2, f"[DİKKAT] {age_msg}", 40))
                        elif is_old is True:
                            loglar.append((4, f"[BİLGİ] {age_msg}", 0))
                    
                    # Typosquatting
                    is_fake, real = self.network_manager.check_typosquatting(domain)
                    if is_fake:
                        puan += 80
                        loglar.append((1, f"[TEHLİKE] '{domain}' adresi '{real}' sitesini taklit ediyor!", 80))
                    else:
                        loglar.append((4, f"[BİLGİ] Domain temiz: {domain}", 0))

                    # VirusTotal Kontrolü
                    is_safe, vt_msg, mal_count = self.network_manager.check_virustotal(link)
                    if is_safe is False:
                        dynamic_score = min(mal_count * 10, 100)
                        puan += dynamic_score
                        loglar.append((1, f"[KRİTİK] VirusTotal: {vt_msg}", dynamic_score))
                    elif is_safe is True:
                        loglar.append((4, f"[BİLGİ] VirusTotal Temiz: {domain}", 0))

                except: pass
            
            puan = min(puan, 100)
            self.generate_report(os.path.basename(file_path), puan, loglar)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Hata", f"Analiz hatası:\n{e}"))
            self.lbl_status.config(text="Hata Oluştu!", fg="red")
        
        finally:
            self.btn_start.config(state='normal', text="TARAMAYI BAŞLAT")

    def generate_report(self, filename, score, logs):
        self.lbl_status.config(text="Analiz Tamamlandı", fg="green")
        self.txt_report.config(state='normal')
        self.txt_report.delete(1.0, tk.END)
        
        if score >= 75:
            durum = "YÜKSEK RİSKLİ"
            renk = "danger"
        elif score >= 50:
            durum = "RİSKLİ"
            renk = "warning"
        elif score >= 25:
            durum = "DÜŞÜK RİSKLİ"
            renk = "attention"
        else:
            durum = "GÜVENLİ"
            renk = "safe"
            
        self.txt_report.insert(tk.END, f"DOSYA ADI: {filename}\n")
        self.txt_report.insert(tk.END, f"RİSK PUANI: {score}/100\n", "baslik")
        self.txt_report.insert(tk.END, f"SONUÇ: {durum}\n", renk)
        self.txt_report.insert(tk.END, "-"*60 + "\n")
        self.txt_report.insert(tk.END, "DETAYLI SONUÇLAR (Önem Sırasına Göre):\n", "normal")
        
        logs.sort(key=lambda x: x[0])
        
        for priority, msg, pts in logs:
            tag = "normal"
            puan_str = f"(+{pts} Puan)" if pts > 0 else "(0 Puan)"
            
            if priority == 1: tag = "danger"
            elif priority == 2: tag = "warning"
            elif priority == 3: tag = "attention" 
            elif priority == 4: tag = "safe"
            
            self.txt_report.insert(tk.END, f">> {msg} {puan_str}\n", tag)
            
        self.txt_report.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingAnalyzerApp(root)
    root.mainloop()