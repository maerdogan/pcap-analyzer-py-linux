# Yol haritası

Bu liste [pcap-analyzer proje panosundan](https://github.com/users/maerdogan/projects/6) alındı ve 2026-11-17 tarihindeki durumu gösterir. Pano dört repoda ortaktır: pcap-analyzer-py, pcap-analyzer-py-k8s, pcap-analyzer-py-docker ve pcap-analyzer-py-linux.

89 maddenin 89 tanesi tamamlandı.

## Temel ürün

| Madde | Alan | Öncelik | Durum |
|---|---|---|---|
| tshark doğrulaması (M0) | Analiz | – | Tamamlandı |
| Analiz motoru ve DuckDB sonuç deposu | Analiz | – | Tamamlandı |
| HTTP/1.1 ve HTTP/2 süre ölçümü | Analiz | – | Tamamlandı |
| HTTPS çözme: TLS key log ve RSA anahtarı | Analiz | – | Tamamlandı |
| RTT ve yakalama noktası tespiti | Analiz | – | Tamamlandı |
| Analiz öncesi filtre | Analiz | – | Tamamlandı |
| URL grupları, host adları ve TCP bağlantı listesi | Analiz | – | Tamamlandı |
| Trafik çifti incelemesi | Analiz | – | Tamamlandı |
| Yavaşlık nedeni analizi ve sorunlar listesi | Analiz | – | Tamamlandı |
| Hassas verilerin maskelenmesi | Güvenlik | – | Tamamlandı |
| Web arayüzü | Arayüz | – | Tamamlandı |
| İki capture karşılaştırma ve iki nokta eşleştirme | Analiz | – | Tamamlandı |
| Veri, grafik ve rapor dışa aktarma | Entegrasyon | – | Tamamlandı |
| Container, Compose, Kubernetes ve kurulum rehberi | Dağıtım | – | Tamamlandı |
| Profesyonel arayüz tasarımı | Arayüz | – | Tamamlandı |
| Yerel cluster kurulumu: NGINX Ingress ve Gateway API | Dağıtım | – | Tamamlandı |
| Güvenlik rehberi | Güvenlik | – | Tamamlandı |
| Giriş kilidi, parola ve veri saklama düzeltmeleri | Güvenlik | – | Tamamlandı |
| Sudo'suz Linux paketi (glibc 2.26+) | Dağıtım | – | Tamamlandı |
| Her ortama ayrı klasör | Dağıtım | – | Tamamlandı |
| Sentetik örnekler, testler ve CI | Kalite | – | Tamamlandı |

<details><summary>tshark doğrulaması (M0)</summary>

**Sonuç:** tshark 4.6 ile alanların davranışı ölçüldü. Gövde birleştirmeyi kapatma, istek ve yanıtları akış başına sırayla eşleştirme ve AppArmor için dosyaları `/tmp` altına kopyalama kararları buradan çıktı.

</details>

<details><summary>Analiz motoru ve DuckDB sonuç deposu</summary>

**Sonuç:** Her analiz tek bir DuckDB dosyasına yazılır. Aynı girdi yeniden işlenmez, kayıtlı sonuç açılır.

**Commit:** [a62cf7f](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/a62cf7f)

</details>

<details><summary>HTTP/1.1 ve HTTP/2 süre ölçümü</summary>

**Sonuç:** İstek başına gönderim, bekleme, servis, ilk bayt, aktarım ve toplam süre ölçülür.

**Commit:** [a62cf7f](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/a62cf7f)

</details>

<details><summary>HTTPS çözme: TLS key log ve RSA anahtarı</summary>

**Sonuç:** Anahtarla şifreli trafik çözülür. Trafik şifreli kalırsa uygulama uyarır.

**Commit:** [a62cf7f](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/a62cf7f)

</details>

<details><summary>RTT ve yakalama noktası tespiti</summary>

**Sonuç:** Bağlantının iki yönü için RTT ölçülür, capture'ın alındığı taraf tahmin edilir ve servis süresi ağ gecikmesinden ayrılır.

**Commit:** [a62cf7f](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/a62cf7f)

</details>

<details><summary>Analiz öncesi filtre</summary>

**Sonuç:** IP veya CIDR, port, zaman aralığı ve Wireshark filtresiyle analiz edilecek trafik baştan daraltılır.

**Commit:** [a62cf7f](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/a62cf7f)

</details>

<details><summary>URL grupları, host adları ve TCP bağlantı listesi</summary>

**Sonuç:** `/users/{id}` gibi URL şablonları, durum kodları, bağlantı başına istek sayısı ve ortalama süre, en yavaş ilk 5 veya %10 istek.

**Commit:** [45dff94](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/45dff94)

</details>

<details><summary>Trafik çifti incelemesi</summary>

**Sonuç:** Kaynak, hedef, port, tür, URL ve boyuta göre özel inceleme ve en yavaş 10 isteğin dökümü.

**Commit:** [45dff94](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/45dff94)

</details>

<details><summary>Yavaşlık nedeni analizi ve sorunlar listesi</summary>

**Sonuç:** Yavaş servis, ağ gecikmesi, paket kaybı, yavaş alıcı, Delayed ACK, kuyruk, gateway hatası ve eksik yanıt gibi nedenler düz dille açıklanır.

**Commit:** [45dff94](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/45dff94)

</details>

<details><summary>Hassas verilerin maskelenmesi</summary>

**Sonuç:** URL, başlık ve gövde önizlemelerindeki bilinen hassas alanlar kaydedilmeden önce maskelenir.

**Commit:** [45dff94](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/45dff94)

</details>

<details><summary>Web arayüzü</summary>

**Sonuç:** Tek admin girişi, capture yükleme, geçmiş, sorunlar, grafikler, sıralanabilir tablolar, istek içeriği ve kayıtlı filtreler.

**Commit:** [afefbc6](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/afefbc6)

</details>

<details><summary>İki capture karşılaştırma ve iki nokta eşleştirme</summary>

**Sonuç:** URL ve aşama başına değişimler görülür. Aynı istek iki noktada eşleştirilir.

**Commit:** [2f57de5](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/2f57de5)

</details>

<details><summary>Veri, grafik ve rapor dışa aktarma</summary>

**Sonuç:** CSV, Excel, JSON, PNG, SVG, tek dosya HTML rapor ve bağlantı başına PCAP.

**Commit:** [2f57de5](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/2f57de5), [56437ab](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/56437ab)

</details>

<details><summary>Container, Compose, Kubernetes ve kurulum rehberi</summary>

**Sonuç:** Container imajı, Compose dosyası, Kubernetes manifestleri, systemd birimi ve `docs/install.md`. Compose ve systemd kurulumu henüz denenmedi, ayrı maddesi var.

**Commit:** [2f57de5](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/2f57de5)

</details>

<details><summary>Profesyonel arayüz tasarımı</summary>

**Sonuç:** Yan menü, metrik bandı, sıralı süre dökümü ve hizalı yavaş istek tabloları.

**Commit:** [848a6ef](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/848a6ef)

</details>

<details><summary>Yerel cluster kurulumu: NGINX Ingress ve Gateway API</summary>

**Sonuç:** Uygulama `analyzer` cluster'ında iki yoldan da erişilebilir. Giriş, yükleme ve 100 MB sınırı Gateway üzerinden denendi.

**Commit:** [289834e](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/289834e)

</details>

<details><summary>Güvenlik rehberi</summary>

**Sonuç:** README'de eksik korumalar, kurulumu yapanın eklemesi gerekenler ve dağıtım şeması yer alır.

**Commit:** [f7c650b](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/f7c650b)

</details>

<details><summary>Giriş kilidi, parola ve veri saklama düzeltmeleri</summary>

**Sonuç:** Sahte `X-Forwarded-For` kilidi aşamaz, sıkıştırılmış dosyalar reddedilir, süresi dolan veriler saatlik silinir, geçersiz parola özetiyle sunucu başlamaz.

**Commit:** [a21da12](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/a21da12), [5f8e2d8](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/5f8e2d8)

</details>

<details><summary>Sudo'suz Linux paketi (glibc 2.26+)</summary>

**Sonuç:** Python, kütüphaneler ve tshark pakete dahil. Ubuntu 18.04 ve Rocky 8 container'larında internetsiz ve root olmadan çalıştı.

**Commit:** [628476f](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/628476f)

</details>

<details><summary>Her ortama ayrı klasör</summary>

**Sonuç:** `kubernetes`, `docker` ve `linux-glibc2.26-server` klasörleri.

**Commit:** [decee1f](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/decee1f)

</details>

<details><summary>Sentetik örnekler, testler ve CI</summary>

**Sonuç:** Süreleri önceden bilinen örnek capture'lar üretilir. Testler GitHub Actions'ta her push'ta çalışır.

**Commit:** [a62cf7f](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/a62cf7f), [2f57de5](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/2f57de5)

</details>

## Güvenilir temel

| Madde | Alan | Öncelik | Durum |
|---|---|---|---|
| Uygulama kodunu Linux paketinden ayır | Dağıtım | Yüksek | Tamamlandı |
| Gerçek capture ile doğrulama: Linux, pod ve worker node | Analiz | Yüksek | Tamamlandı |
| Analiz zaman sınırı ve iptal | Güvenlik | Yüksek | Tamamlandı |
| Capture kalite raporu | Analiz | Yüksek | Tamamlandı |
| Kurulum yollarını uçtan uca doğrulama | Dağıtım | Orta | Tamamlandı |
| Güvenli varsayılanlar: CSRF, HSTS, NetworkPolicy, limitler | Güvenlik | Orta | Tamamlandı |
| Sürüm süreci: etiket, Release ve GHCR imajı | Dağıtım | Orta | Tamamlandı |
| Bağımlılık kilitleme ve zafiyet taraması | Güvenlik | Orta | Tamamlandı |
| GPL lisans uyumunu tamamla | Kalite | Orta | Tamamlandı |
| Lab cluster'ını gerçek veriye hazırla | Güvenlik | Orta | Tamamlandı |
| SECURITY.md, CONTRIBUTING ve issue şablonları | Kalite | Düşük | Tamamlandı |
| Neden açıklamaları için bilgi bankası | Analiz | Yüksek | Tamamlandı |
| Skor tabelalı yeni arayüz | Arayüz | – | Tamamlandı |
| Bozuk capture'ları analiz etme | Analiz | Orta | Tamamlandı |
| Yükleme sınırları: 500 MB capture, 500 MB key log, 200 MB RSA anahtarı | Güvenlik | Orta | Tamamlandı |

<details><summary>Uygulama kodunu Linux paketinden ayır</summary>

**Neden:** `bundle/` uygulama kodunu da içeriyor. `src/` her değiştiğinde paket yeniden üretilmeli ve Git geçmişine yaklaşık 100 MB ekleniyor. Bu listedeki neredeyse her madde `src/` değiştirdiği için ilk bu çözülmeli.

**Kapsam:** Pakette yalnız Python, kütüphaneler ve tshark kalsın. `run.sh` uygulamayı repodaki `src/` klasöründen çalıştırsın. Paket yalnız bağımlılık değişince üretilsin.

**Bitti sayılır:** `src/` değişikliğinden sonra paket üretmeden `run.sh` yeni kodu çalıştırır ve eski dağıtım testleri geçer.

</details>

<details><summary>Gerçek capture ile doğrulama: Linux, pod ve worker node</summary>

**Sonuç:** Gerçek Linux trafiğinde ve analyzer cluster'ında (Calico, tek node) worker node `-i any`, uygulama pod'u ve NGINX pod'u capture'larında istek sayıları tshark ve istemciyle uyuştu. 600 MB'lık gerçek HTTPS node capture'ında da istek sayıları tshark ile aynı. 0.6.1'de bir Linux sunucu, bir `-i any` host ve NetScaler'ın iki tarafından alınmış dört gerçek capture'da istek sayıları, durum kodları, TTFB ve yeniden gönderimler tshark ile uyuştu, parçalı okuma tek geçişle aynı çıktı. Bu testlerde `100-continue` yanıt sınırı, MSS'siz GSO kopyaları, yanlış TLS anahtar uyarısı ve capture sonunda kesilen istekler bulunup düzeltildi. README'deki durum notu buna göre güncellendi. Test cluster'ında iki namespace'teki pod'lar arasında, Service üzerinden giden trafikte istemci, sunucu ve node capture'larında istek sayıları tshark ile, TTFB istemcinin ölçtüğüyle uyuştu; iki nokta eşleşmesi %100. Bu testte DNS süresinin arama alanlarını ve zaman aşımına uğrayan sorguları saymadığı bulunup düzeltildi. 2026-11-08'de iki node'lu, Cilium'lu bir deneme cluster'ında önce VXLAN, sonra Geneve modunda, iki node'un arayüzlerinden ve `tcpdump -i any` ile alınan capture'larda 39 bilinen isteğin sayısı, durum kodları, pod adresleri ve TTFB'si tshark ve istemcinin ölçtüğüyle uyuştu; `-i any` kopyaları ayıklandı. Bu testte tshark 4.2'nin 8472 portundaki VXLAN'ı çözmediği, isteğin paket listesinin tünelde node adreslerini ve kopyaları gösterdiği, paket numaralarının yanlış olduğu ve capture rehberinin 8472'yi atladığı bulunup 0.6.3'te düzeltildi. Geneve testinde bir cevabın iki node'un arayüzündeki capture'a da girmediği görüldü; istemcinin ACK'leri cevabın geldiğini gösterdiği için bu artık "Cevap capture'a girmedi" olarak ayrılıyor.

**Neden:** Uygulama şimdiye kadar yalnız sentetik capture'larla denendi. NetScaler üzerinde dump yetkisi olmadığı için gerçek veri Linux sunucu, pod ve worker node'dan gelecek.

**Kapsam:** Üç noktadan alınan gerçek capture'larda yakalama noktası, eşleştirme ve süreleri Wireshark ile karşılaştır. SNAT, `tcpdump -i any` ve worker node'daki VXLAN veya Geneve sarmalı doğru işlensin. Sarmalı trafikte pod IP'si yerine dış IP görünme riski var, çünkü kod ilk IP değerini alıyor.

**Bitti sayılır:** Her noktadan en az bir gerçek capture'da sonuçlar Wireshark ile uyuşur ve README'deki uyarı güncellenir.

**Karar:** Her noktadan anonimleştirilmiş birer gerçek capture gerekiyor.

</details>

<details><summary>Analiz zaman sınırı ve iptal</summary>

**Neden:** Analizin süre sınırı yok. Varsayılan iki iş hakkı, takılan işlerle dolarsa yeni analizler bekler.

**Kapsam:** tshark ve motor için süre sınırı, arayüzden iptal, yarım kalan işin temizlenmesi.

**Bitti sayılır:** Süresi dolan iş açık bir hatayla biter, geçici dosya bırakmaz ve sıradaki iş başlar.

</details>

<details><summary>Capture kalite raporu</summary>

**Neden:** Kötü capture yanlış teşhis üretir. Kesik paket ve offload uyarısı var, ama capture sırasında düşen paketler gerçek paket kaybıyla karışabiliyor. İlk planda söylediğimiz bu uyarı henüz yok.

**Kapsam:** ACK'lenmiş ama görülmemiş segmentler, capture başında veya sonunda kesilen bağlantılar, tek yönlü trafik ve iki nokta arasındaki saat farkı. Hepsi tek bir güven özetinde toplansın.

**Bitti sayılır:** Her analizin üstünde güven özeti görünür ve sentetik örneklerde beklenen uyarılar çıkar.

</details>

<details><summary>Kurulum yollarını uçtan uca doğrulama</summary>

**Sonuç:** Compose, gerçek systemd ve glibc 2.26, 2.27, 2.28 üzerinde Linux klasörü; yükleme, analiz, dışa aktarma ve silme akışını geçti. `tools/check_install.sh` bunu kurulum rehberini izleyerek yapıyor ve CI her push'ta tekrarlıyor. 2026-11-08'de kendi çekirdekleriyle çalışan, ağsız iki sanal makinede README adımları sudo'suz bir kullanıcıyla baştan sona izlendi: Ubuntu 18.04 (çekirdek 4.15, glibc 2.27) üzerinde linux-glibc2.26-server, CentOS 7.9 (çekirdek 3.10, user namespace kapalı, glibc 2.17) üzerinde linux-glibc2.17-server. İkisinde de giriş, yükleme, analiz, dışa aktarma ve silme, tünelli node capture'ının paket listesi ve body'ler çalıştı; Ubuntu'da dışarıdan HTTPS erişimi de denendi. Kurulum rehberindeki eski 1100 MB Ingress sınırı 1250 MB olarak düzeltildi.

**Neden:** Kurulum yolları elle deneniyordu ve Linux paketi yalnız container'larda çalıştırıldı.

**Kapsam:** Compose, systemd ve gerçek bir eski sunucuda yükleme, analiz ve dışa aktarma akışı.

**Bitti sayılır:** Her yol için `docs/install.md` adımları baştan sona çalışır.

</details>

<details><summary>Güvenli varsayılanlar: CSRF, HSTS, NetworkPolicy, limitler</summary>

**Sonuç:** Oturuma bağlı form token'ı, HTTPS açıkken HSTS, tüm yanıtlarda güvenlik başlıkları, `kubernetes/generic` için `NetworkPolicy`, Compose ve systemd için CPU, bellek ve süreç limitleri. `NetworkPolicy` çıktısı üretildi ama bir cluster'a uygulanmadı.

**Neden:** README'deki eksiklerin bir kısmı kurulumu yapana bırakılmak zorunda değil.

**Kapsam:** TLS açıkken HSTS başlığı, örnek `NetworkPolicy`, Compose için CPU ve bellek limiti, CSRF token.

**Bitti sayılır:** Bu satırlar README'nin eksikler tablosundan çıkar.

</details>

<details><summary>Sürüm süreci: etiket, Release ve GHCR imajı</summary>

**Sonuç:** v0.2.0 etiketi testleri geçti; GHCR imajı ve Release dosyaları oluştu. GHCR paketinin görünürlüğü paket ayarından değiştirilir.

**Neden:** Henüz etiket veya GitHub Release yok. Kimse hangi commit'in hangi sürüm olduğunu göremiyor ve imajı kendi derlemek zorunda.

**Kapsam:** Etiketle tetiklenen CI: testler, GHCR imajı, internetsiz kurulum için imaj arşivi ve sürüm notu.

**Bitti sayılır:** `v0.2.0` etiketi yayımlanmış imaj ve Release üretir.

</details>

<details><summary>Bağımlılık kilitleme ve zafiyet taraması</summary>

**Sonuç:** Kilit dosyası, imaj digest'i, CI taraması, SBOM ve imaj kaynak kanıtı v0.4.0 ile çalıştı.

**Neden:** Python bağımlılıkları ve taban imaj sabit değil, gömülü JavaScript kendini güncellemiyor.

**Kapsam:** Kilit dosyası, imaj digest'i, SBOM, CI'da zafiyet taraması ve imzalı imaj.

**Bitti sayılır:** CI kritik zafiyette uyarır ve her sürümün SBOM'u Release'te bulunur.

</details>

<details><summary>GPL lisans uyumunu tamamla</summary>

**Sonuç:** THIRD_PARTY.md her paket sürümü için kaynak yolunu ve teklifi yazıyor.

**Neden:** Public repoda GPL-2.0-or-later lisanslı tshark ikilileri var. Bugün yalnız Alpine kaynaklarına bağlantı veriliyor.

**Kapsam:** Paketlenen sürümlerin kaynaklarını Release'e ekle veya geçerli bir kaynak teklifi yaz, `THIRD_PARTY.md` dosyasını güncelle.

**Bitti sayılır:** Her paket sürümü için karşılık gelen kaynağa erişim yolu yazılı olur.

</details>

<details><summary>Lab cluster'ını gerçek veriye hazırla</summary>

**Sonuç:** HSTS iki giriş noktasında da açık. 2026-11-06'dan beri her geliştirme ve düzeltme pod'a kendiliğinden dağıtılıyor; pod 0.6.3'te. Kullanıcılar, kayıtlar ve analizler kalıcı diskte, pod yeniden başlayınca kaybolmuyor. 2026-11-07'de canlı Ingress yükleme sınırı 1250m'ye çıkarıldı, üç dosya birlikte yüklenebiliyor. Lab adlarına dış bir CA sertifika veremediği için mevcut sertifika kullanılan makinelere güvenilir olarak ekleniyor; 2026-11-07'de Ubuntu makinede eklendi ve `curl` uyarısız bağlanıyor. 2026-11-07'de admin parolası değiştirildi; yeni parolayla iki giriş noktasından da girildi. 2026-11-08'de sertifika Chrome ve Firefox'un depolarına da eklendi; dört nokta kapandı.

**Neden:** Cluster eski bir sürümdeydi (`628476f`) ve otomatik dağıtım yoktu. Admin parolası sohbet kaydına düştü. Gateway sertifikası self-signed ve HSTS yoktu.

**Kapsam:** Güncel sürüme geçiş, parola değişimi, lab sertifikasının kullanılan makinelerde güvenilir olması ve HSTS.

**Bitti sayılır:** Gerçek capture yüklemeden önce bu dört nokta kapanmış olur.

</details>

<details><summary>SECURITY.md, CONTRIBUTING ve issue şablonları</summary>

**Sonuç:** SECURITY.md, CONTRIBUTING.md ve capture eklememe uyarılı issue şablonları 0.4.0 ile repoda. 2026-11-07'de GitHub'ın özel zafiyet bildirimi açıldı; SECURITY.md'deki Report a vulnerability yolu çalışıyor.

**Neden:** Public projede zafiyet bildirme yolu ve katkı kuralı yok. Issue'lara capture eklenmesi veri sızıntısına yol açabilir.

**Kapsam:** Özel zafiyet bildirimi, katkı rehberi, capture eklememe uyarılı issue şablonları.

**Bitti sayılır:** Dosyalar repoda ve GitHub'ın özel zafiyet bildirimi açık.

</details>

<details><summary>Neden açıklamaları için bilgi bankası</summary>

**Neden:** Herkesin yapay zeka modeline erişimi yok. Açıklamalar uygulamanın içinden gelmeli ve aynı sonuç her zaman aynı metni vermeli.

**Kapsam:** Her neden ve sorun için anlamı, capture'a bağlı satırlar, sıradaki kontroller ve kaynaklar. İçerik `knowledge/` klasöründe, uygulama `knowledge.bin` dosyasını okur. NetScaler RST kodları da okunur.

**Bitti sayılır:** Testler geçer, değişiklik repoya alınır ve Linux paketi yeniden üretilir.

</details>

<details><summary>Skor tabelalı yeni arayüz</summary>

**Sonuç:** Mavi üst bant, son capture şeridi, URL arama, başarılı ve hatalı istek tabelası, iki capture'ı yan yana gösteren karşılaştırma.

**Commit:** [ff33b28](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/commit/ff33b28)

</details>

<details><summary>Bozuk capture'ları analiz etme</summary>

**Sonuç:** Capture bozulan yere kadar analiz ediliyor ve Wireshark'taki gibi bir notla bildiriliyor. Bu durum, düğüm capture'ının sonuna `kubectl delete` mesajı yazıldığında bulundu; o hata da düzeltildi.

**Neden:** Ortasından bozulmuş bir capture, örneğin içine metin yazılmış bir dosya, hiç açılmıyordu.

**Kapsam:** Bozulan yere kadar analiz ve bunu söyleyen bir not.

**Bitti sayılır:** Sonu bozuk sentetik capture bozulan yere kadar analiz edilir ve not görünür.

</details>

<details><summary>Yükleme sınırları: 500 MB capture, 500 MB key log, 200 MB RSA anahtarı</summary>

**Sonuç:** Capture ve key log 500 MB, RSA anahtarı 200 MB. `PCAP_ANALYZER_MAX_SIZE_MB` capture sınırını belirlemeye devam ediyor. Ingress örnekleri üç dosyanın toplamı için 1250 MB kabul ediyor, `tools/pcap-collect.sh` capture'ı 475 MB'ta durduruyor. Her sınır tam sınırında denendi.

**Neden:** Sınırlar 1000 MB capture, 512 MB key log ve 1 MB RSA anahtarıydı; ihtiyaca göre yeniden belirlendi.

**Kapsam:** Uygulama, örnek ayarlar, kurulum rehberi, Ingress örnekleri ve capture toplama aracı.

**Bitti sayılır:** Sınırın bir bayt altı kabul edilir, bir bayt üstü açık bir mesajla reddedilir.

</details>

## Daha derin teşhis

| Madde | Alan | Öncelik | Durum |
|---|---|---|---|
| Zaman serisi: istek, hata ve gecikme grafiği | Analiz | Yüksek | Tamamlandı |
| Capture rehberi: Linux, pod ve worker node komutları | Arayüz | Yüksek | Tamamlandı |
| Backend kırılımı: yük dengeleyici arkasındaki sunucular | Analiz | Yüksek | Tamamlandı |
| tshark korumalı alanı | Güvenlik | Orta | Tamamlandı |
| Ayarlanabilir eşikler ve URL bazlı hedefler | Analiz | Orta | Tamamlandı |
| Waterfall zaman çizelgesi | Arayüz | Orta | Tamamlandı |
| TLS sağlık görünümü | Analiz | Orta | Tamamlandı |
| gRPC ve WebSocket desteği | Analiz | Orta | Tamamlandı |
| Sıkıştırılmış ve parçalı capture'lar | Analiz | Orta | Tamamlandı |
| traceparent ile kesin eşleştirme | Analiz | Düşük | Tamamlandı |
| HAR dışa aktarma | Entegrasyon | Düşük | Tamamlandı |
| Veritabanı protokolleri: PostgreSQL, MySQL, MSSQL, Redis | Analiz | Orta | Tamamlandı |
| NetScaler etkisini iki uçtan ölçme | Analiz | Yüksek | Tamamlandı |
| Trafik incelemede adım istatistikleri ve durum kodları | Analiz | Yüksek | Tamamlandı |
| İstek gönderim süreleri ve 100 Continue | Analiz | Orta | Tamamlandı |
| İsteğin paketleri ve 10 KB body | Arayüz | Orta | Tamamlandı |
| Wireshark karşılaştırması 1: TCP, DNS ve ICMP sorunları, akış grafikleri, filtre ve Decode As | Analiz | Yüksek | Tamamlandı |
| Wireshark karşılaştırması 2: protokol dağılımı, UDP konuşmaları, Flow Graph, akış izleme ve QUIC | Analiz | Orta | Tamamlandı |
| Wireshark karşılaştırması 3: diğer protokollerin süre ölçümü ve SIP/RTP istatistikleri | Analiz | Düşük | Tamamlandı |
| Wireshark 1.1: TCP bayraklarını sorun olarak göster | Analiz | Yüksek | Tamamlandı |
| Wireshark 1.2: Port tekrarı, SACK ve pencere ölçekleme | Analiz | Yüksek | Tamamlandı |
| Wireshark 1.3: DNS hataları | Analiz | Yüksek | Tamamlandı |
| Wireshark 1.4: ICMP ulaşılamaz türleri ve bozuk paketler | Analiz | Yüksek | Tamamlandı |
| Wireshark 1.5: Kayıt sırasında düşürülen paketler | Kalite | Yüksek | Tamamlandı |
| Wireshark 1.6: Bağlantı grafikleri: Stevens/tcptrace, throughput, RTT, pencere | Arayüz | Yüksek | Tamamlandı |
| Wireshark 1.7: IO Graph | Arayüz | Yüksek | Tamamlandı |
| Wireshark 1.8: Display filter | Arayüz | Yüksek | Tamamlandı |
| Wireshark 1.9: Decode As | Analiz | Yüksek | Tamamlandı |
| Wireshark 2.1: Protocol Hierarchy | Arayüz | Orta | Tamamlandı |
| Wireshark 2.2: UDP ve Ethernet konuşmaları, MAC uç noktaları, GeoIP | Analiz | Orta | Tamamlandı |
| Wireshark 2.3: Paket boyutu dağılımı | Arayüz | Orta | Tamamlandı |
| Wireshark 2.4: HTTP Request Sequences ve Load Distribution | Analiz | Orta | Tamamlandı |
| Wireshark 2.5: Flow Graph | Arayüz | Orta | Tamamlandı |
| Wireshark 2.6: Follow Stream ve Export Objects | Güvenlik | Orta | Tamamlandı |
| Wireshark 2.7: QUIC ve HTTP/3 | Analiz | Orta | Tamamlandı |
| Wireshark 3.1: LDAP ve Kerberos süreleri | Analiz | Düşük | Tamamlandı |
| Wireshark 3.2: SMB süreleri | Analiz | Düşük | Tamamlandı |
| Wireshark 3.3: Kafka süreleri | Analiz | Düşük | Tamamlandı |
| Wireshark 3.4: SMTP süreleri | Analiz | Düşük | Tamamlandı |
| Wireshark 3.5: DCERPC, MQTT, AMQP ve FTP süreleri | Analiz | Düşük | Tamamlandı |
| Wireshark 3.6: SIP çağrıları | Analiz | Düşük | Tamamlandı |
| Wireshark 3.7: RTP jitter, kayıp ve sıra bozulması | Analiz | Düşük | Tamamlandı |

<details><summary>Zaman serisi: istek, hata ve gecikme grafiği</summary>

**Neden:** "Sorun ne zaman başladı?" sorusunun cevabı yok. Bugün yalnız gecikme histogramı var ve zamanı göstermiyor.

**Kapsam:** Saniye başına istek, hata oranı, p95, yeniden iletim ve açık bağlantı. Grafikte aralık seçince tablolar filtrelensin.

**Bitti sayılır:** Sentetik örnekte kesintinin başlangıcı grafikten okunur ve seçilen aralık tabloları daraltır.

</details>

<details><summary>Capture rehberi: Linux, pod ve worker node komutları</summary>

**Neden:** Eksik veya yanlış alınan capture analizi baştan bozuyor ve ucuza önlenebilir.

**Kapsam:** IP ve port girilince Linux sunucu, pod ve worker node için hazır `tcpdump` komutu, 100 MB sınırına uygun boyut, TLS key log alma adımları. Her noktanın neyi gösterip neyi göstermediği de yazsın.

**Bitti sayılır:** Rehberdeki komutlarla alınan capture uyarısız analiz edilir.

</details>

<details><summary>Backend kırılımı: yük dengeleyici arkasındaki sunucular</summary>

**Neden:** Gruplama host adına göre yapılıyor. NetScaler arkasında tek bir sunucunun yavaş olması ortalamada kayboluyor.

**Kapsam:** Sunucu IP'si başına istek dağılımı, gecikme, hata ve sıfırlama. Diğerlerinden sapan sunucu işaretlensin.

**Bitti sayılır:** Sentetik örnekte yavaş sunucu tek bakışta bulunur.

</details>

<details><summary>tshark korumalı alanı</summary>

**Sonuç:** CPU ve dosya limiti her yerde. Linux sunucuda ağsız ve yalnız kendi dosyalarıyla, pod'da Landlock ile çalışıyor; test cluster'ında başka analizin dosyası reddedildi.

**Neden:** tshark güvenilmeyen dosya okuyor ve uygulamanın bütün yetkilerini paylaşıyor. Bir tshark açığı tüm capture'ları ortaya çıkarabilir.

**Kapsam:** Ağı kapalı, kendi dizininde, CPU ve bellek limitli çalışma. Sudo'suz Linux paketinde de çalışmalı.

**Bitti sayılır:** tshark süreci başka analizlerin dosyalarını okuyamaz.

</details>

<details><summary>Ayarlanabilir eşikler ve URL bazlı hedefler</summary>

**Sonuç:** Yavaş istek sınırı ve URL hedefleri Ayarlar ekranında. Sınır yeni analizlere uygulanır.

**Neden:** Yavaş istek eşiği kodda 200 ms olarak sabit. Bu değer her servis için doğru değil.

**Kapsam:** Genel eşik ayarı, URL şablonu başına hedef süre, hedefi aşan isteklerin raporlanması.

**Bitti sayılır:** Eşik arayüzden değişir ve neden analizi yeni değere göre çalışır.

</details>

<details><summary>Waterfall zaman çizelgesi</summary>

**Sonuç:** Bağlantı sayfasında istekler aşama renkleriyle tek eksende, PNG ve SVG kaydı var.

**Neden:** Süre dökümü sayı olarak var, ama bağlantıdaki kuyruk ve paralel HTTP/2 akışları gözle görülmüyor. İlk seçimde alınmamıştı (B3).

**Kapsam:** Bir bağlantının isteklerini aşama renkleriyle aynı zaman ekseninde göster.

**Bitti sayılır:** Bağlantı sayfasında çizelge açılır ve PNG olarak kaydedilir.

</details>

<details><summary>TLS sağlık görünümü</summary>

**Sonuç:** TLS sekmesi: sürüm, cipher, ALPN, sürdürülen oturum, cevapsız ClientHello, uyarılar, sertifika bitişi.

**Neden:** Sürüm, SNI ve el sıkışma süresi kaydediliyor ama ayrı bir görünümde sunulmuyor. İlk seçimde alınmamıştı (B9).

**Kapsam:** Sürüm, cipher, ALPN, oturum sürdürme, yanıtsız ClientHello, TLS alert ve görülebiliyorsa sertifika bitiş tarihi.

**Bitti sayılır:** Şifreli capture'da anahtar olmadan da TLS sorunları listelenir.

</details>

<details><summary>gRPC ve WebSocket desteği</summary>

**Sonuç:** Gerçek gRPC ve WebSocket trafiğinde sonuçlar tshark ile uyuştu.

**Neden:** Uzun ömürlü WebSocket bağlantıları yanlışlıkla yavaş istek sayılabilir. gRPC'de hata durumu HTTP kodunda değil `grpc-status` içinde gelir.

**Kapsam:** gRPC metodu ve durumu, WebSocket upgrade ve bağlantı ömrü için ayrı işleme.

**Bitti sayılır:** Örnek capture'larda gRPC hataları görünür ve WebSocket yavaş istek sayılmaz.

</details>

<details><summary>Sıkıştırılmış ve parçalı capture'lar</summary>

**Sonuç:** gzip sınırla açılıyor. Parçalar mergecap ile, yoksa yalnız tshark ile birleşiyor.

**Neden:** `.gz` dosyaları boyut riski nedeniyle reddediliyor. Döngüsel capture'lar birden çok dosyaya bölünüyor.

**Kapsam:** Açılırken boyut sınırını uygulayan güvenli açma ve birden çok dosyayı `mergecap` ile birleştirme. Araç Linux paketine de eklenmeli.

**Bitti sayılır:** Sınırı aşan arşiv açılma sırasında durur ve parçalı capture tek analiz olarak açılır.

</details>

<details><summary>traceparent ile kesin eşleştirme</summary>

**Sonuç:** traceparent trace kimliği eşleştirir, başlık adı ayarlanır.

**Neden:** İki nokta eşleştirmesi yalnız `X-Request-ID` kullanıyor. Bu başlık yoksa eşleşme tahmine dayanıyor.

**Kapsam:** W3C `traceparent` desteği ve kimlik başlığı adının ayarlanabilmesi.

**Bitti sayılır:** `traceparent` taşıyan istekler kesin eşleşme olarak görünür.

</details>

<details><summary>HAR dışa aktarma</summary>

**Sonuç:** Tüm veya filtrelenmiş istekler maskeli HAR olarak iniyor.

**Neden:** HAR, tarayıcı araçları ve web ekiplerinin alışık olduğu ortak biçim.

**Kapsam:** Filtrelenmiş istekleri süre dökümüyle HAR olarak indirme. Maskeleme HAR'da da geçerli olmalı.

**Bitti sayılır:** İndirilen dosya tarayıcının ağ panelinde açılır.

</details>

<details><summary>Veritabanı protokolleri: PostgreSQL, MySQL, MSSQL, Redis</summary>

**Sonuç:** 0.6.3'te geldi. Sorgular tshark'ın kendi çözücüleriyle okunuyor: sorgu metni, süre, sunucu bekleme süresi, satır sayısı ve hata kodu. Yeni Veritabanları görünümü sunucuları, en çok süre alan sorguları, hataları ve en yavaş sorguları gösteriyor; istek sayfası, capture uygulama sunucusunda alındıysa o sırada çalışan sorguları ve en az birinin çalıştığı süreyi listeliyor. Hatalar ve 500 ms'yi aşan sorgular Sorunlar'da, sorgular dışa aktarılabiliyor. Sorgulardaki ve hata mesajlarındaki değerler ? olarak saklanıyor. Standart dışı portlar PCAP_ANALYZER_DB_PORTS ile okunuyor. Sentetik örneklerde tshark ile uyuştu; ayrıca gerçek PostgreSQL 16, MySQL 8.0, SQL Server 2022 ve Redis 7 sunucularında psycopg, mysql-connector, python-tds ve redis-py sürücüleriyle (hazırlanan sorgular, pipeline, RPC, hatalar, yavaş sorgular) denendi. Şifreli veritabanı bağlantıları okunamıyor.

**Neden:** Sunucu tarafı capture'larda "servis yavaş" cevabının arkasında sıkça veritabanı oluyor. tshark bu protokolleri çözebiliyor.

**Kapsam:** Sorgu süresi ve hata görünümü, HTTP isteğiyle zamansal ilişkilendirme.

**Bitti sayılır:** Sentetik PostgreSQL, MySQL, MSSQL ve Redis örneklerinde sorgu süreleri ve hatalar tshark ile uyuşur, yavaş bir HTTP isteğinin aynı anda çalışan sorguları istek sayfasında görünür.

</details>

<details><summary>NetScaler etkisini iki uçtan ölçme</summary>

**Neden:** NetScaler üzerinde capture alınamıyor, ama önündeki ve arkasındaki noktalardan alınan capture'lar aradaki süreyi verir. İstek bazında eşleştirme var, ama "NetScaler ve ağ ne kadar ekledi?" sorusunu URL bazında özetleyen bir görünüm yok.

**Kapsam:** URL başına eklenen sürenin medyan ve p95 özeti, servis süresinden ayrı gösterim, eşleşme oranı ve güven bilgisi. Kimlik başlığı olmayan trafikte de çalışmalı. Ekrandaki gidiş ve dönüş sütunları düzeltilmeli: ortak kimlik başlığı varsa saat düzeltmesi sabit gecikmeyi gidişten silip dönüşe yazıyor. Toplam eklenen süre saatlerden etkilenmez.

**Bitti sayılır:** Sentetik iki nokta örneğinde bilinen gecikme özetten doğru okunur.

</details>

<details><summary>Trafik incelemede adım istatistikleri ve durum kodları</summary>

**Sonuç:** Her adım için (DNS, TCP bağlantısı, TLS, istek başlıkları, 100 Continue beklemesi, istek body'si, ağ, kuyruk, servis, yanıt aktarımı, ilk bayt, toplam) istek sayısı, en düşük, ortalama, medyan, p90, p95 ve en yüksek süre. Tüm durum kodları sayı ve oranlarıyla. Kaynak port filtresi web'de ve `inspect --src-port` ile. En çok istek alan beş kaynak → hedef:port çifti; seçilince kaynak, hedef ve port alanlarını doldurur. Süre nereye gitti tablosu toplam sürenin yanında istek başına ortalamayı da gösterir.

**Neden:** Bir URL'nin yavaşlığında hangi adımın uzadığı ve hataların payı tek tek isteklere bakarak bulunuyordu.

**Kapsam:** İstek adımlarının dağılımı, HTTP durum kodları, kaynak port filtresi, en yoğun kaynak-hedef çiftleri.

**Bitti sayılır:** Sentetik örnekte adım değerleri ve durum kodu oranları testlerdeki beklenenlerle uyuşur.

</details>

<details><summary>İstek gönderim süreleri ve 100 Continue</summary>

**Sonuç:** İstek sayfası başlıkların ve body'nin ne kadar sürede gönderildiğini gösterir. `Expect: 100-continue`'da sunucunun 100 Continue cevabına kadar geçen süre ayrı bir adım, body o cevaptan sayılır; böylece body'yi geç gönderen istemci yavaş sunucudan ayrılır. Gerçek bir capture'da uzun görünen body süresinin istemciden geldiği böyle ayrıldı. Başlıklar ilk paketten taşıp body uzunluğu okunamazsa değer tahmin edilmez, boş kalır.

**Neden:** İstek body'sinin süresi uzun görünüyordu ama istemcinin mi, sunucunun mu beklettiği ayrılamıyordu.

**Kapsam:** İstek başlıklarının ve body'nin gönderilme süresi, `Expect: 100-continue` beklemesi.

**Bitti sayılır:** Sentetik 100 Continue örneğinde bekleme ve body süresi ayrı ve doğru görünür.

</details>

<details><summary>İsteğin paketleri ve 10 KB body</summary>

**Sonuç:** İstek sayfası bağlantının paketlerini istekten bir sonrakine kadar listeler; istek bağlantıyı açtıysa el sıkışma da görünür. Gönderen, TCP işaretleri, seq/ack, uzunluk, pencere, yeniden iletimler ve HTTP veya TLS içeriği; en fazla 300 satır ve bağlantının PCAP'i. Body'ler 2 KB yerine 10 KB; düz HTTP'de body saklanan capture'dan bütün okunur. Paketler yalnız o bağlantıdan seçildiği için 70 MB'lık gerçek bir capture'da ikisi de yaklaşık 1 saniyede açılıyor.

**Neden:** Bir isteğin paket düzeyindeki trafiğine bakmak için capture'ı Wireshark'ta açmak gerekiyordu; body önizlemesi 2 KB'ta kalıyordu.

**Kapsam:** İstek sayfasında o isteğin paketleri ve daha uzun body önizlemesi.

**Bitti sayılır:** Saklanan capture'da isteğin paketleri tshark ile aynı, URL'deki parola ve token'lar maskeli.

</details>

<details><summary>Wireshark karşılaştırması 1: TCP, DNS ve ICMP sorunları, akış grafikleri, filtre ve Decode As</summary>

**Sonuç:** Dokuz adımın hepsi 0.6.4 ve 0.6.5'te tamamlandı. Her adımda sonuçlar sentetik örneklerde tshark'la uyuştu; testler yerelde ve tshark 4.2'de geçiyor.

**Neden:** Wireshark'ın uzman bilgisinde ve istatistiklerinde olup bizde olmayan sinyallerin en sık görülenleri. Bir kısmını tshark'tan zaten okuyoruz ama sorun olarak göstermiyoruz.

**Kapsam:** Adımlar ayrı maddelerde: 1.1 TCP bayraklarını sorun olarak göster; 1.2 Port tekrarı, SACK ve pencere ölçekleme; 1.3 DNS hataları; 1.4 ICMP ulaşılamaz türleri ve bozuk paketler; 1.5 Kayıt sırasında düşürülen paketler; 1.6 Bağlantı grafikleri: Stevens/tcptrace, throughput, RTT, pencere; 1.7 IO Graph; 1.8 Display filter; 1.9 Decode As.

**Bitti sayılır:** Adımların hepsi Tamamlandı.

</details>

<details><summary>Wireshark karşılaştırması 2: protokol dağılımı, UDP konuşmaları, Flow Graph, akış izleme ve QUIC</summary>

**Sonuç:** Yedi adımın hepsi 0.6.5'te tamamlandı. Sonuçlar sentetik örneklerde tshark'ın kendi tablolarıyla uyuştu; testler yerelde ve tshark 4.2'de geçiyor. GeoIP veritabanı dosyası ve SMB örneği açık kaldı.

**Neden:** Capture'ın genel resmini ve tek bir akışın ayrıntısını Wireshark'a geçmeden görmek için.

**Kapsam:** Adımlar ayrı maddelerde: 2.1 Protocol Hierarchy; 2.2 UDP ve Ethernet konuşmaları, MAC uç noktaları, GeoIP; 2.3 Paket boyutu dağılımı; 2.4 HTTP Request Sequences ve Load Distribution; 2.5 Flow Graph; 2.6 Follow Stream ve Export Objects; 2.7 QUIC ve HTTP/3.

**Bitti sayılır:** Adımların hepsi Tamamlandı.

</details>

<details><summary>Wireshark karşılaştırması 3: diğer protokollerin süre ölçümü ve SIP/RTP istatistikleri</summary>

**Sonuç:** Yedi adım 0.6.5'te. Servisler ve VoIP görünümleri, dört yeni sorun ve dört dilde metinler eklendi. Testler yerelde (tshark 4.6) ve tshark 4.2'de geçti, imajdaki tshark 4.4 ile de kontrol edildi; tshark 4.0 bu makinede yok.

**Neden:** Yavaşlık yalnızca HTTP ve veritabanından gelmiyor; kimlik doğrulama, dosya paylaşımı, kuyruk ve ses servisleri de bekletebiliyor.

**Kapsam:** Adımlar ayrı maddelerde: 3.1 LDAP ve Kerberos süreleri; 3.2 SMB süreleri; 3.3 Kafka süreleri; 3.4 SMTP süreleri; 3.5 DCERPC, MQTT, AMQP ve FTP süreleri; 3.6 SIP çağrıları; 3.7 RTP jitter, kayıp ve sıra bozulması.

**Bitti sayılır:** Adımların hepsi Tamamlandı.

**Karar:** Kapsam dışı: RTP ses çalma (konuşmaları dinlenebilir yapar), Wi-Fi, Bluetooth ve USB (sunucu ve pod capture'larında bulunmaz), WPA ve IPsec çözme (şifre veya anahtar saklamayı gerektirir), renk kuralları (web arayüzünde karşılığı yok). Paket yorumları notlarla, zaman referansı istek sayfalarıyla zaten karşılanıyor.

</details>

<details><summary>Wireshark 1.1: TCP bayraklarını sorun olarak göster</summary>

**Sonuç:** 0.6.4'te geldi. Duplicate ACK, out-of-order, window full, zero window probe ve spurious retransmission Sorunlar'da, bağlantılarıyla birlikte. Keep-alive yalnızca ardından reset gelen bağlantılarda, window update yalnızca sıfır pencereden sonra işaretleniyor. Bağlantı sayfası her sayıyı gösteriyor. Sentetik örnekte her sayı tshark'ın bayraklarıyla uyuştu.

**Neden:** Duplicate ACK, out-of-order, window full, keep-alive, zero window probe, window update ve spurious retransmission tshark'tan okunuyor ama Sorunlar'da çıkmıyor.

**Kapsam:** Her bayrak için bağlantı başına sayı, Sorunlar'da ayrı satır ve ilgili bağlantıların listesi; bilgi dosyasında anlam, sıradaki kontroller ve kaynak. Bağlantı sayfasında bayrak sayıları.

**Bitti sayılır:** Sentetik örnekte her bayrağın sayısı tshark'ın `tcp.analysis.*` sayısıyla uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 1.2: Port tekrarı, SACK ve pencere ölçekleme</summary>

**Sonuç:** 0.6.4'te geldi. Bağlantı sayfası her tarafın SACK iznini ve pencere ölçeğini, ölçekleme yoksa gidiş dönüşe göre en yüksek hızı gösteriyor. Sorunlar: tekrar kullanılan port çifti (önceki bağlantıdan bu yana geçen süreyle), 64 KB'tan fazla veri taşıyıp pencere ölçeklemesi olmayan bağlantılar, SACK'sız bağlantılar. D-SACK, alanı tshark 4.0/4.2'de doğrulanamadığı için okunmuyor.

**Neden:** Erken port tekrarı TIME_WAIT sorunlarını, SACK ve pencere ölçeklemenin olmaması da düşük hızı açıklar; bunları hiç okumuyoruz.

**Kapsam:** `tcp.analysis.reused_ports`, SYN'deki SACK izni ve pencere ölçekleme çarpanı, D-SACK blokları. Sorunlar: port numbers reused, pencere ölçekleme kapalı (alıcı penceresi 64 KB ile sınırlı), SACK kapalı.

**Bitti sayılır:** Sentetik örnekte port tekrarı ve kapalı ölçekleme olan bağlantılar doğru işaretlenir; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 1.3: DNS hataları</summary>

**Sonuç:** 0.6.4'te geldi. Cevapsız olanlar dahil her sorgu tipi, yanıt kodu, sunucusu ve kaç kez gönderildiğiyle saklanıyor. Sorunlar: SERVFAIL, REFUSED gibi hatalar, cevapsız sorgular, tekrar gönderilen sorgular ve NXDOMAIN. Hosts sekmesi bunları ad ve sunucuya göre listeliyor, istek sayfası önceki sorgu başarısızsa not düşüyor. Sentetik örnekte yanıt kodları ve cevapsız sorgu sayısı tshark'la uyuştu.

**Neden:** Yalnızca DNS süresini ölçüyoruz; NXDOMAIN, SERVFAIL ve REFUSED gibi hatalar ile cevapsız sorgular görünmüyor.

**Kapsam:** `dns.flags.rcode`, cevapsız ve tekrarlanan sorgular. DNS sorunu olarak hata kodu, ad ve sunucuya göre sayılar; istek sayfasında isteğin DNS sorgusu hatalıysa not.

**Bitti sayılır:** Sentetik örnekte hata kodları ve cevapsız sorgu sayısı tshark'la uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 1.4: ICMP ulaşılamaz türleri ve bozuk paketler</summary>

**Sonuç:** 0.6.4'te geldi. IPv4 ve IPv6'da destination unreachable (admin prohibited dahil) ve time exceeded, alıntıladıkları TCP bağlantısına veya UDP portuna bağlanıyor; router yalnızca 8 bayt alıntılasa da. Bozuk paketler protokol ve mesaja göre sayılıyor. ICMPv6 'packet too big' artık 'fragmentation needed' sayılıyor; ICMPv6 hatalarındaki alıntı paketlerin bağlantıya ve DNS'e karışması düzeltildi.

**Neden:** Şu an yalnızca 'fragmentation needed' okunuyor. Host, port ve 'admin prohibited' cevapları firewall reddini gösterir; bozuk paketler yanlış port çözümü veya bozuk capture işaretidir.

**Kapsam:** ICMP ve ICMPv6 ulaşılamaz türleri, alıntılanan TCP/UDP başlığıyla ilgili bağlantıya bağlanır. `_ws.malformed` ve `_ws.expert` hataları protokole göre sayılır.

**Bitti sayılır:** Sentetik örnekte her ICMP türü doğru bağlantıya bağlanır, bozuk paket sayısı tshark'ın uzman bilgisiyle uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 1.5: Kayıt sırasında düşürülen paketler</summary>

**Sonuç:** 0.6.4'te geldi. pcapng dosyalarında capture aracı, her arayüz, filtre, snaplen ve araç ya da çekirdeğin düşürdüğü paketler Genel bakış'ta görünüyor; düşürme capture güvenini düşürüyor ve uyarı ekliyor. Parçalı yüklemede sayaçlar capture başından saydığı için her arayüzün en büyük değeri alınıyor. Değerler Wireshark'ın pcapng çözücüsünün okuduğuyla uyuştu.

**Neden:** pcapng dosyası kayıt aracının düşürdüğü paket sayısını tutuyor; capture güveni bunu kullanmıyor.

**Kapsam:** pcapng Interface Statistics bloğundan `isb_ifdrop` ve `isb_osdrop` Python'da okunur, arayüz adı ve snaplen ile capture güvenine ve uyarılara eklenir.

**Bitti sayılır:** Düşürme sayısı yazılmış sentetik pcapng'de değer `capinfos` ve Wireshark'ın gösterdiğiyle uyuşur; testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 1.6: Bağlantı grafikleri: Stevens/tcptrace, throughput, RTT, pencere</summary>

**Sonuç:** 0.6.5'te geldi. Bağlantı sayfasında, bir tarafın gönderdiği veri için Wireshark'ın TCP akış grafikleri: sıra numarası (Stevens), ACK, alıcı penceresi ve SACK'li tcptrace, aktarım hızı, gidiş dönüş ve pencere. Sayfa açılınca saklanan capture'dan okunuyor; aynı port çiftini kullanan başka bağlantı zaman aralığıyla dışarıda kalıyor. Değerler tshark'ın alanlarıyla birebir uyuştu.

**Neden:** Bir bağlantının neden yavaş aktığını Wireshark'ın TCP Stream Graphs'ı gibi görmek için.

**Kapsam:** Saklanan capture'dan bağlantı sayfası açılınca hesaplanır; sıra numarası/zaman, yeniden gönderimler ve SACK işaretli, throughput, RTT ve alıcı penceresi grafikleri. CDN kullanılmaz, çizim uygulamanın kendi JS'iyle.

**Bitti sayılır:** Sentetik örnekte noktalar tshark'ın alanlarıyla uyuşur; 70 MB capture'da bir bağlantı 2 saniyenin altında çizilir; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 1.7: IO Graph</summary>

**Sonuç:** 0.6.5'te geldi. Inspect sayfasında paket, bayt, yeniden gönderim, RST ve başarısız istek grafiği; 100 ms'den 1 saate kadar aralık, Inspect filtresiyle daraltma ve seçilen aralığı inceleme. Paketler analiz sırasında 100 ms'lik dilimlerde bağlantı başına sayılıyor; aralıklar Wireshark gibi ilk paketten sayılıyor. Sayılar tshark'ın paket alanlarıyla uyuştu.

**Neden:** Hataların ve trafiğin zaman içinde nasıl değiştiğini görmek için.

**Kapsam:** Capture için saniye başına paket, bayt, yeniden gönderim, RST ve HTTP hata grafikleri; aralık seçimi ve Inspect filtresiyle daraltma. Seçilen aralığa tıklayınca o zamandaki istekler.

**Bitti sayılır:** Sentetik örnekte değerler `tshark -z io,stat` ile uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 1.8: Display filter</summary>

**Sonuç:** 0.6.5'te geldi. Analist ve admin, Inspect sayfasında saklanan capture üzerinde Wireshark display filter çalıştırabiliyor: en fazla 500 paket ve 60 saniye, Durdur düğmesi, her paket bağlantısına ve isteğine bağlı, hatalı filtrede tshark'ın kendi mesajı. Her çalıştırma etkinlik kaydına yazılıyor; URL ve gövdedeki gizli değerler, veritabanı değerleri ve Redis anahtarları gizleniyor. Sonuçlar tshark'ın aynı filtreyle verdiği paketlerle uyuştu.

**Neden:** Inspect yalnızca adres, port, URL ve boyutla filtreliyor; Wireshark'ın filtre dili her alanı kullanabiliyor.

**Kapsam:** Saklanan capture üzerinde `tshark -Y`; filtre tshark'ın kendisiyle doğrulanır, süre ve paket sınırı, iptal düğmesi, sonuçta paket listesi ve ilgili bağlantı ve istek bağlantıları. Analist ve admin rolüne açık.

**Bitti sayılır:** Hatalı filtre açık bir mesaj verir; sınırı aşan filtre durdurulur; sonuç tshark'ın aynı filtreyle verdiği paketlerle uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 1.9: Decode As</summary>

**Sonuç:** 0.6.5'te geldi. Yüklemede, API'de (`decode_as`), CLI'da (`--decode-as`) ve tüm analizler için `PCAP_ANALYZER_DECODE_AS` ile port ve protokol seçilebiliyor (http, http2, tls, pgsql, mysql, tds, resp, dns, vxlan, geneve). Genel bakış'taki 'Yeniden analiz et' saklanan capture'ı yeni seçimle yeni bir analiz olarak okuyor; HTTPS anahtarlarını yeniden istiyor. Seçim sonuç önbelleğinin anahtarında; paket listesi, gövdeler, grafikler ve display filter aynı portları kullanıyor.

**Neden:** Standart dışı portta HTTP, TLS veya veritabanı çalışınca tshark trafiği tanımıyor.

**Kapsam:** `PCAP_ANALYZER_DB_PORTS` ayarı genelleştirilir; analiz sayfasından port ve protokol seçilip capture yeniden analiz edilir; seçim analizle saklanır ve sonuç önbelleğinin anahtarına girer.

**Bitti sayılır:** Standart dışı portta HTTP ve TLS olan sentetik örnek seçimden sonra istekleriyle görünür; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 2.1: Protocol Hierarchy</summary>

**Sonuç:** 0.6.5'te geldi. İstatistikler sekmesinde tshark'ın kendi `io,phs` tablosu analizle birlikte okunuyor; paket ve bayt payları uyuşuyor. Analiz ayarları gereği bir HTTP mesajının parçasını taşıyan her frame HTTP sayılıyor, sayfa bunu söylüyor. Büyük capture parçalı okunduğunda da sonuç aynı; analiz yaklaşık %10 uzadı.

**Neden:** Capture'da hangi trafiğin ne kadar yer tuttuğunu görmek için.

**Kapsam:** `tshark -z io,phs` karşılığı: protokol ağacı, paket ve bayt payları; analiz sırasında hesaplanır ve saklanır.

**Bitti sayılır:** Sentetik örnekte paylar `tshark -z io,phs` ile uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 2.2: UDP ve Ethernet konuşmaları, MAC uç noktaları, GeoIP</summary>

**Sonuç:** 0.6.5'te geldi. UDP ve Ethernet konuşmaları, IPv4, IPv6 ve MAC uç noktaları `conv` ve `endpoints` tablolarıyla uyuşuyor; tünelli frame her katmanda sayılıyor. ARP'nin iki karta verdiği IPv4 adresi İstatistikler'de ve Sorunlar'da görünüyor. GeoIP okuyucusu ve DB-IP'den dosya üreten araç hazır, ama veritabanı dosyası henüz imajda değil.

**Neden:** Yalnızca TCP bağlantılarını ve IP adreslerini gösteriyoruz.

**Kapsam:** UDP konuşmaları (süre, paket, bayt), Ethernet konuşmaları ve MAC uç noktaları, aynı IP'de farklı MAC uyarısı. GeoIP veritabanı imaja gömülü, internet erişimi olmadan; özel adresler için gösterilmez.

**Bitti sayılır:** Sentetik örnekte sayılar `tshark -z conv,udp` ve `-z conv,eth` ile uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 2.3: Paket boyutu dağılımı</summary>

**Sonuç:** 0.6.5'te geldi. Wireshark'ın aralıklarında istemci, sunucu ve TCP dışı trafik ayrı sayılıyor; toplamlar `plen,tree` ile uyuşuyor.

**Neden:** MTU ve küçük paket sorunlarını hızlıca görmek için.

**Kapsam:** `tshark -z plen,tree` aralıklarında paket sayısı ve payı, yöne göre.

**Bitti sayılır:** Sentetik örnekte aralıklar `tshark -z plen,tree` ile uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 2.4: HTTP Request Sequences ve Load Distribution</summary>

**Sonuç:** 0.6.5'te geldi. İsteklerin Referer ve Location başlıkları saklanıyor (gizli değerler maskeli). Yük dağılımı `http_srv,tree` ile, istek ağacındaki bağlantılar `http_seq,tree` ile uyuşuyor; Wireshark'ın ağaç sayıları yerine her bağlantının istek sayısı gösteriliyor.

**Neden:** Bir sayfanın hangi istekleri tetiklediğini ve yükün sunuculara nasıl dağıldığını görmek için.

**Kapsam:** Referer ve Location zincirine göre istek ağacı, yönlendirme zincirleri; host ve sunucu adresine göre istek dağılımı.

**Bitti sayılır:** Sentetik örnekte ağaç ve dağılım `tshark -z http_seq,tree` ve `-z http_srv,tree` ile uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 2.5: Flow Graph</summary>

**Sonuç:** 0.6.5'te geldi. Bağlantı sayfasında düğmeyle, istek sayfasında paket tablosunun yanında görünüm olarak; oklar tshark'ın paket sırası ve yönüyle uyuşuyor, 300 paket sınırı var.

**Neden:** İki taraf arasındaki paket sırasını ok diyagramı olarak görmek için.

**Kapsam:** Bağlantı ve istek sayfasında, saklanan capture'dan açılınca çizilen ok diyagramı: bayraklar, sıra numaraları ve HTTP satırları; paket sınırı.

**Bitti sayılır:** Sentetik örnekte oklar tshark'ın paket sırasıyla uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 2.6: Follow Stream ve Export Objects</summary>

**Sonuç:** 0.6.5'te geldi. Follow Stream TCP, çözülmüş TLS ve tek HTTP/2 akışını 1 MB'a kadar, gizli değerleri maskeli gösteriyor; TLS için key log yeniden isteniyor. 'Trafikteki dosyalar' `--export-objects` ile HTTP ve SMB dosyalarını çıkarıyor, toplam 256 MB. İkisi de yalnızca analist ve admin'e açık, her kullanım etkinlik kaydında, `PCAP_ANALYZER_EXPORT_OBJECTS=0` kapatıyor. HTTP dosyaları tshark'ın çıktısıyla aynı; SMB için sentetik örnek olmadığından yalnızca kodda var.

**Neden:** Gövdenin ilk 10 KB'ı yetmediğinde tüm akışı veya dosyayı görmek için.

**Kapsam:** Tam akış metni (TCP, TLS çözülmüşse, HTTP/2) ve HTTP ile SMB nesnelerinin indirilmesi. Yalnızca analist ve admin rolüne açık, `PCAP_ANALYZER_EXPORT_OBJECTS` ayarıyla kapatılabilir, her indirme etkinlik kaydına yazılır, boyut sınırı var.

**Bitti sayılır:** İzleyici rolü 403 alır, ayar kapalıyken menü görünmez; indirilen dosya `tshark --export-objects` çıktısıyla aynıdır; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 2.7: QUIC ve HTTP/3</summary>

**Sonuç:** 0.6.5'te geldi. Yeni QUIC sekmesi her bağlantıyı gidiş-dönüş, el sıkışma süresi, boyut ve kayıp paketlerle gösteriyor. Key log'la tshark şifreyi çözüyor; HTTP/3 istekleri durum, bekleme ve toplam süreyle listeleniyor. Key log yoksa yalnızca süreler gösteriliyor ve sayfa bunu söylüyor. tshark 4.2 HTTP/3 başlıklarını okuyor. HTTP/3 istekleri henüz genel HTTP sayılarına ve URL listesine girmiyor.

**Neden:** Tarayıcılar ve bazı servisler HTTP/3 kullanıyor; bu trafiği hiç ölçmüyoruz.

**Kapsam:** QUIC bağlantıları, el sıkışma süresi, kayıp ve key log ile şifre çözme; tshark 4.0 ve 4.2 HTTP/3 başlıklarını çözebiliyorsa istekler de, çözemiyorsa yalnızca bağlantı süreleri ve bunu söyleyen bir not.

**Bitti sayılır:** Key log'lu sentetik QUIC örneği çözülür ve süreler tshark'la uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 3.1: LDAP ve Kerberos süreleri</summary>

**Sonuç:** LDAP çağrıları messageID ile, Kerberos çağrıları sırayla eşleşiyor; süreler tshark'ın ldap.time ve kerberos,srt değerleriyle aynı. Adlar cn=? oluyor, arama filtresinden yalnızca öznitelik adları kalıyor, şifre ve kullanıcı adı saklanmıyor. UDP'de tekrar gönderilen istek tek çağrı sayılıyor. İstek sayfası, sunucunun o sırada yaptığı çağrıları gösteriyor. tshark 4.2, 4.4 ve 4.6'da denendi; 4.0 bu makinede yok.

**Neden:** Giriş ve yetki kontrolleri dizin servisinde bekleyince HTTP isteği de bekliyor.

**Kapsam:** Veritabanı maddesindeki gibi istek ve cevap süresi, sonuç kodu, HTTP isteğiyle zaman eşleştirmesi; arama filtreleri ve adlardaki değerler `?` olarak gizlenir.

**Bitti sayılır:** Sentetik örnekte süreler ve hata kodları tshark'la uyuşur, değerler sonuçta görünmez; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 3.2: SMB süreleri</summary>

**Sonuç:** SMB2/3 komutları message ID ile eşleşiyor; STATUS_PENDING ara cevabı çağrıyı bitirmiyor. Süreler smb2,srt ile aynı, NT status kodları adlarıyla gösteriliyor. Dosya adları saklanmıyor, paylaşım adı görünüyor.

**Neden:** Dosya paylaşımındaki yavaşlık uygulamanın cevabını geciktiriyor.

**Kapsam:** SMB2/3 komutlarının süresi ve NT status kodları, dosya adları gizlenir, HTTP isteğiyle zaman eşleştirmesi.

**Bitti sayılır:** Sentetik örnekte süreler `tshark -z smb2,srt` ile uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 3.3: Kafka süreleri</summary>

**Sonuç:** Kafka çağrıları correlation ID ile eşleşiyor, API adı, topic ve hata kodu adıyla geliyor. Fetch ve JoinGroup bilerek beklediği için yavaş sayılmıyor. Mesaj içeriği saklanmıyor.

**Neden:** Mesaj kuyruğuna yazma ve okuma gecikmeleri.

**Kapsam:** Produce, Fetch ve diğer API çağrılarının süresi ve hata kodları, topic adları görünür, mesaj içeriği saklanmaz.

**Bitti sayılır:** Sentetik örnekte süreler ve hata kodları tshark'la uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 3.4: SMTP süreleri</summary>

**Sonuç:** SMTP komutları sırayla cevaplarıyla eşleşiyor, DATA'dan sonraki içerik ayrı bir "message" çağrısı. Adresler ve içerik saklanmıyor, yalnızca komut ve cevap kodu kalıyor.

**Neden:** Bildirim e-postası gönderen uygulamalarda mail sunucusu cevabı geciktirebiliyor.

**Kapsam:** Komut başına süre ve cevap kodu; adresler ve içerik gizlenir.

**Bitti sayılır:** Sentetik örnekte süreler ve kodlar tshark'la uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 3.5: DCERPC, MQTT, AMQP ve FTP süreleri</summary>

**Sonuç:** DCERPC call ID ile (arayüz adı bind'dan, süreler dcerpc.time ile aynı), MQTT paket ID ile, AMQP kanal ve metot ile (sunucunun hata kodlu Channel.Close'u cevap sayılıyor), FTP sırayla eşleşiyor. Hepsi aynı Servisler görünümünde. FTP argümanları ve mesaj içerikleri saklanmıyor; MQTT topic'i görünüyor.

**Neden:** Daha az görülen ama aynı yöntemle ölçülebilen protokoller.

**Kapsam:** Her protokol için istek ve cevap süresi ve hata kodu, değerler gizlenir; aynı veritabanı yapısı ve görünüm.

**Bitti sayılır:** Her protokol için sentetik örnekte süreler tshark'la uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 3.6: SIP çağrıları</summary>

**Sonuç:** VoIP görünümünde çağrı listesi: sonuç, durum kodu, çalmaya kadar geçen süre, INVITE'tan 200 OK'e kurulum süresi, konuşma süresi ve tekrar gönderilen INVITE'lar. Mesaj sayıları sip,stat ile aynı. Numaralar saklanmıyor, Call-ID yalnızca hash olarak duruyor.

**Neden:** Ses servislerinde çağrı kurulumunun ne kadar sürdüğünü ve neden başarısız olduğunu görmek için.

**Kapsam:** Çağrı listesi, INVITE'tan 200'e kurulum süresi, hata kodları ve yeniden gönderimler; numaralar gizlenir.

**Bitti sayılır:** Sentetik örnekte çağrılar `tshark -z sip,stat` ve VoIP çağrı listesiyle uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

<details><summary>Wireshark 3.7: RTP jitter, kayıp ve sıra bozulması</summary>

**Sonuç:** RTP akışları kuran SIP çağrısına bağlanıyor. Kayıp, sıra bozulması, en büyük aralık, en yüksek ve ortalama jitter Wireshark'ın RTP analiziyle aynı yöntemle hesaplanıyor ve rtp,streams ile birebir uyuşuyor. %1'den fazla kayıp veya 30 ms'den fazla jitter Sorunlar'da çıkıyor. Ses saklanmıyor, çalınmıyor. tshark 4.2 jitter'ı eski yöntemle hesapladığı için orada yalnızca kayıp ve aralıklar karşılaştırılıyor.

**Neden:** Ses kalitesi sorunlarının ağdan gelip gelmediğini görmek için.

**Kapsam:** RTP akışları, jitter, kayıp ve sıra bozulması, SIP çağrısına bağlanır. Ses çalma yok.

**Bitti sayılır:** Sentetik örnekte değerler `tshark -z rtp,streams` ile uyuşur; tshark 4.0 ve 4.2'de çalışır, testler yerelde ve CI'da geçer.

</details>

## Ekip ve otomasyon

| Madde | Alan | Öncelik | Durum |
|---|---|---|---|
| Türkçe arayüz | Arayüz | Yüksek | Tamamlandı |
| Referans analiz ve trend | Analiz | Orta | Tamamlandı |
| Analiz notları ve vaka numarası | Arayüz | Orta | Tamamlandı |
| REST API ve API token | Entegrasyon | Orta | Tamamlandı |
| Kullanım rehberi | Kalite | Orta | Tamamlandı |
| linux-glibc2.17-server paketi | Dağıtım | Orta | Tamamlandı |
| CLI eşik kontrolü | Entegrasyon | Düşük | Tamamlandı |
| Helm chart | Dağıtım | Düşük | Tamamlandı |
| Uygulama içi işlem kaydı | Güvenlik | Düşük | Tamamlandı |
| Kullanıcılar ve roller | Güvenlik | Yüksek | Tamamlandı |

<details><summary>Türkçe arayüz</summary>

**Neden:** Neden açıklamaları bilgi bankasından Türkçe geliyor, ama menüler, tablolar ve başlıklar hâlâ İngilizce.

**Kapsam:** Arayüz metinlerini de bilgi bankasına taşımak, arayüzden dil seçimi, rapor ve dışa aktarma başlıkları. Yapay zeka modeli kullanılmaz.

**Bitti sayılır:** Dil seçilebilir ve hazırlanan rapor seçilen dilde çıkar.

</details>

<details><summary>Referans analiz ve trend</summary>

**Sonuç:** Referans seçimi, sapan URL listesi ve Trend sayfası.

**Neden:** Bugün yalnız iki capture karşılaştırılıyor. "Normale göre ne değişti?" sorusu her seferinde elle kuruluyor.

**Kapsam:** Sağlıklı bir analizi referans seçme, sonraki analizleri ona göre gösterme, URL başına çoklu analiz trendi.

**Bitti sayılır:** Yeni analizde referanstan sapan URL'ler kendiliğinden listelenir.

</details>

<details><summary>Analiz notları ve vaka numarası</summary>

**Sonuç:** Vaka numarası, etiket, not, arama ve raporda görünme.

**Neden:** Bulgular uygulama dışında kalıyor ve analiz sonradan vaka ile ilişkilendirilemiyor.

**Kapsam:** Analize vaka numarası, etiket ve not ekleme, geçmişte arama, notların rapora girmesi.

**Bitti sayılır:** Not ve vaka numarası HTML raporda görünür.

</details>

<details><summary>REST API ve API token</summary>

**Sonuç:** /api/v1, iptal edilebilir token ve docs/api.md.

**Neden:** Bugün otomasyon için web oturumu veya sunucuda CLI gerekiyor.

**Kapsam:** Yükleme, iş durumu ve sonuçlar için belgelenmiş API, web girişinden ayrı ve iptal edilebilir token.

**Bitti sayılır:** Bir script capture yükleyip sonucu JSON olarak alır.

</details>

<details><summary>Kullanım rehberi</summary>

**Sonuç:** docs/usage.md örnek analiz ve neden tablosu.

**Neden:** README kurulumu anlatıyor ama sonuçların nasıl okunacağını anlatmıyor.

**Kapsam:** Ekran görüntüleri, örnek bir yavaşlık analizi, her neden türünün açıklaması, README için demo görseli.

**Bitti sayılır:** Yeni bir kullanıcı rehberle örnek analizi yardım almadan bitirir.

</details>

<details><summary>linux-glibc2.17-server paketi</summary>

**Sonuç:** DuckDB 1.2.2 ile centos:7 container'ında tam akış geçti.

**Neden:** CentOS 7 ve RHEL 7 şu an açık bir mesajla reddediliyor. Sınırı DuckDB belirliyor.

**Kapsam:** Bu sürümlerde çalışan DuckDB seçimi veya farklı bir paketleme, kendi klasöründe.

**Bitti sayılır:** CentOS 7 container'ında tam akış çalışır.

**Karar:** Bu işletim sistemleri ortamınızda gerçekten var mı?

</details>

<details><summary>CLI eşik kontrolü</summary>

**Sonuç:** pcap-analyzer check, sınır aşılınca 2 koduyla çıkar.

**Neden:** Test ortamında alınan capture'ı kurallara göre otomatik geçirmeyi sağlar. İlk seçimde alınmamıştı (B17).

**Kapsam:** `p95`, hata oranı gibi eşikler aşılınca hata koduyla çıkan komut.

**Bitti sayılır:** CI adımı eşik aşılınca başarısız olur.

</details>

<details><summary>Helm chart</summary>

**Sonuç:** test cluster'ında kurulum, Ingress, NetworkPolicy, tam akış ve kaldırma geçti. Gateway seçeneği cluster'da denenmedi.

**Neden:** Kustomize manifestleri var, ama birçok ekip Helm ile kuruyor.

**Kapsam:** İmaj, depolama, parola Secret'ı, Ingress veya Gateway ve kaynak limitleri için değerler.

**Bitti sayılır:** `helm install` temiz bir cluster'da çalışan uygulama üretir.

</details>

<details><summary>Uygulama içi işlem kaydı</summary>

**Sonuç:** 0.4.0: olay, adres ve zaman kaydı, İşlem kaydı sayfası. 0.6.2: her kayıt kullanıcıyı da gösteriyor. Kim hangi capture'ı ne zaman yükledi ve kim sonradan açtı kaydediliyor; açma, kullanıcı ve capture başına 30 dakikada bir yazılıyor. Kaydı yalnız admin görüyor, kullanıcıya ve olaya göre süzebiliyor. Capture listesi yükleyeni gösteriyor.

**Neden:** Silme, indirme ve giriş olaylarının izi uygulamada tutulmuyor.

**Kapsam:** Olay, kullanıcı, IP ve zaman kaydı; kimin hangi capture'ı yüklediği ve sonradan kimin incelediği.

**Bitti sayılır:** Yükleme, inceleme, silme ve indirme olayları kişi adıyla sonradan sorgulanabilir.

</details>

<details><summary>Kullanıcılar ve roller</summary>

**Sonuç:** Tercihler, Kullanıcılar ekranı. İzleyici capture'ları açar ve dışa aktarır; analist ayrıca yükler, siler ve not yazar; admin ayrıca kullanıcıları, tercihleri ve API token'larını yönetir. Rol değişikliği hemen geçerli, yeni parola ve silme oturumu kapatır, admin kendi rolünü düşüremez ve kendini silemez. Parola en az 8 karakter. Kullanıcılar veri klasöründeki `users.json`'da scrypt özetiyle durur; repoya ve imaja girmez. Kurulum admin'i ortam değişkeninden gelir ve silinemez. Admin tüm capture'ları tek seferde de silebilir.

**Neden:** Tek ortak hesap vardı: kimin ne yaptığı ayrılamıyordu ve herkes yükleyip silebiliyordu.

**Kapsam:** Admin'in kullanıcı eklediği, rolünü değiştirdiği, parolasını yenilediği ve sildiği ekran. İzleyici, analist ve admin rolleri.

**Bitti sayılır:** İzleyici yükleme ve silme yapamaz, yetkisiz istek 403 alır, admin kendini kilitleyemez.

</details>

## Keşif

| Madde | Alan | Öncelik | Durum |
|---|---|---|---|
| 100 MB üstü capture'lar | Analiz | Düşük | Tamamlandı |

<details><summary>100 MB üstü capture'lar</summary>

**Sonuç:** 0.6.0: varsayılan sınır 1000 MB, 0.6.2 ile 500 MB. 100 MB üstü capture'lar bağlantılar bölünmeden parçalara ayrılıyor (VXLAN, Geneve, GRE ve IP-in-IP içinde de), her parça tshark'a pipe ile gidiyor, sonuçlar ve indirmeler diske akarak yazılıyor. Parçalı ve tek geçiş sonuçları 20 örnek, lab ve gerçek Kubernetes capture'larında bire bir aynı. 1 GB'lık üretilmiş capture 155 saniyede ve en fazla 663 MiB bellekle, gerçek 600 MB'lık node capture'ı 29 saniyede analiz edildi.

**Neden:** 100 MB sınırı bilinçli bir karar. Gerçek ihtiyaç doğarsa önce süre ve bellek ölçülmeli.

**Kapsam:** Performans ölçümü, akışlı işleme, bellek sınırı.

**Karar:** Gerçek capture'lar bu sınırı aşıyor mu?

</details>
