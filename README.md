# Список вразливостей веб-сервера Nginx

Публікується з метою контролю безпеки сайтів на базі веб-серверів Nginx. На замітку дослідникам та власникам електронних ресурсів. В рамках волонтерського проєкту "За вільний і безпечний UAnet!".

Дані вразливості були виявлені дослідниками KR. Laboratories в ході глобального аудиту ресурсів українського сегменту мережі Інтернет й можуть бути використані як легітимними пентестерами, так і зловмисниками для проведення таких атак як: переповнення буфера (buffer overflow), Denial of Service / Distributed Denial of Service Attack (DoS/DDoS), Path Traversal, Local File Inclusion / Remote File Inclusion (LFI/RFI), Cross Site Scripting Attack (XSS), Cross Site Request Forgery / Server Side Request Forgery (CSRF/SSRF), розкриття конфіденційної інформації (Expose Sensitive Information / Information Disclosure), пошкодження або втрата даних, помилки конфігураці та багато інших.   

Ми рекомендуємо українським веб-майстрам і системним адміністраторам регулярно оновлювати серверне програмне забезпечення та використовувати наші рекомендації щодо кібербезпеки, аби мінімізувати потенційні ризики.  

З приводу захисту веб-серверів пишіть нам на електронну скриньку: security[@]kr-labs.com.ua

| **CVE Ідентифікатор** &nbsp; &nbsp; | **Опис** | **Exploit / PoC** |
|-----------------------------------------------------|----------|-------------|
| [**CVE-2017-7529**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7529) | Вразливість дозволяє віддаленому атакуючому розкрити частину пам'яті сервера і таким чином отримати конфіденційну інформацію через некоректну обробку Range-запитів. Вразливість виникає тільки в конфігураціях з увімкненим кешуванням. | [Експлойт1](https://www.exploit-db.com/exploits/42383) [Експлойт2](https://github.com/gemboxteam/exploit-nginx-1.10.3/blob/main/cve-nginx-1.10.3.py) [PoC1](https://x.com/SpiderSec/status/1193557511124553728) [PoC2](https://gist.github.com/thehappydinoa/bc3278aea845b4f578362e9363c51115)|
| [**CVE-2018-16845**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16845) | Розкриття пам'яті в модулі ngx_http_mp4_module може дозволити віддаленому атакуючому отримати доступ до конфіденційної інформації. | [PoC](https://zerodayengineering.com/exploits/nginx-mp4-infoleak.html) |
| [**CVE-2019-9511**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9511) | Надмірне використання ЦП в HTTP/2 при малих оновленнях вікна може дозволити віддаленому атакуючому спричинити відмову в обслуговуванні. | N/a |
| [**CVE-2021-23017**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017) | Однобайтовий запис пам'яті в резолвері може дозволити віддаленому атакуючому спричинити відмову в обслуговуванні або потенційно виконати довільний код. | [PoC1](https://github.com/M507/CVE-2021-23017-PoC/blob/main/poc.py) [PoC2](https://github.com/M507/CVE-2021-23017-PoC) |
| [**CVE-2022-41741**](https://nvd.nist.gov/vuln/detail/CVE-2022-41741) | Вразливість у модулі ngx_http_mp4_module може дозволити локальному атакуючому пошкодити пам'ять робочого процесу Nginx, що призводить до його завершення або інших потенційних наслідків при обробці спеціально створеного аудіо- або відеофайлу. | [Деталі](https://my.f5.com/manage/s/article/K81926432) |
| [**CVE-2022-41742**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41742) | Вразливість у модулі ngx_http_mp4_module може дозволити локальному атакуючому спричинити збій робочого процесу або розкрити пам'ять процесу за допомогою спеціально створеного аудіо- або відеофайлу. |[Деталі](https://my.f5.com/manage/s/article/K28112382)|
| [**CVE-2022-41743**](https://nvd.nist.gov/vuln/detail/CVE-2022-41743) | Вразливість у модулі ngx_http_hls_module може дозволити локальному атакуючому пошкодити пам'ять робочого процесу Nginx, що призводить до його збою або інших потенційних наслідків при обробці спеціально створеного аудіо- або відеофайлу. | N/a |
| [**CVE-2024-7347**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-7347) | Вразливість у модулі ngx_http_mp4_module може дозволити атакуючому здійснити переповнення буфера, що призводить до аварійного завершення роботи процесу. | N/a |

### Джерела
- [NGINX. Security Advisories](https://nginx.org/en/security_advisories.html)
- [NGINX News](https://nginx.org/2024.html)
- [Broadcom. Audit: Nginx CVE-2017-7529](https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=31875)
- [RedHat Customer Portal. CVE-2017-7529](https://access.redhat.com/security/cve/cve-2017-7529)
- [[nginx-announce] nginx security advisory (CVE-2017-7529)](https://mailman.nginx.org/pipermail/nginx-announce/2017/000200.html)
- [[nginx-announce] nginx security advisory (CVE-2018-16845)](https://mailman.nginx.org/pipermail/nginx-announce/2018/000221.html)
- [Nginxpwner - simple tool to look for common Nginx misconfigurations and vulnerabilities.](https://github.com/stark0de/nginxpwner)
- [Cloudflare Blog. On the recent HTTP/2 DoS attacks](https://blog.cloudflare.com/on-the-recent-http-2-dos-attacks/)
- [F5. Updating NGINX for Vulnerabilities in the MP4 and HLS Video-Streaming Modules](https://www.f5.com/company/blog/nginx/updating-nginx-for-vulnerabilities-in-the-mp4-and-hls-video-streaming-modules)
