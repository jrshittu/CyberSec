Yo, Devs!, Buckle up, because you’re about to learn about web security ⚔️.


![CyberStar](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/z60bmb40p3tcjg0tb00f.jpg)

Websites and Apps are like castle, filled with precious data and functionality. But hackers in the shadows armed with sneaky tricks and malicious spells are ready to steal user’s data and crash the kingdom.

But fear not, devs! You have what it takes to build solid, impenetrable products and fight back like a true warrior. In this article, you’ll learn battle-tested strategies to outsmart threats and keep your apps safe and sound.

## Contents
[Modern Threats](#threat)

- [Zero-Day Vulnerabilities](#zero)

- [SQL Injection](#sql)

- [Cross-Site Scripting (XSS)](#css)


[Best Practices](#best)
[Bonus Tips](#tips)
[References](#ref)

## Know the Enemy: Modern Threats <a name="threat"></a>
Before we dive into defensive tactics, let's identify the common modern threats:

- Zero-Day Vulnerabilities <a name="zero"></a>: These newfound exploits, unknown to software vendors, can wreak havoc before patches are developed.

{% embed https://thehackernews.com/2020/04/zero-day-warning-its-possible-to-hack.html %}
> _The default mailing app pre-installed on millions of iPhones and iPads has been found vulnerable to two critical flaws that attackers are exploiting in the wild, at least, from the last two years to spy on high-profile victims.
By The Hacker News_

{% embed https://www.forbes.com/sites/thomasbrewster/2021/12/14/amazon-cisco-microsoft-just-3-of-many-vulnerable-to-log4j-hacks/?sh=5218d97740eb %}

{% embed https://www.wired.com/story/log4j-log4shell/ %}

- SQL Injection <a name="sql"></a>: Malicious code injected through seemingly harmless forms can manipulate databases and steal sensitive information.  

> _"A hacker successfully defaced a page on Microsoft Corp.'s U.K. Web site on Wednesday, resulting in the display of several images, including a photograph of a child waving the flag of Saudi Arabia.
Computer World, 2007"_

{% embed https://www.computerworld.com/article/2542204/microsoft-s-u-k--web-site-hit-by-sql-injection-attack.html %}

> _"GambleForce uses a set of basic yet very effective techniques, including SQL injections and the exploitation of vulnerable website content management systems (CMS) to steal sensitive information, such as user credentials," Singapore-headquartered Group-IB said in a report shared with The Hacker News."_

{% embed https://thehackernews.com/2023/12/new-hacker-group-gambleforce-tageting.html#:~:text=New%20Hacker%20Group%20'GambleForce'%20Tageting%20APAC%20Firms%20Using%20SQL%20Injection%20Attacks,-%EE%A0%82Dec%2014&text=A%20previously%20unknown%20hacker%20outfit,since%20at%20least%20September%202023. %}

- Cross-Site Scripting (XSS)<a name="css"></a>: Attackers inject malicious scripts into your app, hijacking user sessions and potentially commandeering the entire application.

![css](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/cpa8q0g7z7gj7tzjyii1.png) Photo Credit: [BrightSec](https://brightsec.com/blog/xss-attack/)

{% embed https://brightsec.com/blog/xss-attack/ %}

{% embed https://hackernoon.com/exploring-cross-site-scripting-xss-risks-vulnerabilities-and-prevention-measures %}

- Man-in-the-Middle Attacks: Hackers intercept communication between your app and users, eavesdropping and potentially modifying data.

> _Hackers pulled off an elaborate man-in-the-middle campaign to rip off an Israeli startup by intercepting a wire transfer from a Chinese venture-capital firm intended for the new business._

{% embed https://threatpost.com/ultimate-mitm-attack-steals-1m-from-israeli-startup/150840/ %}

{% embed https://news.sophos.com/en-us/2023/05/24/ransomware-tales-the-mitm-attack-that-really-had-a-man-in-the-middle/ %}

- Denial-of-Service (DoS) Attacks: A flood of traffic overwhelms your app's servers, rendering it inaccessible to legitimate users.



## Reference <a name="ref"></a>
[https://news.ycombinator.com/item?id=15977074](https://news.ycombinator.com/item?id=15977074)
[https://thehackernews.com/search/label/zero-day%20exploit](https://thehackernews.com/search/label/zero-day%20exploit)
[Man In the Middle Attacks](https://thehackernews.com/search/label/man-in-the-middle%20attack)
[Latest manipulator-in-the-middle attacks](https://portswigger.net/daily-swig/mitm)
