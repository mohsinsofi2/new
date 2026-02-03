# 🔍 Telegram Checker Bot

**Telegram Checker Bot** is a Python-based Telegram bot for card verification, BIN lookup, fake user generation, and card utilities. It uses web scraping and third-party APIs for validation and data fetching.

# ⚡ Features
## 👤 Features meant for users
- **Card Checker:** Validate card status (Approved/Declined), retrieve card details (bank, brand, country, type)
- **VBV/Non-VBV Check:** Identify if a card is Verified by Visa
- **BIN Lookup:** Fetch issuer, country, scheme, tier and type for any BIN
- **Fake User Generator:** Generate random user profiles using country codes
- **Card Generator:** Produce fake card numbers using BIN
- **Mass Card Checker:** Batch validate multiple cards
- **Inline Keyboards:** User navigation and quick command access
- **Gemini:** ask ai for general questions
## 👮‍♂️ Features meant for Bot Admins / Owner
- **Broadcast:** Broadcast any type of message to all the users at once using a command
- **Ban / Unban Users:** Restrict some users from checking cards if defy the rules
- **Add admin:** Add other admins to the bot to control the system, also remove them if they are not worthy

# ⬇ Bot setup
## 🤖 Cloning
```
git clone https://github.com/aMuL-creates/Checkerbot/
```
## 💾 Database Setup
`Database used : SQLite3` <br>
In order to setup SQLite3 database, run the following command in your terminal
```
python dbsetter.py
```
**OR**<br>
Make a file named : `checkerdata.db` Run following commands one by one in your SQLite3 explorer.
```
--SQLite3
CREATE TABLE Users (user_id INTEGER, state TEXT, post TEXT);
CREATE TABLE Groups (chatid INTEGER, link TEXT);
```
## 🔐 Environment variable
Make a file named : `.env` and add the following variables
- **TOKEN:** Get your Bot token from `@Botfather`
- **GEMINI_API_KEY:** Get your API_KEY from **[Google Ai studio](https://aistudio.google.com/api-keys)** or **[Watch Tutorial](https://youtube.com/clip/Ugkx22pzdGAviy3DE_rHlsICeTLEOwaDCsh-?si=8Dprj9_mnku0qDJb)**
```
.env
TOKEN = "<REPLACE_BOT_TOKEN>"
GEMINI_API_KEY = "<REPLACE_API_KEY>"
```
## 🔑 Bot configs
![Code_snippet](/images/carbon.png)
> The above pic is part of code snippet from `checkerbot.py`

- **botname ![optional](https://img.shields.io/badge/optional-green) :** Replace `ᒪOGIᑕ ᑕᕼK ♡` with your desired name .
- **botusername ![optional](https://img.shields.io/badge/optional-green) :** Replace `@LogicChkBOT1` with your bot username .
- **owner id ![compulsory](https://img.shields.io/badge/compulsory-red) :** Replace `5631537532` with your Telegram user-id . Get your user-id from `@EskoIDBot` .
- **owner link ![optional](https://img.shields.io/badge/optional-green) :** Replace `https://t.me/amitispro` with your user link .
- **owner name ![optional](https://img.shields.io/badge/optional-green) :** Replace `𝘼𝙢𝙞𝙩` with your name .
- **maingroup link ![compulsory](https://img.shields.io/badge/compulsory-red) :** Replace `https://t.me/+p8ZIdF9xfoBhYTk9` with your group link .
- **maingroup chat id ![compulsory](https://img.shields.io/badge/compulsory-red) :** Replace `-1002901633480` . Get your group's chat-id from `@EskoIDBot` .
- **mainchannel ![optional](https://img.shields.io/badge/optional-green) :** Replace `https://t.me/+uRexADKq_rljYjVl` with your channel link .

> **NOTE:** <br>
> ![optional](https://img.shields.io/badge/optional-green) : These won’t affect the database.<br>
> ![compulsory](https://img.shields.io/badge/compulsory-red) : These will affect the database and may break the code.

# 🚅 Run the bot
```
python checkerbot.py
```

# 📚 Requirements

- Python 3.7+
- `requests`
- `beautifulsoup4`
- `python-dotenv`
- `python-telegram-bot`
- `google-genai`

*(See `requirements.txt` for a complete list.)*

# 📝 Usage

After adding the bot to your group/channel and starting it, use the following commands:

| Command       | Usage Example                                    | Description                               | Users | Admin | Owner |
|---------------|--------------------------------------------------|-------------------------------------------|:-----:|:-----:|:-----:|
| `/check`      | `/check cardnumber mm yy cvv`                    | Check a card’s status and get details     |  ✅   |  ✅   |  ✅   |
| `/vbv`        | `/vbv cardnumber mm yy cvv`                      | Verify VBV (Visa) status                  |  ✅   |  ✅   |  ✅   |
| `/bin`        | `/bin BIN`                                       | Lookup BIN issuer details                 |  ✅   |  ✅   |  ✅   |
| `/gen`        | `/gen BIN`                                       | Generate cards from BIN                   |  ✅   |  ✅   |  ✅   |
| `/fake`       | `/fake countrycode`                              | Generate fake user data                   |  ✅   |  ✅   |  ✅   |
| `/mcheck`     | `/mcheck carddetail1 carddetail2 ...`            | Mass check multiple cards                 |  ✅   |  ✅   |  ✅   |
| `/start`      | `/start`                                         | Get bot start menu & keyboard             |  ✅   |  ✅   |  ✅   |
| `/admincmds`  | `/admincmds`                                     | List admin-only commands                  |  ❌   |  ✅   |  ✅   |
| `/addadmin`   | `/addadmin userid`                               | Promote a user to admin                   |  ❌   |  ❌   |  ✅   |
| `/removeadmin`| `/removeadmin userid`                            | Remove a user's admin rights              |  ❌   |  ❌   |  ✅   |
| `/ban_user`    | `/banuser userid`                                | Ban a user from using the bot             |  ❌   |  ✅   |  ✅   |
| `/unban_user`  | `/unbanuser userid`                              | Unban a user                              |  ❌   |  ✅   |  ✅   |
| `/broadcast`  | `/broadcast text`                                | Broadcast message to all users            |  ❌   |  ✅   |  ✅   |
| `/forwardall` | *(reply to msg)* `/forwardall`                   | Forward a message to all users            |  ❌   |  ✅   |  ✅   |
| `/addgroup`   | `/addgroup chatid link`                          | Add allowed group to bot                  |  ❌   |  ❌   |  ✅   |
| `/removegroup`| `/removegroup chatid`                            | Remove allowed group                      |  ❌   |  ❌   |  ✅   |



> **Note:** Commands like `/mcheck` and `/check` are only accessible to the users in authorised groups.

# 🔗 Configuration

- **Token, API key & Owner/Group IDs:** Set in `.env` and in code.
- **APIs:** Card checks, BIN lookup, and user generation use various public APIs and scraping methods.

# ⚠️ Disclaimer
This project is created strictly for educational and research purposes only.<br>
It is designed to demonstrate how credit card validation algorithms (such as the Luhn algorithm) and API handling techniques can be implemented in Python.
- **This tool does not perform any illegal activity**, nor should it be used to check or validate real or stolen card data.
- The developer **does not take responsibility** for any misuse, damage, or legal consequences that may arise from using this project in violation of applicable laws.
- Users are **fully responsible** for ensuring their usage complies with local laws, terms of service, and banking or payment regulations.
- **Do not use this script for unlawful carding, fraud, or unauthorized testing** on live systems.
> If you are learning or researching payment systems, test only with authorized data or sandbox environments provided by legitimate payment processors.
---

**Bot by [Amit Baliarsingh](https://t.me/amitispro)**
