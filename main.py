import telebot
from telebot import types, apihelper
import json
import time
import os
import sys
from datetime import datetime

# Custom Modules
from keep_alive import keep_alive
import database as db
import like_api 
import account_verifier 

apihelper.RETRY_ON_ERROR = True
apihelper.MAX_RETRIES = 3

# --- LOAD CONFIG ---
def load_config():
    if not os.path.exists('config.json'):
        print("❌ config.json not found!")
        sys.exit(1)
    with open('config.json', 'r') as f:
        return json.load(f)

config = load_config()
BOT_TOKEN = config.get('bot_token')
ADMIN_ID = int(config.get('admin_id'))

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="Markdown", threaded=True)
user_steps = {} 

# --- HELPER FUNCTIONS ---
def is_subscribed(user_id):
    required_channels = db.get_channels()
    if not required_channels: return True, []
    not_joined = []
    for channel in required_channels:
        try:
            status = bot.get_chat_member(channel, user_id).status
            if status not in ['member', 'administrator', 'creator']: 
                not_joined.append(channel)
        except Exception: 
            pass
    return (False, not_joined) if not_joined else (True, [])

# --- KEYBOARDS ---
def main_menu():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("👍 Get Server Likes", "📂 Active Account")
    markup.add("👮 Admin Panel", "👤 My Profile")
    return markup

def server_menu():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=3)
    servers = ["BD", "IND", "SG", "BR", "US", "SAC", "NA", "ME", "TH", "VN"]
    markup.add(*[types.KeyboardButton(s) for s in servers])
    markup.add("🔙 Back to Menu")
    return markup

def admin_menu():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("📢 Broadcast", "📊 Statistics")
    markup.add("➕ Add Channel", "➖ Remove Channel")
    markup.add("⚙️ Set Access Cost", "🎁 Grant Access")
    markup.add("🔙 Back to Menu")
    return markup

# --- START HANDLER ---
@bot.message_handler(commands=['start'])
def start_handler(message):
    user_id = message.from_user.id
    db.add_user(message.from_user)
    if user_id in user_steps: del user_steps[user_id]

    subscribed, channels = is_subscribed(user_id)
    if not subscribed:
        markup = types.InlineKeyboardMarkup()
        for ch in channels: 
            markup.add(types.InlineKeyboardButton(f"📢 Join {ch}", url=f"https://t.me/{ch.replace('@', '')}"))
        markup.add(types.InlineKeyboardButton("✅ I Have Joined", callback_data="check_sub"))
        
        bot.send_message(user_id, "⚠️ **Access Denied: Mandatory Subscription**\n\nTo access the features of this bot, you must join our official channels.", reply_markup=markup)
        return

    welcome_msg = (
        f"👋 **Welcome, {message.from_user.first_name}!**\n\n"
        "⚡ **Auto Like & Player Info System** ⚡\n"
        "────────────────────────\n"
        "🔹 *Submit Level 8+ Guest Accounts to earn Premium Access.*\n"
        "🔹 *Use Premium Access to send automated likes.*\n\n"
        "👇 *Please select an option from the menu below to start.*"
    )
    bot.send_message(user_id, welcome_msg, reply_markup=main_menu())

@bot.callback_query_handler(func=lambda call: call.data == "check_sub")
def check_join_callback(call):
    subscribed, _ = is_subscribed(call.from_user.id)
    if subscribed:
        bot.delete_message(call.message.chat.id, call.message.message_id)
        bot.send_message(call.from_user.id, "✅ **Verification Successful!** Welcome to the bot.", reply_markup=main_menu())
    else:
        bot.answer_callback_query(call.id, "❌ You haven't joined all the required channels yet!", show_alert=True)

# --- 1. GET SERVER LIKES (Premium Feature) ---
@bot.message_handler(func=lambda m: m.text == "👍 Get Server Likes")
def get_likes_start(message):
    user_id = message.from_user.id
    
    has_access, expire_date = db.check_subscription(user_id)
    if not has_access and user_id != ADMIN_ID:
        conf = db.get_config()
        bot.reply_to(message, f"❌ **Premium Access Required!**\n\n📌 Requirement: Submit **{conf['req_accounts']}** valid Level 8+ Guest Account(s) using the **📂 Active Account** option.\n🎁 Reward: You will receive **{conf['reward_days']} days** of Premium Access.")
        return

    msg = "🌍 **Select the Target Server:**"
    if user_id != ADMIN_ID: msg += f"\n\n⏳ *Your Premium Expires On:* `{expire_date}`"
    bot.reply_to(message, msg, reply_markup=server_menu())
    user_steps[user_id] = {'step': 'server_select', 'flow': 'likes'}

# --- 2. ACTIVE ACCOUNT SUBMISSION FLOW ---
@bot.message_handler(func=lambda m: m.text == "📂 Active Account")
def active_acc_start(message):
    bot.reply_to(message, "🌍 **Select Account Region:**\nWhich server does your guest account belong to?", reply_markup=server_menu())
    user_steps[message.from_user.id] = {'step': 'server_select', 'flow': 'submit_acc'}

@bot.message_handler(func=lambda m: m.text in ["BD", "IND", "SG", "BR", "US", "SAC", "NA", "ME", "TH", "VN"])
def server_selected(message):
    uid = message.from_user.id
    if uid not in user_steps: return
    
    server = message.text
    user_steps[uid]['server'] = server
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True).add("🔙 Back to Menu")
    
    if user_steps[uid]['flow'] == 'likes':
        user_steps[uid]['step'] = 'uid_input_likes'
        bot.reply_to(message, f"✅ **Server Selected:** {server}\n\n🆔 **Enter the Target Player UID:**", reply_markup=markup)
    elif user_steps[uid]['flow'] == 'submit_acc':
        user_steps[uid]['step'] = 'submit_acc_uid'
        bot.reply_to(message, f"✅ **Server Selected:** {server}\n\n👤 **Enter the Guest Account UID:**", reply_markup=markup)

@bot.message_handler(func=lambda m: user_steps.get(m.from_user.id, {}).get('step') == 'uid_input_likes')
def process_uid_likes(message):
    if message.text == "🔙 Back to Menu": return back_home(message)
    server = user_steps[message.from_user.id]['server']
    target_uid = message.text
    
    msg = bot.reply_to(message, f"⏳ **Processing Likes...**\n_Target UID:_ `{target_uid}`")
    try:
        res = like_api.execute_likes(target_uid, server)
        bot.delete_message(message.chat.id, msg.message_id)
        
        if res['success']: 
            # Full Detailed Reply
            success_text = (
                f"✅ **Likes Delivered Successfully!**\n\n"
                f"👤 **Name:** {res['name']}\n"
                f"🆔 **UID:** `{res['uid']}`\n"
                f"🌍 **Server:** {server}\n"
                f"📊 **Likes Before:** {res['before']}\n"
                f"📈 **Likes After:** {res['after']}\n"
                f"🚀 **Total Likes Sent:** +{int(res['after']) - int(res['before'])}\n"
                f"🤖 **Total Accounts Used:** {res['total_acc']}"
            )
            bot.reply_to(message, success_text, reply_markup=main_menu())
        else: 
            bot.reply_to(message, res['msg'], reply_markup=main_menu())
            
    except Exception as e:
        bot.delete_message(message.chat.id, msg.message_id)
        bot.reply_to(message, "❌ **Error:** Could not process request.", reply_markup=main_menu())
        
    del user_steps[message.from_user.id]

# --- ACCOUNT VERIFICATION SYSTEM ---
@bot.message_handler(func=lambda m: user_steps.get(m.from_user.id, {}).get('step') == 'submit_acc_uid')
def process_submit_uid(message):
    if message.text == "🔙 Back to Menu": return back_home(message)
    user_steps[message.from_user.id]['acc_uid'] = message.text
    user_steps[message.from_user.id]['step'] = 'submit_acc_pass'
    bot.reply_to(message, "🔑 **Enter the Guest Account Password:**")

@bot.message_handler(func=lambda m: user_steps.get(m.from_user.id, {}).get('step') == 'submit_acc_pass')
def process_submit_pass(message):
    if message.text == "🔙 Back to Menu": return back_home(message)
    
    user_id = message.from_user.id
    acc_uid = user_steps[user_id]['acc_uid']
    acc_pass = message.text
    server = user_steps[user_id]['server']
    
    msg = bot.reply_to(message, "⏳ **Verifying Account Credentials & Level...**\n_Please wait, connecting to server..._")
    
    try:
        result = account_verifier.check_and_save_account(acc_uid, acc_pass, server)
        bot.delete_message(message.chat.id, msg.message_id)
        
        if result['success']:
            rewarded, left = db.increment_submitted_account(user_id)
            level = result.get('level', 'N/A')
            
            reply_text = f"✅ **Account Verified Successfully!**\n📊 **Account Level:** {level}\n🌍 **Server:** {server}\n\n"
            
            if rewarded:
                reply_text += f"🎉 **Access Granted!** You have earned Premium Access. You can now use the Auto Like feature."
            else:
                reply_text += f"📈 **Progress:** Submit **{left}** more Level 8+ account(s) to unlock Premium Access."
                
            bot.reply_to(message, reply_text, reply_markup=main_menu())
        else:
            bot.reply_to(message, f"❌ **Verification Failed!**\n{result['msg']}", reply_markup=main_menu())
            
    except Exception as e:
        bot.reply_to(message, "❌ **Network Error:** Failed to connect to verification server. Please try again.", reply_markup=main_menu())
        
    finally:
        if user_id in user_steps:
            del user_steps[user_id]

# --- OTHER HANDLERS ---
@bot.message_handler(func=lambda m: m.text == "🔙 Back to Menu")
def back_home(message):
    if message.from_user.id in user_steps: del user_steps[message.from_user.id]
    bot.reply_to(message, "🏠 **Returned to Main Menu.**", reply_markup=main_menu())

@bot.message_handler(func=lambda m: m.text == "👤 My Profile")
def my_info(message):
    try:
        uid = message.from_user.id
        has_sub, exp = db.check_subscription(uid)
        status = f"✅ Premium (Valid until: {exp})" if has_sub or uid == ADMIN_ID else "❌ Free User"
        bot.reply_to(message, f"👤 **User Profile**\n─────────────────\n**Name:** {message.from_user.first_name}\n**User ID:** `{uid}`\n**Status:** {status}")
    except Exception as e:
        print(e)

# --- ADMIN PANEL ---
@bot.message_handler(func=lambda m: m.text == "👮 Admin Panel")
def admin_panel(message):
    if message.from_user.id == ADMIN_ID: bot.reply_to(message, "👮‍♂️ **Administrator Dashboard**", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: m.text == "⚙️ Set Access Cost")
def set_cost(message):
    if message.from_user.id != ADMIN_ID: return
    msg = bot.reply_to(message, "✍️ **Set Subscription Reward:**\n*Format:* `Accounts, Days` (e.g., `1, 3`)")
    bot.register_next_step_handler(msg, lambda m: db.update_config(*map(int, m.text.split(','))) or bot.reply_to(m, "✅ **Updated!**"))

@bot.message_handler(func=lambda m: m.text == "🎁 Grant Access")
def grant_acc(message):
    if message.from_user.id != ADMIN_ID: return
    msg = bot.reply_to(message, "✍️ **Grant Access:**\n*Format:* `UserID, Days`")
    def process_grant(m):
        try:
            uid, days = map(int, m.text.split(','))
            exp = db.grant_access(uid, days)
            bot.reply_to(m, f"✅ Access Granted to `{uid}` till {exp}")
            bot.send_message(uid, f"🎉 Admin granted you {days} Days Premium!")
        except: bot.reply_to(m, "❌ Invalid Format!")
    bot.register_next_step_handler(msg, process_grant)

@bot.message_handler(func=lambda m: m.text == "📊 Statistics")
def stats(message):
    if message.from_user.id == ADMIN_ID: bot.reply_to(message, f"📊 **Statistics:**\n👥 Total Users: `{db.get_total_users()}`")

@bot.message_handler(func=lambda m: m.text == "➕ Add Channel")
def add_ch(message):
    if message.from_user.id == ADMIN_ID:
        msg = bot.reply_to(message, "📢 **Enter Channel Username (with @):**")
        bot.register_next_step_handler(msg, lambda m: db.add_channel(m.text) and bot.reply_to(m, "✅ **Channel Added!**"))

@bot.message_handler(func=lambda m: m.text == "➖ Remove Channel")
def rem_ch(message):
    if message.from_user.id != ADMIN_ID: return
    chs = db.get_channels()
    if not chs: return bot.reply_to(message, "❌ No channels.")
    markup = types.ReplyKeyboardMarkup(one_time_keyboard=True, resize_keyboard=True)
    for c in chs: markup.add(c)
    bot.register_next_step_handler(bot.reply_to(message, "🗑️ Select:", reply_markup=markup), lambda m: db.remove_channel(m.text) or bot.reply_to(m, "✅ Removed!", reply_markup=admin_menu()))

@bot.message_handler(func=lambda m: m.text == "📢 Broadcast")
def broad(message):
    if message.from_user.id == ADMIN_ID:
        bot.register_next_step_handler(bot.reply_to(message, "📝 **Send message:**"), lambda m: bot.reply_to(m, "✅ Broadcast started."))

# --- RUN (UPDATED FOR VERCEL) ---
if __name__ == "__main__":
    db.init_db()
    print("🚀 Bot Logic Loaded Successfully...")
    # পোলিং বা keep_alive এখানে আর চলবে না, কারণ Vercel Webhook-এর মাধ্যমে কাজ করবে।
