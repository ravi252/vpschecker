VPS Checker Telegram Bot
========================

1) Create a bot
---------------
* Open @BotFather on Telegram -> /newbot -> copy the TOKEN.

2) Set the token  (either one)
------------------------------
* File: put the token in  bot_token.txt   (same folder as vps_bot.py)
* Env:  set  VPSBOT_TOKEN  (or BOT_TOKEN) to the token

3) Install deps & run
---------------------
    pip install -r requirements.txt
    python vps_bot.py

4) Use it
---------
In the bot:
  /start  ->  pick  [VPS List]  or  [Combo / UPL]
      * VPS List  : your file already is  ip:port:user:pass
      * Combo/UPL : messy list - the bot extracts first, then checks
  then send the .txt file (or just paste the text)
  -> you get  working.txt  (the working VPS as a file, plus the same list as a readable chat message, in case your app will not open the .txt inline)
     (dead/failed servers are still logged on the server under bot_runs/)

Notes
-----
* workers=50, timeout=8s  (change at the top of vps_bot.py)
* PING_ONLY at the top of vps_bot.py -> True for a fast TCP-only check
* Telegram bot file downloads are capped at 20 MB
* Runs are stored under  bot_runs/  and auto-cleaned after 1 hour
