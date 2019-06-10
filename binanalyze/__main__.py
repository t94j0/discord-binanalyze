from binanalyze.elf import ELF
from binanalyze import configuration

config = configuration.create()
BOT_NAME = config.get('DEFAULT', 'bot_name')
TOKEN = config.get('DEFAULT', 'token')
TARGET_CHANNEL = config.getint('DEFAULT', 'target_channel')

client = ELF(BOT_NAME, TARGET_CHANNEL)
client.run(TOKEN, bot=True)
