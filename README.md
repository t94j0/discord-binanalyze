# Discord ELF

Read binaries from Discord and perform static analysis on it. This project uses r2pipe to analyze binaries, so all binary formats that radare2 supports can work here also.

## Installation

1. Clone this repository
2. `pip3 install -r ./requirements.txt`
3. [Create a bot account][create bot]
4. Create file `~/.config/binanalyze` like below
5. Set `token` variable in `~/.config/binanalyze`
6. [List bot-accessable channels][list channels]
7. Set `target_channel` for what channel you want the bot to live on
8. Set `bot_name` to whatever you'd like. I named mine `elf`


~/.config/binanalyze
```
[DEFAULT]
bot_name = elf
token = my_token
target_channel = 1234
```

## Usage

### Upload Binaries

Simply upload a binary to the selected channel and the bot will give you an ID to reference that binary in the future

### List Available binaries

`!elf list` - List all ELFs the bot owns. The name is the ID.

### Get Info

`!elf info <id>` - Get info about binary

### Get Functions

`!elf functions <id>` - List functions


### ROP Gadgets

`!elf gadgets <id>` - List all ROP gadgets and output to text format

`!elf gadgets <id> <filter>` - List ROP gadgets that satisfy a filter.

Example:

`!elf gadgets test pop rdi` will list all rop gadgets with `pop rdi`

### Strings

In a similar way of searching for ROP gadgets, you can search for strings

`!elf gadgets <id>` - List all strings and output to text format

`!elf gadgets <id> <filter>` - List strings that contain '<filter>'

Example:

`!elf gadgets test pop rdi` will list all rop gadgets with `pop rdi`


## Warnings

* Radare2 command injection

POC:

Input - `!elf gadgets test pop rdi; !ls`

```
main.py
  0x000012d3                 5f  pop rdi
  0x000012d4                 c3  ret
```

[create bot]: https://discordpy.readthedocs.io/en/latest/discord.html#discord-intro
[list channels]: https://github.com/t94j0/discord-serverlist
