import discord
import tempfile
from datetime import datetime
from discordrouter import Router, message
import r2pipe

BOT_NAME = 'elf'
TOKEN = '<TOKEN>'
TARGET_CHANNEL = 0

class ELF(discord.Client):
    router = Router(f'!{BOT_NAME}', auto_help=True)

    async def on_ready(self):
        print(f'Logged in as {self.user.name}')
        print('------')
        self.attachments = {}

    async def on_message(self, message):
        if message.channel.id != TARGET_CHANNEL:
            return
        if len(message.attachments) == 1:
            if message.author.id == self.user.id:
                return
            await self.handle_attachment(message.channel.send, message.attachments[0])
        else:
            with message.channel.typing():
                await self.router(self, message)

    async def handle_attachment(self, send, attachment):
        await send(f'Uploaded as `{attachment.filename}`')
        self.attachments[attachment.filename] = attachment

    async def write_attachment(self, _id: str, args = []) -> 'r2pipe':
        att = self.attachments[_id]
        filename = f'/tmp/{att.filename}'
        fd = open(filename, 'wb+')
        await att.save(fd)
        return r2pipe.open(filename)

    async def output(self, send, message):
        if message == '':
            await send('`No output`')
            return
        await send(f'```{message}```')


    @message(router, 'list', 'Upload attachment')
    async def _attachment(self, send, **kwargs):
        message = '```'
        for attachment in self.attachments:
            message += f'- {attachment}\n'
        message += '```'
        await send(message)

    @message(router, 'info <id>', 'Get info about binary')
    async def _info(self, items, send, **kwargs):
        _id = items['id']
        r2 = await self.write_attachment(_id)
        out = r2.cmd('i').decode('utf-8')
        await self.output(send, out)

    @message(router, 'functions <id>', 'List binary funcions')
    async def _functions(self, items, send, **kwargs):
        _id = items['id']
        r2 = await self.write_attachment(_id)
        out = r2.cmd('aaaa; afl').decode('utf-8')
        await self.output(send, out)

    @message(router, 'gadgets <id>', 'Get ropgadgets. Add a chain filter to the end')
    async def _functions(self, items, message, send, **kwargs):
        target = items['id']
        # Manually split filter and ID
        _id = target.split(' ')[0]
        _filter = ' '.join(target.split(' ')[1:])
        r2 = await self.write_attachment(_id)

        if _filter != '':
            out = r2.cmd(f'/R {_filter}').decode('utf-8')
            await self.output(send, out)
        else: # non-filtered
            fp = tempfile.NamedTemporaryFile('w')
            fp_name = fp.name
            out = r2.cmd(f'/R').decode('utf-8')
            fp.write(out)
            files = [discord.File(fp_name, f'{_id}_gadgets')]
            await send(files=files)

if __name__ == '__main__':
    client = ELF()
    client.run(TOKEN, bot=True)
