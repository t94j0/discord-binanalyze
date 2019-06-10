import discord
import tempfile
from datetime import datetime
from discordrouter import Router, message
import r2pipe


class ELF(discord.Client):
    router = Router(f'!default', auto_help=True)

    def __init__(self, bot_name: str, channel_id: int):
        super().__init__()
        self.router.set_name(f'!{bot_name}')
        self.channel_id = channel_id

    async def on_ready(self):
        print(f'Logged in as {self.user.name}')
        print('------')
        self.attachments = {}

    async def on_message(self, message):
        if message.channel.id != self.channel_id:
            return

        if len(message.attachments) == 1 and message.author.id != self.user.id:
            await self.handle_attachment(message.channel.send,
                                         message.attachments[0])
        else:
            await self.router(self, message)

    async def handle_attachment(self, send, attachment):
        await send(f'Uploaded as `{attachment.filename}`')
        self.attachments[attachment.filename] = attachment

    async def create_r2pipe(self, _id: str) -> 'r2pipe':
        filename = await self.write_attachment(_id)
        return r2pipe.open(filename)

    async def write_attachment(self, _id: str) -> str:
        _file = self.attachments[_id]
        filename = f'/tmp/{_file.filename}'
        fd = open(filename, 'wb+')
        await _file.save(fd)
        return filename

    async def r2_cmd(self, _id: str, cmd: str) -> str:
        r2 = await self.create_r2pipe(_id)
        return r2.cmd(cmd).decode('utf-8')

    # Output functions
    async def output(self, send, message: str, filename: str):
        if len(message) >= 2000:
            await self.output_file(send, message, filename)
        else:
            await self.output_send(send, message)

    async def output_send(self, send, message: str):
        final = '`No output`' if message == '' else f'```{message}```'
        await send(final)

    async def output_file(self, send, message: str, filename: str):
        print(message)
        fp = tempfile.NamedTemporaryFile('w')
        fp.write(message)
        files = [discord.File(fp.name, filename)]
        await send(files=files)
        fp.close()

    # Message handlers
    @message(router, 'list', 'List all binaries bot owns and their IDs')
    async def _attachment(self, send, **kwargs):
        message = '\n'.join([f'- {a}' for a in self.attachment])
        await self.output(send, message, 'binaries')

    @message(router, 'info <id>', 'Get info about binary')
    async def _info(self, items, send, **kwargs):
        _id = items['id']
        output = await self.r2_cmd(_id, 'i')
        await self.output(send, output, f'{_id}_info')

    @message(router, 'functions <id>', 'List binary functions')
    async def _functions(self, items, send, **kwargs):
        _id = items['id']
        output = await self.r2_cmd(_id, 'aaaa; afl')
        await self.output(send, output, f'{_id}_functions')

    @message(router, 'gadgets <id> <filter>', 'Get ropgadgets with a filter')
    async def _gadgets_filter(self, items, send, **kwargs):
        _id = items['id']
        _filter = items['filter']
        # TODO: Fix injection
        output = await self.r2_cmd(_id, f'/R {_filter}')
        await self.output(send, output, f'{_id}_gadgets_{_filter}')

    @message(router, 'gadgets <id>', 'Get all ropgadgets')
    async def _gadgets_all(self, items, send, **kwargs):
        _id = items['id']
        output = await self.r2_cmd(_id, '/R')
        await self.output_file(send, output, f'{_id}_gadgets')

    @message(router, 'strings <id> <filter>', 'Get strings with a filter')
    async def _strings_filter(self, items, send, **kwargs):
        _id = items['id']
        _filter = items['filter']
        # TODO: Fix injection
        output = await self.r2_cmd(_id, f'izz~{_filter}')
        await self.output(send, output, f'{_id}_strings_{_filter}')

    @message(router, 'strings <id>', 'Get all strings')
    async def _gadgets_all(self, items, send, **kwargs):
        _id = items['id']
        output = await self.r2_cmd(_id, 'izz')
        await self.output_file(send, output, f'{_id}_strings')
