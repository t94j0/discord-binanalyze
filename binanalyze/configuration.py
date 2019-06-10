import os
import configparser


def create() -> 'configparser.ConfigParser':
    config = configparser.ConfigParser()
    config['DEFAULT'] = {
        'bot_name': 'elf',
        'token': 'NONE',
        'target_channel': '0'
    }
    config.read([
        os.path.expanduser('~/.config/binanalyze'),
        os.path.expanduser('~/.binanalyze'), '/etc/binanalyze'
    ])
    return config


if __name__ == '__main__':
    config = create()
    print(config.get('DEFAULT', 'bot_name'))
    print(config.get('DEFAULT', 'token'))
    print(config.getint('DEFAULT', 'target_channel'))
