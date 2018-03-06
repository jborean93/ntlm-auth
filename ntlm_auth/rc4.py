# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import struct


class ARC4(object):
    state = None
    i = 0
    j = 0

    def __init__(self, key):
        # Split up the key into a list
        key_bytes = []
        for i in range(len(key)):
            key_byte = struct.unpack("B", key[i:i + 1])[0]
            key_bytes.append(key_byte)

        # Key-scheduling algorithm (KSA)
        self.state = [n for n in range(256)]
        j = 0
        for i in range(256):
            j = (j + self.state[i] + key_bytes[i % len(key_bytes)]) % 256
            self.state[i], self.state[j] = self.state[j], self.state[i]

    def update(self, value):
        chars = []
        random_gen = self._random_generator()
        for i in range(len(value)):
            byte = struct.unpack("B", value[i:i + 1])[0]
            updated_byte = byte ^ next(random_gen)
            chars.append(updated_byte)
        return bytes(bytearray(chars))

    def _random_generator(self):
        # Pseudo-Random Generation Algorithm (PRGA)
        while True:
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.state[self.i]) % 256
            self.state[self.i], self.state[self.j] = \
                self.state[self.j], self.state[self.i]
            yield self.state[(self.state[self.i] + self.state[self.j]) % 256]
