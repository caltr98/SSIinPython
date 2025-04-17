from mnemonic import Mnemonic
#pip install mnemonic
mnemo = Mnemonic("english")
words = mnemo.generate(strength=128)  # 128 bits = 12 words; use 256 for 24 words
print("Mnemonic:", words)
