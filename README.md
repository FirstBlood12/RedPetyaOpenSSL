# RedPetyaOpenSSL

A complete rewrite of original Red Petya that works on MBR and GPT disks.
In order to work on GPT disks, UEFI needs to support Legacy boot.

# How It Works?

This RedPetyaOpenSSL project works exactly as original Red Petya,
It uses OpenSSL library for public key cryptography.

# How Red Petya Infects MBR Disk?

1. If Red Petya detects MBR disk then Red Petya reads original MBR from sector 0, encrypts every byte of original MBR using
XOR 0x37 and writes the XOR encrypted MBR in sector 56.
2. It encrypts sector 1-33 with XOR 0x37.
3. It generates configuration data for Red Petya kernel like Salsa10 key, 8 byte random nonce and the personal decryption code
is the random salsa10 key used for MFT encryption encrypted with public key cryptography secp192k1 with Janus public key
and base58 encoded.
4. It fills all 512 bytes of sector 55 with 0x37 this sector is the verification sector.
5. It will construct Red Petya bootloader by copying the disk ID and the partition table from original MBR(byte 440-510)
into its own bootloader, It will write the newly constructed Red Petya bootloader to sector 0 and it will write its own
16 bit kernel to sector 34-50
6. It will call undocumented API called NtRaiseHardError with 0xc0000350 error causing operating system to crash

# How Red Petya Infects GPT Disk?

1. If Red Petya detects GPT disk it will get location for backup GPT Header by reading the Primary GPT Header(sector 1),
Backup GPT Header location is in offset 0x20 of the Primary GPT Header sector.
2. It will use SetFilePointerEx to navigate to backup GPT Header which is last sector of the GPT drive,
It will encrypt Backup GPT Header by encrypting it with XOR 0x37(last sector -33 sectors).
3. It will encrypt sector 1-33 with XOR 0x37(Primary GPT Header on GPT disk)
4. It will set disk ID to 7777 and it will manually construct a entry in the partition table of its own bootloader that represents the whole drive.
the 7777 disk ID tells the petya kernel that disk is GPT, and the entry in the partition table that represents the whole drive
is done because some UEFI implementations immediately switch to the BIOS-based CSM booting upon detecting certain types of partition table on the drive
thus executing RedPetya bootloader.
5. It does all the actions that are performed on MBR disk.

# How Is The Personal Decryption Code Generated?

1. Red Petya dropper generates 16 random bytes from Base54 alphabet using CryptGenRandom.
We will call these bytes Salsa10key.
2. Generate a pair of keys: victim private key(victimpriv) and victim public key(victimpub) on secp192k1 curve.
3. Calculate the shared secret based on ECDH, shared_secret = ECDH(victimpriv, Januspub);
The RedPetya author public key is hardcoded in Petya dropper.
4. Calculate the AESKEY = SHA512(shared_secret);
5. XOR the Salsa10key with victimpub(victim public key).
6. Encrypt the result using AES-256 ECB with the key AESKEY(first 32 bytes of SHA512 hash of shared secret).
7. Create a array that will contain the victim public key and encrypted Salsa10key.
8. Base58 encode the victimpublickey and Salsa10key buffer.
9. SHA256 hash the base58 encoded data.
10. Create a buffer that will contain the final personal decryption code(90 bytes)
and it will contain (check1, check2 and base58 encoded victim public key and encrypted Salsa10key,
check1 and check2 are bytes calculated by the formulas:
a = sha256hash[0] & 0xF;
b = (sha256hash[0] & 0xF) < 10;
check1 = (sha256hash[0] >> 4) + 0x57 + ((sha256hash[0] >> 4) < 10 ? 0xD9 : 0);
check2 = a + 0x57 + (b ? 0xD9 : 0);
11. Put the final base58 encoded personal decryption code in sector 54 at offset 0xA9

# How the MFT(Master File Table) encryption works?
1. After the RedPetya dropper crashes the system and PC reboots, the BIOS or UEFI(if supports Legacy boot)
will read sector 0 in memory at physical address 0x7C00.
2. RedPetya bootloader will be loaded at physical address 0x7C00, RedPetya bootloader will read sector 34-50(Red Petya 16 bit kernel)
in physical memory address 0x8000 and will jump there.
3. RedPetya kernel will read sector 54 in memory buffer and will check if the first byte of sector 54 buffer is 0x01(MFT Encrypted),
(the first byte of sector 54) will always be 0x00(MFT Not Encrypted) after RedPetyaDropper was ran,
So because first byte of sector 54 is 0x00, the first thing Red Petya kernel does is set the first byte of sector 54 buffer to 0x01(MFT Encrypted).
Next it will copy Salsa10key(32 bytes) from sector 54 buffer into a temporary buffer, it will overwrite Salsa10key(32 bytes) of sector 54 buffer with zeroes,
It will write sector 54 buffer back to sector 54 of the drive.
4. Red Petya kernel will read sector 55(verification sector) into a buffer, encrypt it using Salsa10 algorithm with the key from the temporary buffer and
8 byte random nonce from sector 54(just after the salsa10 key, the nonce stays permanent).
5. Red Petya kernel will get MFT location for each NTFS partition on the drive and will compute number of sectors for the entire MFT table for each NTFS partition.
6. Red Petya kernel will start reading, encrypting with Salsa10 cipher and writing back the MFT Clusters, Red Petya kernel reads 8 MFT sectors per pass, encrypts them with Salsa10
and writes them back to the drive.
7. While this is done, a number of encrypted MFT clusters is kept in sector 57(this is done in case victim reboots, he gets key and red petya kernel knows how much to decrypt),
Also while MFT encryption is done, number of MFT sectors is also updated on fake CHKDSK which encrypts MFT.
8. After all MFT clusters of every NTFS partition are encrypted, Red Petya kernel triggers a reboot by calling INT 19h.
9. This time BIOS will read RedPetya bootloader and RedPetya bootloader will read and execute RedPetya kernel in memory again.
10. This time RedPetya kernel will read sector 54 again in buffer and it will check the first byte of it, this time first byte of sector 54 is 0x01(MFT Encrypted),
so this time RedPetya kernel displays blinking white skull with red background which blinks.
11. After victim presses any key Red Petya kernel shows what must be done in order to decrypt the hard drive and shows onion urls and personal decryption code.

# How the MFT(Master File Table) decryption works?
1. At this stage the Master File Table has already been encrypted using Salsa10 cipher and the key used for encrypting the MFT has been erased from sector 54.
2. RedPetya kernel reads input from user into a buffer(it reads only the first 16 characters),
the characters must be from Base54 alphabet otherwise they are skipped.
3. The entered 16 byte key is encoded and expanded to 32 byte key using custom algorithm.
4. RedPetya kernel will read the 8 byte nonce from sector 54(it is just before onion links).
5. RedPetya kernel will use the 32 byte key that is get by the user 16 byte key using a custom algorithm.
6. Sector 55(verification sector) will be read in memory buffer and it will be decrypted with Salsa10 256 bit using encoded key from the user and 8 byte nonce from sector 54.
7. RedPetya kernel will check if every byte from decrypted sector 55 buffer is 0x37, if it is then means the key is correct and will be used to decrypt the MFT but if is not
then RedPetyakernel prints Incorrect key and asks for key again.
8. If entered key is correct RedPetya kernel will read sector 54 in buffer, it will set first byte of sector 54 to 0x02(MFT decrypted), it will write the encoded 32 byte key to sector 54 buffer, it will write sector 54 buffer to sector 54 and it will use encoded 32 byte key with 8 byte nonce to decrypt the MFT sectors and it will display Decrypting sector with a progress.
9. After all MFT sectors of all NTFS partitions are decrypted RedPetya kernel will restore original MBR by reading sector 56 in buffer, decrypting every byte of it with XOR 0x37
and writing it to sector 0, it will also do the same to sector 1-33.
10. If disk ID of the MBR is 0x37373737 then RedPetya kernel will decrypt additional sectors always with XOR 0x37(Decrypting Backup GPT Header)

# Salsa10 Encryption Cracked!
Just after a month of Red Petya appereance in 2016 someone has managed to crack Salsa10 in seconds using Genetic Algorithms.
https://github.com/leo-stone/hack-petya
The program needs the encrypted sector 55 with Salsa10 and 8 byte nonce from sector 54 and it recovers the original key in seconds.
However later new variants emerged which used fixed Salsa20 for example Mischa v2 and GoldenEye which were not crackable by external tools.

# Original Author of Red Petya publishes his secp192k1 private key
After almost one year of RedPetya, on June 27 2017 a massive NotPetya(malware based on GoldenEye kernel) malware cyberattack appeared
that was actually wiper and destroyed MFT of infected computers it also used EternalBlue to spread across local networks like a worm.
This forced the original author of Petya to publish his secp192k1 private key:
https://blog.malwarebytes.com/cybercrime/2017/07/the-key-to-the-old-petya-has-been-published-by-the-malware-author/
And program for decrypting Red Petya, Green Petya and Mischa as well as GoldenEye has been created:
https://github.com/hasherezade/petya_key
This program doesnt works on NotPetya because NotPetya Salsa20 keys are not encrypted and turned into personal codes but instead erased and lost forever.
As well it doesnt works for PetrWrap ransomware which is based on Mischa v2 DLL:
https://securelist.com/petrwrap-the-new-petya-based-ransomware-used-in-targeted-attacks/77762/
Because they choose different curve prime192v1 or secp192r1 and they use their own public and private key.
petya_key works for RedPetyaOpenSSL as well.

# Prerequisites:

Microsoft Visual Studio 2010 and later Only use Win32/Release configuration because Debug is not configured properly.
