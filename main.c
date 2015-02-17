#include <string.h>
#include <freefare.h>

/*
 * Compile with: gcc main.c -std=c99 -lfreefare -o main
 */

// global variables

static nfc_context *context;
static nfc_device *device = NULL;
static MifareTag *tags = NULL;
MifareTag tag = NULL;


MifareClassicKey keys[] = {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    {0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0},
    {0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1},
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5},
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5},
    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd},
    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7},
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    {0xFE, 0xDE, 0xCD, 0xBC, 0xAB, 0x9A}
};
MifareClassicBlockNumber blockNumber = 0x04;

void print_buffer(const unsigned char* buffer, size_t bufferSize, bool printNewLine)
{
    for (int i = 0; i < bufferSize; i++) {
        printf("%02X ", buffer[i]);
    }
    if (printNewLine) printf("\n");
}

void create_planraum_key(const MifareClassicKey* keyA, const MifareClassicKey* keyB, const MifareClassicBlock* ownKey)
{
    printf("Entering create_planraum_key()...\n");
    MifareClassicSectorNumber sector = 0x01;
    MifareClassicBlockNumber blockOwnKey = 0x05;
    MifareClassicBlockNumber blockTrailer = 0x07;
    MifareClassicBlock blockData;

    int ret = 0;

    ret = mifare_classic_format_sector(tag, sector);
    printf("mifare_classic_format_sector(): %d\n", ret);

    // write (own) key
    printf("Writing own key block: ");
    print_buffer(&ownKey[0], 16, true);
    ret = mifare_classic_write(tag, blockOwnKey, &ownKey[0]);
    printf("mifare_classic_write(): %d\n", ret);

    // write trailer
    memset(&blockData, 0, 16);
    memcpy(&blockData[0], &keyA[0], 6);
    memcpy(&blockData[6], "\x78\x77\x88\x00", 4);
    memcpy(&blockData[10], &keyB[0], 6);
    printf("Writing trailer block: ");
    print_buffer(&blockData[0], sizeof(blockData), true);
    ret = mifare_classic_write(tag, blockTrailer, &blockData[0]);
    printf("mifare_classic_write(): %d\n", ret);
    printf("Exiting create_planraum_key()...\n");
}


void setup(void)
{
    int res;
    nfc_connstring devices[8];
    size_t device_count;

    nfc_init (&context);
    if (context == NULL) {
        printf("Unable to init libnfc (malloc)\n");
        return;
    }

    device_count = nfc_list_devices (context, devices, 8);
    if (device_count <= 0) {
        printf("No device found\n");
        return;
    }

    for (size_t i = 0; i < device_count; i++) {
        device = nfc_open (context, devices[i]);
        if (!device)
            printf("nfc_open() failed.\n");

        tags = freefare_get_tags (device);
        if (tags == NULL) {
            printf("freefare_get_tags() failed\n");
            return;
        }

        tag = NULL;
        for (int i=0; tags[i]; i++) {
            if ((freefare_get_tag_type(tags[i]) == CLASSIC_1K) ||
                    (freefare_get_tag_type(tags[i]) == CLASSIC_4K)) {
                printf("found MIFARE CLASSIK 1K or 4K\n");
                tag = tags[i];
                if (mifare_classic_connect (tag) >= 0) {
                    printf("mifare_classic_connect() success\n");
                    return;
                } else {
                    printf("mifare_classic_connect() failed\n");
                }
            }
        }
        nfc_close (device);
        device = NULL;
        freefare_free_tags (tags);
        tags = NULL;
    }
    printf("No MIFARE Classic tag on NFC device\n");
}

void cleanup(void)
{
    if (tag) {
        mifare_classic_disconnect (tag);
    }
    if (tags) {
        freefare_free_tags (tags);
        tags = NULL;
    }
    if (device) {
        nfc_close(device);
    }
    nfc_exit(context);
}

bool authenticate(void)
{
    printf("Authentication\n====================\n");
    int i, res;
    for (i=0; i < sizeof(keys)/sizeof(keys[0]); i++) {
        printf("Try %d; MFC_KEY_A; block: %d key: ", i+1, blockNumber);
        print_buffer(keys[i], 6, false);
        res = mifare_classic_authenticate (tag, blockNumber, keys[i], MFC_KEY_A);
        printf(" res: %d\n", res);
        if (res >= 0) break;
    }
    if (res < 0) {
        for (i=0; i < sizeof(keys)/sizeof(keys[0]); i++) {
            printf("Try %d; MFC_KEY_B; block: %d key: ", i+1, blockNumber);
            print_buffer(keys[i], 6, false);
            res = mifare_classic_authenticate (tag, blockNumber, keys[i], MFC_KEY_B);
            printf(" res: %d\n", res);
            if (res >= 0) break;
        }
    }
    if (res >=0) {
        printf("Authentication successful!\n====================\n");
        return true;
    } else {
        printf("Authentication failed!\n====================\n");
        return false;
    }
}

int main(int argc, char *argv[])
{
    setup();

    if (!tag) {
        cleanup();
        return;
    }

    // do stuff

    // UID (4 bytes)
    char *uid;
    uid = freefare_get_tag_uid(tag);
    printf("UID: %s\n", uid);
    //free(uid);

    // Friendly name
    const char *name = freefare_get_tag_friendly_name (tag);
    printf("Friendly name: %s\n", name);

    if (!authenticate()) {
        cleanup();
        return;
    }


    int res;
    char ch;
    printf("w - write to card, block %d\n", blockNumber);
    printf("r - read from card, block %d\n\n", blockNumber);
    printf(": ");
    scanf("%c", &ch);

    switch (ch) {
    case 'w': {
        // write block
        MifareClassicKey newKeyA[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        MifareClassicKey newKeyB[] = {0xFE, 0xDE, 0xCD, 0xBC, 0xAB, 0x9A};
        printf("Writing own key...\n");
        MifareClassicBlock ownKey = {0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78};
        create_planraum_key(newKeyA, newKeyB, &ownKey[0]);
        break;
    }
    case 'r': {
        // read out block
        MifareClassicBlock block;
        memset(block, 0, sizeof(block));
        res = mifare_classic_read(tag, blockNumber, &block);
        if (res >= 0) {
            printf("Block 0x%02X:\n", blockNumber);
            print_buffer(block, sizeof(block), true);
        } else {
            printf("mifare_classic_read() failed\n");
        }
        break;
    }
    } // switch

    /*
            res = mifare_classic_authenticate (tag, blockNumber, newKeyA, MFC_KEY_A);
            if (res >= 0) {
                printf("Authentication with newKeyA success\n");
            } else {
                printf("Authentication with newKeyA failed\n");
            }
            printf(" res: %02X\n", res);

            res = mifare_classic_authenticate (tag, blockNumber, newKeyB, MFC_KEY_B);
            if (res >= 0) {
                printf("Authentication with newKeyB success\n");
            } else {
                printf("Authentication with newKeyB failed\n");
            }
            printf(" res: %02X\n", res);
    */

    /* some tests
    // Authentication
    int i;
    for (blockNumber = 0; blockNumber < 64; blockNumber++) {
        printf("Block %d: ", blockNumber);
        for (i=0; i < sizeof(keys)/sizeof(keys[0]); i++) {
            res = mifare_classic_authenticate (tag, blockNumber, keys[i], MFC_KEY_A);
            if (res >= 0) break;
        }
        if (res >= 0) {
            printf("Authentication successful with key %d\n", i);
        } else {
            printf("Authentication failed\n");
        }
    }

    res = mifare_classic_authenticate (tag, blockNumber, keys[0], MFC_KEY_A);
        if (res >= 0) {
            printf("Authentication successful\n");
        } else {
            printf("Authentication failed\n");
        }

    // read block
    MifareClassicBlock block;
    memset(block, 0, sizeof(block));
    res = mifare_classic_read(tag, blockNumber, &block);
    if (res >= 0) {
        printf("Block 0x%02X:\n", blockNumber);
        print_buffer(block, sizeof(block), true);
    } else {
        printf("mifare_classic_read() failed\n");
    }

    // check permissions
    printf("Got MCAB_R with MFC_KEY_A for block 0x%02X? ", blockNumber);
    if (mifare_classic_get_data_block_permission(tag, blockNumber, MCAB_R, MFC_KEY_A) == 1) {
        printf("yes\n");
    } else {
        printf("no\n");
    }
    printf("Got MCAB_R with MFC_KEY_B for block 0x%02X? ", blockNumber);
    if (mifare_classic_get_data_block_permission(tag, blockNumber, MCAB_R, MFC_KEY_B) == 1) {
        printf("yes\n");
    } else {
        printf("no\n");
    }
            printf("Got MCAB_W with MFC_KEY_A for block 0x%02X? ", blockNumber);
    if (mifare_classic_get_data_block_permission(tag, blockNumber, MCAB_W, MFC_KEY_A) == 1) {
        printf("yes\n");
    } else {
        printf("no\n");
    }
    printf("Got MCAB_W with MFC_KEY_B for block 0x%02X? ", blockNumber);
    if (mifare_classic_get_data_block_permission(tag, blockNumber, MCAB_W, MFC_KEY_B) == 1) {
        printf("yes\n");
    } else {
        printf("no\n");
    }

    // write block
    MifareClassicBlock blockWrite = {
        0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x4A, 0x59, 0x68,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    res = mifare_classic_write(tag, blockNumber, blockWrite);
    if (res == 0) {
        printf("Write successful\n");
    } else {
        printf("Write failed\n");
    }

    */
    cleanup();
}
