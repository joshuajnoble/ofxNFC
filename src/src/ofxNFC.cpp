
ofEvent <ofxNFCEvent> ofxNFCEvent::NFC_READ_EVENT;
ofEvent <ofxNFCEvent> ofxNFCEvent::NFC_WRITE_EVENT;
ofEvent <ofxNFCEvent> ofxNFCEvent::NFC_SEND_EVENT;

ofxNFCEvent::NFC_READ = "nfc_read";
ofxNFCEvent::NFC_WRITE = "nfc_write";
ofxNFCEvent::NFC_SEND = "nfc_send";

ofxNFC::nmModulations = {
            { .nmt = NMT_ISO14443A, .nbr = NBR_106 },
            { .nmt = NMT_ISO14443B, .nbr = NBR_106 },
            { .nmt = NMT_FELICA, .nbr = NBR_212 },
            { .nmt = NMT_FELICA, .nbr = NBR_424 },
            { .nmt = NMT_JEWEL, .nbr = NBR_106 },
          };
