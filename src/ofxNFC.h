
#include <nfc/nfc.h>
#include <nfc/nfc-types.h>

#include <freefare/freefare.h>

MifareClassicKey default_keys[] =
    {
    { 0xff,0xff,0xff,0xff,0xff,0xff },
    { 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
    { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
    { 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
    { 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
    { 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
    { 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
    { 0x00,0x00,0x00,0x00,0x00,0x00 }
    };

const MifareClassicKey default_keyb = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};

const uint8_t ndef_default_msg[33] = {
    0xd1, 0x02, 0x1c, 0x53, 0x70, 0x91, 0x01, 0x09,
    0x54, 0x02, 0x65, 0x6e, 0x4c, 0x69, 0x62, 0x6e,
    0x66, 0x63, 0x51, 0x01, 0x0b, 0x55, 0x03, 0x6c,
    0x69, 0x62, 0x6e, 0x66, 0x63, 0x2e, 0x6f, 0x72,
    0x67
};

    // ISO14443A Anti-Collision
    // these are for accurate communication
const uint8_t  abtReqa[1] = { 0x26 };
const uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
const uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const uint8_t  abtRats[4] = { 0xe0, 0x50, 0x00, 0x00 };
const uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };


struct mifare_classic_key_and_type {
    MifareClassicKey key;
    MifareClassicKeyType type;
};

class ofxNFCEvent : public ofEventArgs {


    public:

    enum STATUS {
        READ_SUCCESS,
        SEND_SUCCESS,
        READ_FAIL,
        SEND_FAIL,
        SEND_CONDITION_NOT_MET,
        WRITE_SUCCESS,
        WRITE_FAIL
    };

    STATUS status;

    static ofEvent <ofxNFCEvent> NFC_READ_EVENT;
    static ofEvent <ofxNFCEvent> NFC_WRITE_EVENT;
    static ofEvent <ofxNFCEvent> NFC_SEND_EVENT;

    vector<char> nfcEventID;
    vector<char> nfcEventData;

};

class ofxNFC : public ofThread
{


public:

    #define MAX_FRAME_LEN 264

    uint8_t readerBytes[MAX_FRAME_LEN];
    uint8_t readerParityBytes[MAX_FRAME_LEN];

    //these are the base objects we need
    nfc_device *pnd;
    nfc_context *context;
    nfc_target nt;


    // mifare tags (different than normal tags)
    MifareTag *tags;

    ofThread thread;
    enum NFCMode { READ, SEND, SEND_CONDITIONAL, MIFARE_WRITE, MIFARE_EMULATE, MIFARE_DES_EMULATE, MIFARE_READ, MIFARE_FORMAT };

    string messageToSend, conditionForSending;

    NFCMode mode;

    nfc_modulation nmModulations[5];
    nfc_target MIFARE_EMULATION;
    nfc_target MIFARE_DES_EMULATION;

    bool  init_mfc_auth;

    ofxNFC () {


    MIFARE_EMULATION.nm.nmt = NMT_ISO14443A,
    MIFARE_EMULATION.nm.nbr = NBR_UNDEFINED,
    MIFARE_EMULATION.nti.nai.abtAtqa[0] = 0x00;
    MIFARE_EMULATION.nti.nai.abtAtqa[1] = 0x04;
    MIFARE_EMULATION.nti.nai.abtUid[0] = 0x08;
    MIFARE_EMULATION.nti.nai.abtUid[1] = 0xab;
    MIFARE_EMULATION.nti.nai.abtUid[2] = 0xcd;
    MIFARE_EMULATION.nti.nai.abtUid[3] = 0xef;
    MIFARE_EMULATION.nti.nai.btSak = 0x09;
    MIFARE_EMULATION.nti.nai.szUidLen = 4;
    MIFARE_EMULATION.nti.nai.szAtsLen = 0;

    nfc_target MIFARE_DES_EMULATION;

    MIFARE_DES_EMULATION.nm.nmt = NMT_ISO14443A;
    MIFARE_DES_EMULATION.nm.nbr = NBR_UNDEFINED;
    MIFARE_DES_EMULATION.nti.nai.abtAtqa[0] = 0x03;
    MIFARE_DES_EMULATION.nti.nai.abtAtqa[1] = 0x44;
    MIFARE_DES_EMULATION.nti.nai.abtUid[0] = 0x08;
    MIFARE_DES_EMULATION.nti.nai.abtUid[1] = 0xab;
    MIFARE_DES_EMULATION.nti.nai.abtUid[2] = 0xcd;
    MIFARE_DES_EMULATION.nti.nai.abtUid[3] = 0xef;

    MIFARE_DES_EMULATION.nti.nai.btSak = 0x20,
    MIFARE_DES_EMULATION.nti.nai.szUidLen = 4,
    MIFARE_DES_EMULATION.nti.nai.abtAts[0] = 0x75;
    MIFARE_DES_EMULATION.nti.nai.abtAts[1] = 0x77;
    MIFARE_DES_EMULATION.nti.nai.abtAts[2] = 0x81;
    MIFARE_DES_EMULATION.nti.nai.abtAts[3] = 0x02;
    MIFARE_DES_EMULATION.nti.nai.abtAts[4] = 0x80;

    MIFARE_DES_EMULATION.nti.nai.szAtsLen = 5;


        nfc_init(&context);

init_mfc_auth = false;

    }

    ~ofxNFC() {
        nfc_close(pnd);
        nfc_exit(context);
    }

    vector<string> listDevices()
    {
        //nfc_list_devices (nfc_context *context, nfc_connstring connstrings[], const size_t connstrings_len)
        nfc_connstring devs[3];
        nfc_list_devices (context, devs, 3);
        vector<string> devices;
        for(int i = 0; i < 3; i++ ){
            string s(devs[i]);
            devices.push_back(s);
        }
        return devices;
    }

    void init()
    {
        //const uint8_t uiPollNr = 20;
        //const uint8_t uiPeriod = 2;

         nfc_init(&context);
          if (context == NULL) {

            exit(EXIT_FAILURE);
          }

        pnd = nfc_open(context, NULL);
    }

    void startRead( )
    {

        int res = nfc_target_init(pnd, &nt, readerBytes, sizeof(readerBytes), 0);
        if(res > 0) {

            mode = READ;
            startThread(true, false);
        }
    }

    void startSendOn( string request, string msg )
    {

        if (nfc_initiator_init(pnd) < 0) {
            nfc_perror(pnd, "nfc_initiator_init");
            nfc_close(pnd);
            nfc_exit(context);
        }

        messageToSend = msg;
        conditionForSending = request;

        mode = SEND_CONDITIONAL;

        startThread(true, false);
    }

    void stop()
    {
        stopThread();
    }

    void startSend( const string& msg )
    {

        if (nfc_initiator_init(pnd) < 0) {
            nfc_perror(pnd, "nfc_initiator_init");
            nfc_close(pnd);
            nfc_exit(context);
        }

        mode = SEND;
        startThread(true, false);
    }

    void startMifareFormat()
    {

         if (nfc_initiator_init(pnd) < 0) {
            nfc_perror(pnd, "nfc_initiator_init");
            nfc_close(pnd);
            nfc_exit(context);
        }


        //messageToSend = msg;
        mode = MIFARE_FORMAT;
        startThread(true, false);
    }

    void startMifareWrite( string msg )
    {
         if (nfc_initiator_init(pnd) < 0) {
            nfc_perror(pnd, "nfc_initiator_init");
            nfc_close(pnd);
            nfc_exit(context);
        }

        messageToSend = msg;
        mode = MIFARE_WRITE;
        startThread(true, false);
    }

    void startMifareDESEmulate()
    {
         if (nfc_initiator_init(pnd) < 0) {
            nfc_perror(pnd, "nfc_initiator_init");
            nfc_close(pnd);
            nfc_exit(context);
        }

        mode = MIFARE_DES_EMULATE;
        startThread(true, false);
    }

    void startMifareEmulate()
    {
         if (nfc_initiator_init(pnd) < 0) {
            nfc_perror(pnd, "nfc_initiator_init");
            nfc_close(pnd);
            nfc_exit(context);
        }

        mode = MIFARE_EMULATE;
        startThread(true, false);
    }

    void startMifareRead()
    {
         if (nfc_initiator_init(pnd) < 0) {
            nfc_perror(pnd, "nfc_initiator_init");
            nfc_close(pnd);
            nfc_exit(context);
        }

        mode = MIFARE_READ;
        startThread(true, false);
    }


    void threadedFunction()
    {

        while( isThreadRunning() != 0 ){
            if( lock() ){
                switch( mode )
                {
                    case READ: {

                        nfc_target targets[3];

                        int res = nfc_initiator_list_passive_targets( pnd, nmModulations[0], &targets[0], 3 );

                        if(nfc_initiator_select_dep_target(pnd, NDM_PASSIVE, NBR_212, 0, &targets[0], 100) > 0)
                        {
                            uint8_t received[MAX_FRAME_LEN];
                            size_t recSize = MAX_FRAME_LEN;
                            int timeout = 200;

                            uint8_t msgArray[messageToSend.length()];
                            for( int i = 0; i < (int) messageToSend.length(); i++ ) {
                                msgArray[i] = (uint8_t) messageToSend[i];
                            }

                            // need a way to figure out some standard messages
                            if(nfc_initiator_transceive_bytes(pnd, &msgArray[0], messageToSend.length(), &received[0], recSize, timeout) > 0)
                            {
                                ofxNFCEvent evt;
                                int i = 0;
                                while(i < (int) recSize) {
                                    evt.nfcEventData.push_back(received[i]);
                                    i++;
                                }

                                evt.status = ofxNFCEvent::READ_SUCCESS;
                                ofNotifyEvent(ofxNFCEvent::NFC_READ_EVENT, evt);

                            } else {
                                ofxNFCEvent evt;
                                evt.status = ofxNFCEvent::READ_FAIL;
                                ofNotifyEvent(ofxNFCEvent::NFC_READ_EVENT, evt);
                            }
                        }
                    }
                    break;
                    case SEND: {

                        int res;
                        // Transmit the command bytes

                        uint8_t msgArray[messageToSend.length()];
                        for( int i = 0; i < (int) messageToSend.length(); i++ ) {
                            msgArray[i] = (uint8_t) messageToSend[i];
                        }

                        res = nfc_target_send_bytes(pnd, msgArray, messageToSend.size(), 500);
                        if (res > 0) {

                          ofxNFCEvent evt;
                          evt.status = ofxNFCEvent::SEND_SUCCESS;

                          ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);

                        } else {
                              ofxNFCEvent evt;
                              evt.status = ofxNFCEvent::SEND_FAIL;

                              ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);
                        }

                    }

                    break;
                    case SEND_CONDITIONAL: {


                        // go quick, timeout set to 50ms, which should be enough, the
                        int numberOfBytesRecd = nfc_target_receive_bytes(pnd, readerBytes, sizeof(readerBytes), 50);
                        if(numberOfBytesRecd > 0)
                        {

                            string request;
                            for( int i = 0; i < numberOfBytesRecd; i++ ) {
                                request.push_back( readerBytes[i] );
                            }

                            if( conditionForSending == request ) {

                                uint8_t txBuffer[ messageToSend.size() ];

                                int res = nfc_target_send_bytes(pnd, &txBuffer[0], messageToSend.size(), 500 );
                                if( res > 0 ) {

                                    ofxNFCEvent evt;
                                    int i = 0;
                                    while(i < (int) messageToSend.size()) {
                                        evt.nfcEventData.push_back(txBuffer[i]);
                                        i++;
                                    }

                                    ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);
                                } else {
                                    ofxNFCEvent evt;
                                    evt.status = ofxNFCEvent::SEND_FAIL;
                                    ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);
                                }
                            } else {

                                ofxNFCEvent evt;
                                evt.status = ofxNFCEvent::SEND_CONDITION_NOT_MET;
                                ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);

                            }
                        }
                    }
                    break;
                    case MIFARE_WRITE: {

                        if(mifareWrite())
                        {
                            ofxNFCEvent evt;
                            evt.status = ofxNFCEvent::WRITE_SUCCESS;
                            ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);

                        }
                    }
                    break;
                    case MIFARE_EMULATE:{
                        //

                          size_t szTx, szRx;
                          uint8_t abtRx[MAX_FRAME_LEN];
                          uint8_t abtTx[MAX_FRAME_LEN];



                          bool success = false;

                            success = target_io(&MIFARE_EMULATION, abtRx, (size_t) szRx, abtTx, &szTx);
                            if (szTx) {
                              if (nfc_target_send_bytes(pnd, abtTx, szTx, 0) < 0) {
                                //nfc_perror(dev, "nfc_target_send_bytes");
                                success = false;
                              }
                            }
                            if (success) {
                              if (init_mfc_auth) {
                                nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false);
                                init_mfc_auth = false;
                              }
                              if ((szRx = nfc_target_receive_bytes(pnd, abtRx, sizeof(abtRx), 0)) < 0) {
                                //nfc_perror(dev, "nfc_target_receive_bytes");
                                success = false;
                               }
                            }

                          if(success)
                          {
                            ofxNFCEvent evt;
                            evt.status = ofxNFCEvent::WRITE_SUCCESS;
                            ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);

                          }
                    }
                    break;
                    case MIFARE_DES_EMULATE:{
                         size_t szTx, szRx;
                          uint8_t abtRx[MAX_FRAME_LEN];
                          uint8_t abtTx[MAX_FRAME_LEN];
                         bool success = false;

                            success = target_io(&MIFARE_DES_EMULATION, abtRx, (size_t) szRx, abtTx, &szTx);
                            if (szTx) {
                              if (nfc_target_send_bytes(pnd, abtTx, szTx, 0) < 0) {
                                //nfc_perror(dev, "nfc_target_send_bytes");
                                success =  false;
                              }
                            }
                            if (success) {
                              if (init_mfc_auth) {
                                nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false);
                                init_mfc_auth = false;
                              }
                              if ((szRx = nfc_target_receive_bytes(pnd, abtRx, sizeof(abtRx), 0)) < 0) {
                                //nfc_perror(dev, "nfc_target_receive_bytes");
                                success = false;
                               }
                            }

                          if(success)
                          {

                            ofxNFCEvent evt;
                            evt.status = ofxNFCEvent::WRITE_SUCCESS;
                            ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);
                          }

                    }
                    break;
                    case MIFARE_READ:{
                        if(mifareRead() != "")
                        {

                            ofxNFCEvent evt;
                            evt.status = ofxNFCEvent::WRITE_SUCCESS;
                            ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);
                        }
                    }
                    break;
                    case MIFARE_FORMAT:{
                        if(mifareFormat())
                        {

                            ofxNFCEvent evt;
                            evt.status = ofxNFCEvent::WRITE_SUCCESS;
                            ofNotifyEvent(ofxNFCEvent::NFC_SEND_EVENT, evt);
                        }
                    }
                    break;
                    default:
                    // nada
                    break;
                }

                unlock();
                ofSleepMillis(50);
            }
        }
    }

private:

bool mifareFormat()
{
    bool hasFormatted = false;
	tags = freefare_get_tags (pnd);
	if (!tags) {
	    return hasFormatted; // nothing to format
	}

	for (int i = 0; tags[i]; i++) {
	    switch (freefare_get_tag_type (tags[i])) {
            case CLASSIC_1K:
            case CLASSIC_4K:
            break;
            default:
            continue;
	    }

	    char *tag_uid = freefare_get_tag_uid (tags[i]);
	    //char buffer[BUFSIZ];

	    ////printf ("Found %s with UID %s. ", freefare_get_tag_friendly_name (tags[i]), tag_uid);

	    cout << "Found " << freefare_get_tag_friendly_name (tags[i]) << " with UID " << tag_uid << endl;


        enum mifare_tag_type tt = freefare_get_tag_type (tags[i]);
        //at_block = 0;

        if (!try_format_sector (tags[i], 0x00)) {
			break;

		    if (tt == CLASSIC_4K) {
                if (!try_format_sector (tags[i], 0x10)) {
                    break;
                }
            }
		}

		switch (tt) {
            case CLASSIC_1K:
                //mod_block = 4;
                if (!format_mifare_classic_1k (tags[i]))
                //error = 1;
                break;
            case CLASSIC_4K:
                //mod_block = 10;
                if (!format_mifare_classic_4k (tags[i]))
                //error = 1;
                break;
            default:
                /* Keep compiler quiet */
                break;
	    }

        hasFormatted = true;
	    free (tag_uid);
	}
    return hasFormatted;
}

bool mifareWrite() // returns whether we wrote anything or not
{

    const uint8_t *output = (uint8_t *) messageToSend.c_str();
    size_t encoded_size;
	uint8_t *tlv_data = tlv_encode (3, output, messageToSend.size(), &encoded_size);


    MifareClassicKey transport_key = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    bool wrote = false;
    tags = freefare_get_tags (pnd);
	if (!tags) {
	    return wrote; // we just look for tags and if we don't find any, exit
	}

	mifare_classic_key_and_type *card_write_keys = new mifare_classic_key_and_type();
    //card_write_keys = malloc (40 * sizeof (*card_write_keys));

	for (int i = 0; tags[i]; i++) {
	    switch (freefare_get_tag_type (tags[i])) {
            case CLASSIC_1K:
            case CLASSIC_4K:
            break;
            default:
            continue;
	    }

	    char *tag_uid = freefare_get_tag_uid (tags[i]);
	    //char buffer[BUFSIZ];

	    cout << "Found " << freefare_get_tag_friendly_name (tags[i]) << "with UID " << tag_uid << endl;

	    for (int n = 0; n < 40; n++) {
            memcpy(card_write_keys[n].key, transport_key, sizeof (transport_key));
            card_write_keys[n].type = MFC_KEY_A;
	    }


        // ----------------------------------------------------------------------------------------------------------
        // only doing ndef right now
        // ----------------------------------------------------------------------------------------------------------
	    //if (write_ndef)
	    //{
		switch (freefare_get_tag_type (tags[i])) {
            case CLASSIC_4K:
                if (!search_sector_key (tags[i], 0x10, &(card_write_keys[0x10].key), &(card_write_keys[0x10].type))) {
                //error = 1;
                free (tag_uid);
                }
                /* fallthrough */
            case CLASSIC_1K:
                if (!search_sector_key (tags[i], 0x00, &(card_write_keys[0x00].key), &(card_write_keys[0x00].type))) {
                //error = 1;
                free (tag_uid);
                }
                break;
            default:

                break;
		}

		//if (!error) {
		    /* Ensure the auth key is always a B one. If not, change it! */
		    switch (freefare_get_tag_type (tags[i])) {
                case CLASSIC_4K:
                if (card_write_keys[0x10].type != MFC_KEY_B) {
                    if( 0 != fix_mad_trailer_block (pnd, tags[i], 0x10, card_write_keys[0x10].key, card_write_keys[0x10].type)) {
                    free (tag_uid);
                    continue;
                    }
                    memcpy (&(card_write_keys[0x10].key), &default_keyb, sizeof (MifareClassicKey));
                    card_write_keys[0x10].type = MFC_KEY_B;
                }
                /* fallthrough */
                case CLASSIC_1K:
                if (card_write_keys[0x00].type != MFC_KEY_B) {
                    if( 0 != fix_mad_trailer_block (pnd, tags[i], 0x00, card_write_keys[0x00].key, card_write_keys[0x00].type)) {
                        //error = 1;
                        free (tag_uid);
                        continue;
                    }
                    memcpy (&(card_write_keys[0x00].key), &default_keyb, sizeof (MifareClassicKey));
                    card_write_keys[0x00].type = MFC_KEY_B;
                }
                break;
                default:
                /* Keep compiler quiet */
                break;
		    }
		//}

        // what is this?
        /*uint8_t *ndef_msg = (uint8_t*)ndef_default_msg;
        size_t ndef_msg_len = sizeof(ndef_default_msg);

		size_t encoded_size;
		uint8_t *tlv_data = tlv_encode (3, ndef_msg, ndef_msg_len, &encoded_size);*/

		/*
		 * At his point, we should have collected all information needed to
		 * succeed.
		 */

        Mad mad;

		// If the card already has a MAD, load it.
		if ((mad = mad_read (tags[i]))) {
		    // If our application already exists, erase it.
		    MifareClassicSectorNumber *sectors, *p;
		    sectors = p = mifare_application_find (mad, mad_nfcforum_aid);
		    if (sectors) {
			while (*p) {
			    if (mifare_classic_authenticate (tags[i], mifare_classic_sector_last_block(*p), default_keyb, MFC_KEY_B) < 0) {
                    //nfc_perror (device, "mifare_classic_authenticate");
                    free (tag_uid);
                    continue;
			    }
			    if (mifare_classic_format_sector (tags[i], *p) < 0) {
                    //nfc_perror (device, "mifare_classic_format_sector");
                    free (tag_uid);
                    continue;
			    }
			    p++;
			}
		    }
		    free (sectors);
		    mifare_application_free (mad, mad_nfcforum_aid);
		}
		else
		{

		    // Create a MAD and mark unaccessible sectors in the card
		    if (!(mad = mad_new ((freefare_get_tag_type (tags[i]) == CLASSIC_4K) ? 2 : 1))) {
                free (tag_uid);
                continue;
		    }

		    MifareClassicSectorNumber max_s;
		    switch (freefare_get_tag_type (tags[i])) {
                case CLASSIC_1K:
                    max_s = 15;
                break;
                case CLASSIC_4K:
                    max_s = 39;
                break;
                default:

                break;
		    }

		    // Mark unusable sectors as so
		    for (size_t s = max_s; s; s--)
		    {
                if (s == 0x10) continue;

                if (!search_sector_key (tags[i], s, &(card_write_keys[s].key), &(card_write_keys[s].type))) {
                    mad_set_aid (mad, s, mad_defect_aid);
                }
                else if ((memcmp (card_write_keys[s].key, transport_key, sizeof (transport_key)) != 0) && (card_write_keys[s].type != MFC_KEY_A)) {
                    // Revert to transport configuration
                    if (mifare_classic_format_sector (tags[i], s) < 0) {
                        //nfc_perror (device, "mifare_classic_format_sector");
                        //error = 1;
                        free (tag_uid);
                    }
                }
		    }
		}

		MifareClassicSectorNumber *sectors = mifare_application_alloc (mad, mad_nfcforum_aid, encoded_size);
		if (!sectors) {
		    //nfc_perror (device, "mifare_application_alloc");
		    //error = EXIT_FAILURE;
		    free (tag_uid);
		}

		if (mad_write (tags[i], mad, card_write_keys[0x00].key, card_write_keys[0x10].key) < 0) {
		    //nfc_perror (device, "mad_write");
		    //error = EXIT_FAILURE;
		    free (tag_uid);
		}

		int s = 0;
		while (sectors[s]) {
		    MifareClassicBlockNumber block = mifare_classic_sector_last_block (sectors[s]);
		    MifareClassicBlock block_data;
		    mifare_classic_trailer_block (&block_data, mifare_classic_nfcforum_public_key_a, 0x0, 0x0, 0x0, 0x6, 0x40, default_keyb);
		    if (mifare_classic_authenticate (tags[i], block, card_write_keys[sectors[s]].key, card_write_keys[sectors[s]].type) < 0) {
                //nfc_perror (device, "mifare_classic_authenticate");
                //error = EXIT_FAILURE;
                free (tag_uid);
		    }
		    if (mifare_classic_write (tags[i], block, block_data) < 0) {
                //nfc_perror (device, "mifare_classic_write");
                //error = EXIT_FAILURE;
                free (tag_uid);
		    }
		    s++;
		}

		if (encoded_size != (size_t) mifare_application_write (tags[i], mad, mad_nfcforum_aid, tlv_data, encoded_size, default_keyb, (MifareClassicKeyType) MCAB_WRITE_KEYB)) {
		    //nfc_perror (device, "mifare_application_write");
		    //error = EXIT_FAILURE;
		    free (tag_uid);
		}

		free (sectors);
		free (tlv_data);
		free (mad);
		wrote = true;
	    }

    return wrote;
}

string mifareRead()
{
    tags = freefare_get_tags (pnd);
    string recv = "";

	if (!tags) {
	    return recv;
	}

	for (int i = 0; tags[i]; i++)
	{


	    switch (freefare_get_tag_type (tags[i])) {
            case CLASSIC_1K:
            case CLASSIC_4K:
            break;
            default:
            continue;
	    }

	    char *tag_uid = freefare_get_tag_uid (tags[i]);
	    //char buffer[BUFSIZ];

	    cout << " Found " << freefare_get_tag_friendly_name (tags[i]) << " with UID " << tag_uid << endl;


		// NFCForum card has a MAD, load it.
		if (0 == mifare_classic_connect (tags[i])) {
		    //
		} else {
		    //nfc_perror (device, "mifare_classic_connect");
		    //error = EXIT_FAILURE;
		    free (tag_uid);
            continue;
		}

        Mad mad;

		if ((mad = mad_read (tags[i]))) {
		    // Dump the NFCForum application using MAD information
		    uint8_t buffer[4096];
		    ssize_t len;
		    if ((len = mifare_application_read (tags[i], mad, mad_nfcforum_aid, buffer, sizeof(buffer), mifare_classic_nfcforum_public_key_a, MFC_KEY_A)) != -1) {
			uint8_t tlv_type;
			uint16_t tlv_data_len;

			uint8_t * tlv_data = tlv_decode (buffer, &tlv_type, &tlv_data_len);
			switch (tlv_type) {
			    case 0x00:
                    cout <<  "NFCForum application contains a \"NULL TLV\"." << endl;	// FIXME: According to [ANNFC1K4K], we should skip this TLV to read further TLV blocks.
                    //error = EXIT_FAILURE;
                    free (tag_uid);
                    continue;
				break;
			    case 0x03:
				//printf (message_stream, "NFCForum application contains a \"NDEF Message TLV\"." << endl;
				break;
			    case 0xFD:
                    cout <<  "NFCForum application contains a \"Proprietary TLV\"." << endl;	// FIXME: According to [ANNFC1K4K], we should skip this TLV to read further TLV blocks.
                    //error = EXIT_FAILURE;
                    free (tag_uid);
                    continue;
				break;
			    case 0xFE:
                    cout <<  "NFCForum application contains a \"Terminator TLV\", no available data." << endl;
                    //error = EXIT_FAILURE;
                    free (tag_uid);
                    continue;
				break;
			    default:
                    cout <<  "NFCForum application contains an invalid TLV." << endl;
                    //error = EXIT_FAILURE;
                    free (tag_uid);
                    continue;
				break;
			}


			/*if (fwrite (tlv_data, 1, tlv_data_len, ndef_stream) != tlv_data_len) {
                    cout <<  "Could not write to file." << endl;
                    //error = EXIT_FAILURE;
                    free (tag_uid);
                    continue;
			}*/

            // copy the TLV data to the string
            stringstream ss;
            ss << tlv_data;
            recv = ss.str();

            free (tlv_data);

		    } else {
                cout <<  "No NFC Forum application." << endl;
                //error = EXIT_FAILURE;
                free (tag_uid);
                continue;
		    }
		} else {
            cout <<  "No MAD detected." << endl;
            //error = EXIT_FAILURE;
            free (tag_uid);
            continue;
		}
		free (mad);
	    }

	freefare_free_tags (tags);
	return recv;
}


int format_mifare_classic_1k (MifareTag tag)
{

    for (int sector = 0; sector < 16; sector++) {
	if (!try_format_sector (tag, sector))
	    return 0;
    }

    return 1;
}

int format_mifare_classic_4k (MifareTag tag)
{

    for (int sector = 0; sector < (32 + 8); sector++) {
	if (!try_format_sector (tag, sector))
	    return 0;
    }
    //printf (DONE_FORMAT);
    return 1;
}

int try_format_sector (MifareTag tag, MifareClassicSectorNumber sector)
{

    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
	MifareClassicBlockNumber block = mifare_classic_sector_last_block (sector);
	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
	    if (0 == mifare_classic_format_sector (tag, sector)) {
		mifare_classic_disconnect (tag);
		return 1;
	    } else if (EIO == errno) {
		//err(EXIT_FAILURE, "sector %d", sector);
	    }
	    mifare_classic_disconnect (tag);
	}

	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
	    if (0 == mifare_classic_format_sector (tag, sector)) {
		mifare_classic_disconnect (tag);
		return 1;
	    } else if (EIO == errno) {
		//err(EXIT_FAILURE, "sector %d", sector);
	    }
	    mifare_classic_disconnect (tag);
	}
    }

    //warnx ("No known authentication key for sector %d", sector);
    return 0;
}

int search_sector_key (MifareTag tag, MifareClassicSectorNumber sector, MifareClassicKey *key, MifareClassicKeyType *key_type)
{
    MifareClassicBlockNumber block = mifare_classic_sector_last_block (sector);

    /*
     * FIXME: We should not assume that if we have full access to trailer block
     *        we also have a full access to data blocks.
     */
    mifare_classic_disconnect (tag);
    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
	    if ((1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYA, MFC_KEY_A)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYB, MFC_KEY_A))) {
		memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
		*key_type = MFC_KEY_A;
		return 1;
	    }
	}
	mifare_classic_disconnect (tag);

	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
	    if ((1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYA, MFC_KEY_B)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYB, MFC_KEY_B))) {
		memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
		*key_type = MFC_KEY_B;
		return 1;
	    }
	}
	mifare_classic_disconnect (tag);
    }

    //warnx ("No known authentication key for sector 0x%02x\n", sector);
    return 0;
}

int fix_mad_trailer_block (nfc_device *device, MifareTag tag, MifareClassicSectorNumber sector, MifareClassicKey key, MifareClassicKeyType key_type)
{
    MifareClassicBlock block;
    mifare_classic_trailer_block (&block, mad_public_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, default_keyb);
    if (mifare_classic_authenticate (tag, mifare_classic_sector_last_block (sector), key, key_type) < 0) {
	//nfc_perror (device, "fix_mad_trailer_block mifare_classic_authenticate");
	return -1;
    }
    if (mifare_classic_write (tag, mifare_classic_sector_last_block (sector), block) < 0) {
	//nfc_perror (device, "mifare_classic_write");
	return -1;
    }
    return 0;
}

bool nfc_target_emulate_tag(nfc_device *dev, nfc_target *pnt)
{
  /*size_t szTx, szRx;
  uint8_t abtRx[MAX_FRAME_LEN];
  uint8_t abtTx[MAX_FRAME_LEN];
  bool loop = true;

  if ((szRx = nfc_target_init(dev, pnt, abtRx, sizeof(abtRx), 0)) < 0) {
    //nfc_perror(dev, "nfc_target_init");
    return false;
  }

  while (loop) {
    loop = target_io(pnt, abtRx, (size_t) szRx, abtTx, &szTx);
    if (szTx) {
      if (nfc_target_send_bytes(dev, abtTx, szTx, 0) < 0) {
        //nfc_perror(dev, "nfc_target_send_bytes");
        return false;
      }
    }
    if (loop) {
      if (init_mfc_auth) {
        nfc_device_set_property_bool(dev, NP_HANDLE_CRC, false);
        init_mfc_auth = false;
      }
      if ((szRx = nfc_target_receive_bytes(dev, abtRx, sizeof(abtRx), 0)) < 0) {
        //nfc_perror(dev, "nfc_target_receive_bytes");
        return false;
      }
    }
  }*/
  return true;
}

bool target_io(nfc_target *pnt, const uint8_t *pbtInput, const size_t szInput, uint8_t *pbtOutput, size_t *pszOutput)
{
  bool loop = true;
  *pszOutput = 0;

  // Show transmitted command
  /*if (!quiet_output) {
    printf("    In: ");
    print_hex(pbtInput, szInput);
  }*/
  if (szInput) {
    switch (pbtInput[0]) {
      case 0x30: // Mifare read
        // block address is in pbtInput[1]
        *pszOutput = 15;
        strcpy((char *)pbtOutput, "You read block ");
        pbtOutput[15] = pbtInput[1];
        break;
      case 0x50: // HLTA (ISO14443-3)
        /*if (!quiet_output) {
          printf("Initiator HLTA me. Bye!\n");
        }*/
        loop = false;
        break;
      case 0x60: // Mifare authA
      case 0x61: // Mifare authB
        // Let's give back a very random nonce...
        *pszOutput = 2;
        pbtOutput[0] = 0x12;
        pbtOutput[1] = 0x34;
        // Next commands will be without CRC
        init_mfc_auth = true;
        break;
      case 0xe0: // RATS (ISO14443-4)
        // Send ATS
        *pszOutput = pnt->nti.nai.szAtsLen + 1;
        pbtOutput[0] = pnt->nti.nai.szAtsLen + 1; // ISO14443-4 says that ATS contains ATS_Length as first byte
        if (pnt->nti.nai.szAtsLen) {
          memcpy(pbtOutput + 1, pnt->nti.nai.abtAts, pnt->nti.nai.szAtsLen);
        }
        break;
      case 0xc2: // S-block DESELECT
        /*if (!quiet_output) {
          printf("Initiator DESELECT me. Bye!\n");
        }*/
        loop = false;
        break;
      default: // Unknown
        /*if (!quiet_output) {
          printf("Unknown frame, emulated target abort.\n");
        }*/
        loop = false;
    }
  }
  // Show transmitted command
  /*if ((!quiet_output) && *pszOutput) {
    printf("    Out: ");
    print_hex(pbtOutput, *pszOutput);
  }*/
  return loop;
}

};

