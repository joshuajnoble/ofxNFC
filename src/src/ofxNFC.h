
#include "../include/nfc/nfc.h"
#include "../include/nfc/nfc-types.h"

//#include "utils/nfc-utils.h"


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

    // ISO14443A Anti-Collision
    // these are for accurate communication
    uint8_t  abtReqa[1] = { 0x26 };
    uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
    uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t  abtRats[4] = { 0xe0, 0x50, 0x00, 0x00 };
    uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

    #define MAX_FRAME_LEN 264

    static uint8_t readerBytes[MAX_FRAME_LEN];
    static uint8_t readerParityBytes[MAX_FRAME_LEN];

    //these are the objects we need
    static nfc_device *pnd;
    static nfc_context *context;
    nfc_target nt;

    ofThread thread;
    enum NFCMode { READ, SEND, SEND_CONDITIONAL };

    string messageToSend, conditionForSending;

    NFCMode mode;

    static nfc_modulation nmModulations[5];

    ofxNFC () {
        nfc_init(&context);
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
        const uint8_t uiPollNr = 20;
        const uint8_t uiPeriod = 2;

        // this is weird but stick with me: we set which modulation
        // patterns we want to recognize *very* explicitly


        const size_t szModulations = 5;


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
                            for( int i = 0; i < messageToSend.length(); i++ ) {
                                msgArray[i] = (uint8_t) messageToSend[i];
                            }

                            // need a way to figure out some standard messages
                            if(nfc_initiator_transceive_bytes(pnd, &msgArray[0], messageToSend.length(), &received[0], recSize, timeout) > 0)
                            {
                                ofxNFCEvent evt;
                                int i = 0;
                                while(i < recSize) {
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
                        for( int i = 0; i < messageToSend.length(); i++ ) {
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
                                    while(i < messageToSend.size()) {
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
                }

                unlock();
                ofSleepMillis(50);
            }
        }
    }
};

