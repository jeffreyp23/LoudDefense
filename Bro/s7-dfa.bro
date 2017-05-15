# Q is a finite set of states.
# ∑ is a finite set of symbols called the alphabet.
# δ is the transition function where δ: Q × ∑ → Q
# q0 is the initial state from where any input is processed (q0 ∈ Q).
# F is a set of final state/states of Q (F ⊆ Q).
#
# Basic DFA implementatie gebasseerd op http://pythonfiddle.com/dfa-simple-implementation/

@load base/frameworks/notice
@load-plugin Crysys::S7comm

module S7Dfa;

# ------------------------------------ DECLARATIES -------------------------------------------

export {

    # Eigen notice types
    redef enum Notice::Type += {
		Unknown_CHANNEL,
        Invalid_IP,
        Unknown_DFA_State
	};

    # Logs toeveoegen
    redef enum Log::ID += { LOG, ASSETS_LOG };

    # Deze redef is nodig, omdat Bro anders de s7 pakketten grotendeels weggooit
    redef ignore_checksums = T;

    # Geef de current mode aan. True voor enforcement en false voor learning
    # Deze waarde kan via bro dynamisch worden aangepast
    const enforcement_mode: bool = F &redef;

    # De basic DFA state structuur
    type DFA_State: record {
        state: string &log;
        symbol: string &log;
    };

    # De basic DFA structuur
    type DFA: record {
        states: set[DFA_State];
        start_state: DFA_State;
        accept_states: set[DFA_State];
        current_state: DFA_State;
    };

    # Alle velden van de S7 header die je wilt gebruiken als symbol
    type DFA_SYMBOL_S7HEADER: record {
        ## the s7 message type
        msgtype: string &log;
        ## the s7 message type number
        msgtypenum: count;
        ## function mode for UD
        funcmode: string &optional &log;
        ## function mode num fo ud
        funcmodenum: count &optional;
        ## the function number of the msg
        functypenum: count;
        ## the function type of the msg
        functype: string &log;
        ## subfunction for ud
        subfunctypenum: count &optional;
        ## subfunction str fo ud
        subfunctype: string &optional &log;
        ## error
        error: count &log;
    };

     # Alle velden van de S7 data die je wilt gebruiken als symbol
    type DFA_SYMBOL_S7DATA: record {
        ## memory area
        area: string &log;
        ## memory areanum
        areanum: count;
        ## the function type of the msg
        dbnum: count &log;
        ## s7 type
        s7type: string &log;
        ## s7 typenum
        s7typenum: count;
        ## s7 address
        address: count &log;
        ## s7 signed data
        sdata: int &optional &log;
        ## s7 unsigned data
        udata: count &optional &log;
        ## s7 real data
        ddata: double &optional &log;
        isread: bool &log;
    };

    type CHANNEL: record {
        srcip: addr &log;
        dstip: addr &log;
    };

    type ASSET: record {
        ip: addr &log;
    };

    # Hier worden alle channels (ip addressen) opgeslagen
    # Moet nog &persistent toegevoegd worden in de live omgeving
    global channels: table[CHANNEL] of DFA &persistent;

    # Alle assets worden hier opgeslagen
    global assets: table[addr] of ASSET &persistent;

    # Zorg ervoor dat bepaalde errors niet gespammed kunnen worden
    global errorOverflow: set[string];
}

# ------------------------------------ EINDE DECLARATIES -------------------------------------------

# ------------------------------------ BRO LOGGING SETUP -------------------------------------------

event bro_init () {

    print "S7Dfa INIT";

    local notice_filter: Log::Filter =
    [
       $name="notice_sqlite",
       $path="/var/log/bro_notice",
       $config=table(["tablename"] = "notice"),
       $writer=Log::WRITER_SQLITE,
       $interv=5 sec
    ];

    Log::add_filter(Notice::LOG, notice_filter);


    local weird_filter: Log::Filter =
    [
      $name="weird_sqlite",
      $path="/var/log/bro_weird",
      $config=table(["tablename"] = "weird"),
      $writer=Log::WRITER_SQLITE,
      $interv=5 sec
    ];

    Log::add_filter(Weird::LOG, weird_filter);

    Log::create_stream(S7Dfa::ASSETS_LOG,
    [
      $columns=ASSET,
      $path="/var/log/bro_assets"
    ]);

    local assets_filter: Log::Filter =
    [
       $name="assets_sqlite",
       $config=table(["tablename"] = "assets"),
       $writer=Log::WRITER_SQLITE
    ];

    Log::add_filter(S7Dfa::ASSETS_LOG, assets_filter);

    if (enforcement_mode) {
       print "Enforcement mode";
    } else {
       print "Learning mode";
    }
}

# ------------------------- EINDE BRO LOGGING SETUP -------------------------------------------

# ------------------------------------ DFA FUNCTIES -------------------------------------------

# DFA transition functie
function transition_to_state_with_input_dfa (msgtype: string, symbol:string, dfa: DFA) {
    # Volgens mij is dat alleen nodig als we een custom transition functie willen.
    # Wat we voor nu willen is denk ik alleen een simpele check of we de data al gezien hebben.

    local search_dfa_state: DFA_State;
    search_dfa_state$state = msgtype;
    search_dfa_state$symbol = symbol;

    dfa$current_state = search_dfa_state;
}

# Kijk of de state die we hebben in de accept states zit
function in_accept_state_dfa (dfa: DFA) : bool {
    return dfa$current_state in dfa$accept_states;
}

# Zet de current state naar de start state
function go_to_initial_state_dfa (dfa: DFA) {
    dfa$current_state = dfa$start_state;
}

function run_dfa (msgtype:string, symbol:string, dfa: DFA) : bool {

    # Ga naar de eerste state
    go_to_initial_state_dfa (dfa);

    # Transition functie
    transition_to_state_with_input_dfa (msgtype, symbol, dfa);

    # Kijk of het resultaat van de transition functie in de accept states zit aka
    # de states geleerd in de learning fase
    return in_accept_state_dfa (dfa);
}

# --------------------------------- EINDE DFA FUNCTIES -------------------------------------------

# --------------------------------- PACKET HANDLING FUNCTIES -------------------------------------

function header2symbol (header: S7comm::InfoS7comm) : DFA_SYMBOL_S7HEADER {

    local new_header: DFA_SYMBOL_S7HEADER = [$msgtype = header$msgtype, $msgtypenum = header$msgtypenum,
                                                $functypenum = header$functypenum, $functype = header$functype,
                                                $error = header$error];

    if (header?$funcmode) {
        new_header$funcmode = header$funcmode;
    }

    if(header?$funcmodenum) {
        new_header$funcmodenum = header$funcmodenum;
    }

    if(header?$subfunctypenum) {
        new_header$subfunctypenum = header$subfunctypenum;
    }

    if(header?$subfunctype) {
        new_header$subfunctype = header$subfunctype;
    }


    return new_header;
}

function data2symbol (data: S7comm::InfoS7data) : DFA_SYMBOL_S7DATA {

    local new_data: DFA_SYMBOL_S7DATA = [$area = data$area, $areanum = data$areanum, $dbnum = data$dbnum,
                                            $s7type = data$s7type, $s7typenum = data$s7typenum, $address = data$address,
                                            $isread = data$isread];

    if(data?$sdata) {
        new_data$sdata = data$sdata;
    }

    if(data?$udata) {
        new_data$udata = data$udata;
    }

    if(data?$ddata) {
        new_data$ddata = data$ddata;
    }

    return new_data;
}

function handlePacket (c: connection) {

     # Lees de channel
    local channel: CHANNEL = [$srcip = c$iso_cotp$id$orig_h, $dstip = c$iso_cotp$id$resp_h];

    # Lees het s7 protocol header deel van het pakket
    local header: S7comm::InfoS7comm = c$s7comm;

    # Lees het s7 protocol data deel van het pakket, als het niet null is
    local data: S7comm::InfoS7data;

    local hasData: bool = F;

    # Check if we data hebben
    if (c?$s7data) {
          data = c$s7data;
          hasData = T;
    }

    # Kijk of we in learning mode zitten of enforcement mode
    if(enforcement_mode) {

        # Is dit ip address een bekende channel?
        if(channel !in channels) {
            # Onbekende channel, dus alarm

            local errMsg = fmt("Unknown channel found. Source: %s, Destination: %s", addr_to_uri(channel$srcip), addr_to_uri(channel$dstip));

            # Als bijvoorbeeld per ongeluk een nieuw device wordt aangesloten,
            # kan deze ervoor zorgen dat er honderden alarms gegeneerd worden.
            # Dit if block voorkomt dat.
            if (errMsg !in errorOverflow) {

                NOTICE([
                    $note=Unknown_CHANNEL,
                    $msg=errMsg,
                    $conn = c
                ]);

                add errorOverflow[errMsg];
            }

        } else {

            # Get DFA voor deze channel
            local channel_enforcement_dfa: DFA = channels[channel];

            # DFA enforcement logic result
            local result: bool = F;

            # DFA enforcement logic

            if(hasData) {
                result = run_dfa (header$msgtype, sha256_hash(header2symbol(header), data2symbol(data)), channel_enforcement_dfa);
            } else {
                result = run_dfa (header$msgtype, sha256_hash(header2symbol(header)), channel_enforcement_dfa);
            }

            # DFA kan state niet vinden, dus alarm
            if (!result) {

                 NOTICE([
                    $note=Unknown_DFA_State,
                    $msg=fmt("%s: %s. Unknown function or different values!", c$s7comm$msgtype, c$s7comm$functype),
                    $conn = c
                ]);

                print "Unknown_DFA_State !!";

            }
        }

     } else {

         # Is er al een channel voor dit ip?
         if (channel !in channels) {

            # Maak een nieuwe channel met bijhorende DFA
            print "[Channels] New channel ";

            # Maak een nieuwe DFA en vul deze in
            local new_channel_dfa: DFA;

            # Maak de eerste DFA state
            local new_dfa_state: DFA_State;
            new_dfa_state$state = header$msgtype;

            if(hasData) {
                new_dfa_state$symbol = sha256_hash(header2symbol(header), data2symbol(data));
            } else {
                new_dfa_state$symbol = sha256_hash(header2symbol(header));
            }

            # Push de accept state
            add new_channel_dfa$accept_states[new_dfa_state];

            # Zet de start state naar de eerste state
            new_channel_dfa$start_state = new_dfa_state;

            # Voeg channel toe
            channels[channel] = new_channel_dfa;

            print "[Channels] Added nieuwe DFA";

            if (channel$srcip !in assets) {

                local src_asset: ASSET = [$ip = channel$srcip];
                assets[src_asset$ip] = src_asset;

                Log::write(S7Dfa::ASSETS_LOG, src_asset);
            }

            if (channel$dstip !in assets) {

                local dst_asset: ASSET = [$ip = channel$dstip];
                assets[dst_asset$ip] = dst_asset;

                Log::write(S7Dfa::ASSETS_LOG, dst_asset);
            }

         } else {

            # Get DFA voor deze channel
            local channel_learning_dfa: DFA = channels[channel];
            local channel_learning_dfa_symbol: string;

            if(hasData) {
                channel_learning_dfa_symbol = sha256_hash(header2symbol(header), data2symbol(data));
            } else {
                channel_learning_dfa_symbol = sha256_hash(header2symbol(header));
            }

            local checkState: DFA_State = [$state = header$msgtype, $symbol = channel_learning_dfa_symbol];

            # Kijk of we deze data al een keer gezien hebben. (check of we de state al hebben)
            if (checkState !in channel_learning_dfa$accept_states) {

                print "Learning: " + c$s7comm$msgtype + ": " + c$s7comm$functype;

                # DFA learning logic
                add channel_learning_dfa$accept_states[checkState];
            }
        }

    }

}

# ----------------------------- EINDE PACKET HANDLING FUNCTIES -------------------------------------

# ---------------------------------------- EVENTS --------------------------------------------------

event siemenss7_packet (c: connection, msgtype: count, functype: count, errno: count) {

    # Normale siemens S7 packets (JOB, ACKs etc)

    handlePacket(c);
}

event siemenss7_ud_packet(c: connection, msgtype: count, functionmode: count, functiontype: count, subfunction: count, errno: count) {

    # Siemens USERDATA packets

    handlePacket(c);
}

event siemenss7_read_data_unsigned(c: connection, area: count, db: count, s7type: count, address: count, data: count) {

    # Siemens function read packets met unsigned data

    handlePacket(c);
}

event siemenss7_read_data_signed(c: connection, area: count, db: count, s7type: count, address: count, data: int) {

    # Siemens function read packets met signed data

    handlePacket(c);
}

event siemenss7_read_data_real(c: connection, area: count, db: count, s7type: count, address: count, data: double) {

    # Siemens function read packets met real data

    # Aangezien er heel veel states kunnen onstaan door decimale, worden ze nu omgezet naar ints.
    c$s7data$ddata = floor(c$s7data$ddata);

    handlePacket(c);
}

event siemenss7_write_data_unsigned(c: connection, area: count, db: count, s7type: count, address: count, data: count) {

    # Siemens function write packets met unsigned data

    handlePacket(c);
}

event siemenss7_write_data_signed(c: connection, area: count, db: count, s7type: count, address: count, data: int) {

    # Siemens function write packets met signed data

    handlePacket(c);
}

event siemenss7_write_data_real(c: connection, area: count, db: count, s7type: count, address: count, data: double) {

    # Siemens function write packets met real data

    # Aangezien er heel veel states kunnen onstaan door decimale, worden ze nu omgezet naar ints.
    c$s7data$ddata = floor(c$s7data$ddata);

    handlePacket(c);
}

# ------------------------------------- EINDE EVENTS -------------------------------------------------