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

export {

    # Eigen notice types
    redef enum Notice::Type += {
		Unknown_IP,
        Invalid_IP,
        Unknown_DFA_State
	};

    # Logs toeveoegen
    redef enum Log::ID += { LOG };

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

    # Het log record
    type DFA_LOG: record {
        channel: addr &log;
        state: string &log;
        symbol: string &log;
    };


    # Hier worden alle channels (ip addressen) opgeslagen
    # Moet nog &persistent toegevoegd worden in de live omgeving
    global channels: table[addr] of DFA &persistent;

}

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

event siemenss7_packet (c: connection, msgtype: count, functype: count, errno: count) {

    # Lees het ip address 
    local ip: addr = c$iso_cotp$id$orig_h;

    # Is dit wel een valid ip address?
    if(!is_v4_addr(ip)) {

        # Nee, dus stuur een notice
        NOTICE([
            $note=Invalid_IP,
            $msg=fmt("Invalid ip address"),
            $conn = c
        ]);

    } else{

        # Lees het s7 protocol header deel van het pakket
        local s7_header = c$s7comm;

        # Lees het s7 protocol data deel van het pakket, als het niet null is
        local s7_data = "";

        if (c?$s7data) {

            # Het lijkt erop dat alle s7data gestript zijn van de voorbeeld pcap files
            print c$s7data;
           # s7_data = c$s7data;
        }

        # Kijk of we in learning mode zitten of enforcement mode
        if(enforcement_mode) {

            # Is dit ip address een bekende channel?
            if(ip !in channels) {
                # Onbekende channel, dus alarm

                NOTICE([
                    $note=Unknown_IP,
                    $msg=fmt("Unknown IP address found: %s",
                    addr_to_uri(ip)),
                    $conn = c
                ]);
            } else {

                # Get DFA voor deze channel
                local channel_enforcement_dfa: DFA = channels[ip];

                # DFA enforcement logic result
                local result: bool = F;

                # DFA enforcement logic
                result = run_dfa (s7_header$msgtype, sha256_hash(s7_header$functypenum), channel_enforcement_dfa);

                # DFA kan state niet vinden, dus alarm
                if (!result) {

                    NOTICE([
                        $note=Unknown_DFA_State,
                        $msg=fmt("Unknown DFA state!"),
                        $conn = c
                    ]);

                    print "Unknown_DFA_State !!";

                }
            }

        } else {

             # Is er al een channel voor dit ip?
            if (ip !in channels) {

                # Maak een nieuwe channel met bijhorende DFA
                print "[Channels] New channel: " + addr_to_uri(ip);

                # Maak een nieuwe DFA en vul deze in
                local new_channel_dfa: DFA;

                # Maak de eerste DFA state
                local new_dfa_state: DFA_State;
                new_dfa_state$state = s7_header$msgtype;
                new_dfa_state$symbol = sha256_hash(s7_header$functypenum);

                # Push de accept state
                add new_channel_dfa$accept_states[new_dfa_state];

                # Zet de start state naar de eerste state
                new_channel_dfa$start_state = new_dfa_state;
                
                # Voeg channel toe
                channels[ip] = new_channel_dfa;

                # Schrijf naar log. (jajaja er wordt dubbel gehashed :) )
                Log::write( S7Dfa::LOG, [$channel=ip,
                                $state=s7_header$msgtype,
                                $symbol=sha256_hash(s7_header$functypenum, s7_data)]);
            
                print "[Channels][" + addr_to_uri(ip) + "] Added nieuwe DFA";

            } else {

                 # Get DFA voor deze channel
                local channel_learning_dfa: DFA = channels[ip];

                local checkState: DFA_State = [$state = s7_header$msgtype, $symbol = sha256_hash(s7_header$functypenum)];

                # Kijk of we deze data al een keer gezien hebben. (check of we de state al hebben)
                if (checkState !in channel_learning_dfa$accept_states) {

                    print "[Channels][" + addr_to_uri(ip) + "][DFA] Nieuwe data (" + s7_header$msgtype +"), learning....";

                    # DFA learning logic
                    add channel_learning_dfa$accept_states[checkState];

                    # Schrijf naar log
                    Log::write( S7Dfa::LOG, [$channel=ip,
                                    $state=checkState$state,
                                    $symbol=checkState$symbol]);
                }
            } 

        }
    }
}

# Eigen logging toevoegen
event bro_init () {
     Log::create_stream(LOG, [$columns=DFA_LOG, $path="dfa"]);

     if (enforcement_mode) {
        print "Enforcement mode";
     } else {
        print "Learning mode";
     }
} 