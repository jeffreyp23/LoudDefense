# Q is a finite set of states.
# ∑ is a finite set of symbols called the alphabet.
# δ is the transition function where δ: Q × ∑ → Q
# q0 is the initial state from where any input is processed (q0 ∈ Q).
# F is a set of final state/states of Q (F ⊆ Q).

@load base/frameworks/notice
@load-plugin Crysys::S7comm

module s7dfa;

export {

    redef enum Notice::Type += {
		Unknown_IP,
	};

    redef ignore_checksums = T;
    global enforcement_mode = F;

    type DFA: record {
        states: vector of count;
        alphabet: vector of string;
        start_state: count;
        accept_states: vector of count;
        current_state: count;
    };


    global channels: table[addr] of DFA &persistent;

}

function transition_to_state_with_input (dfa: DFA) {

}

function in_accept_state (dfa: DFA) {

}

function go_to_initial_state (dfa: DFA) {

}

function run_with_input_list (dfa: DFA) {

}

event siemenss7_packet (c: connection, msgtype: count, functype: count, errno: count) {

    # Lees het ip address 
    local ip: addr = c$iso_cotp$id$orig_h;

    # Is dit wel een valid ip address?
    if(!is_v4_addr(ip)) {

    } else{

        # Is er al een channel voor dit ip?
        if (ip !in channels) {

            # Kijk of we in learning mode zitten of enforcement mode
            if (!enforcement_mode) {
                # Learning mode, dus voeg nieuwe data toe

                # Maak een nieuwe channel met bijhorende DFA
                print "added new channel: " + addr_to_uri(ip);

                local dfa: DFA;
                # Vul DFA in

                # Voeg channel toe
                channels[ip] = dfa;
            } else {
                # Enforcement mode, onbekend ip address, dus alarm

                NOTICE([
                    $note=Unknown_IP,
                    $msg=fmt("Unknown IP address found: %s",
                    addr_to_uri(ip)),
                    $conn = c
                ]);

            }
        }
    }
}