# LoudDefense
Project IACS intrusion detection system

## Inleiding
* De Bro map bevat alle spullen voor Bro
* De rest is de webapplicatie

## Boeiende velden
c: Connection
* c$iso_iso_cotp
```
    type InfoIso: record {
		## Time when the command was sent.
		ts:               time        &log;
		## Unique ID for the connection.
		uid:              string      &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id     &log;
		## COTP msg type.
		msg:             string      &log;
    };
```
* c$s7comm
```
    type InfoS7comm: record {
		## Time when the command was sent.
		ts:               time        &log;
		## Unique ID for the connection.
		uid:              string      &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id     &log;
		## the s7 message type
		msgtype:          string      &log;
		## the s7 message type number
		msgtypenum:       count       ;
        ## function mode for UD
        funcmode:         string      &optional &log;
        ## function mode num fo ud
        funcmodenum:      count       &optional;
		## the function number of the msg
		functypenum:      count       ;
		## the function type of the msg
		functype:         string      &log;
        ## subfunction for ud
        subfunctypenum:    count       &optional;
        ## subfunction str fo ud
        subfunctype:       string      &optional &log;
		##
		error:             count       &log;
    };
```
* c$s7data
```
    type InfoS7data: record {
  		## Time when the command was sent.
  		ts:               time        &log;
  		## Unique ID for the connection.
  		uid:              string      &log;
  		## The connection's 4-tuple of endpoint addresses/ports.
  		id:               conn_id     &log;
  		## memory area
  		area:             string      &log;
  		## memory areanum
  		areanum:          count      ;
  		## the function type of the msg
  		dbnum:            count      &log;
  		## s7 type
  		s7type: 		  string     &log;
  		## s7 typenum
  		s7typenum:        count      ;
  		## s7 address
  		address:          count      &log;
  		## s7 signed data
  		sdata:            int        &optional &log;
  		## s7 unsigned data
  		udata:            count      &optional &log;
  		## s7 real data
  		ddata:            double     &optional &log;
  		isread:           bool       &log;
  
    };
```

## Helper scripts
* clear.sh / Leegt het bro script, dus dan is het makkelijk werken met nano
* run.sh / Runt het bro script. Hierin staat ook de enforcement_mode
* setenv.sh / Zet de bro plugin env variable naar het path van de s7comm plugin

## Handige links
* [Bro] https://www.bro.org/sphinx/script-reference/statements.html
* [Bro] https://www.bro.org/sphinx/scripting/
* [DFA] http://pythonfiddle.com/dfa-simple-implementation/