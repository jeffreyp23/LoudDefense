# LoudDefense
Bro project s7 intrusion detection system

## Inleiding
* Het s7-dfa.bro script bevat de Bro implementatie van de DFA.
* Het sampledata.txt bestand bevat 1 packet van het s7 protocol

## Boeiende velden
c: Connection
* c$iso_iso_cotp
* c$s7comm
* c$s7data

## Helper scripts
* clear.sh / Leegt het bro script, dus dan is het makkelijk werken met nano
* run.sh / Runt het bro script. Hierin staat ook de enforcement_mode
* setenv.sh / Zet de bro plugin env variable naar het path van de s7comm plugin

## Handige links
* [Bro] https://www.bro.org/sphinx/script-reference/statements.html
* [Bro] https://www.bro.org/sphinx/scripting/
* [DFA] http://pythonfiddle.com/dfa-simple-implementation/