Voici un résumé de chaque option de **Nmap** :

1. **SYN Scan** : Envoie des paquets SYN (demande de connexion) et écoute la réponse. Si un SYN/ACK est reçu, le port est ouvert. Si un RST est reçu, il est fermé. C'est rapide et discret.
   
2. **NULL Scan** : Envoie des paquets sans aucun flag activé. Les systèmes conformes à TCP répondent par un RST pour indiquer que le port est fermé. Si rien n'est reçu, le port est considéré comme ouvert/filtré.
   
3. **ACK Scan** : Envoie des paquets avec le flag ACK. Utilisé pour déterminer si les ports sont filtrés ou non, mais pas pour savoir s'ils sont ouverts.
   
4. **FIN Scan** : Envoie des paquets avec le flag FIN. Les ports fermés répondent par un RST, tandis que les ports ouverts/filtrés ne répondent pas.
   
5. **XMAS Scan** : Envoie des paquets avec les flags FIN, URG et PSH activés. Les systèmes fermés répondent par un RST, tandis que les systèmes ouverts ne répondent pas.
   
6. **UDP Scan** : Envoie des paquets UDP pour tester si un port est ouvert. Si aucun message ICMP de port inaccessible n'est reçu, le port est considéré comme ouvert ou filtré.

### To test with nmap here is an example of command line:
sudo nmap -sS -sU -sX -sF -sN -sA <IP>