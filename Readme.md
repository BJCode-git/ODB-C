//note tests unitaires avec gros malloc / mmap

Tests depuis serveur 
scenario 1 : BE -> 100 byte 
Puis IS devant requet pour obtenir 1/2 pages -> cas pas assez header

scenario 2 : header 100 bytes -> 
10 bytes plus une page


1.Considérer configuration file -> ODB sur port -> charger un fichier
2.Résoudre problème chunk -> http1
3.Simplifier le code -> on oublie protocole 
4.Gestion de la libération des buffers.
5.Revoir le sendfile 
6. Note : si crash lors de la récupération de la payload virtuelle -> abort
RAB hash -> fd / struct{LocalBuff,timeout, sendfile}

## http 1.0 / 1.1 parser, see : https://github.com/nodejs/llhttp
## http 2.0 parser, see : https://github.com/nghttp2/nghttp2
## http 3.0 parser, see : https://github.com/ngtcp2/ngtcp2
// get env 
// getenv( "PATH" );

// note : nginx utilise aussi senfile, donc il sera peut-etre nécessaire de l'overwrite

// note : Comme on base l'état des communicatios sur les fd, il faut hooked, dup et dup2 pour enrgistrer les nouveux fd 
// dans les tables et copier l'état (pour des sockets connectées)
// Objet proxy 
ODB C avec runtime avec différents environnements -> Oupsla
ODB C -> juillet avec INFOCOM
Tout avec NSDAI
// Note : Dernière idée : 

Note :
Java -> détecter accès à un buffer
Appli Java -> buffer depuis socket
Si Appli servlet -> Tomcat +Java runtime, interface request / response -> membrane pas socket -> mais la libhttp

Mesures : 
CPU load

CPU time usage 
CPU 

Problème d'allignement mémoire -> autre allocateur (toute allocation alignée) -> fragmentation coûte mémoire
libhttp -> modifier l'allignement mémoire (très spécifique) au niveau librairie -> aligner que ce qui te plait


Bench 	-> charge tout le temps la même -> cpu load
Latence -> impact sur la latence 
Débit 	-> 1 serveur equivalent , front-end / back-end -> eux vont saturer


comparer en mode shortcut / vs payload virtuel overhead sur front-end / back-end
Monter inconvénients pas bénéfices -> besoin de mesurer reduction de charge sur IS.
Baisse de débit + augmentation de latence. -> Pas trop de dégradation -> Débit, Latence
Doublé les mesures

Mesures selon nobre de serveur intermédiaire
Mesures virtuels sans faute ou pas.

Mesure réel 
Mesure virtuel
Mesure virtuelle fauté

Debit, Latence, Charge CPU, Mémoire à haute charge si shortcut traffic -> buffer tcp moins vite remplit

Site traffics réseaux -> partage buffer tcp -> soulage buffer tcp -> montrer connexion monte en débit.

Montrer que pour une charge d'entrée -> on gagne en charge cpu intermédiaire et montrer par dégradation débit + Latence.



Bénéfice sur IS


fournir une publi -> fait le rapport

// faire de l'injection de charge -> https://locust.io/
// measure cpu time -> https://stackoverflow.com/questions/5248915/execution-time-of-c-program

Made In abyss
To Your Eternity

ref : 
	Measure :
		-http://oak.cs.ucla.edu/refs/locust/index.html
		-https://locust.io/
		-https://docs.locust.io/en/stable/writing-a-locustfile.html#httpuser-class
		-https://docs.locust.io/en/stable/increase-performance.html#locust.contrib.fasthttp.FastHttpUser
		-https://hackertarget.com/tshark-tutorial-and-filter-examples/
		-https://labex.io/fr/tutorials/wireshark-use-tshark-for-network-traffic-analysis-415942
		-https://kloudvm.medium.com/simple-bash-script-to-monitor-cpu-memory-and-disk-usage-on-linux-in-10-lines-of-code-e4819fe38bf1


		Piste résolution problème -> appel à init à chaque fonction surchargé comme avant.


perf cpu -> demander à Brice / Téo 
SAR 

Note : 
Problème identifié avec réception virtual to real.
Devrais ajouter possibilité de récupérer en virtuel si pas encore en cours de téléchargement du body.
Dois surtout corriger téléchargement en réél.