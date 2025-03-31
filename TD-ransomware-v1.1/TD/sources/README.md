Q1 :L'algorithme utilisé est le chiffrement XOR, qui applique un XOR entre les données et une clé répétée. Il est peu sécurisé, car une clé courte peut être facilement retrouvée par des analyses ou attaques par répétition.

Q2 : On ne hache pas directement le sel et la clé car un simple hash ne ralentit pas suffisamment les attaques par brute force. Utiliser PBKDF2HMAC permet d'ajouter un facteur d'itérations, rendant le calcul plus coûteux pour un attaquant.

Q3 : Il est préférable de vérifier si token.bin existe déjà pour éviter de recréer un nouveau token à chaque exécution. Cela assure la cohérence des éléments cryptographiques entre les différentes sessions du programme.

Q4 : Pour vérifier si la clé est correcte, on peut la hasher avec le salt et comparer le résultat avec le hash stocké lors du chiffrement.
Si les résultats correspondent, alors la clé est valide.
