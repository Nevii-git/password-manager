#ifndef VAULT_H
#define VAULT_H

#include <stdbool.h>
#include <stddef.h>

// Initialise libsodium (à appeler UNE fois au lancement de l'appli)
int vault_sodium_init(void);

// Vérifie si le fichier de coffre existe déjà
bool vault_exists(void);

// Crée un nouveau coffre avec un mot de passe maître
int vault_create_new(const char* master_pwd);

// Ouvre un coffre existant avec le mot de passe maître
int vault_open(const char* master_pwd);

// Ajoute une entrée (site, id, mdp) au coffre et sauvegarde
int vault_add_entry(const char* site, const char* id, const char* password);

// Récupère TOUTES les entrées (texte lisible "site\tid\tmdp\n...")
// -> renvoie un buffer alloué avec malloc, à libérer avec free()
char* vault_get_all_entries(void);

// Génère un mot de passe aléatoire de longueur len (len >= 1)
// out doit avoir une taille d'au moins len+1
void vault_generate_password(char* out, size_t len);

// Libère les buffers internes en mémoire
void vault_cleanup(void);

#endif
