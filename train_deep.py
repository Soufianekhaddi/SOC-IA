import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import joblib
import pickle

# 1. Chargement des données (Comme avant)
print("[*] Chargement du Dataset...")
# On utilise un dataset d'exemple si tu n'as pas le tien, sinon mets ton csv
data = pd.read_csv('dataset_waf.csv') # Assure-toi d'avoir ce fichier ou utilise tes données

# On mélange
data = data.sample(frac=1).reset_index(drop=True)

# Extraction
urls = data['url'].values
labels = data['label'].values # 1 = Bad, 0 = Good

# 2. Préparation pour le Deep Learning (Tokenization)
# Le Deep Learning ne lit pas de texte, il veut des nombres.
vocab_size = 10000  # On garde les 10,000 "mots/caractères" les plus fréquents
max_length = 200    # On coupe les URLs trop longues
oov_tok = "<OOV>"   # Pour les caractères inconnus

print("[*] Tokenization des URLs...")
tokenizer = Tokenizer(num_words=vocab_size, oov_token=oov_tok, char_level=False)
tokenizer.fit_on_texts(urls)

sequences = tokenizer.texts_to_sequences(urls)
padded = pad_sequences(sequences, maxlen=max_length, padding='post', truncating='post')

# 3. Création du Modèle (Réseau de Neurones)
print("[*] Construction du Réseau de Neurones...")
model = tf.keras.Sequential([
    tf.keras.layers.Embedding(vocab_size, 16, input_length=max_length),
    tf.keras.layers.GlobalAveragePooling1D(),
    tf.keras.layers.Dense(24, activation='relu'), # Couche cachée 1
    tf.keras.layers.Dense(1, activation='sigmoid') # Sortie (Probabilité entre 0 et 1)
])

model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# 4. Entraînement
print("[*] Entraînement en cours (patience...)...")
num_epochs = 5
history = model.fit(padded, labels, epochs=num_epochs, validation_split=0.2, verbose=1)

# 5. Sauvegarde
print("[*] Sauvegarde du Cerveau Deep Learning...")
model.save('waf_deep_model.h5') # Le modèle lourd

# On doit aussi sauvegarder le tokenizer pour parler la même langue que le modèle
with open('tokenizer.pickle', 'wb') as handle:
    pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)

print("✅ Modèle Deep Learning généré avec succès !")
